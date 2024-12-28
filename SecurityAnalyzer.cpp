// SecurityAnalyzer.cpp
#include "SecurityAnalyzer.h"
#include <memory>
#include <queue>
#include <set>
#include <stdexcept>    
#include <winternl.h>
#include <psapi.h>
#include <windows.h>

#pragma comment(lib, "ntdll.lib")

#define DIRECTORY_QUERY                 0x0001
#define SYMBOLIC_LINK_QUERY            0x0001
#define STATUS_NO_MORE_ENTRIES         ((NTSTATUS)0x8000001AL)
#define STATUS_INFO_LENGTH_MISMATCH    ((NTSTATUS)0xC0000004L)
#define SystemExtendedHandleInformation 64

extern "C" {
    NTSTATUS NTAPI NtDuplicateObject(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Options
    );

    NTSTATUS NTAPI NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI NtOpenSymbolicLinkObject(
        PHANDLE LinkHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQuerySymbolicLinkObject(
        HANDLE LinkHandle,
        PUNICODE_STRING LinkTarget,
        PULONG ReturnedLength
    );

    NTSTATUS NTAPI NtOpenSection(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );
}



extern "C" NTSTATUS NTAPI NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

SecurityAnalyzer::SecurityAnalyzer() {}
SecurityAnalyzer::~SecurityAnalyzer() {}

void SecurityAnalyzer::analyzeObjectDependencies(const std::wstring& objectName) {
    struct ObjectAnalysisData {
        std::wstring objectName;
        std::wstring objectType;
        ULONG handleCount;
        ULONG referenceCount;
        std::vector<std::wstring> linkedObjects;
        ACCESS_MASK accessMask;
    };

    ObjectAnalysisData analysisData;
    analysisData.objectName = objectName;

    HANDLE hObject = nullptr;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    UNICODE_STRING uniObjectName;
    RtlInitUnicodeString(&uniObjectName, objectName.c_str());
    InitializeObjectAttributes(&objAttr, &uniObjectName, 0, NULL, NULL);
    IO_STATUS_BLOCK ioStatus = { 0 };

    NTSTATUS status = NtOpenFile(
        &hObject,
        FILE_READ_ATTRIBUTES | FILE_READ_DATA,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ,
        FILE_OPEN_FOR_BACKUP_INTENT
    );

    if (NT_SUCCESS(status)) {
        // Get object type information
        std::vector<BYTE> typeBuffer;
        ULONG typeInfoSize = 0;
        status = NtQueryObject(hObject, ObjectTypeInformation, nullptr, 0, &typeInfoSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH && typeInfoSize > 0) {
            typeBuffer.resize(typeInfoSize);
            status = NtQueryObject(
                hObject,
                ObjectTypeInformation,
                typeBuffer.data(),
                typeInfoSize,
                nullptr
            );

            if (NT_SUCCESS(status)) {
                POBJECT_TYPE_INFORMATION typeInfo =
                    reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeBuffer.data());
                analysisData.objectType = std::wstring(
                    typeInfo->TypeName.Buffer,
                    typeInfo->TypeName.Length / sizeof(WCHAR)
                );
                analysisData.handleCount = typeInfo->TotalNumberOfHandles;
                analysisData.referenceCount = typeInfo->TotalNumberOfObjects;
            }
        }

        // Get handle information
        std::vector<BYTE> buffer(1024 * 1024); // 1MB initial buffer
        ULONG returnLength = 0;

        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            PSYSTEM_HANDLE_INFORMATION_EX handleInfo =
                reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());

            for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
                const auto& handle = handleInfo->Handles[i];

                HANDLE processHandle = OpenProcess(
                    PROCESS_DUP_HANDLE,
                    FALSE,
                    static_cast<DWORD>(handle.UniqueProcessId)
                );

                if (processHandle) {
                    HANDLE dupHandle = nullptr;
                    if (NT_SUCCESS(NtDuplicateObject(
                        processHandle,
                        reinterpret_cast<HANDLE>(handle.HandleValue),
                        GetCurrentProcess(),
                        &dupHandle,
                        0,
                        0,
                        0
                    ))) {
                        std::vector<BYTE> nameBuffer(1024);
                        ULONG nameLength = 0;

                        status = NtQueryObject(
                            dupHandle,
                            ObjectNameInformation,
                            nameBuffer.data(),
                            static_cast<ULONG>(nameBuffer.size()),
                            &nameLength
                        );

                        if (NT_SUCCESS(status)) {
                            POBJECT_NAME_INFORMATION nameInfo =
                                reinterpret_cast<POBJECT_NAME_INFORMATION>(nameBuffer.data());

                            if (nameInfo->Name.Buffer) {
                                std::wstring handleObjectName(
                                    nameInfo->Name.Buffer,
                                    nameInfo->Name.Length / sizeof(WCHAR)
                                );

                                if (handleObjectName == objectName) {
                                    analysisData.accessMask = handle.GrantedAccess;
                                }
                            }
                        }

                        CloseHandle(dupHandle);
                    }
                    CloseHandle(processHandle);
                }
            }
        }

        CloseHandle(hObject);
    }

    if (analysisHandler) {
        analysisHandler(
            analysisData.objectName,
            analysisData.objectType,
            analysisData.handleCount,
            analysisData.referenceCount,
            analysisData.linkedObjects,
            analysisData.accessMask
        );
    }
}

std::map<std::wstring, size_t> SecurityAnalyzer::getObjectTypeStatistics(const std::wstring& targetDirectory) {
    std::map<std::wstring, size_t> statistics;
    HANDLE hDirectory = nullptr;
    UNICODE_STRING uniPath;
    OBJECT_ATTRIBUTES objAttributes = { sizeof(OBJECT_ATTRIBUTES) };

    RtlInitUnicodeString(&uniPath, targetDirectory.c_str());
    InitializeObjectAttributes(&objAttributes, &uniPath, 0, NULL, NULL);

    NTSTATUS status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttributes);
    if (NT_SUCCESS(status)) {
        const ULONG bufferSize = 8192;
        BYTE buffer[bufferSize];
        ULONG context = 0;
        ULONG returnLength;
        BOOLEAN restart = TRUE;

        while (true) {
            status = NtQueryDirectoryObject(
                hDirectory,
                buffer,
                bufferSize,
                FALSE,
                restart,
                &context,
                &returnLength
            );

            if (!NT_SUCCESS(status) || status == STATUS_NO_MORE_ENTRIES) {
                break;
            }

            POBJECT_DIRECTORY_INFORMATION dirInfo =
                reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer);

            while (dirInfo->Name.Length != 0) {
                std::wstring typeName(
                    dirInfo->TypeName.Buffer,
                    dirInfo->TypeName.Length / sizeof(WCHAR)
                );
                statistics[typeName]++;
                dirInfo++;
            }

            restart = FALSE;
        }

        CloseHandle(hDirectory);
    }

    return statistics;
}