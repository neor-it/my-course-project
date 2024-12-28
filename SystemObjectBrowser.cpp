// SystemObjectBrowser.cpp
#include "SystemObjectBrowser.h"
#include <iostream>
#include <vector>

#pragma comment(lib, "ntdll.lib")

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK DesiredAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

extern "C" {
    NTSTATUS NTAPI NtOpenDirectoryObject(
        OUT PHANDLE DirectoryHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryDirectoryObject(
        IN HANDLE DirectoryHandle,
        OUT PVOID Buffer,
        IN ULONG Length,
        IN BOOLEAN ReturnSingleEntry,
        IN BOOLEAN RestartScan,
        IN OUT PULONG Context,
        OUT PULONG ReturnLength OPTIONAL
    );

    NTSTATUS NTAPI NtOpenEvent(
        OUT PHANDLE EventHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryObject(
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
}

#define DIRECTORY_QUERY 0x0001
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001A)
#define EVENT_QUERY_STATE 0x0001

SystemObjectBrowser::SystemObjectBrowser() {}
SystemObjectBrowser::~SystemObjectBrowser() {}

std::wstring SystemObjectBrowser::getSystemErrorMessage(DWORD errorCode) {
    LPWSTR messageBuffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        nullptr
    );

    std::wstring errorMsg = messageBuffer ? messageBuffer : L"Unknown error";
    LocalFree(messageBuffer);
    return errorMsg;
}

// Вспомогательная функция для логирования ошибок
void SystemObjectBrowser::logError(const std::wstring& message, DWORD errorCode) {
    std::wcerr << L"[ERROR] " << message
        << L" (Code: " << errorCode << L", Message: "
        << getSystemErrorMessage(errorCode) << L")" << std::endl;
}

// Выполняет глубокое сканирование директории
void SystemObjectBrowser::performDeepScan(const std::wstring& path, bool recursive) {
    std::wcout << L"Starting deep scan of: " << path << std::endl;
    exploreDirectory(path, L"", recursive);
}

// Рекурсивный обход директории
void SystemObjectBrowser::exploreDirectory(const std::wstring& path, const std::wstring& filterType, bool recursive) {
    auto objects = getDirectoryContents(path, filterType);

    for (const auto& object : objects) {
        const std::wstring fullPath = path + L"\\" + object.first;
        const std::wstring& objectType = object.second;

        std::wcout << L"Found: " << fullPath << L" (Type: " << objectType << L")" << std::endl;

        if (recursive && objectType == L"Directory") {
            exploreDirectory(fullPath, filterType, recursive);
        }

        // Проверяем доступ к объекту
        if (!checkObjectAccess(fullPath)) {
            logError(L"Access check failed for " + fullPath, GetLastError());
        }
    }
}

// Выводит детали объекта
void SystemObjectBrowser::showObjectDetails(const std::wstring& objectName) {
    HANDLE objectHandle = openKernelObject(objectName, EVENT_QUERY_STATE);

    if (!objectHandle) {
        logError(L"Failed to open object: " + objectName, GetLastError());
        return;
    }

    OBJECT_BASIC_INFORMATION basicInfo;
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryObject(
        objectHandle,
        ObjectBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        std::wcerr << L"Failed to query object details for: " << objectName << std::endl;
        NtClose(objectHandle);
        return;
    }

    // Отображаем детали
    std::wcout << L"\nObject Details for: " << objectName << std::endl
        << L"===========================================" << std::endl
        << L"Handle Count: " << basicInfo.HandleCount << std::endl
        << L"Reference Count: " << basicInfo.PointerCount << std::endl
        << L"Paged Pool Usage: " << basicInfo.PagedPoolUsage << L" bytes" << std::endl
        << L"Non-Paged Pool Usage: " << basicInfo.NonPagedPoolUsage << L" bytes" << std::endl
        << L"Security Descriptor Size: " << basicInfo.SecurityDescriptorLength << L" bytes" << std::endl
        << L"Attributes: 0x" << std::hex << basicInfo.Attributes << std::dec << std::endl;

    NtClose(objectHandle);
}

// Извлекает содержимое директории
std::vector<std::pair<std::wstring, std::wstring>> SystemObjectBrowser::getDirectoryContents(
    const std::wstring& path,
    const std::wstring& filterType
) {
    std::vector<std::pair<std::wstring, std::wstring>> objects;
    HANDLE dirHandle = openKernelObject(path, DIRECTORY_QUERY);

    if (!dirHandle) {
        logError(L"Failed to open directory: " + path, GetLastError());
        return objects;
    }

    BYTE buffer[4096];
    ULONG context = 0;
    BOOLEAN restart = TRUE;

    while (true) {
        ULONG returnLength = 0;
        NTSTATUS status = NtQueryDirectoryObject(
            dirHandle,
            buffer,
            sizeof(buffer),
            FALSE,
            restart,
            &context,
            &returnLength
        );

        if (status == STATUS_NO_MORE_ENTRIES) {
            break;
        }

        if (!NT_SUCCESS(status)) {
            logError(L"Directory query failed for: " + path, RtlNtStatusToDosError(status));
            break;
        }

        POBJECT_DIRECTORY_INFORMATION dirInfo = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer);
        while (dirInfo->Name.Length > 0) {
            std::wstring typeName(dirInfo->TypeName.Buffer, dirInfo->TypeName.Length / sizeof(wchar_t));
            std::wstring objectName(dirInfo->Name.Buffer, dirInfo->Name.Length / sizeof(wchar_t));

            if (filterType.empty() || typeName == filterType) {
                objects.emplace_back(objectName, typeName);
            }

            dirInfo++;
        }

        restart = FALSE;
    }

    NtClose(dirHandle);
    return objects;
}

// Проверяет доступ к объекту
bool SystemObjectBrowser::checkObjectAccess(const std::wstring& fullPath) {
    HANDLE hObject = OpenEventW(EVENT_QUERY_STATE, FALSE, fullPath.c_str());
    if (!hObject) {
        return false;
    }

    CloseHandle(hObject);
    return true;
}

HANDLE SystemObjectBrowser::openKernelObject(const std::wstring& path, ACCESS_MASK access) {
    UNICODE_STRING unicodePath;
    OBJECT_ATTRIBUTES objAttributes;

    RtlInitUnicodeString(&unicodePath, path.c_str());
    InitializeObjectAttributes(&objAttributes, &unicodePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE handle = nullptr;
    NTSTATUS status = NtOpenDirectoryObject(&handle, access, &objAttributes);

    if (!NT_SUCCESS(status)) {
        return nullptr;
    }

    return handle;
}

void SystemObjectBrowser::listDirectoryObjects(
    const std::wstring& path,
    const std::wstring& filterType,
    bool recursive
) {
    auto objects = getDirectoryContents(path, filterType);
    for (const auto& object : objects) {
        std::wstring fullObjectPath = path + L"\\" + object.first;
        std::wstring objectType = object.second;

        std::wcout << L"Found object: " << fullObjectPath << L" (Type: " << objectType << L")" << std::endl;

        if (recursive && objectType == L"Directory") {
            listDirectoryObjects(fullObjectPath, filterType, recursive);
        }

        if (!checkObjectAccess(fullObjectPath)) {
            continue;
        }
    }
}