// DeadlockDetector.cpp

#include "DeadlockDetector.h"
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <algorithm>
#include <queue>
#include <set>
#include <Psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

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
}

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
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

// NT API function declarations
extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemExtendedHandleInformation 64

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

DeadlockDetector::DeadlockDetector() :
    isRunning(false),
    detectionInterval(1000) {
}

DeadlockDetector::~DeadlockDetector() {
    stopDetection();
}

void DeadlockDetector::startDetection() {
    if (!isRunning) {
        isRunning = true;
        detectionThread = std::thread([this]() {
            while (isRunning) {
                detectDeadlocks();
                std::this_thread::sleep_for(std::chrono::milliseconds(detectionInterval));
            }
            });
    }
}
void DeadlockDetector::stopDetection() {
    if (isRunning) {
        isRunning = false;
        if (detectionThread.joinable()) {
            detectionThread.join();
        }
        waitChains.clear();
    }
}

void DeadlockDetector::setDetectionInterval(DWORD milliseconds) {
    detectionInterval = milliseconds;
}

void DeadlockDetector::enableLiveMonitoring(bool enable) {
    if (enable && !isRunning) {
        startDetection();
    }
    else if (!enable && isRunning) {
        stopDetection();
    }
}

std::vector<WaitChainInfo> DeadlockDetector::getWaitChain(DWORD processId, DWORD threadId) {
    std::vector<WaitChainInfo> chain;
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);

    if (!hThread) {
        return chain;
    }

    HANDLE hCurrentProcess = GetCurrentProcess();
    std::vector<BYTE> buffer;
    ULONG bufferSize = 1024 * 1024; // Start with 1MB
    ULONG returnLength = 0;

    do {
        buffer.resize(bufferSize);
        NTSTATUS status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
            buffer.data(),
            bufferSize,
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            break;
        }

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
            continue;
        }

        CloseHandle(hThread);
        return chain;
    } while (true);

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo =
        reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        const auto& handle = handleInfo->Handles[i];

        if (handle.UniqueProcessId != processId) {
            continue;
        }

        HANDLE hObject;
        NTSTATUS status = NtDuplicateObject(
            hThread,
            (HANDLE)handle.HandleValue,
            hCurrentProcess,
            &hObject,
            0,
            0,
            0
        );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        OBJECT_BASIC_INFORMATION basicInfo;
        status = NtQueryObject(
            hObject,
            ObjectBasicInformation,
            &basicInfo,
            sizeof(basicInfo),
            nullptr
        );

        if (NT_SUCCESS(status)) {
            PVOID typeInfo = nullptr;
            ULONG typeInfoLength = 0;

            status = NtQueryObject(
                hObject,
                ObjectTypeInformation,
                nullptr,
                0,
                &typeInfoLength
            );

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                std::vector<BYTE> typeInfoBuffer(typeInfoLength);
                status = NtQueryObject(
                    hObject,
                    ObjectTypeInformation,
                    typeInfoBuffer.data(),
                    typeInfoLength,
                    nullptr
                );

                if (NT_SUCCESS(status)) {
                    POBJECT_TYPE_INFORMATION type =
                        reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeInfoBuffer.data());

                    WaitChainInfo info;
                    info.waitingProcessId = processId;
                    info.waitingThreadId = threadId;
                    info.waitObject = (HANDLE)handle.HandleValue;
                    info.objectType = std::wstring(
                        type->TypeName.Buffer,
                        type->TypeName.Length / sizeof(WCHAR)
                    );

                    chain.push_back(info);
                }
            }
        }

        CloseHandle(hObject);
    }

    CloseHandle(hThread);
    return chain;
}

bool DeadlockDetector::hasCycle(const std::vector<WaitChainInfo>& chain) {
    std::set<DWORD> visited;
    for (const auto& info : chain) {
        if (!visited.insert(info.waitingThreadId).second) {
            return true;
        }
    }
    return false;
}


void DeadlockDetector::updateWaitChains() {
    waitChains.clear();

    DWORD processes[1024];
    DWORD needed;

    if (!EnumProcesses(processes, sizeof(processes), &needed)) {
        return;
    }

    DWORD numProcesses = needed / sizeof(DWORD);

    for (DWORD i = 0; i < numProcesses; i++) {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );

        if (!hProcess) {
            continue;
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 threadEntry;
            threadEntry.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &threadEntry)) {
                do {
                    if (threadEntry.th32OwnerProcessID == processes[i]) {
                        auto chain = getWaitChain(processes[i], threadEntry.th32ThreadID);
                        if (!chain.empty()) {
                            waitChains[processes[i]] = chain;
                        }
                    }
                } while (Thread32Next(hSnapshot, &threadEntry));
            }
            CloseHandle(hSnapshot);
        }

        CloseHandle(hProcess);
    }
}

void DeadlockDetector::detectDeadlocks() {
    if (!isRunning) {
        return;
    }

    std::vector<DWORD> processes(1024);
    DWORD cbNeeded;

    if (!EnumProcesses(processes.data(), sizeof(DWORD) * 1024, &cbNeeded)) {
        return;
    }

    DWORD numProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < numProcesses; i++) {
        if (processes[i] == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess == nullptr) continue;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processes[i]) {
                        WaitChainInfo info;
                        info.waitingProcessId = processes[i];
                        info.waitingThreadId = te32.th32ThreadID;

                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            FILETIME creation, exit, kernel, user;
                            if (GetThreadTimes(hThread, &creation, &exit, &kernel, &user)) {
                                if (exit.dwLowDateTime == 0 && exit.dwHighDateTime == 0) {
                                    waitChains[processes[i]].push_back(info);
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
        CloseHandle(hProcess);
    }
}


bool DeadlockDetector::analyzeWaitChain(const std::vector<WaitChainInfo>& chain) {
    if (chain.empty()) {
        return false;
    }

    std::set<std::pair<DWORD, DWORD>> edges;

    for (size_t i = 0; i < chain.size() - 1; i++) {
        edges.insert(std::make_pair(
            chain[i].waitingThreadId,
            chain[i + 1].waitingThreadId
        ));
    }

    // Check if last thread waits for any previous thread
    auto lastThread = chain.back().waitingThreadId;
    for (const auto& info : chain) {
        if (info.waitingThreadId != lastThread) {
            auto edge = std::make_pair(lastThread, info.waitingThreadId);
            if (edges.find(edge) != edges.end()) {
                return true; // Cycle detected
            }
        }
    }

    return false;
}