// KernelObjectTracker.cpp
#include "KernelObjectTracker.h"
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <set>

#pragma comment(lib, "ntdll.lib")

#define DIRECTORY_QUERY                 0x0001
#define SYMBOLIC_LINK_QUERY            0x0001

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

KernelObjectTracker::KernelObjectTracker() : isTracking(false) {}

KernelObjectTracker::~KernelObjectTracker() { stopTracking(); }

void KernelObjectTracker::startTracking(const std::wstring& path) {
    if (isTracking) {
        return;
    }

    trackedPath = path;
    isTracking = true;
    trackingThread = std::thread(&KernelObjectTracker::trackingThreadFunc, this);
}

void KernelObjectTracker::stopTracking() {
    if (!isTracking) {
        return;
    }

    isTracking = false;
    if (trackingThread.joinable()) {
        trackingThread.join();
    }
}

void KernelObjectTracker::setStateChangeHandler(std::function<void(const ObjectStateChangeInfo&)> handler) {
    stateChangeHandler = handler;
}

std::map<std::wstring, ObjectStats> KernelObjectTracker::getTrackingStatistics() {
    return statistics;
}

void KernelObjectTracker::updateStats() {
    HANDLE hDirectory = nullptr;
    OBJECT_ATTRIBUTES objAttributes = { 0 };
    UNICODE_STRING uniPath = { 0 };

    RtlInitUnicodeString(&uniPath, trackedPath.c_str());

    InitializeObjectAttributes(&objAttributes,
        &uniPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    NTSTATUS status = NtOpenDirectoryObject(&hDirectory,
        DIRECTORY_QUERY,
        &objAttributes);

    if (!NT_SUCCESS(status)) {
        return;
    }

    std::vector<std::pair<std::wstring, std::wstring>> currentObjects;
    const ULONG bufferSize = 8192;
    ULONG context = 0;
    ULONG returnLength;
    BYTE buffer[bufferSize] = { 0 };
    BOOLEAN restart = TRUE;

    while (TRUE) {
        status = NtQueryDirectoryObject(hDirectory,
            buffer,
            bufferSize,
            FALSE,
            restart,
            &context,
            &returnLength);

        if (!NT_SUCCESS(status)) {
            break;
        }

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        while (info->Name.Length != 0) {
            std::wstring name(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
            std::wstring type(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));

            currentObjects.push_back({ name, type });

            ObjectStats& stats = statistics[name];
            stats.handleCount = 0;
            stats.referenceCount = 0;
            stats.memoryUsage = 0;
            GetSystemTime(&stats.lastAccessTime);

            info++;
        }

        restart = FALSE;
    }

    CloseHandle(hDirectory);
}

void KernelObjectTracker::trackingThreadFunc() {
    std::vector<std::pair<std::wstring, std::wstring>> prevObjects;

    while (isTracking) {
        auto currentObjects = queryDirectoryObjects(trackedPath);

        if (!prevObjects.empty()) {
            handleStateChanges(prevObjects, currentObjects);
        }

        prevObjects = std::move(currentObjects);
        updateStats();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

std::vector<std::pair<std::wstring, std::wstring>> KernelObjectTracker::queryDirectoryObjects(const std::wstring& path) {
    std::vector<std::pair<std::wstring, std::wstring>> objects;

    HANDLE hDirectory = nullptr;
    OBJECT_ATTRIBUTES objAttributes = { 0 };
    UNICODE_STRING uniPath = { 0 };

    RtlInitUnicodeString(&uniPath, path.c_str());
    InitializeObjectAttributes(&objAttributes, &uniPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttributes))) {
        const ULONG bufferSize = 8192;
        ULONG context = 0;
        ULONG returnLength;
        BYTE buffer[bufferSize] = { 0 };
        BOOLEAN restart = TRUE;

        while (TRUE) {
            NTSTATUS status = NtQueryDirectoryObject(hDirectory,
                buffer,
                bufferSize,
                FALSE,
                restart,
                &context,
                &returnLength);

            if (!NT_SUCCESS(status)) {
                break;
            }

            POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
            while (info->Name.Length != 0) {
                std::wstring name(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
                std::wstring type(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
                objects.emplace_back(name, type);
                info++;
            }

            restart = FALSE;
        }

        CloseHandle(hDirectory);
    }

    return objects;
}

void KernelObjectTracker::handleStateChanges(
    const std::vector<std::pair<std::wstring, std::wstring>>& prevObjects,
    const std::vector<std::pair<std::wstring, std::wstring>>& currentObjects) {

    std::set<std::pair<std::wstring, std::wstring>> prevSet(prevObjects.begin(), prevObjects.end());
    std::set<std::pair<std::wstring, std::wstring>> currSet(currentObjects.begin(), currentObjects.end());

    for (const auto& obj : currSet) {
        if (prevSet.find(obj) == prevSet.end()) {
            reportStateChange(obj, L"Created");
        }
    }

    for (const auto& obj : prevSet) {
        if (currSet.find(obj) == currSet.end()) {
            reportStateChange(obj, L"Deleted");
        }
    }
}

void KernelObjectTracker::reportStateChange(const std::pair<std::wstring, std::wstring>& object, const std::wstring& changeType) {
    ObjectStateChangeInfo changeInfo;
    changeInfo.objectName = object.first;
    changeInfo.objectType = object.second;
    changeInfo.stateChange = changeType;
    GetSystemTime(&changeInfo.timestamp);

    if (stateChangeHandler) {
        stateChangeHandler(changeInfo);
    }
}



bool KernelObjectTracker::compareObjectSets(
    const std::vector<std::pair<std::wstring, std::wstring>>& oldSet,
    const std::vector<std::pair<std::wstring, std::wstring>>& newSet) {
    return oldSet == newSet;
}
