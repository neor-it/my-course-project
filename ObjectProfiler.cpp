#include "ObjectProfiler.h"
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <ctime>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

// Додаємо оголошення функцій
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemHandleInformation 16
#define SystemExtendedHandleInformation 64
    

// Додаємо оголошення функцій
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemHandleInformation 16
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


typedef NTSTATUS(NTAPI* NtQueryObject_t)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );
#ifndef DIRECTORY_ALL_ACCESS
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#endif
const LPWSTR privileges[] = {
    const_cast<LPWSTR>(SE_SECURITY_NAME),
    const_cast<LPWSTR>(SE_BACKUP_NAME),
    const_cast<LPWSTR>(SE_RESTORE_NAME),
    const_cast<LPWSTR>(SE_TCB_NAME),
    const_cast<LPWSTR>(SE_TAKE_OWNERSHIP_NAME)
};
extern "C" {
    NTSTATUS NTAPI NtOpenDirectoryObject(
        OUT PHANDLE DirectoryHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );
}
extern "C" {
    NTSTATUS NTAPI NtOpenSymbolicLinkObject(
        OUT PHANDLE LinkHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );
}

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif
extern "C" {
    NTSTATUS NTAPI NtOpenEvent(
        OUT PHANDLE EventHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );
}
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x00000001
#endif
#define SYNCHRONIZE               0x00100000L
#define EVENT_QUERY_STATE        0x0001
#define SECTION_QUERY           0x0001

#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x00000020
#endif

extern "C" {
    NTSTATUS NTAPI NtOpenSection(
        OUT PHANDLE SectionHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );
}

#define EVENT_QUERY_STATE 0x0001

ObjectProfiler::ObjectProfiler() {
    GetSystemTime(&lastResetTime);
}

ObjectProfiler::~ObjectProfiler() {
    for (auto& [name, context] : profiledObjects) {
        if (context.isActive) {
            stopProfiling(name);
        }
    }
}
void ObjectProfiler::startProfiling(const std::wstring& targetObject) {
    std::wcout << L"Starting profiling for: " << targetObject << std::endl;

    // Спочатку отримуємо всі необхідні привілеї
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // Увімкнення привілею налагодження
            auto success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            std::wcout << L"Debug privilege enabled: " << (success ? L"Yes" : L"No") << std::endl;
        }
        CloseHandle(hToken);
    }

    std::lock_guard<std::mutex> lock(profilerMutex);
    auto& context = profiledObjects[targetObject];

    if (!context.isActive) {
        context.isActive = true;
        context.stats = ObjectLifetimeStats{};
        context.stats.creationTime = std::chrono::system_clock::now();
        context.pattern = ObjectUsagePattern{};

        updateStats(targetObject);
        startStatisticsUpdate(targetObject);
        std::wcout << L"Profiling started successfully" << std::endl;
    }
}


void ObjectProfiler::startStatisticsUpdate(const std::wstring& objectName) {
    // Створюємо подію для сигналізації зупинки
    HANDLE hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hStopEvent) {
        stopEvents[objectName] = hStopEvent;

        std::thread([this, objectName, hStopEvent]() {
            std::wcout << L"Background update thread started for: " << objectName << std::endl;

            while (WaitForSingleObject(hStopEvent, 1000) == WAIT_TIMEOUT) {
                std::lock_guard<std::mutex> lock(profilerMutex);
                auto it = profiledObjects.find(objectName);
                if (it == profiledObjects.end() || !it->second.isActive) {
                    break;
                }
                updateStats(objectName);
            }

            std::wcout << L"Background update thread stopped for: " << objectName << std::endl;
            }).detach();
    }
}


void ObjectProfiler::stopProfiling(const std::wstring& targetObject) {
    std::lock_guard<std::mutex> lock(profilerMutex);

    // Сигналізуємо потоку про зупинку
    auto eventIt = stopEvents.find(targetObject);
    if (eventIt != stopEvents.end()) {
        SetEvent(eventIt->second);
        CloseHandle(eventIt->second);
        stopEvents.erase(eventIt);
    }

    auto it = profiledObjects.find(targetObject);
    if (it != profiledObjects.end()) {
        it->second.isActive = false;
        updateStats(targetObject);
    }
}

ObjectLifetimeStats ObjectProfiler::getLifetimeStats(const std::wstring& objectName) {
    std::lock_guard<std::mutex> lock(profilerMutex);

    auto it = profiledObjects.find(objectName);
    if (it != profiledObjects.end()) {
        updateStats(objectName);
        auto& stats = it->second.stats;

        // Оновлюємо статистику часу життя
        if (stats.creationTime != std::chrono::system_clock::time_point()) {
            auto now = std::chrono::system_clock::now();
            auto duration = now - stats.creationTime;
            stats.lifetime = duration;
        }

        return stats;
    }

    return ObjectLifetimeStats{};
}

ObjectUsagePattern ObjectProfiler::getUsagePattern(const std::wstring& objectName) {
    std::lock_guard<std::mutex> lock(profilerMutex);

    auto it = profiledObjects.find(objectName);
    if (it != profiledObjects.end()) {
        return it->second.pattern;
    }
    return ObjectUsagePattern();
}


void ObjectProfiler::detectAnomalies(const std::wstring& objectName) {
    std::lock_guard<std::mutex> lock(profilerMutex);

    auto it = profiledObjects.find(objectName);
    if (it == profiledObjects.end()) {
        return;
    }

    const auto& pattern = it->second.pattern;
    const auto& stats = it->second.stats;

    // Аналізуємо аномалії
    bool hasAnomaly = false;
    std::wstring anomalyDescription;

    // Перевірка на аномально високу кількість відкритих хендлів
    if (stats.handleCount > stats.peakHandleCount * 0.9) {
        hasAnomaly = true;
        anomalyDescription += L"High handle count detected. ";
    }

    // Перевірка на різкі зміни в патерні доступу
    if (!pattern.accessTimes.empty()) {
        auto lastAccess = pattern.accessTimes.back();
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - lastAccess);

        if (duration.count() > 60) { // Більше години без доступу
            hasAnomaly = true;
            anomalyDescription += L"Unusual access pattern detected. ";
        }
    }

    // Перевірка на аномальне використання пам'яті
    if (stats.memoryUsage > 1024 * 1024 * 100) { // Більше 100MB
        hasAnomaly = true;
        anomalyDescription += L"High memory usage detected. ";
    }

    if (hasAnomaly && anomalyHandler) {
        AnomalyRecord record;
        record.timestamp = std::chrono::system_clock::now();
        record.objectName = objectName;
        record.anomalyType = L"Usage anomaly";
        record.description = anomalyDescription;

        anomalyHistory.push_back(record);
        anomalyHandler(record);
    }
}

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

void ObjectProfiler::updateStats(const std::wstring& objectName) {
    auto& context = profiledObjects[objectName];
    if (!context.isActive) {
        return;
    }

    HANDLE hObject = nullptr;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    UNICODE_STRING uniObjectName;

    // 1. Спочатку включаємо всі необхідні привілеї
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }

        CloseHandle(hToken);
    }

    // 2. Відкриваємо об'єкт з повними правами
    RtlInitUnicodeString(&uniObjectName, objectName.c_str());

    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &uniObjectName;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    // 3. Пробуємо різні типи доступу
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // A. Спочатку як директорія
    status = NtOpenDirectoryObject(&hObject, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &objAttr);
    if (!NT_SUCCESS(status)) {
        // B. Як мютекс
        status = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, objectName.c_str()) ? STATUS_SUCCESS : GetLastError();
        if (status != STATUS_SUCCESS) {
            // C. Як event
            status = OpenEventW(EVENT_ALL_ACCESS, FALSE, objectName.c_str()) ? STATUS_SUCCESS : GetLastError();
            if (status != STATUS_SUCCESS) {
                // D. Як семафор
                status = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, objectName.c_str()) ? STATUS_SUCCESS : GetLastError();
            }
        }
    }

    if (NT_SUCCESS(status) || status == STATUS_SUCCESS) {
        // 4. Отримуємо детальну інформацію
        OBJECT_BASIC_INFORMATION basicInfo = { 0 };
        ULONG returnLength = 0;

        status = NtQueryObject(
            hObject,
            ObjectBasicInformation,
            &basicInfo,
            sizeof(basicInfo),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            // 5. Оновлюємо всю статистику
            context.stats.handleCount = basicInfo.HandleCount;
            context.stats.currentHandleCount = basicInfo.HandleCount;
            context.stats.referenceCount = basicInfo.PointerCount;
            context.stats.memoryUsage = basicInfo.PagedPoolUsage + basicInfo.NonPagedPoolUsage;

            if (basicInfo.HandleCount > context.stats.peakHandleCount) {
                context.stats.peakHandleCount = basicInfo.HandleCount;
            }

            context.stats.totalHandleOpenCount++;

            // 6. Додаємо шаблон використання
            DWORD processId = GetCurrentProcessId();

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcess) {
                WCHAR processName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH)) {
                    context.pattern.accessingProcesses.push_back(processName);
                }
                CloseHandle(hProcess);
            }

            context.pattern.accessTimes.push_back(std::chrono::system_clock::now());
            context.pattern.processAccessCount[processId]++;
        }

        CloseHandle(hObject);
    }

    GetSystemTime(&context.stats.lastAccessTime);
}


bool ObjectProfiler::isAnomalous(const ObjectUsagePattern& pattern) {
    if (pattern.accessTimes.size() < 2) {
        return false;
    }

    std::vector<double> intervals;
    for (size_t i = 1; i < pattern.accessTimes.size(); ++i) {
        auto diff = pattern.accessTimes[i] - pattern.accessTimes[i - 1];
        intervals.push_back(std::chrono::duration<double>(diff).count());
    }

    double sum = 0;
    for (double interval : intervals) {
        sum += interval;
    }
    double mean = sum / intervals.size();

    double sqSum = 0;
    for (double interval : intervals) {
        double diff = interval - mean;
        sqSum += (diff * diff);
    }
    double stdDev = std::sqrt(sqSum / intervals.size());

    for (double interval : intervals) {
        if (std::abs(interval - mean) > 3 * stdDev) {
            return true;
        }
    }

    size_t accessThreshold = 100;
    if (pattern.accessTimes.size() > accessThreshold) {
        auto now = std::chrono::system_clock::now();
        size_t recentAccesses = 0;

        for (const auto& time : pattern.accessTimes) {
            if ((now - time) < std::chrono::minutes(1)) {
                recentAccesses++;
            }
        }

        if (recentAccesses > accessThreshold) {
            return true;
        }
    }

    return false;
}

void ObjectProfiler::exportProfilingData(const std::wstring& filepath) {
    std::lock_guard<std::mutex> lock(profilerMutex);

    std::wofstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open output file");
    }

    file << L"Object Profiling Report\n";
    file << L"Generated: " << getCurrentTimeString() << L"\n\n";

    for (const auto& [name, context] : profiledObjects) {
        file << L"Object: " << name << L"\n";
        file << L"Status: " << (context.isActive ? L"Active" : L"Inactive") << L"\n";

        auto duration = std::chrono::system_clock::now() - context.stats.creationTime;
        auto hours = std::chrono::duration_cast<std::chrono::hours>(duration).count();
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count() % 60;

        file << L"Lifetime: " << hours << L" hours, " << minutes << L" minutes\n";
        file << L"Total Handles: " << context.stats.totalHandleOpenCount << L"\n";
        file << L"Current Handles: " << context.stats.currentHandleCount << L"\n";
        file << L"Peak Handles: " << context.stats.peakHandleCount << L"\n";
        file << L"Memory Usage: " << formatMemorySize(context.stats.memoryUsage) << L"\n";

        file << L"\nAccess Pattern:\n";
        for (size_t i = 0; i < context.pattern.accessTimes.size(); ++i) {
            auto timePoint = context.pattern.accessTimes[i];
            file << L"  " << formatTimePoint(timePoint)
                << L" by " << context.pattern.accessingProcesses[i] << L"\n";
        }

        file << L"\nProcess Access Statistics:\n";
        for (const auto& [pid, count] : context.pattern.processAccessCount) {
            std::wstring processName = getProcessName(pid);
            file << L"  " << processName << L" (PID: " << pid << L"): "
                << count << L" accesses\n";
        }

        file << L"\n----------------------------------------\n\n";
    }

    if (!anomalyHistory.empty()) {
        file << L"\nAnomaly History:\n";
        for (const auto& anomaly : anomalyHistory) {
            file << L"Time: " << formatTimePoint(anomaly.timestamp) << L"\n";
            file << L"Object: " << anomaly.objectName << L"\n";
            file << L"Type: " << anomaly.anomalyType << L"\n";
            file << L"Description: " << anomaly.description << L"\n\n";
        }
    }
}

std::wstring ObjectProfiler::getProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        WCHAR processName[MAX_PATH];
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
            CloseHandle(hProcess);
            return std::wstring(processName);
        }
        CloseHandle(hProcess);
    }
    return L"Unknown Process";
}

std::wstring ObjectProfiler::getCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm timeinfo;
    localtime_s(&timeinfo, &time);
    std::wstringstream wss;
    wss << std::put_time(&timeinfo, L"%Y-%m-%d %H:%M:%S");
    return wss.str();
}
std::wstring ObjectProfiler::formatTimePoint(const std::chrono::system_clock::time_point& timePoint) {
    auto time = std::chrono::system_clock::to_time_t(timePoint);
    struct tm timeinfo;
    localtime_s(&timeinfo, &time);
    std::wstringstream wss;
    wss << std::put_time(&timeinfo, L"%Y-%m-%d %H:%M:%S");
    return wss.str();
}
std::wstring ObjectProfiler::formatMemorySize(SIZE_T bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    int unitIndex = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024 && unitIndex < 3) {
        size /= 1024;
        unitIndex++;
    }

    std::wstringstream wss;
    wss << std::fixed << std::setprecision(2) << size << L" " << units[unitIndex];
    return wss.str();
}