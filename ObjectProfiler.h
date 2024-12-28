// ObjectProfiler.h
#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <mutex>
#include <functional>
#include <psapi.h>

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

struct ObjectLifetimeStats {
    std::chrono::system_clock::time_point creationTime;
    std::chrono::duration<double> lifetime;
    uint64_t totalHandleOpenCount;
    uint64_t handleCount;
    uint64_t currentHandleCount;
    uint64_t peakHandleCount;
    uint64_t referenceCount;
    SIZE_T memoryUsage;
    SYSTEMTIME lastAccessTime;
};

struct ObjectUsagePattern {
    std::vector<std::chrono::system_clock::time_point> accessTimes;
    std::vector<std::wstring> accessingProcesses;
    std::map<DWORD, uint64_t> processAccessCount;
};

struct AnomalyRecord {
    std::chrono::system_clock::time_point timestamp;
    std::wstring objectName;
    std::wstring anomalyType;
    std::wstring description;
};

using AnomalyHandler = std::function<void(const AnomalyRecord&)>;

class ObjectProfiler {
public:
    ObjectProfiler();
    ~ObjectProfiler();

    void startProfiling(const std::wstring& targetObject);
    void stopProfiling(const std::wstring& targetObject);

    ObjectLifetimeStats getLifetimeStats(const std::wstring& objectName);
    ObjectUsagePattern getUsagePattern(const std::wstring& objectName);

    void detectAnomalies(const std::wstring& objectName);
    void exportProfilingData(const std::wstring& filepath);

    void setAnomalyHandler(AnomalyHandler handler) { anomalyHandler = handler; }

private:
    std::map<std::wstring, HANDLE> stopEvents; // Для зберігання подій зупинки

    struct ProfilingContext {
        ObjectLifetimeStats stats;
        ObjectUsagePattern pattern;
        bool isActive;
    };

    std::map<std::wstring, ProfilingContext> profiledObjects;
    std::vector<AnomalyRecord> anomalyHistory;
    std::mutex profilerMutex;
    SYSTEMTIME lastResetTime;
    AnomalyHandler anomalyHandler;

    void updateStats(const std::wstring& objectName);
    void startStatisticsUpdate(const std::wstring& objectName);
    bool isAnomalous(const ObjectUsagePattern& pattern);
    std::wstring getProcessName(DWORD processId);
    std::wstring getCurrentTimeString();
    std::wstring formatTimePoint(const std::chrono::system_clock::time_point& timePoint);
    std::wstring formatMemorySize(SIZE_T bytes);
};
