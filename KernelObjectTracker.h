// KernelObjectTracker.h
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <map>
#include <set>

struct ObjectStateChangeInfo {
    std::wstring objectName;
    std::wstring objectType;
    std::wstring stateChange;
    SYSTEMTIME timestamp;
};

struct ObjectStats {
    ULONG handleCount;
    ULONG referenceCount;
    SIZE_T memoryUsage;
    SYSTEMTIME lastAccessTime;
};

class KernelObjectTracker {
public:
    KernelObjectTracker();
    ~KernelObjectTracker();

    void startTracking(const std::wstring& path);
    void stopTracking();
    void setStateChangeHandler(std::function<void(const ObjectStateChangeInfo&)> handler);
    std::map<std::wstring, ObjectStats> getTrackingStatistics();
    void updateStats();

    std::vector<std::pair<std::wstring, std::wstring>> queryDirectoryObjects(const std::wstring& path);
    void handleStateChanges(
        const std::vector<std::pair<std::wstring, std::wstring>>& prevObjects,
        const std::vector<std::pair<std::wstring, std::wstring>>& currentObjects
    );
    void reportStateChange(const std::pair<std::wstring, std::wstring>& object, const std::wstring& changeType);

private:
    void trackingThreadFunc();
    bool compareObjectSets(
        const std::vector<std::pair<std::wstring, std::wstring>>& oldSet,
        const std::vector<std::pair<std::wstring, std::wstring>>& newSet
    );

    std::thread trackingThread;
    std::atomic<bool> isTracking;
    std::wstring trackedPath;
    std::function<void(const ObjectStateChangeInfo&)> stateChangeHandler;
    std::map<std::wstring, ObjectStats> statistics;

    std::set<std::wstring> ignoredObjects; 
    SYSTEMTIME lastResetTime;             
};
