// DeadlockDetector.h
#pragma once
#include <windows.h>
#include <vector>
#include <map>
#include <string>
#include <thread>

struct WaitChainInfo {
    DWORD waitingProcessId;
    DWORD waitingThreadId;
    HANDLE waitObject;
    std::wstring objectName;
    std::wstring objectType;
};

class DeadlockDetector {
public:
    std::map<DWORD, std::vector<WaitChainInfo>> waitChains;

    DeadlockDetector();
    ~DeadlockDetector();

    void startDetection();
    void stopDetection();
    bool hasCycle(const std::vector<WaitChainInfo>& chain);

    void detectDeadlocks();
    std::vector<WaitChainInfo> getWaitChain(DWORD processId, DWORD threadId);

    void setDetectionInterval(DWORD milliseconds);
    void enableLiveMonitoring(bool enable);

private:
    bool isRunning;
    DWORD detectionInterval;
    std::thread detectionThread;


    bool analyzeWaitChain(const std::vector<WaitChainInfo>& chain);
    void updateWaitChains();
};