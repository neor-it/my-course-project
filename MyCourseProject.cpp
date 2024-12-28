#include "KernelObjectTracker.h"
#include "SecurityAnalyzer.h"
#include "SystemObjectBrowser.h"
#include "AnalyticsReporter.h"
#include "ObjectProfiler.h"
#include "DeadlockDetector.h"
#include <iostream>
#include <string>
#include <iomanip>
#include <chrono>
#include <limits>
#include <thread>
#include <sstream>

void showDeadlockMenu(DeadlockDetector& detector);
void showBrowserMenu(SystemObjectBrowser& browser);
void showMonitoringMenu(KernelObjectTracker& tracker, bool& monitoringActive);
void showAnalyticsMenu(AnalyticsReporter& reporter, SecurityAnalyzer& analyzer);
void showSecurityMenu(SecurityAnalyzer& analyzer);
void showProfilerMenu(ObjectProfiler& profiler);


void handleObjectStateChange(const ObjectStateChangeInfo& stateInfo) {
    SYSTEMTIME& time = const_cast<SYSTEMTIME&>(stateInfo.timestamp);
    std::wcout << std::setfill(L'0')
        << time.wYear << L"-"
        << std::setw(2) << time.wMonth << L"-"
        << std::setw(2) << time.wDay << L" "
        << std::setw(2) << time.wHour << L":"
        << std::setw(2) << time.wMinute << L":"
        << std::setw(2) << time.wSecond << L" - ";

    std::wcout << L"Object " << stateInfo.objectName
        << L" (" << stateInfo.objectType << L") "
        << stateInfo.stateChange << L"\n";
}

std::wstring formatTimePoint(const std::chrono::system_clock::time_point& timePoint) {
    std::time_t timeT = std::chrono::system_clock::to_time_t(timePoint);
    struct tm timeinfo;
    localtime_s(&timeinfo, &timeT);
    std::wstringstream wss;
    wss << std::put_time(&timeinfo, L"%Y-%m-%d %H:%M:%S");
    return wss.str();
}

void handleAnomaly(const AnomalyRecord& anomaly) {
    std::wcout << L"\n[ANOMALY DETECTED]\n"
        << L"Time: " << formatTimePoint(anomaly.timestamp) << L"\n"
        << L"Object: " << anomaly.objectName << L"\n"
        << L"Type: " << anomaly.anomalyType << L"\n"
        << L"Description: " << anomaly.description << L"\n\n";
    #include <sstream>
#include "DeadlockDetector.h"
}

void handleSecurityAnalysis(
    const std::wstring& objectName,
    const std::wstring& objectType,
    ULONG handleCount,
    ULONG referenceCount,
    const std::vector<std::wstring>& linkedObjects,
    ACCESS_MASK accessMask) {

    std::wcout << L"\nSecurity Analysis Results for: " << objectName << L"\n"
        << L"Type: " << objectType << L"\n"
        << L"Handle Count: " << handleCount << L"\n"
        << L"Reference Count: " << referenceCount << L"\n"
        << L"Access Mask: 0x" << std::hex << accessMask << std::dec << L"\n";

    if (!linkedObjects.empty()) {
        std::wcout << L"Linked Objects:\n";
        for (const auto& obj : linkedObjects) {
            std::wcout << L"  - " << obj << L"\n";
        }
    }
}

int getValidInput(int min, int max) {
    int input;
    while (true) {
        if (std::wcin >> input) {
            std::wcin.ignore(1000, L'\n');
            if (input >= min && input <= max) {
                return input;
            }
        }
        else {
            std::wcin.clear();
            std::wcin.ignore(1000, L'\n');
        }
        std::wcout << L"Please enter a number between " << min << L" and " << max << L": ";
    }
}


void showProfilerMenu(ObjectProfiler& profiler) {
    while (true) {
        std::wcout << L"\n--- Object Profiler Menu ---\n"
            << L"1. Start Profiling Object\n"
            << L"2. Stop Profiling Object\n"
            << L"3. View Object Statistics\n"
            << L"4. Export Profiling Data\n"
            << L"5. Detect Anomalies\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 5);
        std::wstring objectName, filepath;

        switch (choice) {
        case 0:
            return;

        case 1:
            std::wcout << L"Enter object name to profile: ";
            std::getline(std::wcin, objectName);
            profiler.startProfiling(objectName);
            std::wcout << L"Started profiling: " << objectName << L"\n";
            break;

        case 2:
            std::wcout << L"Enter object name to stop profiling: ";
            std::getline(std::wcin, objectName);
            profiler.stopProfiling(objectName);
            std::wcout << L"Stopped profiling: " << objectName << L"\n";
            break;

        case 3:
            std::wcout << L"Enter object name to view statistics: ";
            std::getline(std::wcin, objectName);

            try {
                auto stats = profiler.getLifetimeStats(objectName);
                auto pattern = profiler.getUsagePattern(objectName);

                auto now = std::chrono::system_clock::now();
                auto duration = now - stats.creationTime;
                auto hours = std::chrono::duration_cast<std::chrono::hours>(duration).count();
                auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count() % 60;

                std::wcout << L"\nStatistics for: " << objectName << L"\n"
                    << L"Lifetime: " << hours << L" hours, " << minutes << L" minutes\n"
                    << L"Total Handle Opens: " << stats.totalHandleOpenCount << L"\n"
                    << L"Current Handles: " << stats.currentHandleCount << L"\n"
                    << L"Peak Handles: " << stats.peakHandleCount << L"\n"
                    << L"Memory Usage: " << (stats.memoryUsage / 1024) << L" KB\n"
                    << L"Access Count: " << pattern.accessTimes.size() << L"\n";

                if (!pattern.accessTimes.empty()) {
                    std::wcout << L"\nRecent Access Pattern:\n";
                    size_t showCount = (pattern.accessTimes.size() < 5) ? pattern.accessTimes.size() : size_t(5);
                    for (size_t i = pattern.accessTimes.size() - showCount; i < pattern.accessTimes.size(); ++i) {
                        std::wcout << L"  " << pattern.accessingProcesses[i] << L"\n";
                    }
                }
            }
            catch (const std::exception& e) {
                std::wcout << L"Error retrieving statistics: "
                    << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
            }
            break;

        case 4:
            std::wcout << L"Enter output filepath: ";
            std::getline(std::wcin, filepath);
            try {
                profiler.exportProfilingData(filepath);
                std::wcout << L"Profiling data exported to: " << filepath << L"\n";
            }
            catch (const std::exception& e) {
                std::wcout << L"Error exporting data: "
                    << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
            }
            break;

        case 5:
            std::wcout << L"Enter object name to check for anomalies: ";
            std::getline(std::wcin, objectName);
            profiler.detectAnomalies(objectName);
            std::wcout << L"Anomaly detection completed\n";
            break;
        }
    }
}

void showDeadlockMenu(DeadlockDetector& detector) {
    while (true) {
        std::wcout << L"\n--- Deadlock Detection Menu ---\n"
            << L"1. Start Deadlock Detection\n"
            << L"2. Stop Deadlock Detection\n"
            << L"3. View Detected Deadlocks\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 3);

        switch (choice) {
        case 0:
            detector.stopDetection();
            return;

        case 1:
            detector.startDetection();
            std::wcout << L"Deadlock detection started.\n";
            break;

        case 2:
            detector.stopDetection();
            std::wcout << L"Deadlock detection stopped.\n";
            break;

        case 3: {
            for (const auto& [pid, chain] : detector.waitChains) {
                if (detector.hasCycle(chain)) {
                    std::wcout << L"\nDeadlock detected in process " << pid << L":\n";
                    for (const auto& info : chain) {
                        std::wcout << L"Thread " << info.waitingThreadId
                            << L" waiting on process " << info.waitingProcessId << L"\n";
                    }
                }
            }
            break;
        }
        }
    }
}

void showBrowserMenu(SystemObjectBrowser& browser) {
    while (true) {
        std::wcout << L"\n--- Object Browser Menu ---\n"
            << L"1. List Directory Objects\n"
            << L"2. Filter Objects by Type\n"
            << L"3. View Object Details\n"
            << L"4. Deep Directory Scan\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 4);
        std::wstring path, objectName, typeFilter;

        switch (choice) {
        case 0: return;

        case 1:
            std::wcout << L"Enter directory path (e.g., \\BaseNamedObjects): ";
            std::getline(std::wcin, path);
            browser.listDirectoryObjects(path);
            break;

        case 2:
            std::wcout << L"Enter directory path: ";
            std::getline(std::wcin, path);
            std::wcout << L"Enter object type filter (e.g., Event, Mutex): ";
            std::getline(std::wcin, typeFilter);
            browser.listDirectoryObjects(path, typeFilter);
            break;

        case 3:
            std::wcout << L"Enter object name: ";
            std::getline(std::wcin, objectName);
            browser.showObjectDetails(objectName);
            break;

        case 4:
            std::wcout << L"Enter root directory for deep scan: ";
            std::getline(std::wcin, path);
            browser.performDeepScan(path, true);
            break;
        }
    }
}

void showMonitoringMenu(KernelObjectTracker& tracker, bool& monitoringActive) {
    while (true) {
        std::wcout << L"\n--- Monitoring Menu ---\n"
            << L"1. " << (monitoringActive ? L"Stop" : L"Start") << L" Monitoring\n"
            << L"2. View Monitoring Statistics\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 2);
        std::wstring path;

        switch (choice) {
        case 0: return;

        case 1:
            if (!monitoringActive) {
                std::wcout << L"Enter directory to monitor: ";
                std::getline(std::wcin, path);
                tracker.startTracking(path);
                monitoringActive = true;
                std::wcout << L"Monitoring started.\n";
            }
            else {
                tracker.stopTracking();
                monitoringActive = false;
                std::wcout << L"Monitoring stopped.\n";
            }
            break;

        case 2:
            if (monitoringActive) {
                auto stats = tracker.getTrackingStatistics();
                std::wcout << L"\nMonitoring Statistics:\n"
                    << L"====================\n";

                for (const auto& [name, stat] : stats) {
                    std::wcout << L"Object: " << name << L"\n"
                        << L"  Handles: " << stat.handleCount << L"\n"
                        << L"  References: " << stat.referenceCount << L"\n"
                        << L"  Memory: " << stat.memoryUsage << L" bytes\n"
                        << L"  Last Access: "
                        << std::setfill(L'0')
                        << stat.lastAccessTime.wYear << L"-"
                        << std::setw(2) << stat.lastAccessTime.wMonth << L"-"
                        << std::setw(2) << stat.lastAccessTime.wDay << L" "
                        << std::setw(2) << stat.lastAccessTime.wHour << L":"
                        << std::setw(2) << stat.lastAccessTime.wMinute << L":"
                        << std::setw(2) << stat.lastAccessTime.wSecond << L"\n"
                        << L"--------------------\n";
                }
            }
            else {
                std::wcout << L"Monitoring is not active.\n";
            }
            break;
        }
    }
}

void showAnalyticsMenu(AnalyticsReporter& reporter, SecurityAnalyzer& analyzer) {
    while (true) {
        std::wcout << L"\n--- Analytics Menu ---\n"
            << L"1. Generate Analysis Report\n"
            << L"2. Object Type Analysis\n"
            << L"3. Deep Object Analysis\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 3);
        std::wstring path, objectName;

        switch (choice) {
        case 0: return;

        case 1: {
            AnalyticsConfig config;
            std::wstring outputPath;

            std::wcout << L"Enter target directory: ";
            std::getline(std::wcin, config.targetDirectory);

            std::wcout << L"Select output format (1-Text, 2-JSON): ";
            int formatChoice = getValidInput(1, 2);
            config.format = (formatChoice == 1) ? ReportFormat::Text : ReportFormat::JSON;

            std::wcout << L"Enter output file path: ";
            std::getline(std::wcin, outputPath);
            config.outputPath = outputPath;
            config.includeAnalytics = true;

            try {
                reporter.generateAnalyticsReport(config);
                std::wcout << L"Report generated: " << outputPath << L"\n";
            }
            catch (const std::exception& e) {
                std::wcout << L"Report generation failed: "
                    << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
            }
            break;
        }

        case 2: {
            std::wcout << L"Enter directory for type analysis: ";
            std::getline(std::wcin, path);

            try {
                auto typeStats = analyzer.getObjectTypeStatistics(path);
                std::wcout << L"\nObject Type Distribution:\n"
                    << L"=======================\n";

                for (const auto& [type, count] : typeStats) {
                    std::wcout << type << L": " << count << L" instances\n";
                }
            }
            catch (const std::exception& e) {
                std::wcout << L"Analysis failed: "
                    << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
            }
            break;
        }

        case 3: {
            std::wcout << L"Enter object name for deep analysis: ";
            std::getline(std::wcin, objectName);

            try {
                analyzer.analyzeObjectDependencies(objectName);
            }
            catch (const std::exception& e) {
                std::wcout << L"Analysis failed: "
                    << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
            }
            break;
        }
        }
    }
}

void showSecurityMenu(SecurityAnalyzer& analyzer) {
    while (true) {
        std::wcout << L"\n--- Security Menu ---\n"
            << L"1. Analyze Object Security\n"
            << L"2. Object Access Audit\n"
            << L"0. Back to Main Menu\n"
            << L"Select option: ";

        int choice = getValidInput(0, 2);
        std::wstring objectName;

        switch (choice) {
        case 0: return;

        case 1:
            std::wcout << L"Enter object name for security analysis: ";
            std::getline(std::wcin, objectName);
            analyzer.analyzeObjectDependencies(objectName);
            break;

        case 2:
            std::wcout << L"Enter object name for access audit: ";
            std::getline(std::wcin, objectName);
            analyzer.analyzeObjectDependencies(objectName);
            break;
        }
    }
}

int main() {
    SystemObjectBrowser browser;
    KernelObjectTracker tracker;
    AnalyticsReporter reporter;
    SecurityAnalyzer analyzer;
    ObjectProfiler profiler;
    DeadlockDetector detector;
    bool monitoringActive = false;

    tracker.setStateChangeHandler(handleObjectStateChange);
    analyzer.setAnalysisHandler(handleSecurityAnalysis);
    profiler.setAnomalyHandler(handleAnomaly);

    while (true) {
        std::wcout << L"\n=== Kernel Object Management System ===\n"
            << L"1. Object Browser\n"
            << L"2. Monitoring\n"
            << L"3. Analytics\n"
            << L"4. Security\n"
            << L"5. Profiler\n"
            << L"6. Deadlock Detector\n"
            << L"0. Exit\n"
            << L"Select module: ";

        int choice = getValidInput(0, 6);

        switch (choice) {
        case 0:
            if (monitoringActive) {
                tracker.stopTracking();
            }
            detector.stopDetection();
            std::wcout << L"Exiting...\n";
            return 0;

        case 1:
            showBrowserMenu(browser);
            break;

        case 2:
            showMonitoringMenu(tracker, monitoringActive);
            break;

        case 3:
            showAnalyticsMenu(reporter, analyzer);
            break;

        case 4:
            showSecurityMenu(analyzer);
            break;

        case 5:
            showProfilerMenu(profiler);
            break;

        case 6:
            showDeadlockMenu(detector);
            break;
        }
    }
}