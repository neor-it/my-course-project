// AnalyticsReporter.h
#pragma once
#include <string>
#include <vector>
#include <memory>
#include "KernelObjectTracker.h"
#include "SecurityAnalyzer.h"

enum class ReportFormat {
    Text,
    JSON
};

struct AnalyticsConfig {
    ReportFormat format;
    bool includeAnalytics;
    std::wstring outputPath;
    std::wstring targetDirectory;
};

class AnalyticsReporter {
public:
    AnalyticsReporter();
    ~AnalyticsReporter();

    void generateAnalyticsReport(const AnalyticsConfig& config);

private:
    std::unique_ptr<KernelObjectTracker> objectTracker;
    std::unique_ptr<SecurityAnalyzer> securityAnalyzer;

    void writeToFile(const std::wstring& filePath, ReportFormat format, const std::wstring& content);
    std::wstring formatStats(const std::map<std::wstring, ObjectStats>& stats);
    std::wstring formatAnalytics(const std::vector<ObjectRelation>& relations);
    std::wstring formatTypeStats(const std::map<std::wstring, size_t>& typeStats);
    std::wstring generateJsonOutput(const std::wstring& content);
    std::wstring getCurrentTime();
    std::wstring formatTime(const SYSTEMTIME& st);
    std::wstring formatByteSize(SIZE_T bytes);
    std::wstring escapeJson(const std::wstring& input);
    std::wstring escapeXml(const std::wstring& input);
};