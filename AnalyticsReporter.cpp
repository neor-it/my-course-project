// AnalyticsReporter.cpp
#include "AnalyticsReporter.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

AnalyticsReporter::AnalyticsReporter() {
    securityAnalyzer = std::make_unique<SecurityAnalyzer>();
    objectTracker = std::make_unique<KernelObjectTracker>();
}

AnalyticsReporter::~AnalyticsReporter() = default;

void AnalyticsReporter::generateAnalyticsReport(const AnalyticsConfig& config) {
    std::wstringstream report;

    report << L"Windows Kernel Object Analysis Report\n";
    report << L"Generated: " << getCurrentTime() << L"\n\n";

    std::wstring targetPath = config.targetDirectory.empty() ?
        L"\\BaseNamedObjects" : config.targetDirectory;
    report << L"Target Directory: " << targetPath << L"\n\n";

    try {
        auto typeStats = securityAnalyzer->getObjectTypeStatistics(targetPath);
        report << L"=== Object Type Distribution ===\n\n";

        size_t totalObjects = 0;
        for (const auto& [type, count] : typeStats) {
            totalObjects += count;
        }

        for (const auto& [type, count] : typeStats) {
            double percentage = (count * 100.0) / totalObjects;
            report << type << L": "
                << count << L" objects ("
                << std::fixed << std::setprecision(1) << percentage << L"%)\n";
        }
        report << L"\nTotal Object Count: " << totalObjects << L"\n\n";
    }
    catch (const std::exception& e) {
        report << L"Analysis Error: "
            << std::wstring(e.what(), e.what() + strlen(e.what())) << L"\n";
    }

    if (!config.outputPath.empty()) {
        writeToFile(config.outputPath, config.format, report.str());
    }
}

void AnalyticsReporter::writeToFile(
    const std::wstring& filePath,
    ReportFormat format,
    const std::wstring& content) {

    std::wofstream outFile(filePath);
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to create output file");
    }

    switch (format) {
    case ReportFormat::Text:
        outFile << content;
        break;

    case ReportFormat::JSON:
        outFile << generateJsonOutput(content);
        break;
    }

    outFile.close();
}

std::wstring AnalyticsReporter::formatStats(
    const std::map<std::wstring, ObjectStats>& stats) {

    std::wstringstream ss;
    ss << L"\n=== Object Statistics ===\n\n";

    for (const auto& [name, stat] : stats) {
        ss << L"Object: " << name << L"\n"
            << L"  Handle Count: " << stat.handleCount << L"\n"
            << L"  Reference Count: " << stat.referenceCount << L"\n"
            << L"  Memory Usage: " << formatByteSize(stat.memoryUsage) << L"\n"
            << L"  Last Access: " << formatTime(stat.lastAccessTime) << L"\n\n";
    }

    return ss.str();
}

std::wstring AnalyticsReporter::formatAnalytics(
    const std::vector<ObjectRelation>& relations) {

    std::wstringstream ss;
    ss << L"\n=== Object Relations ===\n\n";

    for (const auto& rel : relations) {
        ss << L"Source: " << rel.sourceObject << L"\n"
            << L"Target: " << rel.targetObject << L"\n"
            << L"Relation Type: " << rel.relationType << L"\n\n";
    }

    return ss.str();
}

std::wstring AnalyticsReporter::formatTypeStats(
    const std::map<std::wstring, size_t>& typeStats) {

    std::wstringstream ss;
    ss << L"\n=== Type Statistics ===\n\n";

    size_t total = 0;
    for (const auto& [_, count] : typeStats) {
        total += count;
    }

    for (const auto& [type, count] : typeStats) {
        double percentage = (count * 100.0) / total;
        ss << type << L": " << count << L" objects ("
            << std::fixed << std::setprecision(1) << percentage << L"%)\n";
    }

    return ss.str();
}

std::wstring AnalyticsReporter::generateJsonOutput(const std::wstring& content) {
    std::wstringstream ss;
    ss << L"{\n"
        << L"  \"timestamp\": \"" << getCurrentTime() << L"\",\n"
        << L"  \"content\": \"" << escapeJson(content) << L"\"\n"
        << L"}";
    return ss.str();
}

std::wstring AnalyticsReporter::getCurrentTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::wstringstream ss;
    ss << std::setfill(L'0')
        << st.wYear << L"-"
        << std::setw(2) << st.wMonth << L"-"
        << std::setw(2) << st.wDay << L" "
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond;
    return ss.str();
}

std::wstring AnalyticsReporter::formatTime(const SYSTEMTIME& st) {
    std::wstringstream ss;
    ss << std::setfill(L'0')
        << st.wYear << L"-"
        << std::setw(2) << st.wMonth << L"-"
        << std::setw(2) << st.wDay << L" "
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond;
    return ss.str();
}

std::wstring AnalyticsReporter::formatByteSize(SIZE_T bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    int unitIndex = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024 && unitIndex < 3) {
        size /= 1024;
        unitIndex++;
    }

    std::wstringstream ss;
    ss << std::fixed << std::setprecision(2) << size << L" " << units[unitIndex];
    return ss.str();
}

std::wstring AnalyticsReporter::escapeJson(const std::wstring& input) {
    std::wstringstream ss;
    for (wchar_t c : input) {
        switch (c) {
        case L'"': ss << L"\\\""; break;
        case L'\\': ss << L"\\\\"; break;
        case L'\b': ss << L"\\b"; break;
        case L'\f': ss << L"\\f"; break;
        case L'\n': ss << L"\\n"; break;
        case L'\r': ss << L"\\r"; break;
        case L'\t': ss << L"\\t"; break;
        default:
            if (c < 32) {
                ss << L"\\u" << std::hex << std::setw(4)
                    << std::setfill(L'0') << static_cast<int>(c);
            }
            else {
                ss << c;
            }
        }
    }
    return ss.str();
}

std::wstring AnalyticsReporter::escapeXml(const std::wstring& input) {
    std::wstringstream ss;
    for (wchar_t c : input) {
        switch (c) {
        case L'<': ss << L"&lt;"; break;
        case L'>': ss << L"&gt;"; break;
        case L'&': ss << L"&amp;"; break;
        case L'"': ss << L"&quot;"; break;
        case L'\'': ss << L"&apos;"; break;
        default: ss << c;
        }
    }
    return ss.str();
}