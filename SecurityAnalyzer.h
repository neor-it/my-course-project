// SecurityAnalyzer.h
#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <map>
#include <functional>

#define ObjectNameInfo 1
#define ObjectTypeInfo 2
#define ObjectNameInformation (OBJECT_INFORMATION_CLASS)1

struct HandleData {
    DWORD processId;
    DWORD handleValue;
    std::wstring objectType;
    std::wstring objectName;
};

struct ObjectRelation {
    std::wstring sourceObject;
    std::wstring targetObject;
    std::wstring relationType;
};

using SecurityAnalysisHandler = std::function<void(
    const std::wstring& objectName,
    const std::wstring& objectType,
    ULONG handleCount,
    ULONG referenceCount,
    const std::vector<std::wstring>& linkedObjects,
    ACCESS_MASK accessMask
    )>;

class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    ~SecurityAnalyzer();

    std::map<std::wstring, size_t> getObjectTypeStatistics(const std::wstring& targetDirectory);
    void setAnalysisHandler(SecurityAnalysisHandler handler) {
        analysisHandler = handler;
    }
    void analyzeObjectDependencies(const std::wstring& objectName);

private:
    SecurityAnalysisHandler analysisHandler;
};