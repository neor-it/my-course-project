#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>

class SystemObjectBrowser {
public:
    SystemObjectBrowser();
    ~SystemObjectBrowser();

    HANDLE openKernelObject(const std::wstring& path, ACCESS_MASK access);

    void exploreDirectory(const std::wstring& path, const std::wstring& filterType, bool recursive);

    void performDeepScan(const std::wstring& path, bool recursive = false);

    void listDirectoryObjects(const std::wstring& path, const std::wstring& filterType = L"", bool recursive = false);

    void showObjectDetails(const std::wstring& objectName);

    std::vector<std::pair<std::wstring, std::wstring>> getDirectoryContents(const std::wstring& path, const std::wstring& filterType);

    std::wstring getSystemErrorMessage(DWORD errorCode);

    bool checkObjectAccess(const std::wstring& fullPath);

    void logError(const std::wstring& message, DWORD errorCode);
};
