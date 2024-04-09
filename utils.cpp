#include "pch.h"
#include "utils.h"
#include <cstdlib>
#include <cwchar>
#include <Psapi.h>


wchar_t* c2w(const char* charStr) {
    // 获取所需的缓冲区大小
    size_t size;
    mbstowcs_s(&size, NULL, 0, charStr, 0);

    // 分配缓冲区
    wchar_t* wcharStr = new wchar_t[size + 1];

    // 执行转换
    mbstowcs_s(nullptr, wcharStr, size + 1, charStr, size);

    return wcharStr;
}


std::wstring GetProcessName(int PID) {
    // 获取当前进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        return L"";
    }

    // 获取当前进程模块句柄
    HMODULE hModule;
    DWORD dwNeeded;
    if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwNeeded)) {
        // 获取进程模块文件名
        TCHAR szProcessPath[MAX_PATH];
        GetModuleFileNameEx(hProcess, hModule, szProcessPath, sizeof(szProcessPath) / sizeof(TCHAR));

        // 使用 PathFindFileName 提取文件名部分

        std::wstring szProcessName = PathFindFileName(szProcessPath);

        // 关闭进程句柄
        CloseHandle(hProcess);

        return szProcessName;
    }
    else {
        //std::cout << "Error getting process modules." << std::endl;
        // 关闭进程句柄
        CloseHandle(hProcess);
        return L"";
    }
}

std::wstring GetProcessPath(int PID) {
    // 获取当前进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        return L"";
    }

    // 获取当前进程模块句柄
    HMODULE hModule;
    DWORD dwNeeded;
    if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwNeeded)) {
        // 获取进程模块文件名
        TCHAR szProcessPath[MAX_PATH];
        GetModuleFileNameEx(hProcess, hModule, szProcessPath, sizeof(szProcessPath) / sizeof(TCHAR));

        std::wstring szProcessName = szProcessPath;

        // 关闭进程句柄
        CloseHandle(hProcess);

        return szProcessName;
    }
    else {
        //std::cout << "Error getting process modules." << std::endl;
        // 关闭进程句柄
        CloseHandle(hProcess);
        return L"";
    }
}

