#include "pch.h"
#include "utils.h"
#include <cstdlib>
#include <cwchar>
#include <Psapi.h>


wchar_t* c2w(const char* charStr) {
    // ��ȡ����Ļ�������С
    size_t size;
    mbstowcs_s(&size, NULL, 0, charStr, 0);

    // ���仺����
    wchar_t* wcharStr = new wchar_t[size + 1];

    // ִ��ת��
    mbstowcs_s(nullptr, wcharStr, size + 1, charStr, size);

    return wcharStr;
}


std::wstring GetProcessName(int PID) {
    // ��ȡ��ǰ���̾��
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        return L"";
    }

    // ��ȡ��ǰ����ģ����
    HMODULE hModule;
    DWORD dwNeeded;
    if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwNeeded)) {
        // ��ȡ����ģ���ļ���
        TCHAR szProcessPath[MAX_PATH];
        GetModuleFileNameEx(hProcess, hModule, szProcessPath, sizeof(szProcessPath) / sizeof(TCHAR));

        // ʹ�� PathFindFileName ��ȡ�ļ�������

        std::wstring szProcessName = PathFindFileName(szProcessPath);

        // �رս��̾��
        CloseHandle(hProcess);

        return szProcessName;
    }
    else {
        //std::cout << "Error getting process modules." << std::endl;
        // �رս��̾��
        CloseHandle(hProcess);
        return L"";
    }
}

std::wstring GetProcessPath(int PID) {
    // ��ȡ��ǰ���̾��
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        return L"";
    }

    // ��ȡ��ǰ����ģ����
    HMODULE hModule;
    DWORD dwNeeded;
    if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwNeeded)) {
        // ��ȡ����ģ���ļ���
        TCHAR szProcessPath[MAX_PATH];
        GetModuleFileNameEx(hProcess, hModule, szProcessPath, sizeof(szProcessPath) / sizeof(TCHAR));

        std::wstring szProcessName = szProcessPath;

        // �رս��̾��
        CloseHandle(hProcess);

        return szProcessName;
    }
    else {
        //std::cout << "Error getting process modules." << std::endl;
        // �رս��̾��
        CloseHandle(hProcess);
        return L"";
    }
}

