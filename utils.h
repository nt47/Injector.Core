#pragma once
#include <Shlwapi.h>
#include <string>
#pragma comment(lib, "Shlwapi.lib") //�ļ���������
wchar_t* c2w(const char* charStr);
std::wstring GetProcessName(int PID);
std::wstring GetProcessPath(int PID);