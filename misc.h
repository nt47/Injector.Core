#pragma once
#include"utils.h"

typedef struct _SHARED_DATA
{
    wchar_t src_exe_folder[MAX_PATH];
    wchar_t src_dll_folder[MAX_PATH];

    wchar_t target_exe_folder[MAX_PATH];
    wchar_t target_exe_name[MAX_PATH];

} SHARED_DATA, * PSHARED_DATA;

extern HANDLE g_hEvent;
bool ShareMemory(LPVOID pParam);