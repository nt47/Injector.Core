#pragma once
#include"utils.h"

typedef struct _SHARED_DATA
{
    wchar_t exe_folder[MAX_PATH];
    wchar_t dll_folder[MAX_PATH];
} SHARED_DATA, * PSHARED_DATA;

extern HANDLE g_hEvent;
bool ShareMemory();