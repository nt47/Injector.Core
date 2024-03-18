#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

namespace Injector64 {

	typedef HINSTANCE(WINAPI* f_LoadLibraryA)(const char* lpLibFilename);
	typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);


#ifdef _WIN64
	typedef BOOL(WINAPIV* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

	struct MANUAL_MAPPING_DATA
	{
		f_LoadLibraryA pLoadLibraryA;
		f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
		f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
		BYTE* pbase;
		HINSTANCE hMod;
		DWORD fdwReasonParam;
		LPVOID reservedParam;
		BOOL SEHSupport;
	};


	//Note: Exception support only x64 with build params /EHa or /EHc
	bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
	void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
}