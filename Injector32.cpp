#include"pch.h"
#include"Injector32.h"
#include"Utils.h"

#if defined(DISABLE_OUTPUT)
#define Msg(data, ...)
#else
#define Msg(text, ...) wprintf(text, __VA_ARGS__);
#endif

namespace Injector32 {


	HMODULE GetRemoteModuleHandleByProcessHandleA(HANDLE hProcess, const char* szModuleName)
	{
		HMODULE hMods[1024] = { 0 };
		DWORD cbNeeded = 0, i = 0;
		char szModName[MAX_PATH];
		if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, 3)) //http://msdn.microsoft.com/en-us/library/ms682633(v=vs.85).aspx
		{
			for (i = 0; i <= cbNeeded / sizeof(HMODULE); i++)
			{
				if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName)))
				{
					if (strstr(_strlwr(szModName), szModuleName))
					{
						return hMods[i];
					}
				}
			}
		}
		return NULL;
	}


	long GetProcessExportTable32(HANDLE hProcess, const char* ModuleName, IAT_EAT_INFO tbinfo[], int tb_info_max)
	{
		ULONG muBase = 0, count = 0;
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)new BYTE[sizeof(IMAGE_DOS_HEADER)];
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)new BYTE[sizeof(IMAGE_NT_HEADERS32)];
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)new BYTE[sizeof(IMAGE_EXPORT_DIRECTORY)];
		DWORD dwStup = 0, dwOffset = 0;
		char strName[130];
		//拿到目标模块的BASE
		muBase = (ULONG)GetRemoteModuleHandleByProcessHandleA(hProcess, ModuleName);
		if (!muBase)
		{
			printf("GetRemoteModuleHandleByProcessHandleA failed!", "GetProcessExportTable32");
			return 0;
		}
		//获取IMAGE_DOS_HEADER
		ReadProcessMemory(hProcess, (PVOID)muBase, pDosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
		//获取IMAGE_NT_HEADERS
		ReadProcessMemory(hProcess, (PVOID)(muBase + pDosHeader->e_lfanew), pNtHeaders, sizeof(IMAGE_NT_HEADERS32), NULL);
		if (pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
		{
			return 0;
		}
		ReadProcessMemory(hProcess, (PVOID)(muBase + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress), pExport, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);
		ReadProcessMemory(hProcess, (PVOID)(muBase + pExport->Name), strName, sizeof(strName), NULL);

		if (pExport->NumberOfNames < 0 || pExport->NumberOfNames>8192)
		{
			return 0;
		}
		for (int i = 0; i < pExport->NumberOfNames; i++)
		{
			char bFuncName[100];
			ULONG ulPointer;
			USHORT usFuncId;
			ULONG64 ulFuncAddr;

			ReadProcessMemory(hProcess, (PVOID)(muBase + pExport->AddressOfNames + i * 4), &ulPointer, 4, 0);
			RtlZeroMemory(bFuncName, 100);
			ReadProcessMemory(hProcess, (PVOID)(muBase + ulPointer), bFuncName, 100, 0);
			ReadProcessMemory(hProcess, (PVOID)(muBase + pExport->AddressOfNameOrdinals + i * 2), &usFuncId, 2, 0);
			ReadProcessMemory(hProcess, (PVOID)(muBase + pExport->AddressOfFunctions + 4 * usFuncId), &ulPointer, 4, 0);
			ulFuncAddr = muBase + ulPointer;

			printf("\t%d\t%llx\t%s\n", usFuncId, ulFuncAddr, bFuncName);

			strcpy(tbinfo[count].ModuleName, ModuleName);
			strcpy(tbinfo[count].FuncName, bFuncName);
			tbinfo[count].Address = ulFuncAddr;
			tbinfo[count].RecordAddr = (ULONG64)(muBase + pExport->AddressOfFunctions + 4 * usFuncId);
			tbinfo[count].ModBase = muBase;
			count++;
			if (count > (ULONG)tb_info_max)
				goto exit_sub;
		}
	exit_sub:
		delete[]pDosHeader;
		delete[]pExport;
		delete[]pNtHeaders;
		return count;
	}


	//获得32位进程中某个DLL导出函数的地址
	ULONG64 GetProcAddressIn32BitProcess(HANDLE hProcess, const char* ModuleName, const char* FuncName)
	{
		ULONG64 RetAddr = 0;
		PIAT_EAT_INFO pInfo = (PIAT_EAT_INFO)malloc(4096 * sizeof(IAT_EAT_INFO));
		long count = GetProcessExportTable32(hProcess, ModuleName, pInfo, 2048);
		wprintf(L"\tcount:\t%d\n", count);
		if (!count)
			return NULL;
		for (int i = 0; i < count; i++)
		{
			if (!_stricmp(pInfo[i].FuncName, FuncName))
			{
				RetAddr = pInfo[i].Address;
				break;
			}
		}
		free(pInfo);
		return RetAddr;
	}





	BYTE Shellcode32[] = { "\x55\x8B\xEC\x83\xEC\x54\x83\x7D\x08\x00\x75\x0F\x8B\x45\x08\xC7\x40\x0C\x40\x40\x40\x00\xE9\x92\x02\x00\x00\x8B\x4D\x08\x8B\x51\x08\x89\x55\xF8\x8B\x45\xF8\x8B\x48\x3C\x8B\x55\xF8\x8D\x44\x0A\x18\x89\x45\xF0\x8B\x4D\x08\x8B\x11\x89\x55\xB8\x8B\x45\x08\x8B\x48\x04\x89\x4D\xC8\x8B\x55\xF0\x8B\x45\xF8\x03\x42\x10\x89\x45\xAC\x8B\x4D\xF0\x8B\x55\xF8\x2B\x51\x1C\x89\x55\xD4\x0F\x84\xD9\x00\x00\x00\xB8\x08\x00\x00\x00\x6B\xC8\x05\x8B\x55\xF0\x83\x7C\x0A\x64\x00\x0F\x84\xC3\x00\x00\x00\xB8\x08\x00\x00\x00\x6B\xC8\x05\x8B\x55\xF0\x8B\x45\xF8\x03\x44\x0A\x60\x89\x45\xF4\xB9\x08\x00\x00\x00\x6B\xD1\x05\x8B\x45\xF0\x8B\x4D\xF4\x03\x4C\x10\x64\x89\x4D\xC4\x8B\x55\xF4\x3B\x55\xC4\x0F\x83\x8D\x00\x00\x00\x8B\x45\xF4\x83\x78\x04\x00\x0F\x84\x80\x00\x00\x00\x8B\x4D\xF4\x8B\x51\x04\x83\xEA\x08\xD1\xEA\x89\x55\xC0\x8B\x45\xF4\x83\xC0\x08\x89\x45\xDC\xC7\x45\xD8\x00\x00\x00\x00\xEB\x12\x8B\x4D\xD8\x83\xC1\x01\x89\x4D\xD8\x8B\x55\xDC\x83\xC2\x02\x89\x55\xDC\x8B\x45\xD8\x3B\x45\xC0\x74\x35\x8B\x4D\xDC\x0F\xB7\x11\xC1\xFA\x0C\x83\xFA\x03\x75\x25\x8B\x45\xF4\x8B\x4D\xF8\x03\x08\x8B\x55\xDC\x0F\xB7\x02\x25\xFF\x0F\x00\x00\x03\xC8\x89\x4D\xD0\x8B\x4D\xD0\x8B\x11\x03\x55\xD4\x8B\x45\xD0\x89\x10\xEB\xB1\x8B\x4D\xF4\x8B\x55\xF4\x03\x51\x04\x89\x55\xF4\xE9\x67\xFF\xFF\xFF\xB8\x08\x00\x00\x00\xC1\xE0\x00\x8B\x4D\xF0\x83\x7C\x01\x64\x00\x0F\x84\xCB\x00\x00\x00\xBA\x08\x00\x00\x00\xC1\xE2\x00\x8B\x45\xF0\x8B\x4D\xF8\x03\x4C\x10\x60\x89\x4D\xE8\x8B\x55\xE8\x83\x7A\x0C\x00\x0F\x84\xA9\x00\x00\x00\x8B\x45\xE8\x8B\x4D\xF8\x03\x48\x0C\x89\x4D\xBC\x8B\x55\xBC\x52\xFF\x55\xB8\x89\x45\xCC\x8B\x45\xE8\x8B\x4D\xF8\x03\x08\x89\x4D\xEC\x8B\x55\xE8\x8B\x45\xF8\x03\x42\x10\x89\x45\xE4\x83\x7D\xEC\x00\x75\x06\x8B\x4D\xE4\x89\x4D\xEC\xEB\x12\x8B\x55\xEC\x83\xC2\x04\x89\x55\xEC\x8B\x45\xE4\x83\xC0\x04\x89\x45\xE4\x8B\x4D\xEC\x83\x39\x00\x74\x46\x8B\x55\xEC\x8B\x02\x25\x00\x00\x00\x80\x74\x1A\x8B\x4D\xEC\x8B\x11\x81\xE2\xFF\xFF\x00\x00\x52\x8B\x45\xCC\x50\xFF\x55\xC8\x8B\x4D\xE4\x89\x01\xEB\x1E\x8B\x55\xEC\x8B\x45\xF8\x03\x02\x89\x45\xB4\x8B\x4D\xB4\x83\xC1\x02\x51\x8B\x55\xCC\x52\xFF\x55\xC8\x8B\x4D\xE4\x89\x01\xEB\xA0\x8B\x55\xE8\x83\xC2\x14\x89\x55\xE8\xE9\x4A\xFF\xFF\xFF\xB8\x08\x00\x00\x00\x6B\xC8\x09\x8B\x55\xF0\x83\x7C\x0A\x64\x00\x74\x48\xB8\x08\x00\x00\x00\x6B\xC8\x09\x8B\x55\xF0\x8B\x45\xF8\x03\x44\x0A\x60\x89\x45\xB0\x8B\x4D\xB0\x8B\x51\x0C\x89\x55\xE0\xEB\x09\x8B\x45\xE0\x83\xC0\x04\x89\x45\xE0\x83\x7D\xE0\x00\x74\x19\x8B\x4D\xE0\x83\x39\x00\x74\x11\x6A\x00\x6A\x01\x8B\x55\xF8\x52\x8B\x45\xE0\x8B\x08\xFF\xD1\xEB\xD8\xC6\x45\xFF\x00\x8B\x55\x08\x8B\x42\x14\x50\x8B\x4D\x08\x8B\x51\x10\x52\x8B\x45\xF8\x50\xFF\x55\xAC\x0F\xB6\x4D\xFF\x85\xC9\x74\x0C\x8B\x55\x08\xC7\x42\x0C\x50\x50\x50\x00\xEB\x09\x8B\x45\x08\x8B\x4D\xF8\x89\x48\x0C\x8B\xE5\x5D\xC2\x04\x00" };



	bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) {


		IMAGE_NT_HEADERS32* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER32* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			Msg(L"Invalid file\n");
			return false;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) { //检测dll的所属平台
			Msg(L"Invalid platform\n");
			return false;
		}

		Msg(L"File ok\n");

		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!pTargetBase) {
			Msg(L"Target process memory allocation failed (ex) 0x%X\n", GetLastError());
			return false;
		}

		DWORD oldp = 0;
		VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

		MANUAL_MAPPING_DATA32 data = { 0 };
		data.pLoadLibraryA = (DWORD)GetProcAddressIn32BitProcess(hProc, "kernel32.dll", "LoadLibraryA");
		data.pGetProcAddress = (DWORD)GetProcAddressIn32BitProcess(hProc, "kernel32.dll", "GetProcAddress");

		SEHExceptionSupport = false;

		data.pbase = (DWORD)pTargetBase;
		data.fdwReasonParam = fdwReason;
		data.reservedParam = (DWORD)lpReserved;
		data.SEHSupport = SEHExceptionSupport;


		//File header
		if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
			Msg(L"Can't write file header 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			return false;
		}


		IMAGE_SECTION_HEADER32* pSectionHeader = IMAGE_FIRST_SECTION32(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->SizeOfRawData) {
				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
					Msg(L"Can't map sections: 0x%x\n", GetLastError());
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					return false;
				}
			}
		}

		//Mapping params
		BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA32), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!MappingDataAlloc) {
			Msg(L"Target process mapping allocation failed (ex) 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			return false;
		}

		if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA32), nullptr)) { //寫入映射
			Msg(L"Can't write mapping 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			return false;
		}

		//Shell code
		void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode) {
			Msg(L"Memory shellcode allocation failed (ex) 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			return false;
		}

		if (!WriteProcessMemory(hProc, pShellcode, Shellcode32, 0x1000, nullptr)) { //寫入Shell Code
			Msg(L"Can't write shellcode 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}

		Msg(L"Mapped DLL at %p\n", pTargetBase);
		Msg(L"Mapping info at %p\n", MappingDataAlloc);
		Msg(L"Shell code at %p\n", pShellcode);

		Msg(L"Data allocated\n");

#ifdef _DEBUG
		Msg(L"My shellcode pointer %p\n", Shellcode);
		Msg(L"Target point %p\n", pShellcode);
		system("pause");
#endif

		//LPVOID pAllocConsole = (LPVOID)GetProcAddressIn32BitProcess(hProc, "kernel32.dll", "AllocConsole");
		//HANDLE hThread1 = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pAllocConsole, nullptr, 0, nullptr);
		//Msg(L"=============================================\n");
		//return false;


		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
		if (!hThread) {
			Msg(L"Thread creation failed 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}
		CloseHandle(hThread);

		Msg(L"Thread created at: %p, waiting for return...\n", pShellcode);

		DWORD hCheck = NULL;
		while (!hCheck) {
			DWORD exitcode = 0;
			GetExitCodeProcess(hProc, &exitcode);
			if (exitcode != STILL_ACTIVE) {
				Msg(L"Process crashed, exit code: %d\n", exitcode);
				return false;
			}

			MANUAL_MAPPING_DATA32 data_checked = { 0 };
			ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);//讀取内存
			hCheck = data_checked.hMod;

			if (hCheck == (DWORD)0x404040) {
				Msg(L"Wrong mapping ptr\n");
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
				VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
				return false;
			}
			else if (hCheck == (DWORD)0x505050) {
				Msg(L"WARNING: Exception support failed!\n");
			}

			Sleep(10);
		}

		BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
		if (emptyBuffer == nullptr) {
			Msg(L"Unable to allocate memory\n");
			return false;
		}
		memset(emptyBuffer, 0, 1024 * 1024 * 20);

		//CLEAR PE HEAD
		if (ClearHeader) {
			if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
				Msg(L"WARNING!: Can't clear HEADER\n");
			}
		}
		//END CLEAR PE HEAD


		if (ClearNonNeededSections) { //清除不必要的節（節一節的），遍歷操作和結構有關，不多深究
			pSectionHeader = IMAGE_FIRST_SECTION32(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
						strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
						strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
						Msg(L"Processing %s removal\n", c2w((const char*)pSectionHeader->Name));
						if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
							Msg(L"Can't clear section %s: 0x%x\n", c2w((const char*)pSectionHeader->Name), GetLastError());
						}
					}
				}
			}
		}

		if (AdjustProtections) { //自動調整内存保護屬性
			pSectionHeader = IMAGE_FIRST_SECTION32(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					DWORD old = 0;
					DWORD newP = PAGE_READONLY;//0x2

					if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
						newP = PAGE_READWRITE;//0x4
					}
					else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
						newP = PAGE_EXECUTE_READ;//0x20
					}
					if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
						Msg(L"section %s set as %lX\n", c2w((const char*)pSectionHeader->Name), newP);
					}
					else {
						Msg(L"FAIL: section %s not set as %lX\n", c2w((const char*)pSectionHeader->Name), newP);
					}
				}
			}
			DWORD old = 0;
			VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION32(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
		}

		if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
			Msg(L"WARNING: Can't clear shellcode\n");
		}
		if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
			Msg(L"WARNING: can't release shell code memory\n");
		}
		if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
			Msg(L"WARNING: can't release mapping data memory\n");
		}

		free(emptyBuffer);//防止内存泄露
		return true;
	}



}











