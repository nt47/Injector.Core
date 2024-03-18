#include"pch.h"
#include "Injector64.h"
#include"Utils.h"

#if defined(DISABLE_OUTPUT)
#define Msg(data, ...)
#else
#define Msg(text, ...) wprintf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

namespace Injector64 {


	bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) {
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			Msg(L"Invalid file\n");
			return false;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != CURRENT_ARCH) { //���dll������ƽ̨
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

		MANUAL_MAPPING_DATA data = { 0 };
		data.pLoadLibraryA = LoadLibraryA;
		data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
		data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
		SEHExceptionSupport = false;
#endif
		data.pbase = pTargetBase;
		data.fdwReasonParam = fdwReason;
		data.reservedParam = lpReserved;
		data.SEHSupport = SEHExceptionSupport;


		//File header
		if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
			Msg(L"Can't write file header 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			return false;
		}

		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
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
		BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!MappingDataAlloc) {
			Msg(L"Target process mapping allocation failed (ex) 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			return false;
		}

		if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) { //����ӳ��
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

		if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) { //����Shell Code
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

		HINSTANCE hCheck = NULL;
		int n = 0;
		while (!hCheck) {
			DWORD exitcode = 0;
			GetExitCodeProcess(hProc, &exitcode);
			if (exitcode != STILL_ACTIVE) {
				Msg(L"Process crashed, exit code: %d\n", exitcode);
				return false;
			}

			MANUAL_MAPPING_DATA data_checked = { 0 };
			ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);//�xȡ�ڴ�
			hCheck = data_checked.hMod;

			if (hCheck == (HINSTANCE)0x404040) {
				Msg(L"Wrong mapping ptr\n");
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
				VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
				return false;
			}
			else if (hCheck == (HINSTANCE)0x505050) {
				Msg(L"WARNING: Exception support failed!\n");
			}
			if (n == 100)
			{
				Msg(L"Waiting for return time out\n");
				return false;
			}
			Sleep(10);
			n++;
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


		if (ClearNonNeededSections) { //�������Ҫ�Ĺ�����һ���ģ�����v�����ͽY�����P�������
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
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

		if (AdjustProtections) { //�Ԅ��{���ڴ汣�o����
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
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
			VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
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

		free(emptyBuffer);//��ֹ�ڴ�й¶
		return true;
	}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
	void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
		if (!pData) {
			pData->hMod = (HINSTANCE)0x404040;
			return;
		}

		BYTE* pBase = pData->pbase;
		auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

		auto _LoadLibraryA = pData->pLoadLibraryA;
		auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
		auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
		auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

		BYTE* LocationDelta = pBase - pOpt->ImageBase;
		if (LocationDelta) {
			if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
				auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
				while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
					UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

					for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
						if (RELOC_FLAG(*pRelativeInfo)) {
							UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
							*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
						}
					}
					pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
				}
			}
		}

		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
			auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name) {
				char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
				HINSTANCE hDll = _LoadLibraryA(szMod);

				ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
				ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

				if (!pThunkRef)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
						*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else {
						auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
						*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
					}
				}
				++pImportDescr;
			}
		}

		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}

		bool ExceptionSupportFailed = false;

#ifdef _WIN64

		if (pData->SEHSupport) {
			auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			if (excep.Size) {
				if (!_RtlAddFunctionTable(
					reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
					excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
					ExceptionSupportFailed = true;
				}
			}
		}

#endif

		_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

		if (ExceptionSupportFailed)
			pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
		else
			pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
	}

}



