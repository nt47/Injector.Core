#pragma once
#include <stdlib.h>
#include <stdio.h>
#include<Psapi.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>



namespace Injector32 {
#pragma pack(4)
    typedef struct _IMAGE_SECTION_HEADER32 {
        BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
        } Misc;
        DWORD   VirtualAddress;
        DWORD   SizeOfRawData;
        DWORD   PointerToRawData;
        DWORD   PointerToRelocations;
        DWORD   PointerToLinenumbers;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   Characteristics;
    } IMAGE_SECTION_HEADER32, * PIMAGE_SECTION_HEADER32;
#pragma pack(pop)

#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER32)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#pragma pack(4)
    struct MANUAL_MAPPING_DATA32
    {
        DWORD pLoadLibraryA;
        DWORD pGetProcAddress;


        DWORD pbase;
        DWORD hMod;
        DWORD fdwReasonParam;
        DWORD reservedParam;
        BOOL SEHSupport;
    };
#pragma pack(pop)



    //Note: Exception support only x64 with build params /EHa or /EHc
    bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);




    typedef struct _IAT_EAT_INFO
    {
        char ModuleName[256];
        char FuncName[64];
        ULONG64 Address;
        ULONG64 RecordAddr;
        ULONG64        ModBase;//just for export table
    } IAT_EAT_INFO, * PIAT_EAT_INFO;

    ULONG64 GetProcAddressIn32BitProcess(HANDLE hProcess, const char* ModuleName, const char* FuncName);

}
