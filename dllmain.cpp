// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <string>
#include "Macros.h"
#include"Injector32.h"
#include"Injector64.h"
#include"utils.h"
#include <locale>
#include<tchar.h>
#include"misc.h"
#include"CAutoMutex.h"

#if defined(DISABLE_OUTPUT)
#define Msg(data, ...)
#else
#define Msg(text, ...) wprintf(text, __VA_ARGS__);
#endif


using namespace std;

API DLLEXPORT void Console()
{
	wchar_t title[56];
	swprintf_s(title, L"Debug Window - %d", GetCurrentProcessId());

	setlocale(LC_ALL, "chs");
	AllocConsole();
	SetConsoleTitle(title);
	//freopen_s("CON", "w", stdout);
	FILE* consoleOutput;
	freopen_s(&consoleOutput, "CONOUT$", "w", stdout);
}

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {//此函数检测目标进程是否为32位进程
		Msg(L"Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

bool Is32BitExe(const wchar_t* exePath) {

	DWORD dwFileType;

	BOOL bRet = GetBinaryType(exePath, &dwFileType);
	if (!bRet)
	{
		DWORD Err = GetLastError();
		Msg(L"GetBinaryType failed: 0x%X\n", Err);
	}
	if (dwFileType == SCS_32BIT_BINARY)
		return true;

	return false;
}

int GetArchitecture(const wchar_t* dllPath) {
	// 打开DLL文件
	HANDLE hFile = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open DLL file. Error code: " << GetLastError() << std::endl;
		return false;
	}

	// 读取PE头
	IMAGE_DOS_HEADER dosHeader;
	DWORD bytesRead;
	if (!ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
		std::cerr << "Failed to read DOS header. Error code: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 验证PE头
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS header signature." << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 移动文件指针到PE头
	if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		std::cerr << "Failed to move file pointer to PE header. Error code: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 读取PE头的签名
	DWORD peSignature;
	if (!ReadFile(hFile, &peSignature, sizeof(DWORD), &bytesRead, NULL)) {
		std::cerr << "Failed to read PE signature. Error code: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 验证PE头的签名
	if (peSignature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid PE signature." << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 读取PE头
	IMAGE_FILE_HEADER fileHeader;
	if (!ReadFile(hFile, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL)) {
		std::cerr << "Failed to read file header. Error code: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	// 检查文件头的位数信息
	if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		std::cout << "The DLL is 32-bit." << std::endl;
	}
	else if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "The DLL is 64-bit." << std::endl;
	}
	else {
		std::cout << "Unknown architecture." << std::endl;
	}

	// 关闭文件句柄
	CloseHandle(hFile);

	return fileHeader.Machine;
}


BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\"))) { continue; }

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			// 查询 Dos 设备名
			if (!QueryDosDevice(szDrive, szDevName, 100)) { return FALSE; }

			// 命中
			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0) {
				// 复制驱动器
				lstrcpy(pszNtPath, szDrive);

				// 复制路径
				lstrcat(pszNtPath, pszDosPath + cchDevName);

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

// 获取进程全路径
BOOL GetProcessFullPath(HANDLE hProcess, wstring& fullPath) {
	TCHAR		szImagePath[MAX_PATH];
	TCHAR		pszFullPath[MAX_PATH];

	// 初始化失败
	if (!pszFullPath) { return FALSE; }
	pszFullPath[0] = '\0';


	// 获取进程完整路径失败
	if (!GetProcessImageFileName(
		hProcess,					// 进程句柄
		szImagePath,				// 接收进程所属文件全路径的指针
		MAX_PATH					// 缓冲区大小
	)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	// 路径转换失败
	if (!DosPathToNtPath(szImagePath, pszFullPath)) {

		return FALSE;
	}

	// 导出文件全路径
	fullPath = pszFullPath;

	return TRUE;
}

bool IsProcess32Bit(HANDLE hProcess)
{
	wstring fullPath;
	GetProcessFullPath(hProcess, fullPath);

	Msg(L"%s\n", fullPath);

	return Is32BitExe(fullPath.c_str());
}

BOOL IsProcess64Bit(HANDLE hProcess)
{
	// 判断64位系统下, 进程指定是32位还是64位
	BOOL bWow64Process = FALSE;

	// 判断进程是否处于WOW64仿真环境中
	IsWow64Process(hProcess, &bWow64Process);

	return !bWow64Process;
}



//判断进程id是否存在
//@param:process_id:需要传入的进程id值
//return:True:存在，False:不存在
API DLLEXPORT BOOL isExistProcess(DWORD process_id)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {

		if (pe.th32ProcessID == process_id)
		{
			return TRUE;
		}
	}
	CloseHandle(hSnapshot);
	return FALSE;
}

API DLLEXPORT bool IsDebuggerAttached(DWORD PID) {
	
	// 打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		DWORD Err = GetLastError();
		Msg(L"OpenProcess failed: 0x%X\n", Err);
		return FALSE;
	}

	// 检测目标进程是否被调试器附加
	BOOL isDebuggerPresent = FALSE;
	if (!CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent)) {
		Msg(L"Failed to check debugger presence");
		CloseHandle(hProcess);
		return false;
	}

	// 关闭目标进程句柄
	CloseHandle(hProcess);

	return isDebuggerPresent ? true : false;
}



BOOL Inject32a(int PID, const wchar_t* dllPath)//这个路径是个绝对路径
{
	const char* testPath = "C:\\Users\\Pudge\\source\\repos\\Dpi\\FixDpi.Monitor\\FixDpi.Monitor\\bin\\Release\\HiJack32.dll";
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		DWORD Err = GetLastError();
		Msg(L"OpenProcess failed: 0x%X\n", Err);
		return FALSE;
	}


	// 在目标进程中分配内存以存储DLL路径
	LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(testPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == NULL) {
		std::wcout << "Failed to allocate memory in target process" << std::endl;
		CloseHandle(hProcess);
		return FALSE;
	}

	// 写入DLL路径到目标进程内存
	if (!WriteProcessMemory(hProcess, pDllPath, testPath, strlen(testPath) + 1, NULL)) {
		std::wcout << "Failed to write DLL path to target process memory" << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// 获取LoadLibraryA函数地址
	//LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	LPVOID pLoadLibrary = (LPVOID)Injector32::GetProcAddressIn32BitProcess(hProcess, "kernel32.dll", "LoadLibraryA");

	if (pLoadLibrary == NULL) {
		std::wcout << "Failed to get address of LoadLibraryA" << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// 在目标进程中创建远程线程执行LoadLibraryA函数
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
	if (hRemoteThread == NULL) {
		std::wcout << "Failed to create remote thread in target process" << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	std::wcout << "WaitForSingleObject" << std::endl;
	// 等待远程线程执行完毕
	WaitForSingleObject(hRemoteThread, INFINITE);

	// 清理资源
	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);


	return TRUE;
}

API DLLEXPORT BOOL Inject(int PID, const wchar_t* dllPath)
{
	CAutoMutex MutexLock;

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (g_hEvent == NULL) {
		std::cout << "Failed to create g_event. Error code: " << GetLastError() << std::endl;
		return false;
	}


	CloseHandle(CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)ShareMemory,NULL,NULL,NULL));

	// 等待进程事件信号
	WaitForSingleObject(g_hEvent, INFINITE);


	// 关闭进程事件句柄
	CloseHandle(g_hEvent);

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		Msg(L"OpenProcess failed: 0x%X\n", Err);
		return FALSE;
	}

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		Msg(L"Dll file doesn't exist\n");
		return FALSE;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		Msg(L"Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		return FALSE;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		Msg(L"Filesize invalid.\n");
		File.close();
		return FALSE;
	}

	BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		Msg(L"Can't allocate dll file.\n");
		File.close();
		return FALSE;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	Msg(L"Mapping...\n");

	if (!IsProcess64Bit(hProc) && !IsProcess64Bit(GetCurrentProcess()))//如果目标进程是32位，并且自身进程也是32位
	{
		Msg(L"Prepare to inject Process 32-bit.\n");
		if (GetArchitecture(dllPath) == IMAGE_FILE_MACHINE_AMD64)//如果DLL是64位的
		{
			Msg(L"32-bit Process can't load 64-bit dll\n");//32位进程不能注入64位DLL
			return FALSE;
		}
		if (!Injector32::ManualMapDll(hProc, pSrcData, FileSize)) {
			delete[] pSrcData;
			CloseHandle(hProc);
			Msg(L"Error while mapping.\n");
			return FALSE;
		}
	}
	else if (!IsProcess64Bit(hProc) && IsProcess64Bit(GetCurrentProcess()))//否则如果目标进程是32位，并且自身进程是64位
	{
		Msg(L"Prepare to inject Process 32-bit.\n");
		if (GetArchitecture(dllPath) == IMAGE_FILE_MACHINE_AMD64)//如果DLL是64位的
		{
			Msg(L"32-bit Process can't be load 64-bit dll\n");//32位进程不能注入64位DLL
			return FALSE;
		}
		if (!Injector32::ManualMapDll(hProc, pSrcData, FileSize)) {
			delete[] pSrcData;
			CloseHandle(hProc);
			Msg(L"Error while mapping.\n");
			return FALSE;
		}
	}
	else if (IsProcess64Bit(hProc) && IsProcess64Bit(GetCurrentProcess()))//否则如果目标进程是64位，并且自身进程也是64位
	{
		Msg(L"Prepare to inject Process 64-bit.\n");
		if (GetArchitecture(dllPath) == IMAGE_FILE_MACHINE_I386)//如果DLL是32位的
		{
			Msg(L"64-bit Process can't load 32-bit dll\n");//64位进程不能注入32位DLL
			return FALSE;
		}

		if (!Injector64::ManualMapDll(hProc, pSrcData, FileSize)) {//采用64位手动映射注入
			delete[] pSrcData;
			CloseHandle(hProc);
			Msg(L"Error while mapping.\n");
			return FALSE;
		}
	}
	else if (IsProcess64Bit(hProc) && !IsProcess64Bit(GetCurrentProcess()))//否则如果目标进程是64位，并且自身进程也是32位
	{
		Msg(L"Prepare to inject Process 64-bit.\n");
		if (GetArchitecture(dllPath) == IMAGE_FILE_MACHINE_I386)//如果DLL是32位的
		{
			Msg(L"64-bit Process can't load 32-bit dll\n");//64位进程不能注入32位DLL
			return FALSE;
		}

		Msg(L"Not support 32-bit to 64-bit for the time being.\n");//暂时不支持
	}

	delete[] pSrcData;

	CloseHandle(hProc);

	Msg(L"Everything is OK\n");
	return TRUE;
}

//如果开启CLR会导致平台不兼容而导致注入的目标进程崩溃，删除DllMain也没用
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

