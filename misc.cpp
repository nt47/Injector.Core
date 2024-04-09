#include"pch.h"
#include"misc.h"
#include<iostream>

// 全局变量，用于线程之间共享
HANDLE g_hEvent=NULL;

bool ShareMemory(LPVOID pParam)
{
    // 创建共享内存
    HANDLE hMapFile = CreateFileMapping(
        INVALID_HANDLE_VALUE,   // 使用页面文件创建共享内存
        NULL,                   // 默认安全级别
        PAGE_READWRITE,         // 可读写访问权限
        0,                      // 高位字节偏移量
        sizeof(SHARED_DATA),        // 共享内存大小（字节）
        L"Injector.SharedMemory");     // 共享内存名称

    if (hMapFile == NULL)
    {
        std::cout << "Could not create file mapping object (" << GetLastError() << ")." << std::endl;
        return false;
    }

    // 将共享内存映射到进程的地址空间
    PSHARED_DATA shared_data = (PSHARED_DATA)MapViewOfFile(
        hMapFile,           // 共享内存句柄
        FILE_MAP_WRITE,     // 写访问权限
        0,
        0,
        sizeof(SHARED_DATA));

    if (shared_data == NULL)
    {
        std::cout << "Could not map view of file (" << GetLastError() << ")." << std::endl;
        CloseHandle(hMapFile);
        return false;
    }

    // 在共享内存中写入数据
    TCHAR tzSrcPath[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), tzSrcPath, MAX_PATH); //获取本目录下的
    PathRemoveFileSpec(tzSrcPath);

    GetCurrentDirectory(sizeof(shared_data->src_exe_folder), shared_data->src_exe_folder);
    wcscpy_s(shared_data->src_dll_folder, sizeof(shared_data->src_dll_folder), tzSrcPath);


    TCHAR tzTargetFolder[MAX_PATH];
    TCHAR tzTargetName[MAX_PATH];

    wcscpy_s(tzTargetName, sizeof(tzTargetName), (wchar_t*)pParam);//只保留文件名
    PathStripPath(tzTargetName);

    wcscpy_s(tzTargetFolder, sizeof(tzTargetFolder), (wchar_t*)pParam);//只保留目录
    PathRemoveFileSpec(tzTargetFolder);


    wcscpy_s(shared_data->target_exe_folder, sizeof(shared_data->target_exe_folder), tzTargetFolder);
    wcscpy_s(shared_data->target_exe_name, sizeof(shared_data->target_exe_name), tzTargetName);

    // 发送进程事件信号
    SetEvent(g_hEvent);



    // 创建一个事件，用于通知另一个进程数据已写入
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, L"Injector.Event001");
    if (hEvent == NULL)
    {
        //MessageBox(0, L"创建事件失败", 0, 0);
        std::cout << "Could not create event object (" << GetLastError() << ")." << std::endl;
        UnmapViewOfFile(shared_data);
        CloseHandle(hMapFile);
        return false;
    }

    // 等待另一个进程读取数据完毕
    WaitForSingleObject(hEvent, INFINITE);

    //MessageBox(0, L"事件结束", 0, 0);
    // 清理资源
    CloseHandle(hEvent);
    UnmapViewOfFile(shared_data);
    CloseHandle(hMapFile);

    return true;
}