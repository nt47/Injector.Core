#include"pch.h"
#include"misc.h"
#include<iostream>

// ȫ�ֱ����������߳�֮�乲��
HANDLE g_hEvent=NULL;

bool ShareMemory()
{
    // ���������ڴ�
    HANDLE hMapFile = CreateFileMapping(
        INVALID_HANDLE_VALUE,   // ʹ��ҳ���ļ����������ڴ�
        NULL,                   // Ĭ�ϰ�ȫ����
        PAGE_READWRITE,         // �ɶ�д����Ȩ��
        0,                      // ��λ�ֽ�ƫ����
        sizeof(SHARED_DATA),        // �����ڴ��С���ֽڣ�
        L"Injector.SharedMemory");     // �����ڴ�����

    if (hMapFile == NULL)
    {
        std::cout << "Could not create file mapping object (" << GetLastError() << ")." << std::endl;
        return false;
    }

    // �������ڴ�ӳ�䵽���̵ĵ�ַ�ռ�
    PSHARED_DATA shared_data = (PSHARED_DATA)MapViewOfFile(
        hMapFile,           // �����ڴ���
        FILE_MAP_WRITE,     // д����Ȩ��
        0,
        0,
        sizeof(SHARED_DATA));

    if (shared_data == NULL)
    {
        std::cout << "Could not map view of file (" << GetLastError() << ")." << std::endl;
        CloseHandle(hMapFile);
        return false;
    }

    // �ڹ����ڴ���д������
    TCHAR tzPath[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), tzPath, MAX_PATH); //��ȡ��Ŀ¼�µ�
    PathRemoveFileSpec(tzPath);

    GetCurrentDirectory(sizeof(shared_data->exe_folder), shared_data->exe_folder);
    wcscpy_s(shared_data->dll_folder, sizeof(shared_data->dll_folder), tzPath);


    // ���ͽ����¼��ź�
    SetEvent(g_hEvent);



    // ����һ���¼�������֪ͨ��һ������������д��
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, L"Injector.Event001");
    if (hEvent == NULL)
    {
        //MessageBox(0, L"�����¼�ʧ��", 0, 0);
        std::cout << "Could not create event object (" << GetLastError() << ")." << std::endl;
        UnmapViewOfFile(shared_data);
        CloseHandle(hMapFile);
        return false;
    }

    // �ȴ���һ�����̶�ȡ�������
    WaitForSingleObject(hEvent, INFINITE);

    //MessageBox(0, L"�¼�����", 0, 0);
    // ������Դ
    CloseHandle(hEvent);
    UnmapViewOfFile(shared_data);
    CloseHandle(hMapFile);

    return true;
}