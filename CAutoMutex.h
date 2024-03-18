#pragma once
class CAutoMutex
{
public:
    CAutoMutex();
    ~CAutoMutex();

private:

    bool Create(const TCHAR* pName);

    void Release();

    bool Wait();

    // ������
    HANDLE m_mutex;
};