#include"pch.h"
#include"CAutoMutex.h"


CAutoMutex::CAutoMutex()
{
    Create(TEXT("auto_mutex"));
    Wait();
}

CAutoMutex::~CAutoMutex()
{
    Release();
}


bool CAutoMutex::Create(const TCHAR* pName)
{
    m_mutex = ::CreateMutex(NULL, FALSE, pName);
    if (m_mutex == NULL || ::GetLastError() == ERROR_ALREADY_EXISTS)
    {
        return false;
    }
    else
        return true;
}

void CAutoMutex::Release()
{
    if (m_mutex != NULL)
    {
        ReleaseMutex(m_mutex);
        CloseHandle(m_mutex);
        m_mutex = NULL;
    }
}

bool CAutoMutex::Wait()
{
    UINT32 ret = ::WaitForSingleObject(m_mutex, 0);
    if (WAIT_FAILED == ret || WAIT_TIMEOUT == ret)
    {
        return false;
    }
    else
        return true;
}