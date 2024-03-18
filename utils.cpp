#include "pch.h"
#include "utils.h"
#include <cstdlib>
#include <cwchar>
#include <string>


wchar_t* c2w(const char* charStr) {
    // ��ȡ����Ļ�������С
    size_t size;
    mbstowcs_s(&size, NULL, 0, charStr, 0);

    // ���仺����
    wchar_t* wcharStr = new wchar_t[size + 1];

    // ִ��ת��
    mbstowcs_s(nullptr, wcharStr, size + 1, charStr, size);

    return wcharStr;
}

