#include "pch.h"
#include "utils.h"
#include <cstdlib>
#include <cwchar>
#include <string>


wchar_t* c2w(const char* charStr) {
    // 获取所需的缓冲区大小
    size_t size;
    mbstowcs_s(&size, NULL, 0, charStr, 0);

    // 分配缓冲区
    wchar_t* wcharStr = new wchar_t[size + 1];

    // 执行转换
    mbstowcs_s(nullptr, wcharStr, size + 1, charStr, size);

    return wcharStr;
}

