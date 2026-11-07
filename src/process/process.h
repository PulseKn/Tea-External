#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <src/globals.h>

class _process
{
public:
    uintptr_t get_pid(const wchar_t* name);
    uintptr_t get_module_base();
    HANDLE open_handle();
};

inline _process* process = new _process();