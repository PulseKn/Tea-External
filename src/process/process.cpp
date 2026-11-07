#include "process.h"

#include <vector>
#include <winver.h>

#pragma comment(lib, "Version.lib")

namespace
{
    bool supported_build(DWORD pid)
    {
        const HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!handle)
            return false;

        std::vector<wchar_t> path(32768);
        DWORD length = static_cast<DWORD>(path.size());
        const bool found = QueryFullProcessImageNameW(handle, 0, path.data(), &length) != FALSE;
        CloseHandle(handle);
        if (!found)
            return false;

        DWORD unused = 0;
        const DWORD bytes = GetFileVersionInfoSizeW(path.data(), &unused);
        if (!bytes)
            return false;
        std::vector<uint8_t> version(bytes);
        if (!GetFileVersionInfoW(path.data(), 0, bytes, version.data()))
            return false;

        VS_FIXEDFILEINFO* info = nullptr;
        UINT size = 0;
        return VerQueryValueW(version.data(), L"\\", reinterpret_cast<void**>(&info), &size) &&
            info && size >= sizeof(*info) && LOWORD(info->dwFileVersionMS) == 744;
    }
}

uintptr_t _process::get_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{ };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snap, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, name) && supported_build(entry.th32ProcessID)) {
                globals::process_id = entry.th32ProcessID;
                CloseHandle(snap);
                return globals::process_id;
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return 0;
}

uintptr_t _process::get_module_base() {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, globals::process_id);
    MODULEENTRY32W entry{ };
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap, &entry)) {
        do {
            if (!_wcsicmp(entry.szModule, globals::process_name.c_str())) {
                CloseHandle(snap);
                return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            }
        } while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return 0;
}

HANDLE _process::open_handle() {
    const HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, globals::process_id);
    return process;
}
