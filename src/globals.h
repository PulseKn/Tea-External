#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

namespace globals {
    inline HANDLE handle;
    inline uintptr_t base;
    inline int process_id;

    inline std::wstring process_name = L"RobloxPlayerBeta.exe";

    inline uintptr_t data_model;
    inline uintptr_t script_context;
    inline uintptr_t lua_state;
    inline uintptr_t caps_remote;

    namespace injector
    {
        inline constexpr const wchar_t* se_debug_privilege_name = L"SeDebugPrivilege";
        inline constexpr const wchar_t* io_completion_type_name = L"IoCompletion";
        inline constexpr uintptr_t handle_scan_start = 4;
        inline constexpr uintptr_t handle_scan_end = 8192;
        inline constexpr uintptr_t handle_scan_step = 4;
        inline constexpr size_t object_type_info_buffer_size = 10000;
        inline constexpr size_t tp_direct_size = 72;
        inline constexpr size_t tp_direct_callback_offset = 56;
        inline constexpr uintptr_t max_user_address = 0x7FFFFFFFFFFF;
        inline constexpr size_t cave_scan_chunk = 0x100000;
    }
}