#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <src/globals.h>
#include <src/memory/memory.h>

inline uintptr_t rebase(uintptr_t address)
{
	return globals::base + address;
}

namespace offsets
{
    inline const uintptr_t print = 0x1d071a0;
    inline const uintptr_t task_defer = 0x43c38d0;
    inline const uintptr_t get_global_state = 0x425f7a0;

    namespace scheduler
    {
        inline constexpr uintptr_t task_scheduler = 0x8f026a8;
        inline constexpr uintptr_t fps = 0xb0;
    }

    namespace data_model
    {
        inline const uintptr_t fake_data_model = 0x8f59810;
        inline const uintptr_t real_data_model = 0x1f8;
        inline const uintptr_t game_loaded = 0x5c8;

        inline const uintptr_t children = 0x70;
        inline const uintptr_t script_context = 0x440;
    }

    namespace instance
    {
        inline const uintptr_t name = 0x68;
    }

    namespace luau
    {
        inline const uintptr_t luavm_load = 0x42560b0;

        inline const uintptr_t l_userdata = 0x28;
        inline const uintptr_t l_global = 0x78;
        inline const uintptr_t lua_top = 0x70;
        inline const uintptr_t g_mainthread = 0x1a0;
        inline const uintptr_t g_registry = 0x618;
        inline const uintptr_t tbl_tt = 0x2;

        inline const uintptr_t cl_isc = 0x3;
        inline const uintptr_t cl_proto = 0x18;
        inline const uintptr_t cl_func = 0x28;

        inline const uintptr_t p_userdata = 0x38;
        inline const uintptr_t p_nested = 0x30;
        inline const uintptr_t p_sizep = 0xa8;

        inline const uintptr_t tv_value = 0x0;
        inline const uintptr_t tv_tt = 0xC;
        inline const uintptr_t tv_size = 0x10;

        inline const int t_tbl = 7;
        inline const int t_function = 8;

        inline const uint64_t max_capabilities = 0x3FFFFFFFFFFFFFFFull;
    }

    namespace core
    {
        inline const uintptr_t identity = 0x60;
        inline const uintptr_t capabilities = 0x50;
    }

    namespace string
    {
        inline const uintptr_t string_length = 0x18;
    }

    namespace vm
    {
        inline constexpr uint32_t t_string = 6;
        inline constexpr uint32_t t_userdata = 9;

        inline constexpr uintptr_t ts_hash = 0x10;
        inline constexpr uintptr_t ts_len = 0x14;
        inline constexpr uintptr_t ts_data = 0x18;

        inline constexpr uintptr_t tbl_lsizenode = 0x6;
        inline constexpr uintptr_t tbl_node = 0x20;

        inline constexpr uintptr_t node_key_value = 0x10;
        inline constexpr uintptr_t node_key_tt = 0x1C;

        inline constexpr uintptr_t udata_tag = 0x3;
        inline constexpr uintptr_t udata_data = 0x10;

        inline constexpr uintptr_t l_gt = 0x8;

        inline constexpr uintptr_t g_udatadirect = 0x920;

        inline constexpr uintptr_t udatadirect_stride = 0x48;
        inline constexpr uintptr_t udatadirect_namecalltm = 0x20;
        inline constexpr uintptr_t udatadirect_namecall = 0x40;
        inline constexpr uint32_t udatadirect_slots = 130;
    }

    namespace signer
    {
        inline constexpr uintptr_t verify = 0x42fd780;
        inline constexpr uintptr_t key = 0x670f264;

        inline constexpr uint32_t key_value = 0x74171870;
        inline constexpr std::array<uint8_t, 4> marker{0x32, 0xC4, 0x6A, 1};
        inline constexpr size_t minimum_payload = 256;
        inline constexpr size_t maximum_payload = 64 * 1024 * 1024;
        inline constexpr size_t trailer_size = 24;
    }
}
