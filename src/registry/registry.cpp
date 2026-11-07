#include "registry.h"

template <class T>
bool read_probe_value(uintptr_t address, T& value, const char* field)
{
    const auto result = memory->read_array(address, std::span<T>(&value, 1));
    if (!result.ok(sizeof(T))) {
        std::printf("[-] could not read %s at 0x%llX (error %lu)\n",
            field, static_cast<unsigned long long>(address), result.error);
        return false;
    }
    return true;
}

void _registry::probe_registry(uintptr_t state)
{
    uintptr_t global = 0;
    if (!read_probe_value(state + offsets::luau::l_global, global, "lua_State.global"))
        return;
    if (!global) {
        printf("[-] registry probe: lua_state.global is null\n");
        return;
    }

    uintptr_t mainthread = 0;
    if (!read_probe_value(global + offsets::luau::g_mainthread, mainthread, "global_State.mainthread"))
        return;
    if (!mainthread) {
        printf("[-] global_state.mainthread is null\n");
        return;
    }

    uintptr_t mainthread_global = 0;
    if (!read_probe_value(mainthread + offsets::luau::l_global, mainthread_global, "mainthread.global"))
        return;

    if (mainthread_global != global) {
        printf("[-] mainthread.global=0x%llX does not match\n", static_cast<unsigned long long>(mainthread_global));
        return;
    }

    const uintptr_t registry_value = global + offsets::luau::g_registry;
    int tag = -1;
    if (!read_probe_value(registry_value + offsets::luau::tv_tt, tag, "registry TValue.tt"))
        return;
    if (tag != offsets::luau::t_tbl) {
        printf("[-] registry tvalue.tt=%d, expected %d\n", tag, offsets::luau::t_tbl);
        return;
    }

    uintptr_t table = 0;
    if (!read_probe_value(registry_value + offsets::luau::tv_value, table, "registry TValue.value"))
        return;
    if (!table) {
        printf("[-] registry table is null\n");
        return;
    }

    uint8_t table_tag = 0;
    if (!read_probe_value(table + offsets::luau::tbl_tt, table_tag, "registry LuaTable.tt"))
        return;
    if (table_tag != offsets::luau::t_tbl) {
        printf("[-] registry probe: registry LuaTable.tt=%u, expected %d\n", table_tag, offsets::luau::t_tbl);
        return;
    }

}