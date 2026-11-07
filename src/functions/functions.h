#pragma once

#include <cstdint>
#include <string>
#include <vector>

class _functions
{
public:
	bool print(const std::string& message, uint32_t level = 0);
	int  luavm_load(uintptr_t lua_state, const std::string& container, const std::string& chunkname, int env = 0);
	bool task_defer(uintptr_t lua_state);
	uintptr_t get_global_state(uintptr_t script_context, uintptr_t* out_a, uintptr_t* out_b);

private:
	std::vector<uint8_t> build_message_call(uintptr_t fn_offset, uint32_t arg1, const std::string& message);
	std::vector<uint8_t> build_call(uintptr_t fn_offset, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4);
	std::vector<uint8_t> build_call_ret(uintptr_t fn_offset, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t ret_slot);
};

inline _functions* functions = new _functions();
