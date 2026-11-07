#include "functions.h"

#include <src/roblox/offsets.h>
#include <src/injector/injector.h>

#include <cstdio>
#include <cstring>

bool _functions::print(const std::string& message, uint32_t level)
{
	return injector->fire(build_message_call(offsets::print, level, message));
}

int _functions::luavm_load(uintptr_t lua_state, const std::string& container, const std::string& chunkname, int env)
{
	if (!lua_state || container.empty()) {
		return -1;
	}

	const uintptr_t data_ptr = injector->alloc_remote(container.size(), PAGE_READWRITE);
	const uintptr_t string_ptr = injector->alloc_remote(0x20, PAGE_READWRITE);
	const uintptr_t name_ptr = injector->alloc_remote(chunkname.size() + 1, PAGE_READWRITE);
	const uintptr_t ret_slot = injector->alloc_remote(0x8, PAGE_READWRITE);

	auto free_all = [&]() {
		injector->free_remote(data_ptr);
		injector->free_remote(string_ptr);
		injector->free_remote(name_ptr);
		injector->free_remote(ret_slot);
	};

	if (!data_ptr || !string_ptr || !name_ptr || !ret_slot) {
		free_all();
		return -1;
	}

	const uint64_t sentinel = 0xFEEEFEEEFEEEFEEE;
	if (!injector->write_remote(ret_slot, &sentinel, sizeof(sentinel))) {
		free_all();
		return -1;
	}

	if (!injector->write_remote(data_ptr, container.data(), container.size()) ||
		!injector->write_remote(name_ptr, chunkname.c_str(), chunkname.size() + 1)) {
		free_all();
		return -1;
	}

	uint8_t string_object[0x20] = {};
	const uint64_t size = container.size();
	memcpy(string_object + 0x00, &data_ptr, sizeof(data_ptr));
	memcpy(string_object + 0x10, &size, sizeof(size));
	memcpy(string_object + 0x18, &size, sizeof(size));

	if (!injector->write_remote(string_ptr, string_object, sizeof(string_object))) {
		free_all();
		return -1;
	}

	if (!injector->fire(build_call_ret(offsets::luau::luavm_load,
		lua_state, string_ptr, name_ptr, (uintptr_t)(uint32_t)env, ret_slot))) {
		free_all();
		return -1;
	}

	uint64_t result = 0;
	bool done = false;
	for (int i = 0; i < 400 && !done; i++) {
		Sleep(5);
		if (injector->read_remote(ret_slot, &result, sizeof(result)))
			done = (result != sentinel);
	}

	free_all();

	if (!done) {
		printf("[-] luavm_load: callback never ran\n");
		return -1;
	}

	return (int)(uint32_t)result;
}

bool _functions::task_defer(uintptr_t lua_state)
{
	if (!lua_state) {
		return false;
	}

	const uintptr_t ret_slot = injector->alloc_remote(0x8, PAGE_READWRITE);
	if (!ret_slot) {
		return false;
	}

	const uint64_t sentinel = 0xFEEEFEEEFEEEFEEE;
	if (!injector->write_remote(ret_slot, &sentinel, sizeof(sentinel))) {
		injector->free_remote(ret_slot);
		return false;
	}

	if (!injector->fire(build_call_ret(offsets::task_defer, lua_state, 0, 0, 0, ret_slot))) {
		injector->free_remote(ret_slot);
		return false;
	}

	uint64_t result = 0;
	bool done = false;
	for (int i = 0; i < 400 && !done; i++) {
		Sleep(5);
		if (injector->read_remote(ret_slot, &result, sizeof(result)))
			done = (result != sentinel);
	}

	injector->free_remote(ret_slot);

	if (!done) {
		printf("[-] task_defer: callback never ran\n");
		return false;
	}

	return true;
}

uintptr_t _functions::get_global_state(uintptr_t script_context, uintptr_t* out_a, uintptr_t* out_b)
{
	if (!script_context) {
		return 0;
	}

	const uintptr_t scratch = injector->alloc_remote(0x18, PAGE_READWRITE);
	if (!scratch) {
		return 0;
	}

	const uintptr_t ret_slot = scratch + 0x00;
	const uintptr_t out1_slot = scratch + 0x08;
	const uintptr_t out2_slot = scratch + 0x10;

	const uint64_t sentinel = 0xFEEEFEEEFEEEFEEE;

	if (!injector->write_remote(ret_slot, &sentinel, sizeof(sentinel))) {
		injector->free_remote(scratch);
		return 0;
	}

	if (!injector->fire(build_call_ret(offsets::get_global_state,
		script_context, out1_slot, out2_slot, 0, ret_slot))) {
		injector->free_remote(scratch);
		return 0;
	}

	uint64_t result = 0;
	bool done = false;
	for (int i = 0; i < 400 && !done; i++) {
		Sleep(5);
		if (injector->read_remote(ret_slot, &result, sizeof(result)))
			done = (result != sentinel);
	}

	if (!done) {
		printf("[-] get_global_state: callback never ran\n");
		injector->free_remote(scratch);
		return 0;
	}

	uint64_t a = 0, b = 0;
	injector->read_remote(out1_slot, &a, sizeof(a));
	injector->read_remote(out2_slot, &b, sizeof(b));

	injector->free_remote(scratch);

	*out_a = a;
	*out_b = b;

	return result;
}

std::vector<uint8_t> _functions::build_message_call(uintptr_t fn_offset, uint32_t arg1, const std::string& message)
{
	const uintptr_t module_handle_address = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"));

	std::vector<uint8_t> code;
	auto bytes = [&](std::initializer_list<uint8_t> ops) { code.insert(code.end(), ops); };
	auto dword = [&](uint32_t v) { for (int i = 0; i < 4; i++) code.push_back(uint8_t(v >> (i * 8))); };
	auto qword = [&](uintptr_t v) { for (int i = 0; i < 8; i++) code.push_back(uint8_t(v >> (i * 8))); };

	bytes({ 0x48, 0x83, 0xEC, 0x28 });
	bytes({ 0x33, 0xC9 });
	bytes({ 0x48, 0xB8 }); qword(module_handle_address);
	bytes({ 0xFF, 0xD0 });
	bytes({ 0x48, 0x05 }); dword((uint32_t)fn_offset);
	bytes({ 0x49, 0x89, 0xC2 });
	bytes({ 0xB9 }); dword(arg1);
	bytes({ 0x48, 0x8D, 0x15, 0x08, 0x00, 0x00, 0x00 });
	bytes({ 0x41, 0xFF, 0xD2 });
	bytes({ 0x48, 0x83, 0xC4, 0x28 });
	bytes({ 0xC3 });
	code.insert(code.end(), message.begin(), message.end());
	code.push_back(0);
	return code;
}

std::vector<uint8_t> _functions::build_call(uintptr_t fn_offset, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	const uintptr_t module_handle_address = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"));

	std::vector<uint8_t> code;
	auto bytes = [&](std::initializer_list<uint8_t> ops) { code.insert(code.end(), ops); };
	auto dword = [&](uint32_t v) { for (int i = 0; i < 4; i++) code.push_back(uint8_t(v >> (i * 8))); };
	auto qword = [&](uintptr_t v) { for (int i = 0; i < 8; i++) code.push_back(uint8_t(v >> (i * 8))); };

	bytes({ 0x48, 0x83, 0xEC, 0x28 });
	bytes({ 0x48, 0xB8 }); qword(module_handle_address);
	bytes({ 0x33, 0xC9 });
	bytes({ 0xFF, 0xD0 });
	bytes({ 0x48, 0x05 }); dword((uint32_t)fn_offset);
	bytes({ 0x48, 0xB9 }); qword(a1);
	bytes({ 0x48, 0xBA }); qword(a2);
	bytes({ 0x49, 0xB8 }); qword(a3);
	bytes({ 0x49, 0xB9 }); qword(a4);
	bytes({ 0xFF, 0xD0 });
	bytes({ 0x48, 0x83, 0xC4, 0x28 });
	bytes({ 0xC3 });
	return code;
}

std::vector<uint8_t> _functions::build_call_ret(uintptr_t fn_offset, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t ret_slot)
{
	const uintptr_t module_handle_address = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"));

	std::vector<uint8_t> code;
	auto bytes = [&](std::initializer_list<uint8_t> ops) { code.insert(code.end(), ops); };
	auto dword = [&](uint32_t v) { for (int i = 0; i < 4; i++) code.push_back(uint8_t(v >> (i * 8))); };
	auto qword = [&](uintptr_t v) { for (int i = 0; i < 8; i++) code.push_back(uint8_t(v >> (i * 8))); };

	bytes({ 0x48, 0x83, 0xEC, 0x28 });
	bytes({ 0x48, 0xB8 }); qword(module_handle_address);
	bytes({ 0x33, 0xC9 });
	bytes({ 0xFF, 0xD0 });
	bytes({ 0x48, 0x05 }); dword((uint32_t)fn_offset);
	bytes({ 0x48, 0xB9 }); qword(a1);
	bytes({ 0x48, 0xBA }); qword(a2);
	bytes({ 0x49, 0xB8 }); qword(a3);
	bytes({ 0x49, 0xB9 }); qword(a4);
	bytes({ 0xFF, 0xD0 });
	bytes({ 0x48, 0xA3 }); qword(ret_slot);
	bytes({ 0x48, 0x83, 0xC4, 0x28 });
	bytes({ 0xC3 });

	return code;
}
