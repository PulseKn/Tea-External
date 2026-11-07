#pragma once

#include <Windows.h>
#include <atomic>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

#include <src/memory/memory.h>
#include <src/roblox/offsets.h>
#include <src/functions/functions.h>
#include <src/injector/injector.h>

#include <Luau/Compiler.h>
#include <Luau/ParseOptions.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/Bytecode.h>
#include <Luau/BytecodeUtils.h>
#include <lua.h>

#include <dependencies/zstd/include/xxhash.h>
#include <dependencies/zstd/include/zstd.h>

class _execution
{
public:
	std::string compile_script(const std::string& src, bool resolve_http = true);

	void set_thread_capabilities(uintptr_t state, uint64_t lvl, uint64_t caps);

	uintptr_t closure_from_top(uintptr_t state);
	void set_proto_caps(uintptr_t root, uintptr_t caps);

	bool execute(const std::string& script, const std::string& chunkname = "@Xploits", bool resolve_http = true);

	uintptr_t initialize();
	void reset() noexcept { m_faulted.store(false); }

private:
	std::atomic_bool m_faulted{ false };

	void write_userdata(uintptr_t proto, uintptr_t caps);
	uintptr_t read_userdata(uintptr_t proto);
};

inline _execution* execution = new _execution();
