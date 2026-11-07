#pragma once

#include <src/globals.h>
#include <src/roblox/offsets.h>
#include <src/memory/memory.h>

#include <string>
#include <cstdint>

class _instances
{
public:
	uintptr_t get_data_model();

	uintptr_t get_script_context();
	
	std::string read_string(uint64_t string);

	std::string get_name(uintptr_t instance);
};

inline _instances* instances = new _instances();