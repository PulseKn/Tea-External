#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

class _injector
{
public:
	bool initialize();
	bool fire(const std::vector<uint8_t>& code);
	uintptr_t alloc_remote(size_t size, DWORD protect);
	bool write_remote(uintptr_t address, const void* data, size_t size);
	void free_remote(uintptr_t address);
	bool read_remote(uintptr_t address, void* out, size_t size);

private:
	HANDLE find_io_completion_handle(HANDLE process_handle);
	uintptr_t find_code_cave(HANDLE process_handle, size_t cave_size);

	HANDLE m_completion_handle = nullptr;
	uintptr_t m_cave_address = 0;
};

inline _injector* injector = new _injector();