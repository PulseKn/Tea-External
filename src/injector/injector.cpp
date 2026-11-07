#include "injector.h"

#include <src/globals.h>
#include <src/process/process.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

using nt_query_object_fn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using zw_set_io_completion_fn = LONG(WINAPI*)(HANDLE, PVOID, PVOID, LONG, SIZE_T);

static nt_query_object_fn nt_query_object_ptr = nullptr;
static zw_set_io_completion_fn zw_set_io_completion_ptr = nullptr;

static bool enable_privilege(const wchar_t* privilege_name, DWORD attributes)
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
		return false;

	LUID privilege_luid;
	if (!LookupPrivilegeValueW(nullptr, privilege_name, &privilege_luid)) {
		CloseHandle(token);
		return false;
	}

	TOKEN_PRIVILEGES privileges = {};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = privilege_luid;
	privileges.Privileges[0].Attributes = attributes;

	BOOL result = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
	DWORD error = GetLastError();
	CloseHandle(token);
	return result && error != ERROR_NOT_ALL_ASSIGNED;
}

bool _injector::initialize()
{
	if (!enable_privilege(globals::injector::se_debug_privilege_name, SE_PRIVILEGE_ENABLED))
		printf("[!] SeDebugPrivilege not granted\n");

	const auto pid = process->get_pid(globals::process_name.c_str());
	if (!pid) {
		printf("[-] Roblox 0.744 process not found\n");
		return false;
	}

	const auto handle = process->open_handle();
	if (!handle) {
		printf("[-] OpenProcess failed\n");
		return false;
	}
	globals::handle = handle;

	const auto base = process->get_module_base();
	if (!base) {
		printf("[-] Failed getting module base\n");
		return false;
	}
	globals::base = base;

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	nt_query_object_ptr = (nt_query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
	zw_set_io_completion_ptr = (zw_set_io_completion_fn)GetProcAddress(ntdll, "ZwSetIoCompletion");

	if (!nt_query_object_ptr || !zw_set_io_completion_ptr) {
		printf("[-] Failed resolving ntdll\n");
		return false;
	}

	m_completion_handle = find_io_completion_handle(globals::handle);
	if (!m_completion_handle) {
		printf("[-] IoCompletion handle not found\n");
		return false;
	}

	m_cave_address = find_code_cave(globals::handle, globals::injector::tp_direct_size);
	if (!m_cave_address) {
		printf("[-] Code cave not found\n");
		return false;
	}

	return true;
}

bool _injector::fire(const std::vector<uint8_t>& code)
{
	if (!m_completion_handle || !m_cave_address) {
		return false;
	}

	uintptr_t remote_code = alloc_remote(code.size(), PAGE_EXECUTE_READWRITE);
	if (!remote_code) {
		printf("[-] VirtualAllocEx failed\n");
		return false;
	}

	if (!write_remote(remote_code, code.data(), code.size())) {
		printf("[-] shellcode write failed: 0x%lX\n", GetLastError());
		free_remote(remote_code);
		return false;
	}

	uint8_t direct[globals::injector::tp_direct_size] = {};
	memcpy(direct + globals::injector::tp_direct_callback_offset, &remote_code, sizeof(remote_code));

	if (!write_remote(m_cave_address, direct, sizeof(direct))) {
		free_remote(remote_code);
		return false;
	}

	const LONG status = zw_set_io_completion_ptr(m_completion_handle, (PVOID)m_cave_address, nullptr, 0, 0);
	if (status < 0) {
		free_remote(remote_code);
		return false;
	}

	return true;
}

uintptr_t _injector::alloc_remote(size_t size, DWORD protect)
{
	return (uintptr_t)VirtualAllocEx(globals::handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
}

bool _injector::write_remote(uintptr_t address, const void* data, size_t size)
{
	SIZE_T bytes_written = 0;
	return WriteProcessMemory(globals::handle, (LPVOID)address, data, size, &bytes_written) != FALSE;
}

bool _injector::read_remote(uintptr_t address, void* out, size_t size)
{
	SIZE_T bytes_read = 0;
	return ReadProcessMemory(globals::handle, (LPCVOID)address, out, size, &bytes_read) != FALSE
		&& bytes_read == size;
}

void _injector::free_remote(uintptr_t address)
{
	VirtualFreeEx(globals::handle, (LPVOID)address, 0, MEM_RELEASE);
}

HANDLE _injector::find_io_completion_handle(HANDLE process_handle)
{
	std::vector<uint8_t> type_info(globals::injector::object_type_info_buffer_size);
	const uintptr_t type_info_base = reinterpret_cast<uintptr_t>(type_info.data());

	for (uintptr_t raw_handle = globals::injector::handle_scan_start;
		raw_handle < globals::injector::handle_scan_end;
		raw_handle += globals::injector::handle_scan_step) {

		HANDLE dup_handle = nullptr;
		if (!DuplicateHandle(process_handle, reinterpret_cast<HANDLE>(raw_handle),
			GetCurrentProcess(), &dup_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
			continue;

		bool matched = false;
		const LONG status = nt_query_object_ptr(dup_handle, 2, type_info.data(), (ULONG)globals::injector::object_type_info_buffer_size, nullptr);

		if (status >= 0) {
			uintptr_t name_pointer = 0;
			uint16_t name_length = 0;
			memcpy(&name_pointer, type_info.data() + 8, 8);
			memcpy(&name_length, type_info.data() + 0, 2);
			const intptr_t name_offset = (intptr_t)(name_pointer - type_info_base);

			if (name_pointer && name_length >= 2 && name_offset >= 0 &&
				(size_t)name_offset <= globals::injector::object_type_info_buffer_size - name_length) {
				std::wstring type_name((const wchar_t*)(type_info.data() + name_offset), name_length / 2);
				matched = type_name == globals::injector::io_completion_type_name;
			}
		}

		if (matched)
			return dup_handle;
		CloseHandle(dup_handle);
	}
	return nullptr;
}

uintptr_t _injector::find_code_cave(HANDLE process_handle, size_t cave_size)
{
	const std::vector<uint8_t> needle(cave_size, 0);
	const size_t overlap = cave_size - 1;
	MEMORY_BASIC_INFORMATION mbi = {};
	uintptr_t address = 0;

	while (address < globals::injector::max_user_address) {
		if (!VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi)))
			break;

		const uintptr_t base = mbi.BaseAddress ? (uintptr_t)mbi.BaseAddress : 0;
		const size_t region_size = mbi.RegionSize;

		if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE && region_size >= cave_size) {
			size_t offset = 0;
			while (offset + cave_size <= region_size) {
				size_t chunk_size = std::min(globals::injector::cave_scan_chunk, region_size - offset);
				std::vector<uint8_t> buffer(chunk_size);
				SIZE_T bytes_read = 0;

				if (!ReadProcessMemory(process_handle, (LPCVOID)(base + offset),
					buffer.data(), chunk_size, &bytes_read) || bytes_read < cave_size)
					break;

				const auto end = buffer.begin() + bytes_read;
				const auto hit = std::search(buffer.begin(), end, needle.begin(), needle.end());
				if (hit != end)
					return base + offset + (size_t)(hit - buffer.begin());

				const size_t next_offset = offset + std::max(chunk_size - overlap, (size_t)1);
				if (next_offset <= offset)
					break;
				offset = next_offset;
			}
		}

		const uintptr_t next_address = base + region_size;
		if (next_address <= address)
			break;
		address = next_address;
	}
	return 0;
}
