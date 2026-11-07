#include "hooks.h"

#include <src/globals.h>
#include <src/roblox/offsets.h>
#include <src/injector/injector.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace
{
	template <class T>
	T rd(uintptr_t address)
	{
		T value{};
		injector->read_remote(address, &value, sizeof(T));
		return value;
	}

	bool plausible(uint64_t pointer)
	{
		return pointer >= 0x10000 && pointer < 0x7FFFFFFFFFFFull && (pointer & 7) == 0;
	}

	bool in_text(uint64_t pointer)
	{
		return pointer >= globals::base + 0x1000 && pointer < globals::base + 0x630a45c;
	}

	uint32_t luau_hash(const char* data, size_t length)
	{
		uint32_t a = 0, b = 0;
		uint32_t h = static_cast<uint32_t>(length);
		auto rol = [](uint32_t x, uint32_t s) { return (x >> s) | (x << (32 - s)); };
		while (length >= 32)
		{
			uint32_t block[3];
			std::memcpy(block, data, 12);
			a += block[0];
			b += block[1];
			h += block[2];
			a ^= h; a -= rol(h, 14);
			b ^= a; b -= rol(a, 11);
			h ^= b; h -= rol(b, 25);
			data += 12;
			length -= 12;
		}
		for (size_t i = length; i > 0; --i)
			h ^= (h << 5) + (h >> 2) + static_cast<uint8_t>(data[i - 1]);
		return h;
	}

	uintptr_t find_string_node(uintptr_t table, const char* key, int& stride, uintptr_t* out_tstring = nullptr)
	{
		const uint8_t lsizenode = rd<uint8_t>(table + offsets::vm::tbl_lsizenode);
		if (lsizenode > 14)
			return 0;
		const uintptr_t node_base = rd<uintptr_t>(table + offsets::vm::tbl_node);
		if (!plausible(node_base))
			return 0;

		const size_t count = size_t(1) << lsizenode;
		const size_t keylen = std::strlen(key);

		for (int candidate : { 0x20, 0x28 })
		{
			const size_t bytes = count * candidate;
			if (bytes == 0 || bytes > (1u << 20))
				continue;
			std::vector<uint8_t> nodes(bytes);
			if (!injector->read_remote(node_base, nodes.data(), bytes))
				continue;
			for (size_t i = 0; i < count; ++i)
			{
				const uint8_t* n = nodes.data() + i * candidate;
				uint32_t key_tt;
				std::memcpy(&key_tt, n + offsets::vm::node_key_tt, 4);
				if (key_tt != offsets::vm::t_string)
					continue;
				const uintptr_t tstring = *reinterpret_cast<const uintptr_t*>(n + offsets::vm::node_key_value);
				if (!plausible(tstring))
					continue;
				if (rd<uint32_t>(tstring + offsets::vm::ts_len) != keylen)
					continue;
				char data[64] = {};
				if (keylen >= sizeof(data) ||
					!injector->read_remote(tstring + offsets::vm::ts_data, data, keylen) ||
					std::memcmp(data, key, keylen) != 0)
					continue;
				stride = candidate;
				if (out_tstring)
					*out_tstring = tstring;
				return node_base + i * candidate;
			}
		}
		return 0;
	}
}

bool _hooks::probe()
{

	const uintptr_t L = globals::lua_state;
	if (!plausible(L) || !plausible(globals::data_model))
	{
		printf("[-] hooks: lua_state/data_model not ready\n");
		return false;
	}

	const uintptr_t g = rd<uintptr_t>(L + offsets::luau::l_global);
	if (!plausible(g))
	{
		printf("[-] hooks: lua_state.global unreadable\n");
		return false;
	}

	const uintptr_t gt = rd<uintptr_t>(L + offsets::vm::l_gt);
	if (!plausible(gt) || rd<uint8_t>(gt + offsets::luau::tbl_tt) != offsets::luau::t_tbl)
	{
		printf("[-] hooks: lua_state.gt is not a table (0x%llX)\n",
			static_cast<unsigned long long>(gt));
		return false;
	}

	int stride = 0;
	uintptr_t game_tstring = 0;
	const uintptr_t game_node = find_string_node(gt, "game", stride, &game_tstring);
	if (!game_node)
	{
		return false;
	}

	const uint32_t val_tt = rd<uint32_t>(game_node + offsets::luau::tv_tt);
	const uintptr_t udata = rd<uintptr_t>(game_node + offsets::luau::tv_value);
	if (val_tt != offsets::vm::t_userdata || !plausible(udata))
	{
		return false;
	}
	if (rd<uintptr_t>(udata + offsets::vm::udata_data) != globals::data_model)
	{
		return false;
	}
	const uint32_t tag = rd<uint8_t>(udata + offsets::vm::udata_tag);
	if (tag >= offsets::vm::udatadirect_slots)
	{
		return false;
	}

	const uintptr_t entry = g + offsets::vm::g_udatadirect + tag * offsets::vm::udatadirect_stride;
	const uint32_t tm_tt = rd<uint32_t>(entry + offsets::vm::udatadirect_namecalltm + 0xC);
	const uintptr_t closure = rd<uintptr_t>(entry + offsets::vm::udatadirect_namecalltm);
	if (tm_tt != offsets::luau::t_function || !plausible(closure))
	{
		printf("[-] hooks: udatadirect[%u].namecalltm is not a function (tt=%u)\n", tag, tm_tt);
		return false;
	}
	if (rd<uint8_t>(closure + offsets::luau::cl_isc) != 1)
	{
		printf("[-] hooks: namecalltm closure is not a C closure\n");
		return false;
	}
	const uintptr_t original = rd<uintptr_t>(closure + offsets::luau::cl_func);
	if (!in_text(original))
	{
		printf("[-] hooks: original namecall c.f out of range (0x%llX)\n", static_cast<unsigned long long>(original));
		return false;
	}
	const uintptr_t direct_fn = rd<uintptr_t>(entry + offsets::vm::udatadirect_namecall);
	if (game_tstring)
	{
		const uint32_t stored = rd<uint32_t>(game_tstring + offsets::vm::ts_hash);
		const uint32_t computed = luau_hash("game", 4);
		const uint32_t decoded = stored - static_cast<uint32_t>(game_tstring + offsets::vm::ts_hash);
		if (decoded != computed)
		{
			printf("[-] hooks: tstring hash mismatch\n");
			return false;
		}
	}
	return true;
}
