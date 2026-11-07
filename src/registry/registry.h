#pragma once

#include <src/memory/memory.h>
#include <src/roblox/offsets.h>

class _registry
{
public:
	void probe_registry(uintptr_t state);
};

inline _registry* registry = new _registry();
