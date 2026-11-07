#pragma once

class _hooks
{
public:
	bool probe();
};

inline _hooks* hooks = new _hooks();
