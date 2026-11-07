#include "memory.h"

io_result _process_memory::read_into(uintptr_t address, std::span<std::byte> destination) const noexcept {
    if (destination.empty())
        return {};

    if (!globals::handle || globals::handle == INVALID_HANDLE_VALUE || !address)
        return { 0, ERROR_INVALID_PARAMETER };

    SIZE_T transferred{};
    const BOOL success = ReadProcessMemory(globals::handle, reinterpret_cast<const void*>(address), destination.data(), destination.size(), &transferred);

    if (!success)
        return { transferred, GetLastError() };

    return transferred == destination.size() ? io_result{ transferred, ERROR_SUCCESS } : io_result{ transferred, ERROR_PARTIAL_COPY };
}

io_result _process_memory::write_from(uintptr_t address, std::span<const std::byte> source) const noexcept {
    if (source.empty())
        return {};

    if (!globals::handle || globals::handle == INVALID_HANDLE_VALUE || !address)
        return { 0, ERROR_INVALID_PARAMETER };

    SIZE_T transferred{};
    const BOOL success = WriteProcessMemory(globals::handle, reinterpret_cast<void*>(address), source.data(), source.size(), &transferred);

    if (!success)
        return { transferred, GetLastError() };

    return transferred == source.size() ? io_result{ transferred, ERROR_SUCCESS } : io_result{ transferred, ERROR_PARTIAL_COPY };
}
