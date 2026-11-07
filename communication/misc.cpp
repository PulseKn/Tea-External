#include "misc.hpp"

#include <Windows.h>
#include <lz4.h>
#include <src/roblox/offsets.h>

#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

namespace
{
    constexpr size_t max_data_size = 10 * 1024 * 1024;

    void set_clipboard(std::string_view text)
    {
        if (text.size() > 1024 * 1024 || text.find('\0') != std::string_view::npos)
            throw std::runtime_error("setclipboard: invalid text");

        const int wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (wide_size == 0 && !text.empty())
            throw std::runtime_error("setclipboard: invalid UTF-8");
        std::wstring wide(wide_size, L'\0');
        if (wide_size && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), wide_size))
            throw std::runtime_error("setclipboard: invalid UTF-8");

        const HWND owner = GetConsoleWindow();
        if (!owner || !OpenClipboard(owner))
            throw std::runtime_error("setclipboard: could not open clipboard");
        HGLOBAL storage = GlobalAlloc(GMEM_MOVEABLE, (wide.size() + 1) * sizeof(wchar_t));
        if (!storage)
        {
            CloseClipboard();
            throw std::runtime_error("setclipboard: allocation failed");
        }
        void* bytes = GlobalLock(storage);
        if (!bytes)
        {
            GlobalFree(storage);
            CloseClipboard();
            throw std::runtime_error("setclipboard: allocation failed");
        }
        std::memcpy(bytes, wide.c_str(), (wide.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(storage);
        if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT, storage))
        {
            GlobalFree(storage);
            CloseClipboard();
            throw std::runtime_error("setclipboard: could not update clipboard");
        }
        CloseClipboard();
    }
}

std::string misc_request(std::string_view operation, std::string_view payload)
{
    if (operation == "lz4compress")
    {
        if (payload.size() > max_data_size)
            throw std::runtime_error("lz4compress: data exceeds 10 MiB");
        const int capacity = LZ4_compressBound(static_cast<int>(payload.size()));
        if (!capacity)
            throw std::runtime_error("lz4compress: invalid input size");
        std::string compressed(capacity, '\0');
        const int size = LZ4_compress_default(payload.data(), compressed.data(),
            static_cast<int>(payload.size()), capacity);
        if (!size)
            throw std::runtime_error("lz4compress: compression failed");
        compressed.resize(size);
        return compressed;
    }
    if (operation == "lz4decompress")
    {
        const size_t end = payload.find('\n');
        if (end == std::string_view::npos || end > 8)
            throw std::runtime_error("lz4decompress: invalid size");
        size_t expected = 0;
        const auto parsed = std::from_chars(payload.data(), payload.data() + end, expected);
        if (parsed.ec != std::errc{} || parsed.ptr != payload.data() + end || expected > max_data_size)
            throw std::runtime_error("lz4decompress: invalid size");
        payload.remove_prefix(end + 1);
        if (payload.size() > static_cast<size_t>(LZ4_compressBound(static_cast<int>(max_data_size))))
            throw std::runtime_error("lz4decompress: data exceeds limit");
        std::string decompressed(expected, '\0');
        const int size = LZ4_decompress_safe(payload.data(), decompressed.data(),
            static_cast<int>(payload.size()), static_cast<int>(expected));
        if (size < 0 || static_cast<size_t>(size) != expected)
            throw std::runtime_error("lz4decompress: invalid data or size");
        return decompressed;
    }
    if (operation == "setclipboard")
    {
        set_clipboard(payload);
        return {};
    }
    if (operation == "setfpscap")
    {
        double fps = 0;
        const auto parsed = std::from_chars(payload.data(), payload.data() + payload.size(), fps);
        if (parsed.ec != std::errc{} || parsed.ptr != payload.data() + payload.size() ||
            !std::isfinite(fps) || fps < 0)
            throw std::runtime_error("setfpscap: invalid FPS");
        if (fps == 0 || fps > 250)
            fps = 250;

        uintptr_t scheduler = 0;
        const uintptr_t pointer = rebase(offsets::scheduler::task_scheduler);
        if (!memory->read_array(pointer, std::span(&scheduler, 1)).ok(sizeof(scheduler)) || !scheduler)
            throw std::runtime_error("setfpscap: TaskScheduler unavailable");
        const uintptr_t field = scheduler + offsets::scheduler::fps;
        double previous = 0;
        if (!memory->read_array(field, std::span(&previous, 1)).ok(sizeof(previous)) ||
            !std::isfinite(previous) || previous <= 0 || previous > 1)
            throw std::runtime_error("setfpscap: FPS field is invalid");
        const double frame_time = 1.0 / fps;
        if (!memory->write(field, frame_time))
            throw std::runtime_error("setfpscap: could not write FPS field");
        return {};
    }
    throw std::runtime_error("misc: unknown operation");
}
