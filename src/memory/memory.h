#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <src/globals.h>

#include <stddef.h>
#include <stdint.h>
#include <span>
#include <type_traits>
#include <iostream>

struct io_result {
    size_t transferred{};
    DWORD error{};

    constexpr bool ok(size_t expected) const noexcept {
        return error == ERROR_SUCCESS && transferred == expected;
    }

    constexpr explicit operator bool() const noexcept {
        return error == ERROR_SUCCESS;
    }
};

class _process_memory {
public:
    io_result read_into(uintptr_t address, std::span<std::byte> destination) const noexcept;
    io_result write_from(uintptr_t address, std::span<const std::byte> source) const noexcept;

    template <class T> requires std::is_trivially_copyable_v<T>
    T read(uintptr_t address) const noexcept {
        T value{};
        read_into(address, std::as_writable_bytes(std::span<T, 1>{ &value, 1 }));
        return value;
    }

    template <class T> requires std::is_trivially_copyable_v<T>
    bool write(uintptr_t address, const T& value) const noexcept {
        return write_from(address, std::as_bytes(std::span<const T, 1>{ &value, 1 })).ok(sizeof(T));
    }

    template <class T> requires std::is_trivially_copyable_v<T>
    io_result read_array(uintptr_t address, std::span<T> destination) const noexcept {
        return read_into(address, std::as_writable_bytes(destination));
    }

    template <class T> requires std::is_trivially_copyable_v<T>
    io_result write_array(uintptr_t address, std::span<const T> source) const noexcept {
        return write_from(address, std::as_bytes(source));
    }
};

inline _process_memory* memory = new _process_memory();


template <class T>
bool read_value(uintptr_t address, T& value)
{
    return address && memory->read_array(address, std::span(&value, 1)).ok(sizeof(T));
}