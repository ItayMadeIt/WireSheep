#pragma once
#include "WireDefs.h"
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h> // import custom compiler functions for faster swap
#endif

class Endianness
{
public:
    // Static function to check system's endianness (computed once)
    static bool isBigEndian();

    // Convert an X-bit value from system to little endian
    template<typename T>
    static T toNetwork(const T& value);

    // Convert an X-bit value from little endian to system
    template<typename T>
    static T fromNetwork(const T& value);

private:
    // Static const that stores whether the system is big-endian (computed once)
    static const bool bigEndian;

    // Swap the endiannes of a value
    template <typename T>
    static T swapEndian(T value);

    // Static initializer to compute whether the system is big endian
    static bool isSystemBigEndian();


};


// Convert an X-bit value from system to little endian

template<typename T>
T Endianness::toNetwork(const T& value)
{
    if (bigEndian)
    {
        return value; // System is already big-endian
    }

    return swapEndian(value); // Swap to big-endian
}

// Convert an X-bit value from little endian to system

template<typename T>
T Endianness::fromNetwork(const T& value)
{
    if (bigEndian)
    {
        return value; // System is already big-endian
    }
    return swapEndian(value); // Swap to system endianness
}

// Swaps between the 2
template<typename T>
T Endianness::swapEndian(T value)
{
    if constexpr (sizeof(T) == 1) {
        return value; // No need to swap 1-byte values
    }
    else if constexpr (sizeof(T) == 2) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(value); // GCC / Clang intrinsic for 16-bit
#elif defined(_MSC_VER)
        return _byteswap_ushort(value);  // MSVC intrinsic for 16-bit
#else
        return static_cast<T>((value >> 8) | (value << 8)); // Manual swap for 16-bit
#endif
    }
    else if constexpr (sizeof(T) == 4) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(value); // GCC / Clang intrinsic for 32-bit
#elif defined(_MSC_VER)
        return _byteswap_ulong(value);   // MSVC intrinsic for 32-bit
#else
        return static_cast<T>(((value >> 24) & 0x000000FF) |
                ((value >> 8) & 0x0000FF00) |
                ((value << 8) & 0x00FF0000) |
                ((value << 24) & 0xFF000000)); // Manual swap for 32-bit
#endif
    }
    else if constexpr (sizeof(T) == 8) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap64(value); // GCC / Clang intrinsic for 64-bit
#elif defined(_MSC_VER)
        return _byteswap_uint64(value);  // MSVC intrinsic for 64-bit
#else
        return static_cast<T>(((value >> 56) & 0x00000000000000FF) |
                ((value >> 40) & 0x000000000000FF00) |
                ((value >> 24) & 0x0000000000FF0000) |
                ((value >> 8) & 0x00000000FF000000) |
                ((value << 8) & 0x000000FF00000000) |
                ((value << 24) & 0x0000FF0000000000) |
                ((value << 40) & 0x00FF000000000000) |
                ((value << 56) & 0xFF00000000000000)); // Manual swap for 64-bit
#endif
    }
    else {
        static_assert(sizeof(T) <= 8, "Unsupported type size for endianness conversion");
        return value; // Fallback in case of unexpected type size
    }
}
