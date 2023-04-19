#pragma once
#include <cstdint>

inline uint32_t FNV1A_RUNTIME(const char* str) noexcept {
    if (!str) {
        return 0;
    }

    uint32_t value = 0x811C9DC5;
    for (int i = 0; str[i] != 0; ++i) {
        value = value ^ str[i];
        value *= 0x1000193;
    }

    return value;
} 

constexpr inline uint32_t FNV1A(const char* str, uint32_t value = 0x811C9DC5) noexcept {
    return (!*str) ? value : FNV1A(str + 1, (value ^ uint32_t(*str)) * 0x1000193);
}