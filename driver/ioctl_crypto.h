#pragma once

#ifdef _KERNEL_MODE
typedef UINT8 uint8_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef SIZE_T size_t;
#else
#include <stddef.h>
#include <stdint.h>
#endif

#define MM_XOR_MASK            0x12345678u
#define MM_KEY_ROTATE_INTERVAL 1000u

#ifdef __cplusplus
extern "C" {
#endif

static inline void MmXorCrypt(void* buffer, size_t size, uint32_t key)
{
    uint8_t* bytes = (uint8_t*)buffer;
    size_t i;

    if (!buffer || size == 0)
        return;

    for (i = 0; i < size; ++i)
        bytes[i] ^= (uint8_t)(key >> ((i & 3u) * 8u));
}

static inline uint32_t MmRotateKey(uint32_t key)
{
    return (key << 7) | (key >> 25);
}

#ifdef __cplusplus
}
#endif
