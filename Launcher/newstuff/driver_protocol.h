#pragma once

// Must match PUBG-Memory-Visualization/driver/driver.h
#include <Windows.h>
#include <cstdint>

#define MM_USER_DEVICE L"\\\\.\\MyMemoryDriver"

#define MM_IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MM_IOCTL_PING         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MM_IOCTL_HANDSHAKE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MM_IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MM_PING_MAGIC 0x4D4D454Du /* 'MMEM' */
#define MM_XOR_MASK   0x12345678u

#pragma pack(push, 1)
typedef struct _MEMORY_PING_RESPONSE {
    uint32_t magic;
    uint32_t version;
} MEMORY_PING_RESPONSE;
#pragma pack(pop)
