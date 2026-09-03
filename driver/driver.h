#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <stdint.h>
#endif

#include "ioctl_crypto.h"

#ifndef CTL_CODE
#ifdef _WIN32
#include <Windows.h>
#else
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED     0
#define FILE_ANY_ACCESS     0
#endif
#endif

#define DEVICE_NAME     L"\\Device\\MyMemoryDriver"
#define SYM_LINK_NAME   L"\\DosDevices\\MyMemoryDriver"
#define USER_DEVICE     L"\\\\.\\MyMemoryDriver"

#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDSHAKE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MM_MAX_READ   (64 * 1024)
#define MM_MAX_WRITE  (64 * 1024)
#define MM_PING_MAGIC 0x4D4D454Du /* 'MMEM' */

#pragma pack(push, 1)

typedef struct _MEMORY_READ_REQUEST {
    uint32_t process_id;
    uint64_t address;
    uint32_t size;
} MEMORY_READ_REQUEST;

typedef struct _MEMORY_WRITE_REQUEST {
    uint32_t process_id;
    uint64_t address;
    uint32_t size;
    /* Payload bytes follow immediately in the IOCTL input buffer. */
} MEMORY_WRITE_REQUEST;

typedef struct _MEMORY_PING_RESPONSE {
    uint32_t magic;
    uint32_t version;
} MEMORY_PING_RESPONSE;

#pragma pack(pop)

#ifdef _KERNEL_MODE

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH MmDispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH MmDispatchDeviceControl;

#endif
