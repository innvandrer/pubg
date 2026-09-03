#pragma once

#ifdef _KERNEL_MODE

#include <ntddk.h>

#define EPROCESS_DIRECTORY_TABLE_BASE_OFFSET 0x28

ULONG Cr3GetDirectoryTableBaseOffset(void);

NTSTATUS ReadMemoryByCR3(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size);

NTSTATUS WriteMemoryByCR3(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size);

#endif /* _KERNEL_MODE */
