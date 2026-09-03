#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

// ntoskrnl.exe base in kernel (from EnumDeviceDrivers).
uint64_t GetNtoskrnlBase();

// Parse the on-disk ntoskrnl and return the kernel VA of an export.
uint64_t GetKernelExport(const char* moduleName, const char* exportName);

// Resolve pool-alloc exports before BYOVD load (pure usermode; warms export cache).
bool PreCacheNtoskrnlExports(std::string* outError = nullptr);

// Allocation mode for kernel memory used during manual mapping.
enum class KernelAllocMode
{
    Pool,           // ExAllocatePool2 / ExAllocatePoolWithTag (default, widely available)
    IndependentPages // MmAllocateIndependentPagesEx (no pool tag, executable by default)
};

// Allocate kernel memory for the driver image using the selected mode.
// Falls back to Pool internally if IndependentPages is requested but unavailable.
uint64_t KernelAllocateMemory(uint32_t size, KernelAllocMode mode,
                                uint32_t tag = 0x4D767244, std::string* outError = nullptr); // 'DrvM'

// Free kernel memory allocated with IndependentPages (Pool allocations are left as-is).
bool KernelFreeMemory(uint64_t base, uint32_t size, KernelAllocMode mode, std::string* outError = nullptr);

// Execute x64 shellcode in executable kernel pool via NtAddAtom redirect (kdmapper-style).
uint64_t RunKernelShellcode(const uint8_t* shellcode, size_t size, uint64_t* outStatus = nullptr,
                            std::string* outError = nullptr);

// Allocate NonPagedPoolExecute via ExAllocatePoolWithTag / ExAllocatePool2 (NtAddAtom hook).
uint64_t KernelAllocatePool(uint32_t size, uint32_t tag = 0x4D767244, std::string* outError = nullptr); // 'DrvM'

// Call a kernel function(arg1, arg2) and return its RAX (NTSTATUS).
int32_t KernelCall2(uint64_t func, uint64_t arg1, uint64_t arg2, std::string* outError = nullptr);

// Clone a valid DRIVER_OBJECT (+ DriverExtension) from a loaded kernel driver.
// Required for manual-mapped drivers whose DriverEntry calls IoCreateDevice.
uint64_t CloneKernelDriverObject(const wchar_t* driverObjectName,
                                 const wchar_t* alternateDriverObjectName = nullptr,
                                 std::string* outError = nullptr);

// True on Windows 11 24H2 (build 26100) and later, where gdrv cannot patch ntoskrnl .text.
bool IsWindows11_24H2OrLater();
