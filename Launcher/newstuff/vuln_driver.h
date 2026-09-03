#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

// Supported BYOVD providers for kernel memory R/W during manual mapping.
enum class VulnDriverType : int
{
    Gdrv = 0,       // Gigabyte gdrv.sys  (\\.\GIO)  – kernel VA memcpy
    RTCore64 = 1,   // MSI RTCore64.sys    (\\.\RTCore64) – physical memory
    Dbutil = 2,     // Dell dbutil_2_3.sys (\\.\DBUtil_2_3) – kernel VA R/W
    Cpuz = 3,       // CPU-Z cpuz141.sys   (\\.\cpuz141) – physical memory (MSR-based CR3)
    Count
};

struct VulnDriverInfo
{
    VulnDriverType type;
    const wchar_t* displayName;
    const wchar_t* defaultFileName;
    const wchar_t* devicePath;
    const wchar_t* serviceName;
    const wchar_t* driverObjectName; // kernel \Driver\... name for ObReferenceObjectByName
};

const VulnDriverInfo& GetVulnDriverInfo(VulnDriverType type);
const wchar_t* VulnDriverTypeName(VulnDriverType type);

// Load the vulnerable driver via SCM, open its device, and prepare R/W primitives.
bool VulnDriverLoad(VulnDriverType type, const wchar_t* sysPath, std::wstring* errorOut = nullptr);
void VulnDriverUnload();
bool VulnDriverIsLoaded();
VulnDriverType VulnDriverGetLoadedType();

HANDLE VulnDriverDevice();

// Path of the BYOVD image loaded via SCM (empty if not loaded).
std::wstring VulnDriverLoadedPath();

// Kernel virtual-address read/write (physical drivers translate internally).
bool VulnReadKernelMemory(uint64_t address, void* buffer, size_t size);
bool VulnWriteKernelMemory(uint64_t address, const void* buffer, size_t size, DWORD* win32ErrorOut = nullptr);

// Resolve a driver filename or path across known search folders.
// Search order: absolute/as-given, exe\drivers\, <repo>\drivers\, exe dir, Desktop\Drivers, LOADER_DRIVERS_DIR.
std::wstring ResolveDriverFile(const std::wstring& fileNameOrPath);
std::vector<std::wstring> GetDriverSearchRoots();

// Convenience: resolve BYOVD file for the selected provider.
std::wstring VulnDriverDefaultPath(VulnDriverType type);
