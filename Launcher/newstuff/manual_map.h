#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

#include "vuln_driver.h"
#include "kernel_utils.h"

// ------------------------------------------------------------------
// Manual mapping loader for kernel drivers (BYOVD)
// ------------------------------------------------------------------
class ManualMapper {
public:
    ManualMapper();
    ~ManualMapper();

    bool LoadDriver(const wchar_t* sysPath, VulnDriverType vulnType, KernelAllocMode allocMode,
                    std::wstring* errorOut = nullptr);
    bool UnloadDriver();
    bool IsLoaded() const { return loaded; }

    uint64_t MappedBase() const { return kernelBase; }

private:
    bool OpenDriverFile(const wchar_t* sysPath);
    bool ParsePEHeaders();
    bool BuildLocalImage();
    bool AllocateKernelMemory(KernelAllocMode allocMode);
    bool WriteDriverImage();
    bool ResolveImports();
    bool ApplyRelocations();
    bool CallDriverEntry();
    void Cleanup();

    bool ProcessImportTable();

    uint8_t* localImage;
    SIZE_T localImageSize;
    uint64_t kernelBase;
    uint64_t preferredImageBase;
    uint64_t entryPointRva;
    VulnDriverType vulnType;
    bool loaded;
};

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------
bool ManualMapDriver(const wchar_t* sysPath, VulnDriverType vulnType,
                     KernelAllocMode allocMode = KernelAllocMode::Pool,
                     std::wstring* errorOut = nullptr);
bool UnloadManualMapDriver();

// SCM fallback (testing). Returns false unless the kernel service reaches RUNNING.
bool LoadDriverViaService(const wchar_t* sysPath, const wchar_t* serviceName,
                          std::wstring* errorOut = nullptr);
bool UnloadDriverViaService(const wchar_t* serviceName, std::wstring* errorOut = nullptr);
bool DriverServiceExists(const wchar_t* serviceName);
bool IsManualMapDriverLoaded();
