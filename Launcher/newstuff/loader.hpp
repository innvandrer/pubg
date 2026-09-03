#pragma once
#include <string>
#include "kernel_utils.h"

// ------------------------------------------------------------------
// Driver loader facade for the ImGui launcher GUI.
// ------------------------------------------------------------------
namespace DriverLoader
{
    enum class VulnDriverChoice
    {
        Gdrv = 0,
        RTCore64 = 1,
        Dbutil = 2,
        Cpuz = 3
    };

    const char* VulnDriverChoiceLabel(VulnDriverChoice choice);

    // Manual map via BYOVD (real mapping – no SCM for target driver).
    bool LoadDriverManualMap(const std::string& sysPath, VulnDriverChoice vuln,
                             KernelAllocMode allocMode = KernelAllocMode::Pool,
                             bool fallbackToScm = false,
                             std::string* statusOut = nullptr);

    // SCM service loader (testing fallback). Succeeds only if the service is RUNNING and ping works.
    bool LoadDriverScm(const std::string& sysPath, std::string* statusOut = nullptr);

    // Unload: SCM stop/delete if this process loaded via SCM or the service exists;
    // otherwise release manual-map state. CLI unload in a new process still finds the SCM service.
    bool UnloadDriver(std::string* statusOut = nullptr);

    // Ping the mapped/loaded driver device.
    bool PingDriver(std::string* statusOut = nullptr);

    // True after a successful load until unload completes.
    bool IsDriverLoaded();

    // "Manual Map (BYOVD)", "SCM", or "None".
    const char* GetLoadMethodLabel();
}
