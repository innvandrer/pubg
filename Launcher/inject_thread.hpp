#pragma once

#include "config.h"
#include "newstuff/loader.hpp"
#include "newstuff/kernel_utils.h"

#include <atomic>
#include <string>

// One-click PUBG Steam inject flow.
// The worker thread closes/relaunches PUBG via Steam, loads the driver, and starts
// the overlay/aim-assist thread. The UI polls GetInjectStatus() each frame.

enum class InjectState
{
    Idle,
    Terminating,
    Launching,
    WaitingForGame,
    LoadingDriver,
    StartingOverlay,
    Running,
    Failed,
    Stopping
};

struct InjectSettings
{
    Config config;

    // Driver load options (mirror the Kernel Driver panel selections).
    std::string driverPath = "MyMemoryDriver.sys";
    DriverLoader::VulnDriverChoice vulnDriver = DriverLoader::VulnDriverChoice::Gdrv;
    KernelAllocMode kernelAllocMode = KernelAllocMode::Pool;
    bool autoFallbackToScm = false;
};

InjectState GetInjectState();
bool IsInjectBusy();
bool IsInjectRunning();
std::string GetInjectStatus();
void SetInjectStatus(const std::string& s);

bool IsLauncherAdmin();
std::string CheckInjectPrerequisites(const InjectSettings& settings);

// Start the inject worker thread. Returns immediately; the thread detaches and
// updates GetInjectState() / GetInjectStatus().
void StartInjectThread(const InjectSettings& settings);

// Signal the worker to stop. If `terminateGame` is true the configured game
// process is terminated. Blocks up to `timeoutMs` for the overlay to shut down.
void StopInjectThread(bool terminateGame, uint32_t timeoutMs = 5000);
