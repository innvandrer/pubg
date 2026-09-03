#pragma once

#include <string>
#include "config.h"

// PUBG client panel API for the unified launcher.
// Loads config.json, attaches to TslGame.exe, and runs the ESP/AI overlay
// in a dedicated thread with its own D3D11/ImGui context.

bool PUBGPanelLoadConfig(const std::string& path, std::string* statusOut);
bool PUBGPanelAttach(std::string* statusOut);
bool PUBGPanelLaunchOverlay(std::string* statusOut);
bool PUBGPanelIsOverlayRunning();
std::string PUBGPanelGetStatus();

// Start the overlay with the provided config. Replaces the current global config
// and launches the overlay thread. Returns immediately.
bool PUBGPanelStartOverlay(const Config& config, std::string* statusOut);

// Signal the overlay thread to stop and wait up to `timeoutMs` for it to exit.
bool PUBGPanelStopOverlay(std::string* statusOut, uint32_t timeoutMs = 5000);
