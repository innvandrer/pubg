#include "client_panel.hpp"

#include "config.h"
#include "log.hpp"
#include "driver.h"
#include "driver_comm.h"
#include "overlay.h"
#include "pattern_scanner.h"
#include "ai_aimassist/aim_assist.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <cmath>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>

static DriverSession g_overlayDriver;
static Config g_overlayConfig;

static std::atomic<bool> g_overlayRunning{ false };
static std::atomic<bool> g_overlayThreadActive{ false };
static std::atomic<bool> g_overlayStopRequested{ false };
static std::mutex g_overlayStatusMutex;
static std::string g_overlayStatus = "Load config and launch overlay.";

static std::atomic<bool> g_overlayReady{ false };

static void SetOverlayStatus(const std::string& s)
{
    {
        std::lock_guard<std::mutex> lock(g_overlayStatusMutex);
        g_overlayStatus = s;
    }
    if (s.find("[-]") != std::string::npos)
        LogError(s);
    else
        LogInfo(s);
}

static bool OverlayDriverRead(uint32_t pid, uint64_t address, void* buffer, size_t size)
{
    return g_overlayDriver.Read(pid, address, buffer, size);
}

static uint32_t FindProcessId(const std::string& name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe{ sizeof(pe) };
    uint32_t pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

static std::string ExeDirectory()
{
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH))
        return {};

    const int len = WideCharToMultiByte(CP_ACP, 0, path, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};

    std::string narrow(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, path, -1, narrow.data(), len, nullptr, nullptr);

    const size_t pos = narrow.find_last_of("\\/");
    if (pos == std::string::npos)
        return {};

    narrow.resize(pos);
    return narrow;
}

static float Distance3D(const Vector3& a, const Vector3& b)
{
    const float dx = a.x - b.x;
    const float dy = a.y - b.y;
    const float dz = a.z - b.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz) / 100.f;
}

static std::vector<Player> GatherPlayers(
    uint32_t pid,
    const Config& config,
    const GameOffsets& offsets,
    const Vector3& local_pos)
{
    std::vector<Player> players;
    if (!offsets.uworld)
        return players;

    uint64_t uworld_ptr = 0;
    if (!OverlayDriverRead(pid, offsets.uworld, &uworld_ptr, sizeof(uworld_ptr)) || !uworld_ptr)
        return players;

    uint64_t level = 0;
    if (!OverlayDriverRead(pid, uworld_ptr + config.offset_uworld_persistent_level, &level, sizeof(level)) || !level)
        return players;

    struct TArray {
        uint64_t data;
        int32_t count;
        int32_t max;
    } actors{};

    if (!OverlayDriverRead(pid, level + config.offset_level_actors, &actors, sizeof(actors)))
        return players;

    if (!actors.data || actors.count <= 0 || actors.count > 4096)
        return players;

    for (int32_t i = 0; i < actors.count; ++i) {
        uint64_t actor = 0;
        if (!OverlayDriverRead(pid, actors.data + static_cast<uint64_t>(i) * 8, &actor, sizeof(actor)) || !actor)
            continue;

        uint64_t root = 0;
        if (!OverlayDriverRead(pid, actor + config.offset_actor_root, &root, sizeof(root)) || !root)
            continue;

        Vector3 pos{};
        if (!OverlayDriverRead(pid, root + 0x1D0, &pos, sizeof(pos)))
            continue;

        if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
            continue;

        Player p{};
        p.pos = pos;
        p.distance = Distance3D(local_pos, pos);

        float health = 100.f;
        OverlayDriverRead(pid, actor + config.offset_actor_health, &health, sizeof(health));
        p.health = health;
        p.max_health = 100.f;
        p.is_alive = health > 0.f;

        char name_buf[32]{};
        OverlayDriverRead(pid, actor + config.offset_actor_player_name, name_buf, sizeof(name_buf) - 1);
        if (name_buf[0])
            p.name = name_buf;
        else
            p.name = "Entity";

        players.push_back(std::move(p));
    }

    return players;
}

static bool ReadViewMatrix(uint32_t pid, uint64_t view_matrix_addr, float out[4][4])
{
    return OverlayDriverRead(pid, view_matrix_addr, out, sizeof(float) * 16);
}

static void PollKeybinds(Config& config)
{
    if (GetAsyncKeyState(config.key_toggle_menu) & 1)
        config.show_menu = !config.show_menu;

    if (GetAsyncKeyState(config.key_toggle_esp) & 1)
        config.esp_enabled = !config.esp_enabled;

    if (GetAsyncKeyState(config.key_toggle_health) & 1)
        config.esp_health_bar = !config.esp_health_bar;
}

static void OverlayThread()
{
    g_overlayThreadActive = true;
    g_overlayRunning = true;
    g_overlayReady = false;

    if (!g_overlayDriver.Open()) {
        SetOverlayStatus("[-] Driver not reachable. Load MyMemoryDriver first.");
        g_overlayRunning = false;
        g_overlayThreadActive = false;
        return;
    }

    const uint32_t pid = FindProcessId(g_overlayConfig.process_name);
    if (!pid) {
        SetOverlayStatus("[-] Process not found: " + g_overlayConfig.process_name);
        g_overlayDriver.Close();
        g_overlayRunning = false;
        g_overlayThreadActive = false;
        return;
    }

    SetOverlayStatus("[*] Resolving offsets...");
    PatternScanner scanner(pid, OverlayDriverRead);
    GameOffsets offsets{};
    if (!scanner.Resolve(
            offsets,
            g_overlayConfig.module_name,
            g_overlayConfig.pattern_uworld,
            g_overlayConfig.pattern_view_matrix,
            g_overlayConfig.offset_uworld,
            g_overlayConfig.offset_view_matrix)) {
        SetOverlayStatus("[-] Pattern scan failed — set offsets in config.json");
    } else {
        SetOverlayStatus("[+] Offsets resolved.");
    }

    Overlay overlay;
    if (!overlay.Initialize(g_overlayConfig.window_title)) {
        SetOverlayStatus("[-] Overlay init failed.");
        g_overlayDriver.Close();
        g_overlayRunning = false;
        g_overlayThreadActive = false;
        return;
    }

    AimAssist ai(g_overlayConfig);
    if (ai.Initialize(ExeDirectory())) {
        overlay.SetAimAssist(&ai);
        ai.Start();
    } else {
        SetOverlayStatus("[-] AI aim assist init failed (missing model weights?).");
    }

    g_overlayReady = true;
    SetOverlayStatus("[+] Overlay running.");

    Vector3 local_pos{};
    float view_matrix[4][4]{};

    while (overlay.ProcessMessages() && !g_overlayStopRequested.load()) {
        PollKeybinds(g_overlayConfig);

        if (offsets.view_matrix)
            ReadViewMatrix(pid, offsets.view_matrix, view_matrix);

        overlay.SetViewMatrix(view_matrix);

        const auto players = GatherPlayers(pid, g_overlayConfig, offsets, local_pos);

        overlay.BeginFrame();
        overlay.Render(players, g_overlayConfig);
        overlay.EndFrame();

        std::this_thread::sleep_for(std::chrono::milliseconds(8));
    }

    ai.Stop();
    overlay.Shutdown();
    g_overlayDriver.Close();
    g_overlayRunning = false;
    g_overlayThreadActive = false;
    g_overlayReady = false;
    SetOverlayStatus("[*] Overlay stopped.");
}

bool PUBGPanelLoadConfig(const std::string& path, std::string* statusOut)
{
    if (statusOut) statusOut->clear();

    if (!g_overlayConfig.Load(path)) {
        g_overlayConfig.SaveDefault(path);
        if (statusOut) *statusOut = "[*] Created default config: " + path;
    } else {
        if (statusOut) *statusOut = "[+] Config loaded: " + path;
    }
    return true;
}

bool PUBGPanelAttach(std::string* statusOut)
{
    if (statusOut) statusOut->clear();

    if (g_overlayThreadActive) {
        if (statusOut) *statusOut = "[*] Overlay is already active.";
        return true;
    }

    DriverSession testSession;
    if (!testSession.Open()) {
        if (statusOut) *statusOut = "[-] Driver not reachable. Load MyMemoryDriver first.";
        return false;
    }
    testSession.Close();

    const uint32_t pid = FindProcessId(g_overlayConfig.process_name);
    if (!pid) {
        if (statusOut) *statusOut = "[-] Process not found: " + g_overlayConfig.process_name;
        return false;
    }

    if (statusOut) *statusOut = "[+] Process found (PID " + std::to_string(pid) + "). Ready to launch overlay.";
    return true;
}

bool PUBGPanelLaunchOverlay(std::string* statusOut)
{
    if (statusOut) statusOut->clear();

    if (g_overlayThreadActive) {
        if (statusOut) *statusOut = "[-] Overlay is already running.";
        return false;
    }

    g_overlayStopRequested = false;
    std::thread(OverlayThread).detach();

    if (statusOut) *statusOut = "[*] Launching overlay thread...";
    return true;
}

bool PUBGPanelStartOverlay(const Config& config, std::string* statusOut)
{
    if (statusOut) statusOut->clear();

    if (g_overlayThreadActive) {
        if (statusOut) *statusOut = "[-] Overlay is already running.";
        return false;
    }

    g_overlayConfig = config;
    g_overlayStopRequested = false;
    std::thread(OverlayThread).detach();

    if (statusOut) *statusOut = "[*] Launching overlay thread...";
    return true;
}

bool PUBGPanelStopOverlay(std::string* statusOut, uint32_t timeoutMs)
{
    if (statusOut) statusOut->clear();

    if (!g_overlayThreadActive) {
        if (statusOut) *statusOut = "[*] Overlay is not running.";
        return true;
    }

    g_overlayStopRequested = true;
    SetOverlayStatus("[*] Stopping overlay...");

    const auto start = std::chrono::steady_clock::now();
    while (g_overlayThreadActive.load() &&
           std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < static_cast<int64_t>(timeoutMs)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    if (g_overlayThreadActive) {
        if (statusOut) *statusOut = "[-] Overlay thread did not stop in time.";
        return false;
    }

    if (statusOut) *statusOut = "[+] Overlay stopped.";
    return true;
}

bool PUBGPanelIsOverlayRunning()
{
    return g_overlayThreadActive;
}

std::string PUBGPanelGetStatus()
{
    std::lock_guard<std::mutex> lock(g_overlayStatusMutex);
    return g_overlayStatus;
}
