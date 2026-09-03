#include "ai_aimassist/aim_assist.h"
#include "config.h"
#include "driver_comm.h"
#include "overlay.h"
#include "pattern_scanner.h"

#include "../driver/manual_map.h"

#include <TlHelp32.h>
#include <cstddef>
#include <cmath>
#include <iostream>
#include <thread>
#include <vector>

static DriverSession g_driver;

static bool DriverRead(uint32_t pid, uint64_t address, void* buffer, size_t size)
{
    return g_driver.Read(pid, address, buffer, size);
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

static void PollKeybinds(Config& config)
{
    if (GetAsyncKeyState(config.key_toggle_menu) & 1)
        config.show_menu = !config.show_menu;

    if (GetAsyncKeyState(config.key_toggle_esp) & 1)
        config.esp_enabled = !config.esp_enabled;

    if (GetAsyncKeyState(config.key_toggle_health) & 1)
        config.esp_health_bar = !config.esp_health_bar;
}

static bool ReadViewMatrix(uint32_t pid, uint64_t view_matrix_addr, float out[4][4])
{
    return DriverRead(pid, view_matrix_addr, out, sizeof(float) * 16);
}

static float Distance3D(const Vector3& a, const Vector3& b)
{
    const float dx = a.x - b.x;
    const float dy = a.y - b.y;
    const float dz = a.z - b.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz) / 100.f;
}

/*
 * Walk UE4 actor array — offsets are configurable and must be validated per build.
 */
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
    if (!DriverRead(pid, offsets.uworld, &uworld_ptr, sizeof(uworld_ptr)) || !uworld_ptr)
        return players;

    uint64_t level = 0;
    if (!DriverRead(pid, uworld_ptr + config.offset_uworld_persistent_level, &level, sizeof(level)) || !level)
        return players;

    struct TArray {
        uint64_t data;
        int32_t count;
        int32_t max;
    } actors{};

    if (!DriverRead(pid, level + config.offset_level_actors, &actors, sizeof(actors)))
        return players;

    if (!actors.data || actors.count <= 0 || actors.count > 4096)
        return players;

    for (int32_t i = 0; i < actors.count; ++i) {
        uint64_t actor = 0;
        if (!DriverRead(pid, actors.data + static_cast<uint64_t>(i) * 8, &actor, sizeof(actor)) || !actor)
            continue;

        uint64_t root = 0;
        if (!DriverRead(pid, actor + config.offset_actor_root, &root, sizeof(root)) || !root)
            continue;

        Vector3 pos{};
        if (!DriverRead(pid, root + 0x1D0, &pos, sizeof(pos)))
            continue;

        if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
            continue;

        Player p{};
        p.pos = pos;
        p.distance = Distance3D(local_pos, pos);

        float health = 100.f;
        DriverRead(pid, actor + config.offset_actor_health, &health, sizeof(health));
        p.health = health;
        p.max_health = 100.f;
        p.is_alive = health > 0.f;

        char name_buf[32]{};
        DriverRead(pid, actor + config.offset_actor_player_name, name_buf, sizeof(name_buf) - 1);
        if (name_buf[0])
            p.name = name_buf;
        else
            p.name = "Entity";

        players.push_back(std::move(p));
    }

    return players;
}

int main(int argc, char** argv)
{
    const std::string config_path = (argc > 1) ? argv[1] : "config.json";

    Config config;
    if (!config.Load(config_path))
        config.SaveDefault(config_path);

    if (!g_driver.Open()) {
        std::cerr << "Driver not reachable. Load it first:\n"
                  << "  loader.exe load ..\\x64\\Release\\MyMemoryDriver.sys\n";
        return 1;
    }

    const uint32_t pid = FindProcessId(config.process_name);
    if (!pid) {
        std::cerr << "Process not found: " << config.process_name << "\n";
        g_driver.Close();
        return 1;
    }

    PatternScanner scanner(pid, DriverRead);
    GameOffsets offsets{};
    if (!scanner.Resolve(
            offsets,
            config.module_name,
            config.pattern_uworld,
            config.pattern_view_matrix,
            config.offset_uworld,
            config.offset_view_matrix)) {
        std::cerr << "Warning: pattern scan failed — set offsets in config.json\n";
    } else {
        std::cout << "UWorld @ 0x" << std::hex << offsets.uworld << std::dec << "\n";
        if (offsets.view_matrix)
            std::cout << "ViewMatrix @ 0x" << std::hex << offsets.view_matrix << std::dec << "\n";
    }

    Overlay overlay;
    if (!overlay.Initialize(config.window_title)) {
        std::cerr << "Overlay init failed\n";
        g_driver.Close();
        return 1;
    }

    std::string exe_dir;
    {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring ws(path);
        const size_t pos = ws.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            exe_dir = std::string(ws.begin(), ws.begin() + static_cast<std::ptrdiff_t>(pos));
    }

    AimAssist ai(config);
    if (ai.Initialize(exe_dir)) {
        overlay.SetAimAssist(&ai);
        ai.Start();
    } else {
        std::cerr << "AI aim assist init failed (missing model weights?)\n";
    }

    Vector3 local_pos{};
    float view_matrix[4][4]{};

    while (overlay.ProcessMessages()) {
        PollKeybinds(config);

        if (offsets.view_matrix)
            ReadViewMatrix(pid, offsets.view_matrix, view_matrix);

        overlay.SetViewMatrix(view_matrix);

        const auto players = GatherPlayers(pid, config, offsets, local_pos);

        overlay.BeginFrame();
        overlay.Render(players, config);
        overlay.EndFrame();

        std::this_thread::sleep_for(std::chrono::milliseconds(8));
    }

    ai.Stop();
    overlay.Shutdown();
    g_driver.Close();
    return 0;
}
