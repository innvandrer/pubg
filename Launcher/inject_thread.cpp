#include "inject_thread.hpp"
#include "client_panel.hpp"
#include "log.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <winreg.h>
#include <Psapi.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>

#pragma comment(lib, "shell32.lib")

static std::wstring AnsiToWide(const std::string& narrow)
{
    if (narrow.empty())
        return {};
    const int len = MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, nullptr, 0);
    if (len <= 0)
        return {};
    std::wstring wide(static_cast<size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, wide.data(), len);
    return wide;
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

namespace
{
    std::atomic<InjectState> g_state{ InjectState::Idle };
    std::atomic<bool> g_busy{ false };
    std::atomic<bool> g_stopRequested{ false };
    std::atomic<bool> g_terminateGameOnStop{ false };
    std::mutex g_statusMutex;
    std::string g_status = "Press Inject to start the one-click PUBG flow.";

    void SetStatus(const std::string& s)
    {
        {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            g_status = s;
        }
        LogInfo(s);
    }

    void SetFailed(const std::string& msg)
    {
        SetStatus(msg);
        LogError(msg);
        g_state = InjectState::Failed;
        g_busy = false;
    }

    bool IsRunningAsAdmin()
    {
        BOOL admin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &admin);
            FreeSid(adminGroup);
        }
        return admin == TRUE;
    }

    uint32_t FindProcessId(const std::string& name)
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

    bool TerminateProcessByName(const std::string& name)
    {
        bool any = false;
        for (int pass = 0; pass < 8; ++pass) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                break;

            PROCESSENTRY32 pe{ sizeof(pe) };
            if (Process32First(snap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, name.c_str()) == 0) {
                        HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (proc) {
                            TerminateProcess(proc, 1);
                            CloseHandle(proc);
                            any = true;
                        }
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);

            if (!FindProcessId(name))
                break;
            Sleep(250);
        }
        return any;
    }

    std::wstring FindSteamExe()
    {
        HKEY hKey = nullptr;
        wchar_t buffer[MAX_PATH] = {};
        DWORD size = sizeof(buffer);
        DWORD type = 0;

        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"SteamExe", nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS && type == REG_SZ) {
                RegCloseKey(hKey);
                return buffer;
            }
            RegCloseKey(hKey);
        }

        size = sizeof(buffer);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"InstallPath", nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS && type == REG_SZ) {
                RegCloseKey(hKey);
                std::wstring path = buffer;
                if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
                    path += L'\\';
                path += L"Steam.exe";
                return path;
            }
            RegCloseKey(hKey);
        }

        static const wchar_t* fallbacks[] = {
            L"C:\\Program Files (x86)\\Steam\\Steam.exe",
            L"C:\\Program Files\\Steam\\Steam.exe"
        };
        for (const wchar_t* path : fallbacks) {
            if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
                return path;
        }
        return {};
    }

    struct EnumWindowContext {
        uint32_t pid = 0;
        std::wstring titleSubstring;
        HWND result = nullptr;
    };

    BOOL CALLBACK FindWindowByTitleAndPidCallback(HWND hwnd, LPARAM lParam)
    {
        auto* ctx = reinterpret_cast<EnumWindowContext*>(lParam);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (ctx->pid != 0 && pid != ctx->pid)
            return TRUE;
        if (!IsWindowVisible(hwnd))
            return TRUE;

        wchar_t title[256] = {};
        GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0])));
        if (wcsstr(title, ctx->titleSubstring.c_str()) != nullptr) {
            ctx->result = hwnd;
            return FALSE;
        }
        return TRUE;
    }

    HWND FindGameWindow(uint32_t pid, const std::string& titleSubstring)
    {
        EnumWindowContext ctx{};
        ctx.pid = pid;
        ctx.titleSubstring = AnsiToWide(titleSubstring);
        EnumWindows(FindWindowByTitleAndPidCallback, reinterpret_cast<LPARAM>(&ctx));
        return ctx.result;
    }

    HWND FindGameWindowByTitle(const std::string& titleSubstring)
    {
        EnumWindowContext ctx{};
        ctx.titleSubstring = AnsiToWide(titleSubstring);
        EnumWindows(FindWindowByTitleAndPidCallback, reinterpret_cast<LPARAM>(&ctx));
        return ctx.result;
    }

    static void InjectWorker(InjectSettings settings)
    {
        struct BusyGuard { ~BusyGuard() { g_busy = false; } } guard;

        g_stopRequested = false;
        g_terminateGameOnStop = settings.config.inject_stop_terminates_game;
        SetStatus("[*] Starting one-click PUBG flow...");
        g_state = InjectState::Launching;

        if (!IsRunningAsAdmin()) {
            SetFailed("[-] Run the launcher as Administrator to use the Steam inject flow.");
            return;
        }

        if (settings.config.inject_close_existing) {
            g_state = InjectState::Terminating;
            SetStatus("[*] Closing existing PUBG processes...");
            TerminateProcessByName(settings.config.inject_process_name);
            TerminateProcessByName(settings.config.inject_alt_process_name);

            for (int i = 0; i < 20; ++i) {
                if (!FindProcessId(settings.config.inject_process_name) &&
                    !FindProcessId(settings.config.inject_alt_process_name)) {
                    break;
                }
                Sleep(500);
            }
        }

        g_state = InjectState::Launching;
        SetStatus("[*] Launching PUBG via Steam...");

        const std::wstring appid = std::to_wstring(settings.config.inject_steam_appid);
        const std::wstring url = L"steam://rungameid/" + appid;
        HINSTANCE launchResult = ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        bool launched = reinterpret_cast<INT_PTR>(launchResult) > 32;

        if (!launched) {
            const std::wstring steamExe = FindSteamExe();
            if (!steamExe.empty()) {
                const std::wstring args = L"-applaunch " + appid;
                launchResult = ShellExecuteW(nullptr, L"open", steamExe.c_str(), args.c_str(), nullptr, SW_SHOWNORMAL);
                launched = reinterpret_cast<INT_PTR>(launchResult) > 32;
            }
        }

        if (!launched) {
            SetFailed("[-] Failed to launch PUBG via Steam. Steam is not installed or not registered.");
            return;
        }

        g_state = InjectState::WaitingForGame;
        SetStatus("[*] Waiting for PUBG game window...");

        uint32_t pid = 0;
        HWND gameWindow = nullptr;
        const auto waitStart = std::chrono::steady_clock::now();
        const int timeoutMs = settings.config.inject_launch_timeout_ms > 0 ? settings.config.inject_launch_timeout_ms : 120000;

        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - waitStart).count() < timeoutMs) {
            pid = FindProcessId(settings.config.inject_process_name);
            if (!pid)
                pid = FindProcessId(settings.config.inject_alt_process_name);

            if (pid) {
                gameWindow = FindGameWindow(pid, settings.config.inject_window_title);
                if (!gameWindow)
                    gameWindow = FindGameWindowByTitle(settings.config.inject_window_title);
            } else {
                gameWindow = FindGameWindowByTitle(settings.config.inject_window_title);
            }

            if (pid && gameWindow)
                break;

            Sleep(500);
        }

        if (!pid) {
            SetFailed("[-] Game launch timeout: PUBG process not found.");
            return;
        }
        if (!gameWindow) {
            SetFailed("[-] Game window timeout: found process but no visible window matching '" + settings.config.inject_window_title + "'.");
            return;
        }

        g_state = InjectState::LoadingDriver;
        SetStatus("[*] Loading MyMemoryDriver.sys...");

        std::string driverStatus;
        const bool loaded = DriverLoader::LoadDriverManualMap(
            settings.driverPath,
            settings.vulnDriver,
            settings.kernelAllocMode,
            settings.autoFallbackToScm,
            &driverStatus);
        SetStatus(driverStatus);

        if (!loaded) {
            SetFailed("[-] Driver load failed.");
            return;
        }

        g_state = InjectState::StartingOverlay;
        SetStatus("[*] Starting overlay and aim assist...");

        Config overlayConfig = settings.config;
        overlayConfig.process_name = settings.config.inject_process_name;
        overlayConfig.window_title = settings.config.inject_window_title;

        std::string overlayStatus;
        if (!PUBGPanelStartOverlay(overlayConfig, &overlayStatus)) {
            SetStatus(overlayStatus);
            SetFailed("[-] Overlay start failed.");
            return;
        }

        const auto overlayStart = std::chrono::steady_clock::now();
        const int overlayTimeoutMs = 15000;
        bool overlayReady = false;
        bool overlayFailed = false;

        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - overlayStart).count() < overlayTimeoutMs) {
            if (!PUBGPanelIsOverlayRunning()) {
                overlayFailed = true;
                break;
            }
            const std::string s = PUBGPanelGetStatus();
            if (s.find("[+] Overlay running") != std::string::npos) {
                overlayReady = true;
                break;
            }
            if (s.find("[-]") != std::string::npos) {
                overlayFailed = true;
                break;
            }
            Sleep(100);
        }

        if (overlayFailed) {
            SetFailed("[-] Overlay failed to initialize.");
            return;
        }
        if (!overlayReady) {
            SetFailed("[-] Overlay start timed out.");
            return;
        }

        g_state = InjectState::Running;
        SetStatus("[+] Overlay active.");

        while (!g_stopRequested.load()) {
            if (!PUBGPanelIsOverlayRunning()) {
                SetStatus("[*] Overlay stopped unexpectedly.");
                break;
            }
            Sleep(100);
        }

        g_state = InjectState::Stopping;
        SetStatus("[*] Stopping PUBG inject flow...");

        if (g_terminateGameOnStop.load()) {
            TerminateProcessByName(settings.config.inject_process_name);
            TerminateProcessByName(settings.config.inject_alt_process_name);
        }

        std::string stopStatus;
        PUBGPanelStopOverlay(&stopStatus, 10000);

        g_state = InjectState::Idle;
        SetStatus("[*] Detached.");
    }
}

InjectState GetInjectState()
{
    return g_state.load();
}

bool IsInjectBusy()
{
    return g_busy.load();
}

bool IsInjectRunning()
{
    const auto state = g_state.load();
    return state == InjectState::Running || state == InjectState::StartingOverlay || state == InjectState::WaitingForGame;
}

std::string GetInjectStatus()
{
    std::lock_guard<std::mutex> lock(g_statusMutex);
    return g_status;
}

void SetInjectStatus(const std::string& s)
{
    SetStatus(s);
}

void StartInjectThread(const InjectSettings& settings)
{
    if (g_busy.exchange(true)) {
        return;
    }
    g_state = InjectState::Launching;
    g_stopRequested = false;
    std::thread(InjectWorker, settings).detach();
}

void StopInjectThread(bool terminateGame, uint32_t timeoutMs)
{
    (void)timeoutMs;
    g_terminateGameOnStop = terminateGame;
    g_stopRequested = true;
    SetStatus("[*] Stop requested.");
}

bool IsLauncherAdmin()
{
    return IsRunningAsAdmin();
}

std::string CheckInjectPrerequisites(const InjectSettings& settings)
{
    std::string result;

    if (!IsRunningAsAdmin())
        result += "[-] Not running as Administrator.\n";

    if (FindSteamExe().empty())
        result += "[-] Steam installation not found.\n";

    const std::string exeDir = ExeDirectory();
    if (!exeDir.empty()) {
        auto IsAbsolutePath = [](const std::string& p) {
            return p.size() >= 2 && std::isalpha(static_cast<unsigned char>(p[0])) && p[1] == ':';
        };

        const std::string driverPath = IsAbsolutePath(settings.driverPath)
            ? settings.driverPath
            : exeDir + "\\" + settings.driverPath;

        const int len = MultiByteToWideChar(CP_ACP, 0, driverPath.c_str(), -1, nullptr, 0);
        if (len > 0) {
            std::wstring wide(static_cast<size_t>(len - 1), L'\0');
            MultiByteToWideChar(CP_ACP, 0, driverPath.c_str(), -1, wide.data(), len);
            if (GetFileAttributesW(wide.c_str()) == INVALID_FILE_ATTRIBUTES)
                result += "[-] Driver file not found: " + driverPath + "\n";
        }

        if (GetFileAttributesW(AnsiToWide(exeDir + "\\opencv_world470.dll").c_str()) == INVALID_FILE_ATTRIBUTES)
            result += "[-] opencv_world470.dll not found next to Launcher.exe.\n";

        if (GetFileAttributesW(AnsiToWide(exeDir + "\\runtime\\yolov3-tiny.weights").c_str()) == INVALID_FILE_ATTRIBUTES)
            result += "[-] YOLO weights not found: runtime\\yolov3-tiny.weights.\n";
    }

    if (!result.empty())
        result += "[*] Some inject prerequisites are missing; the flow may fail.";

    return result;
}
