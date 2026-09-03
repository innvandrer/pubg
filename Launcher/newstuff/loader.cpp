#include "loader.hpp"
#include "manual_map.h"
#include "vuln_driver.h"
#include "driver.h"
#include "driver_comm.h"
#include "log.hpp"

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string>

namespace DriverLoader
{
    static bool g_loadedViaScm = false;
    static bool g_driverLoaded = false;

    static void SetStatusAndLog(std::string* statusOut, const std::string& msg, bool error)
    {
        if (statusOut)
            statusOut->assign(msg);
        if (error)
            LogError(msg);
        else
            LogInfo(msg);
        printf("%s\n", msg.c_str());
        fflush(stdout);
    }

    static std::wstring PathToWide(const std::string& path)
    {
        if (path.empty())
            return {};

        const int len = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
        if (len <= 0)
            return {};

        std::wstring wide(static_cast<size_t>(len - 1), L'\0');
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wide.data(), len);
        return wide;
    }

    static std::string WideToNarrow(const std::wstring& wide)
    {
        if (wide.empty())
            return {};

        const int len = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0)
            return {};

        std::string narrow(static_cast<size_t>(len - 1), '\0');
        WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, narrow.data(), len, nullptr, nullptr);
        return narrow;
    }

    static bool FileExists(const std::wstring& path)
    {
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    static void ShowLoaderConsole()
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        const DWORD type = (hOut && hOut != INVALID_HANDLE_VALUE)
            ? GetFileType(hOut) : FILE_TYPE_UNKNOWN;
        if (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK)
        {
            setvbuf(stdout, nullptr, _IONBF, 0);
            setvbuf(stderr, nullptr, _IONBF, 0);
            return;
        }
        if (HWND console = GetConsoleWindow())
            ShowWindow(console, SW_SHOW);
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
    }

    static bool IsRunningAsAdmin()
    {
        BOOL admin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
        {
            CheckTokenMembership(nullptr, adminGroup, &admin);
            FreeSid(adminGroup);
        }
        return admin == TRUE;
    }

    static std::wstring NormalizeDriverPath(const std::wstring& input)
    {
        return ResolveDriverFile(input);
    }

    static const wchar_t* ServiceName()
    {
        return L"MyMemoryDriver";
    }

    static VulnDriverType ToNative(VulnDriverChoice choice)
    {
        switch (choice)
        {
        case VulnDriverChoice::RTCore64: return VulnDriverType::RTCore64;
        case VulnDriverChoice::Dbutil:   return VulnDriverType::Dbutil;
        case VulnDriverChoice::Cpuz:     return VulnDriverType::Cpuz;
        default:                         return VulnDriverType::Gdrv;
        }
    }

    const char* VulnDriverChoiceLabel(VulnDriverChoice choice)
    {
        switch (choice)
        {
        case VulnDriverChoice::RTCore64: return "MSI RTCore64.sys";
        case VulnDriverChoice::Dbutil:   return "Dell dbutil_2_3.sys";
        case VulnDriverChoice::Cpuz:     return "CPU-Z cpuz141.sys";
        default:                         return "Gigabyte gdrv.sys";
        }
    }

    bool LoadDriverManualMap(const std::string& sysPath, VulnDriverChoice vuln,
                             KernelAllocMode allocMode, bool fallbackToScm, std::string* statusOut)
    {
        if (statusOut) statusOut->clear();
        g_loadedViaScm = false;
        ShowLoaderConsole();

        if (!IsRunningAsAdmin())
        {
            SetStatusAndLog(statusOut, "[-] Run Launcher.exe as Administrator.", true);
            printf("[-] Run Launcher.exe as Administrator.\n");
            return false;
        }

        const std::wstring targetPath = NormalizeDriverPath(PathToWide(sysPath));
        if (!FileExists(targetPath))
        {
            char buf[768];
            sprintf_s(buf, "[-] Target driver not found: %s", WideToNarrow(targetPath).c_str());
            printf("%s\n", buf);
            SetStatusAndLog(statusOut, buf, true);
            return false;
        }

        const VulnDriverType native = ToNative(vuln);
        const std::wstring vulnPath = VulnDriverDefaultPath(native);
        if (!FileExists(vulnPath))
        {
            char buf[768];
            sprintf_s(buf, "[-] BYOVD driver missing. Place %s at: %s",
                WideToNarrow(GetVulnDriverInfo(native).defaultFileName).c_str(),
                WideToNarrow(vulnPath).c_str());
            printf("%s\n", buf);
            SetStatusAndLog(statusOut, buf, true);
            return false;
        }

        if (vuln == VulnDriverChoice::Gdrv && IsWindows11_24H2OrLater())
        {
            const char* msg = "[-] Gigabyte gdrv cannot patch ntoskrnl .text on Windows 11 24H2 (build >= 26100). Use RTCore64 or CPU-Z.";
            printf("%s\n", msg);
            SetStatusAndLog(statusOut, msg, true);

            if (!fallbackToScm)
                return false;

            printf("[*] gdrv blocked on 24H2; falling back to SCM as requested.\n");
            if (statusOut)
                statusOut->append("\n[*] Falling back to SCM load...");
            return LoadDriverScm(sysPath, statusOut);
        }

        const char* modeLabel = (allocMode == KernelAllocMode::IndependentPages) ? "IndependentPages" : "Pool";
        printf("[*] Manual mapping driver (build %s %s): %ls via %s (alloc=%s, fallback=%s)\n",
            __DATE__, __TIME__, targetPath.c_str(), VulnDriverChoiceLabel(vuln),
            modeLabel, fallbackToScm ? "yes" : "no");
        printf("[*] BYOVD file: %ls\n", vulnPath.c_str());

        std::wstring error;
        if (!ManualMapDriver(targetPath.c_str(), native, allocMode, &error))
        {
            if (statusOut)
            {
                char buf[768];
                sprintf_s(buf, "[-] Manual map failed: %s", WideToNarrow(error).c_str());
                SetStatusAndLog(statusOut, buf, true);
            }

            if (!fallbackToScm)
                return false;

            printf("[*] Manual map failed; falling back to SCM as requested.\n");
            if (statusOut)
                statusOut->append("\n[*] Falling back to SCM load...");
            return LoadDriverScm(sysPath, statusOut);
        }

        g_driverLoaded = true;
        SetStatusAndLog(statusOut, "[+] Driver loaded via manual mapping (BYOVD).", false);
        return true;
    }

    bool LoadDriverScm(const std::string& sysPath, std::string* statusOut)
    {
        if (statusOut) statusOut->clear();
        ShowLoaderConsole();

        if (!IsRunningAsAdmin())
        {
            SetStatusAndLog(statusOut, "[-] Run Launcher.exe as Administrator.", true);
            printf("[-] Run Launcher.exe as Administrator.\n");
            return false;
        }

        const std::wstring targetPath = NormalizeDriverPath(PathToWide(sysPath));
        if (!FileExists(targetPath))
        {
            char buf[768];
            sprintf_s(buf, "[-] Target driver not found: %s", WideToNarrow(targetPath).c_str());
            printf("%s\n", buf);
            SetStatusAndLog(statusOut, buf, true);
            return false;
        }

        printf("[*] Loading driver via SCM: %ls\n", targetPath.c_str());

        std::wstring scmError;
        if (!LoadDriverViaService(targetPath.c_str(), ServiceName(), &scmError))
        {
            const std::string msg = scmError.empty()
                ? "[-] SCM load failed."
                : WideToNarrow(scmError);
            SetStatusAndLog(statusOut, msg, true);
            return false;
        }

        std::string pingStatus;
        bool pingOk = false;
        for (int attempt = 0; attempt < 10 && !pingOk; ++attempt)
        {
            if (attempt > 0)
                Sleep(100);
            pingStatus.clear();
            pingOk = PingDriver(&pingStatus);
        }
        if (!pingOk)
        {
            UnloadDriverViaService(ServiceName());
            char buf[768];
            sprintf_s(buf, "[-] SCM service did not stay running; ping failed. %s", pingStatus.c_str());
            printf("%s\n", buf);
            SetStatusAndLog(statusOut, buf, true);
            return false;
        }

        g_loadedViaScm = true;
        g_driverLoaded = true;
        SetStatusAndLog(statusOut, "[+] Driver loaded via SCM (RUNNING, ping ok).", false);
        return true;
    }

    bool UnloadDriver(std::string* statusOut)
    {
        if (statusOut) statusOut->clear();

        const bool scmThisProcess = g_loadedViaScm;
        const bool mapperThisProcess = IsManualMapDriverLoaded();
        const bool scmPresent = DriverServiceExists(ServiceName());

        if (!scmThisProcess && !mapperThisProcess && !scmPresent)
        {
            SetStatusAndLog(statusOut, "[-] No driver loaded (no SCM service, no manual-map session in this process).", true);
            return false;
        }

        std::string msg;
        if (scmThisProcess || scmPresent)
        {
            std::wstring scmError;
            if (!UnloadDriverViaService(ServiceName(), &scmError))
            {
                const std::string fail = scmError.empty()
                    ? "[-] SCM unload failed."
                    : WideToNarrow(scmError);
                SetStatusAndLog(statusOut, fail, true);
                return false;
            }
            g_loadedViaScm = false;
            g_driverLoaded = false;
            msg = "[+] Driver unloaded (SCM).";
        }

        if (mapperThisProcess)
        {
            UnloadManualMapDriver();
            g_driverLoaded = false;
            if (!msg.empty())
                msg += " ";
            msg += "[+] Manual map state cleared (vuln driver handle released).";
        }

        SetStatusAndLog(statusOut, msg, false);
        return true;
    }

    bool IsDriverLoaded()
    {
        return g_driverLoaded;
    }

    const char* GetLoadMethodLabel()
    {
        if (!g_driverLoaded)
            return "None";
        return g_loadedViaScm ? "SCM" : "Manual Map (BYOVD)";
    }

    bool PingDriver(std::string* statusOut)
    {
        if (statusOut) statusOut->clear();

        DriverSession session;
        if (!session.Open())
        {
            char buf[160];
            sprintf_s(buf, "[-] Failed to open/ping driver (error %lu). Is it loaded?", GetLastError());
            SetStatusAndLog(statusOut, buf, true);
            return false;
        }

        // DriverSession already performs the handshake; report success and close.
        SetStatusAndLog(statusOut, "[+] PING ok: handshake succeeded.", false);
        session.Close();
        return true;
    }
}
