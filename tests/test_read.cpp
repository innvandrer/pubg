// Phase 1 memory read/write smoke test using DriverSession.
// Safe target: this process only (stack buffer + own PE image). Never TslGame.
//
// A missing PID must fail fast in the driver (PsLookupProcessByProcessId).
// This harness does not depend on PUBG being running.
//
// VM retest notes:
// - Ping can succeed while test_read freezes the guest: METHOD_BUFFERED
//   SystemBuffer is input and output. After a 16-byte self-read, the old
//   driver used req->size from the overwritten buffer (0xAFAEADAC from the
//   0xA0..0xAF pattern) and XOR-walked kernel VA. Usermode's 8s IOCTL timeout
//   cannot unstick that. The driver must copy the request to a stack local
//   before filling SystemBuffer, and never __writecr3.

#include "../client/driver_comm.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <string>

static void FailWin32(const char* what)
{
    const DWORD err = GetLastError();
    if (err == ERROR_TIMEOUT)
    {
        std::fprintf(stderr,
            "FAIL: %s timed out after %lu ms (IOCTL did not complete). "
            "Driver may be stuck in the read/write path.\n",
            what, DriverSession::kIoctlTimeoutMs);
    }
    else
    {
        std::fprintf(stderr, "FAIL: %s failed (win32=%lu).\n", what, err);
    }
    std::fflush(stderr);
}

static uint32_t get_current_pid()
{
    return static_cast<uint32_t>(GetCurrentProcessId());
}

static uint64_t get_module_base(uint32_t pid, const wchar_t* module_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    uint64_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, module_name) == 0) {
                base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return base;
}

static int test_encrypted_round_trip(DriverSession& session, uint32_t pid)
{
    alignas(16) uint8_t original[16]{};
    for (size_t i = 0; i < sizeof(original); ++i)
        original[i] = static_cast<uint8_t>(0xA0u + i);

    const uint64_t address = reinterpret_cast<uint64_t>(original);
    uint8_t readback[16]{};

    std::printf("[*] test_read: encrypted read 16 bytes at %p ...\n", original);
    std::fflush(stdout);

    if (!session.Read(pid, address, readback, sizeof(readback))) {
        FailWin32("encrypted read");
        return 1;
    }

    if (std::memcmp(original, readback, sizeof(original)) != 0) {
        std::fprintf(stderr, "FAIL: round-trip mismatch\n");
        std::fflush(stderr);
        return 1;
    }

    std::printf("PASS: encrypted read round-trip (16 bytes at %p)\n", original);
    std::fflush(stdout);
    return 0;
}

static int test_write_round_trip(DriverSession& session, uint32_t pid)
{
    alignas(8) uint64_t value = 0x0123456789ABCDEFull;
    const uint64_t address = reinterpret_cast<uint64_t>(&value);
    const uint64_t new_value = 0xFEDCBA9876543210ull;
    uint64_t readback = 0;

    std::printf("[*] test_read: encrypted write + read at %p ...\n", &value);
    std::fflush(stdout);

    if (!session.Write(pid, address, &new_value, sizeof(new_value))) {
        FailWin32("encrypted write");
        return 1;
    }

    if (value != new_value) {
        std::fprintf(stderr, "FAIL: local value not updated after write\n");
        std::fflush(stderr);
        return 1;
    }

    if (!session.Read(pid, address, &readback, sizeof(readback))) {
        FailWin32("read after write");
        return 1;
    }

    if (readback != new_value) {
        std::fprintf(stderr, "FAIL: read after write mismatch (got 0x%llX)\n",
            static_cast<unsigned long long>(readback));
        std::fflush(stderr);
        return 1;
    }

    std::printf("PASS: write + read round-trip at %p\n", &value);
    std::fflush(stdout);
    return 0;
}

static int test_module_pe_header(DriverSession& session, uint32_t pid)
{
    const uint64_t base = get_module_base(pid, L"test_read.exe");
    if (base == 0) {
        std::fprintf(stderr, "WARN: could not resolve test_read.exe base; skipping PE header test\n");
        std::fflush(stderr);
        return 0;
    }

    std::printf("[*] test_read: PE header read at 0x%llX ...\n",
        static_cast<unsigned long long>(base));
    std::fflush(stdout);

    uint16_t dos_magic = 0;
    if (!session.Read(pid, base, &dos_magic, sizeof(dos_magic))) {
        FailWin32("PE header read");
        return 1;
    }

    if (dos_magic != 0x5A4D) { /* 'MZ' */
        std::fprintf(stderr, "FAIL: expected MZ signature, got 0x%04X\n", dos_magic);
        std::fflush(stderr);
        return 1;
    }

    std::printf("PASS: PE DOS header at module base 0x%llX (MZ)\n",
        static_cast<unsigned long long>(base));
    std::fflush(stdout);
    return 0;
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::printf("[*] test_read: opening \\\\.\\MyMemoryDriver (ping+handshake, %lu ms IOCTL timeout)\n",
        DriverSession::kIoctlTimeoutMs);
    std::fflush(stdout);

    DriverSession session;
    if (!session.Open()) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        {
            std::fprintf(stderr,
                "FAIL: DriverSession::Open failed (win32=%lu ERROR_FILE_NOT_FOUND). "
                "Load the signed driver and run Launcher.exe ping first.\n", err);
        }
        else if (err == ERROR_TIMEOUT)
        {
            std::fprintf(stderr,
                "FAIL: DriverSession::Open timed out during ping/handshake (win32=%lu). "
                "Device exists but IOCTL did not complete.\n", err);
        }
        else
        {
            std::fprintf(stderr,
                "FAIL: DriverSession::Open failed (win32=%lu). Load driver and run ping first.\n",
                err);
        }
        std::fflush(stderr);
        return 1;
    }

    std::printf("[+] test_read: device open, ping+handshake ok\n");
    std::fflush(stdout);

    const uint32_t pid = get_current_pid();
    std::printf("Using PID %u (self)\n", pid);
    std::fflush(stdout);

    int failures = 0;
    failures += test_encrypted_round_trip(session, pid);
    failures += test_write_round_trip(session, pid);
    failures += test_module_pe_header(session, pid);

    session.Close();

    if (failures == 0) {
        std::printf("All tests passed.\n");
        std::fflush(stdout);
        return 0;
    }

    std::printf("%d test(s) failed.\n", failures);
    std::fflush(stdout);
    return 1;
}
