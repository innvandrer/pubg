#include "loader.h"

#include "../driver/driver.h"
#include "../driver/ioctl_crypto.h"
#include "../driver/manual_map.h"

#include <filesystem>
#include <iostream>

namespace pmv::loader {

DWORD load_driver(const LoadOptions& options)
{
    if (options.driver_path.empty() || !std::filesystem::exists(options.driver_path))
        return ERROR_FILE_NOT_FOUND;

    if (!LoadDriverViaServiceW(options.driver_path.c_str(), options.service_name.c_str()))
        return GetLastError();

    return 0;
}

DWORD unload_driver(const std::wstring& service_name)
{
    if (!UnloadDriverViaServiceW(service_name.c_str()))
        return GetLastError();
    return 0;
}

HANDLE open_device()
{
    return CreateFileW(
        USER_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

} // namespace pmv::loader

static void print_usage()
{
    std::wcout << L"MyMemoryDriver loader\n"
               << L"  loader.exe load   <path\\MyMemoryDriver.sys>\n"
               << L"  loader.exe unload\n"
               << L"  loader.exe ping\n";
}

static bool verify_handshake(HANDLE device)
{
    uint32_t key = static_cast<uint32_t>(
        GetTickCount64() ^
        (static_cast<uint64_t>(GetCurrentProcessId()) << 16) ^
        static_cast<uint64_t>(GetCurrentThreadId()));

    if (key == 0)
        key = 0xDEADBEEFu;

    uint32_t response = key;
    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_HANDSHAKE,
            &key,
            sizeof(key),
            &response,
            sizeof(response),
            &returned,
            nullptr) ||
        returned != sizeof(response) ||
        response != (key ^ MM_XOR_MASK)) {
        std::wcerr << L"IOCTL handshake failed: " << GetLastError() << L"\n";
        return false;
    }

    return true;
}

static bool ping_driver()
{
    HANDLE device = pmv::loader::open_device();
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"open device failed: " << GetLastError() << L"\n";
        return false;
    }

    MEMORY_PING_RESPONSE response{};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_PING,
        nullptr,
        0,
        &response,
        sizeof(response),
        &returned,
        nullptr);

    if (!ok) {
        std::wcerr << L"IOCTL ping failed: " << GetLastError() << L"\n";
        CloseHandle(device);
        return false;
    }

    if (response.magic != MM_PING_MAGIC) {
        std::wcerr << L"unexpected ping magic\n";
        CloseHandle(device);
        return false;
    }

    const bool handshake_ok = verify_handshake(device);
    CloseHandle(device);

    if (!handshake_ok)
        return false;

    std::wcout << L"driver ok magic=0x" << std::hex << response.magic
               << L" version=" << std::dec << response.version
               << L" handshake=ok\n";
    return true;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::wstring cmd = argv[1];

    if (cmd == L"load") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        pmv::loader::LoadOptions opts{};
        opts.driver_path = argv[2];
        opts.service_name = L"MyMemoryDriver";

        DWORD err = pmv::loader::load_driver(opts);
        if (err != 0) {
            std::wcerr << L"load failed: " << err << L"\n";
            return static_cast<int>(err);
        }

        std::wcout << L"driver loaded\n";
        return ping_driver() ? 0 : 2;
    }

    if (cmd == L"unload") {
        DWORD err = pmv::loader::unload_driver(L"MyMemoryDriver");
        if (err != 0) {
            std::wcerr << L"unload failed: " << err << L"\n";
            return static_cast<int>(err);
        }
        std::wcout << L"driver unloaded\n";
        return 0;
    }

    if (cmd == L"ping")
        return ping_driver() ? 0 : 2;

    print_usage();
    return 1;
}
