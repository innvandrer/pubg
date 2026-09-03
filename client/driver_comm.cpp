#include "driver_comm.h"

#include <cstring>

bool DriverSession::DeviceIoControlTimed(DWORD code, void* inBuf, DWORD inLen,
                                         void* outBuf, DWORD outLen, DWORD* returned,
                                         DWORD timeoutMs)
{
    if (returned)
        *returned = 0;
    if (handle_ == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return false;

    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(
        handle_,
        code,
        inBuf,
        inLen,
        outBuf,
        outLen,
        &bytes,
        &ov);

    if (!ok)
    {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            CloseHandle(ov.hEvent);
            SetLastError(err);
            return false;
        }

        const DWORD wait = WaitForSingleObject(ov.hEvent, timeoutMs);
        if (wait != WAIT_OBJECT_0)
        {
            CancelIoEx(handle_, &ov);
            WaitForSingleObject(ov.hEvent, 2000);
            CloseHandle(ov.hEvent);
            SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : wait);
            return false;
        }
    }

    if (!GetOverlappedResult(handle_, &ov, &bytes, FALSE))
    {
        const DWORD err = GetLastError();
        CloseHandle(ov.hEvent);
        SetLastError(err);
        return false;
    }

    if (returned)
        *returned = bytes;
    CloseHandle(ov.hEvent);
    return true;
}

bool DriverSession::Open()
{
    Close();

    handle_ = CreateFileW(
        USER_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);

    if (handle_ == INVALID_HANDLE_VALUE)
        return false;

    if (!Ping()) {
        const DWORD pingErr = GetLastError();
        Close();
        SetLastError(pingErr ? pingErr : ERROR_INVALID_FUNCTION);
        return false;
    }

    if (!Handshake()) {
        const DWORD hsErr = GetLastError();
        Close();
        SetLastError(hsErr ? hsErr : ERROR_INVALID_DATA);
        return false;
    }

    return true;
}

void DriverSession::Close()
{
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }

    session_key_ = 0;
    message_count_ = 0;
}

void DriverSession::RotateKeyIfNeeded()
{
    if (++message_count_ < MM_KEY_ROTATE_INTERVAL)
        return;

    message_count_ = 0;
    session_key_ = MmRotateKey(session_key_);
}

bool DriverSession::Handshake()
{
    uint32_t key = static_cast<uint32_t>(
        GetTickCount64() ^
        (static_cast<uint64_t>(GetCurrentProcessId()) << 16) ^
        static_cast<uint64_t>(GetCurrentThreadId()));

    if (key == 0)
        key = 0xDEADBEEFu;

    uint32_t response = key;
    DWORD returned = 0;

    if (!DeviceIoControlTimed(
            IOCTL_HANDSHAKE,
            &key,
            sizeof(key),
            &response,
            sizeof(response),
            &returned) ||
        returned != sizeof(response)) {
        return false;
    }

    if (response != (key ^ MM_XOR_MASK))
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    session_key_ = key;
    message_count_ = 0;
    return true;
}

bool DriverSession::Ping()
{
    MEMORY_PING_RESPONSE ping{};
    DWORD returned = 0;

    if (!DeviceIoControlTimed(
            IOCTL_PING,
            nullptr,
            0,
            &ping,
            sizeof(ping),
            &returned) ||
        returned != sizeof(ping)) {
        return false;
    }

    if (ping.magic != MM_PING_MAGIC)
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

bool DriverSession::Read(uint32_t pid, uint64_t address, void* buffer, size_t size)
{
    if (!IsReady() || !buffer || size == 0 || size > MM_MAX_READ)
        return false;

    MEMORY_READ_REQUEST req{};
    req.process_id = pid;
    req.address = address;
    req.size = static_cast<uint32_t>(size);

    std::vector<uint8_t> encrypted_req(sizeof(req));
    memcpy(encrypted_req.data(), &req, sizeof(req));
    MmXorCrypt(encrypted_req.data(), encrypted_req.size(), session_key_);
    RotateKeyIfNeeded();

    DWORD returned = 0;
    if (!DeviceIoControlTimed(
            IOCTL_READ_MEMORY,
            encrypted_req.data(),
            static_cast<DWORD>(encrypted_req.size()),
            buffer,
            static_cast<DWORD>(size),
            &returned) ||
        returned != size) {
        return false;
    }

    MmXorCrypt(buffer, size, session_key_);
    RotateKeyIfNeeded();
    return true;
}

bool DriverSession::Write(uint32_t pid, uint64_t address, const void* buffer, size_t size)
{
    if (!IsReady() || !buffer || size == 0 || size > MM_MAX_WRITE)
        return false;

    std::vector<uint8_t> payload(sizeof(MEMORY_WRITE_REQUEST) + size);
    auto* req = reinterpret_cast<MEMORY_WRITE_REQUEST*>(payload.data());
    req->process_id = pid;
    req->address = address;
    req->size = static_cast<uint32_t>(size);
    memcpy(payload.data() + sizeof(MEMORY_WRITE_REQUEST), buffer, size);

    MmXorCrypt(payload.data(), sizeof(MEMORY_WRITE_REQUEST), session_key_);
    RotateKeyIfNeeded();
    MmXorCrypt(payload.data() + sizeof(MEMORY_WRITE_REQUEST), size, session_key_);
    RotateKeyIfNeeded();

    DWORD returned = 0;
    return DeviceIoControlTimed(
        IOCTL_WRITE_MEMORY,
        payload.data(),
        static_cast<DWORD>(payload.size()),
        nullptr,
        0,
        &returned);
}
