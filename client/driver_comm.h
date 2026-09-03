#pragma once

#include "../driver/driver.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <vector>

class DriverSession {
public:
    static constexpr DWORD kIoctlTimeoutMs = 8000;

    bool Open();
    void Close();

    bool IsOpen() const { return handle_ != INVALID_HANDLE_VALUE; }
    bool IsReady() const { return handle_ != INVALID_HANDLE_VALUE && session_key_ != 0; }

    bool Read(uint32_t pid, uint64_t address, void* buffer, size_t size);
    bool Write(uint32_t pid, uint64_t address, const void* buffer, size_t size);
    bool Ping();

private:
    bool Handshake();
    void RotateKeyIfNeeded();
    bool DeviceIoControlTimed(DWORD code, void* inBuf, DWORD inLen,
                              void* outBuf, DWORD outLen, DWORD* returned,
                              DWORD timeoutMs = kIoctlTimeoutMs);

    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint32_t session_key_ = 0;
    uint32_t message_count_ = 0;
};
