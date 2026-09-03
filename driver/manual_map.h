#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Kernel manual mapping is not implemented — it is used to evade driver
 * signature enforcement and anti-cheat. Use LoadDriverViaServiceW() instead.
 */
BOOL ManualMapDriver(const char* driver_path);

/* Standard SCM load (test-signed driver required). Returns TRUE on success. */
BOOL LoadDriverViaServiceW(const wchar_t* driver_path, const wchar_t* service_name);

BOOL UnloadDriverViaServiceW(const wchar_t* service_name);

#ifdef __cplusplus
}
#endif
