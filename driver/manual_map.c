#include "manual_map.h"

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsvc.h>

static void CanonicalizeSysPathW(const wchar_t* path, wchar_t* out, size_t cch)
{
    wchar_t tmp[MAX_PATH];
    size_t n;
    const wchar_t* src = path ? path : L"";

    while (*src == L'"' || *src == L'\'')
        ++src;
    wcsncpy_s(tmp, _countof(tmp), src, _TRUNCATE);
    n = wcslen(tmp);
    while (n > 0 && (tmp[n - 1] == L'"' || tmp[n - 1] == L'\''))
        tmp[--n] = L'\0';

    if (wcsncmp(tmp, L"\\??\\", 4) == 0)
        memmove(tmp, tmp + 4, (wcslen(tmp + 4) + 1) * sizeof(wchar_t));
    else if (wcsncmp(tmp, L"\\\\?\\", 4) == 0)
        memmove(tmp, tmp + 4, (wcslen(tmp + 4) + 1) * sizeof(wchar_t));

    if (GetFullPathNameW(tmp, (DWORD)cch, out, NULL) == 0)
        wcsncpy_s(out, cch, tmp, _TRUNCATE);
}

static BOOL GetFileSizeW64(const wchar_t* path, ULONGLONG* outSize)
{
    LARGE_INTEGER sz;
    HANDLE h;

    *outSize = 0;
    h = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) {
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);
    *outSize = (ULONGLONG)sz.QuadPart;
    return TRUE;
}

static BOOL QueryImagePathW(SC_HANDLE svc, wchar_t* out, size_t cch)
{
    DWORD needed = 0;
    QUERY_SERVICE_CONFIGW* cfg;
    BOOL ok;

    out[0] = L'\0';
    QueryServiceConfigW(svc, NULL, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0)
        return FALSE;

    cfg = (QUERY_SERVICE_CONFIGW*)malloc(needed);
    if (!cfg)
        return FALSE;
    ok = QueryServiceConfigW(svc, cfg, needed, &needed);
    if (ok && cfg->lpBinaryPathName)
        wcsncpy_s(out, cch, cfg->lpBinaryPathName, _TRUNCATE);
    free(cfg);
    return ok;
}

BOOL ManualMapDriver(const char* driver_path)
{
    (void)driver_path;
    fprintf(stderr,
        "[manual_map] Kernel manual mapping is not available in this project.\n"
        "             Use LoadDriverViaService() or loader.exe (see build.md).\n");
    return FALSE;
}

BOOL LoadDriverViaServiceW(const wchar_t* driver_path, const wchar_t* service_name)
{
    wchar_t requested[MAX_PATH];
    wchar_t existing[MAX_PATH];
    wchar_t existingCanon[MAX_PATH];
    ULONGLONG reqSize = 0;
    ULONGLONG existSize = 0;
    SC_HANDLE scm;
    SC_HANDLE svc = NULL;
    DWORD err;
    int attempt;
    BOOL sameBinary;
    SERVICE_STATUS status;

    if (!driver_path || !service_name)
        return FALSE;

    CanonicalizeSysPathW(driver_path, requested, _countof(requested));
    if (!GetFileSizeW64(requested, &reqSize))
        return FALSE;

    wprintf(L"[*] SCM: requested ImagePath=\"%ls\" size=%llu\n",
        requested, (unsigned long long)reqSize);

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return FALSE;

    svc = OpenServiceW(scm, service_name, SERVICE_ALL_ACCESS);
    if (svc) {
        if (!QueryImagePathW(svc, existing, _countof(existing))) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
        CanonicalizeSysPathW(existing, existingCanon, _countof(existingCanon));
        GetFileSizeW64(existingCanon, &existSize);
        wprintf(L"[*] SCM: existing ImagePath=\"%ls\" size=%llu\n",
            existing, (unsigned long long)existSize);

        sameBinary = (_wcsicmp(existingCanon, requested) == 0 && existSize == reqSize);
        if (!sameBinary) {
            wprintf(L"[*] SCM: leftover ImagePath mismatch; STOP+DELETE, will not StartService on leftover.\n");
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            Sleep(500);
            if (!DeleteService(svc) && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE) {
                fwprintf(stderr,
                    L"[-] SCM: service marked for deletion (Win32 1072). Reboot required.\n");
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return FALSE;
            }
            CloseServiceHandle(svc);
            svc = NULL;
            Sleep(200);
        }
    }

    if (!svc) {
        for (attempt = 0; attempt < 40 && !svc; ++attempt) {
            svc = CreateServiceW(
                scm, service_name, service_name,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                requested, NULL, NULL, NULL, NULL, NULL);
            if (svc)
                break;
            err = GetLastError();
            if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
                Sleep(250);
                continue;
            }
            if (err == ERROR_SERVICE_EXISTS) {
                svc = OpenServiceW(scm, service_name, SERVICE_ALL_ACCESS);
                if (!svc)
                    break;
                if (!QueryImagePathW(svc, existing, _countof(existing)))
                    break;
                CanonicalizeSysPathW(existing, existingCanon, _countof(existingCanon));
                if (_wcsicmp(existingCanon, requested) != 0) {
                    ControlService(svc, SERVICE_CONTROL_STOP, &status);
                    Sleep(500);
                    if (!ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                            SERVICE_ERROR_NORMAL, requested,
                            NULL, NULL, NULL, NULL, NULL, NULL)) {
                        fwprintf(stderr,
                            L"[-] SCM: refusing StartService on leftover ImagePath=\"%ls\" (Win32=%lu)\n",
                            existing, GetLastError());
                        CloseServiceHandle(svc);
                        CloseServiceHandle(scm);
                        return FALSE;
                    }
                }
                break;
            }
            break;
        }
    }

    if (!svc) {
        err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE)
            fwprintf(stderr, L"[-] SCM: service marked for deletion (Win32 1072). Reboot required.\n");
        CloseServiceHandle(scm);
        return FALSE;
    }

    if (!QueryImagePathW(svc, existing, _countof(existing))) {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return FALSE;
    }
    CanonicalizeSysPathW(existing, existingCanon, _countof(existingCanon));
    if (_wcsicmp(existingCanon, requested) != 0) {
        fwprintf(stderr,
            L"[-] SCM: refusing StartService. Bound ImagePath=\"%ls\" != requested \"%ls\"\n",
            existing, requested);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return FALSE;
    }

    wprintf(L"[*] SCM: StartService ImagePath=\"%ls\"\n", existing);
    if (!StartServiceW(svc, 0, NULL)) {
        err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
        if (!QueryImagePathW(svc, existing, _countof(existing))) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
        CanonicalizeSysPathW(existing, existingCanon, _countof(existingCanon));
        if (_wcsicmp(existingCanon, requested) != 0) {
            fwprintf(stderr,
                L"[-] SCM: ALREADY_RUNNING leftover ImagePath=\"%ls\"; refusing success.\n",
                existing);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    wprintf(L"[+] SCM: service %ls is RUNNING ImagePath=\"%ls\"\n", service_name, existing);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return TRUE;
}

BOOL UnloadDriverViaServiceW(const wchar_t* service_name)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return FALSE;

    SC_HANDLE service = OpenServiceW(scm, service_name, SERVICE_STOP | DELETE);
    if (!service) {
        CloseServiceHandle(scm);
        return FALSE;
    }

    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    BOOL ok = DeleteService(service);
    if (!ok && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
        ok = TRUE;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
}
