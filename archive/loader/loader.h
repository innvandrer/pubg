#pragma once

#include <Windows.h>
#include <string>

namespace pmv::loader {

struct LoadOptions {
    std::wstring driver_path;
    std::wstring service_name = L"PubgMemVis";
    bool         unload_existing = true;
};

/* Install + start a test-signed driver via SCM. Returns Win32 error code (0 = ok). */
DWORD load_driver(const LoadOptions& options);

/* Stop service and delete driver service entry. */
DWORD unload_driver(const std::wstring& service_name);

/* Open handle to \\\\.\\MyMemoryDriver after driver is loaded. */
HANDLE open_device();

} // namespace pmv::loader
