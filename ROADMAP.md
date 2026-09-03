# PUBG Memory Visualization — Roadmap

> **Note:** This file supersedes the older planning doc at `Desktop/Project PUBG-Memory-Visualization.js`. Use this roadmap as the canonical source of truth.

---

## Project Overview

**Goal:** Build a kernel-mode PUBG memory reader with ESP and Aimbot.

**Core approach:** Stealthy kernel driver with:

- CR3 bypass for memory reads/writes
- Obfuscated IOCTL communication (handshake + XOR session)
- Manual mapping (BYOVD) to load the driver without SCM traces

**Current phase:** Phase 3 — PUBG live-game proof + driver hiding

---

## Completed Work

| Phase | Task | Status |
|-------|------|--------|
| 1 | CR3 bypass, write support, obfuscated IOCTL | Done |
| 1 | Build pipeline (WDK, signing, SCM, ping, `test_read`) | Done |
| 1 | CLI loader with handshake-verified ping | Done |
| 1 | VM / test signing notes | Done — `build.md` |
| 2.1 | BYOVD manual mapping (PE mapper + providers) | Done — `Launcher/newstuff/` |
| 2.1 | GUI driver control panel (dropdown, Manual Map + SCM buttons) | Done |
| 2.1 | BYOVD provider support (gdrv, RTCore64, dbutil, cpuz) | Done |
| 2.1 | Driver search paths (exe → repo → Desktop → env) | Done — `vuln_driver.cpp` |
| 2.1 | BYOVD integration in Loader repo | Done — `drivers\` + post-build copy |
| 2.1 | SCM fallback for dev iteration | Done |
| 2.1 | `build.md` BYOVD setup guide | Done |
| 2.1b | GUI ping IOCTL fix | Done — `driver_protocol.h` |
| 2.2 | Unified `Launcher.exe` project | Done — replaces `loader.exe` and `client.exe` |
| 2.2 | PUBG ESP/AI overlay merged into Launcher | Done — `client_panel.cpp` |
| 2.2 | One-click PUBG / Steam inject flow | Done — `inject_thread.cpp` |
| 2.2 | Injector config fields in `config.json` | Done |
| 2.2 | Status log + diagnostics + legacy cleanup | Done |
| 2.2 | 900×720 Launcher GUI (Launch / Driver / PUBG tabs, no clipped controls) | Done — `main.cpp` / `main.hpp` |
| 2.2 | CLI stdout piping for `load`/`ping`/`unload` (`_dup2`) | Done |
| 2.3 | SCM load: verify driver is RUNNING + ping before reporting success | Done |
| 2.3 | SCM load: canonical `binPath` passed to `CreateService` (no Win32 2) | Done |
| 2.3 | SCM load: ImagePath mismatch detection + stop/delete leftover service | Done |
| 2.3 | Test-sign `MyMemoryDriver.sys` (`CN=PubgMemVisTest`) | Done — `scripts/sign_driver.ps1` |
| 2.3 | OpenCV `opencv_world470.dll` delay-loaded (CLI needs no CUDA) | Done |
| 2.3 | CUDA / NPP / cuDNN / cuBLAS copied by `build.ps1` from `ai-aimassist-source` | Done |
| 2.3 | YOLO weights copied at build time | Done |
| 2.3 | Kernel read: `MmCopyVirtualMemory` at PASSIVE_LEVEL (no CR3 at DPC) | Done |
| 2.3 | Fix METHOD_BUFFERED SystemBuffer overwrite (2.9 GB XOR-walk / VM freeze) | Done — `driver.c` |
| 2.3 | `test_read.exe`: self-process encrypted read + write + PE header | Done — all PASS in VM |
| 2.3 | VM smoke test: SCM load → ping → `test_read` → unload (full pass) | Done — `tester` VM |
| 2.3 | RTCore physical R/W: chunked 4/2/1-byte IOCTLs + value-field layout | Done |
| 2.3 | CR3 discovery: physical RAM ranges from registry (not first 4GB only) | Done |
| 2.3 | `GetPhysicalMemoryRanges`: CM_RESOURCE_LIST parse + GlobalMemoryStatusEx fallback | Done |

---

## VM Testing Summary

| Test | Result | Notes |
|------|--------|-------|
| **Build** (`build.ps1 -SkipLoad`) | Pass | All projects compile Release x64 |
| **Test-sign** (`scripts/sign_driver.ps1`) | Pass | Authenticode Valid, `CN=PubgMemVisTest` |
| **SCM load → ping → `test_read` → unload** | Pass | `tester` VM (Win11 25H2 / build 26200, Test Mode on) |
| **Manual Map (RTCore64)** | Fail (VM limitation) | RTCore physical IOCTL returns Win32 87; VirtualBox does not expose physical pages via MapIoSpace |
| **BattlEye + Test Mode** | Fail (expected) | BattlEye explicitly rejects Test-Signing Mode |

**Conclusion:** SCM is confirmed working in the VM (engineering proof). Manual Map requires bare-metal hardware (RTCore physical R/W blocked in VirtualBox). Test Mode must be **off** for BattlEye; test signing must be **on** for SCM.

---

## Current Phase: Live-Game / Bare-Metal

### Immediate next steps

| # | Task | Notes |
|---|------|-------|
| 1 | Test Manual Map on bare-metal host (not VM) | Copy `Launcher.exe` + `MyMemoryDriver.sys` + `drivers\RTCore64.sys`; turn testsigning ON on host |
| 2 | Verify CR3 probe succeeds on physical hardware | Look for `System CR3 = 0x...` in console |
| 3 | Turn testsigning OFF + launch PUBG, then Manual Map | BattlEye should reach lobby |
| 4 | PUBG → Manual tab → Load config → Attach | Verify `TslGame.exe` is reachable via driver |
| 5 | Launch overlay; confirm ESP renders | Need `opencv_world470.dll`, CUDA DLLs, `runtime\yolov3-tiny.weights` |

---

## Remaining Roadmap

| Phase | Task | Description |
|-------|------|-------------|
| **3.0** | Manual-map on bare metal | RTCore / CPU-Z working on physical machine (CR3 scan confirmed) |
| **3.1** | PUBG attach + overlay proof | End-to-end: driver → attach → ESP visible in-game |
| **3.2** | Driver hiding | Remove from `PsLoadedModuleList`, unlink from `\\Driver\\` namespace |
| **3.3** | Signature obfuscation | XOR strings, dynamic imports, hash IOCTL codes |
| **4.0** | Aimbot | Target selection, smoothing, prediction, humanization |
| **4.1** | ESP enhancements | Item ESP, vehicle ESP, radar overlay |
| **4.2** | Offset maintenance | Pattern-scan update cycle after PUBG patches |
| **5.0** | Release candidate | Full detection audit, cleanup, final build |

---

## File Structure

```
Dev/
└── PUBG-Memory-Visualization/
    ├── driver/                    # MyMemoryDriver (CR3, encrypted IOCTL)
    ├── Launcher/                  # Unified GUI/CLI launcher
    │   ├── main.cpp               # Launcher UI + Launch/Driver/PUBG tabs (900×720)
    │   ├── client_panel.cpp       # PUBG overlay panel wrapper
    │   ├── inject_thread.cpp      # One-click PUBG / Steam inject flow
    │   ├── log.cpp                # Central status log + launcher.log
    │   └── newstuff/              # manual_map, vuln_driver, kernel_utils, loader
    ├── client/                    # ESP overlay sources (compiled into Launcher)
    ├── scripts/
    │   ├── sign_driver.ps1        # Test-sign MyMemoryDriver.sys
    │   ├── copy_runtime_deps.ps1  # OpenCV + CUDA DLLs + YOLO weights
    │   └── vm_smoke_test.ps1      # VirtualBox guest CLI smoke test
    ├── tests/test_read.cpp        # Encrypted read/write self-process harness
    ├── build.ps1, build.md, test_plan.md, ROADMAP.md
    └── x64/Release/
        ├── MyMemoryDriver.sys     # Test-signed, 16624 bytes
        ├── Launcher.exe
        ├── test_read.exe
        ├── drivers/               # BYOVD .sys files (RTCore64, gdrv, …)
        ├── runtime/               # YOLO cfg, weights, labels
        └── opencv_world470.dll    # + CUDA/NPP DLLs

BYOVD search order: <exe>\drivers\ → <repo>\drivers\ → exe dir → Desktop\Drivers → LOADER_DRIVERS_DIR
```

---

## Success Criteria

| Component | Status | Notes |
|-----------|--------|-------|
| CR3 read/write | Done | `MmCopyVirtualMemory` at PASSIVE_LEVEL |
| Obfuscated IOCTL | Done | Handshake + XOR session |
| CLI build + `test_read` | Done | All PASS in VM |
| Test-sign driver | Done | Authenticode Valid, `CN=PubgMemVisTest` |
| SCM load + ping (VM) | Done | Confirmed |
| SCM ImagePath / leftover-service guard | Done | Confirmed |
| GUI composition (900×720, tabs, no clipping) | Done | |
| OpenCV delay-load (CLI needs no CUDA) | Done | |
| CUDA/YOLO runtime packaging | Done | `copy_runtime_deps.ps1` |
| BYOVD manual mapper (RTCore, VM) | Blocked — VM | Win32 87 on physical IOCTL |
| BYOVD manual mapper (bare metal) | Not yet tested | Next step |
| PUBG attach + overlay (live game) | Not yet tested | Needs manual map working |
| Driver hiding (`PsLoadedModuleList`) | Not started | |
| Aimbot | Not started | |
| End-to-end vs BattlEye | Not yet tested | |

---

## Related Docs

| Doc | Location |
|-----|----------|
| Driver build guide | [build.md](build.md) |
| Phase 1 test plan | [test_plan.md](test_plan.md) |
| VM smoke test script | [scripts/vm_smoke_test.ps1](scripts/vm_smoke_test.ps1) |
