# PUBG Memory Visualization — Build Guide

Complete build instructions for the kernel driver and the unified Launcher (BYOVD driver loader + PUBG ImGui client) on **Windows 10/11 x64**.

See also: [ROADMAP.md](ROADMAP.md) for project phases, current status, and remaining work.

---

## Quick start

From an **Administrator** PowerShell at the repo root (test signing must be on — see section 2):

```powershell
.\build.ps1 -Configuration Release -RunTests
```

This script:

1. Finds MSBuild (VS 2022) and checks for WDK
2. Builds `MyMemoryDriver.sys`, `Launcher.exe`, and `test_read.exe`
3. Copies OpenCV + CUDA/NPP runtime DLLs next to `Launcher.exe` (from `ai-aimassist-source`, not git)
4. Creates a test code-signing PFX if missing (`$env:USERPROFILE\PubgMemVisTest.pfx`, password **`test1234`**)
5. Signs the driver with `signtool` (also runs as a driver post-build unless `-SkipSign`)
6. Loads the driver via SCM (`Launcher.exe load`)
7. Runs `Launcher.exe ping` (IOCTL_PING + XOR handshake)
8. With `-RunTests`: runs `test_read.exe` (encrypted read/write on self-process)

Common flags:

| Flag | Purpose |
|------|---------|
| `-SkipSign` | Build only; skip signtool (requires testsigning + unsigned load policy) |
| `-SkipLoad` | Build + sign; do not load or ping |
| `-SkipTestBuild` | Skip `test_read.exe` |
| `-RunTests` | After ping, run `test_read.exe` memory harness |
| `-WhatIf` | Print planned steps without executing |
| `-CertPassword` | Override default PFX password (`test1234`) |
| `-DriverProject` | Custom path to driver `.vcxproj` |

Output directory: `x64\Release\` (or `x64\Debug\`).

Manual ping after a `-SkipLoad` build:

```powershell
x64\Release\Launcher.exe load x64\Release\MyMemoryDriver.sys
x64\Release\Launcher.exe ping
```

Structured tests: see [test_plan.md](test_plan.md).

---

## 1. Prerequisites

| Tool | Version |
|------|---------|
| Visual Studio | 2022 with **Desktop development with C++** |
| Windows SDK | 10.0.22621+ |
| Windows Driver Kit (WDK) | Match your VS version |
| ImGui | vendored under `third_party/imgui` (see below) |

### Fetch ImGui

From the repo root:

```powershell
mkdir third_party
git clone --depth 1 https://github.com/ocornut/imgui.git third_party/imgui
```

Required source files for the client:

- `third_party/imgui/imgui.cpp`
- `third_party/imgui/imgui_draw.cpp`
- `third_party/imgui/imgui_tables.cpp`
- `third_party/imgui/imgui_widgets.cpp`
- `third_party/imgui/backends/imgui_impl_dx11.cpp`
- `third_party/imgui/backends/imgui_impl_win32.cpp`

Include paths:

- `third_party/imgui`
- `third_party/imgui/backends`

---

## 2. Enable test signing

Required for **test-signed** `.sys` drivers during development. A Test Mode watermark is **not** enough to load a completely unsigned image — Windows still returns **Win32 577** (`ERROR_INVALID_IMAGE_HASH`) for `NotSigned` drivers.

```powershell
# Admin PowerShell
bcdedit /set testsigning on
# Reboot is required for this to take effect. This guide does not reboot for you.
shutdown /r /t 0
```

Verify after reboot:

```powershell
bcdedit | findstr testsigning
# testsigning             Yes
```

Then sign the driver (`.\build.ps1 -SkipLoad` or `scripts\sign_driver.ps1`). Import the test `.cer` to **Trusted Publishers** + **Root** if load still returns 577 after signing (see section 3).

---

## 3. Create a test code-signing certificate

`build.ps1` and the driver post-build (`scripts\sign_driver.ps1`) create this automatically. The PFX stays in your user profile — do not commit it.

```powershell
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=PubgMemVis Test" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -HashAlgorithm SHA256

Export-PfxCertificate -Cert $cert -FilePath "$env:USERPROFILE\PubgMemVisTest.pfx" -Password (ConvertTo-SecureString "test1234" -AsPlainText -Force)
```

Sign the built driver:

```powershell
# Preferred
.\scripts\sign_driver.ps1 -DriverSys "x64\Release\MyMemoryDriver.sys"

# Or:
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 /f "$env:USERPROFILE\PubgMemVisTest.pfx" /p test1234 "x64\Release\MyMemoryDriver.sys"
```

Install cert to **Trusted Root** + **Trusted Publishers** (local dev only, Admin):

```powershell
Import-PfxCertificate -FilePath "$env:USERPROFILE\PubgMemVisTest.pfx" -Password (ConvertTo-SecureString "test1234" -AsPlainText -Force) -CertStoreLocation Cert:\LocalMachine\Root
Import-PfxCertificate -FilePath "$env:USERPROFILE\PubgMemVisTest.pfx" -Password (ConvertTo-SecureString "test1234" -AsPlainText -Force) -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

---

## 4. Build the kernel driver

### Automated (recommended)

```powershell
.\build.ps1 -Configuration Release -SkipLoad   # build + sign only
```

### Visual Studio solution

Open `PUBG-Memory-Visualization.sln` in VS 2022. Projects:

| Project | Output |
|---------|--------|
| `MyMemoryDriver` | `x64\Release\MyMemoryDriver.sys` |
| `Launcher` | `x64\Release\Launcher.exe` |
| `test_read` | `x64\Release\test_read.exe` |

`Launcher` is the unified GUI/CLI executable: it loads the driver via BYOVD manual map or SCM, and hosts the PUBG ESP/AI overlay client in the same process.

The driver project is a **WDM** kernel driver compiling:

- `driver/driver.c`
- `driver/cr3_memory.c`

Signing is done via `build.ps1` / `scripts\sign_driver.ps1` (`EnableTestSign` is off in the project because some WDK kits do not ship signtool; the post-build target calls `sign_driver.ps1` instead). Visual Studio / MSBuild-only driver builds are test-signed the same way unless `PUBG_SKIP_DRIVER_SIGN=1`.

### Manual project creation (alternative)

1. Visual Studio → **Create new project** → **Kernel Mode Driver, Empty (KMDF)** → name `MyMemoryDriver`
2. Target **x64 / Release**
3. Remove default `.c` files; add:
   - `driver/driver.c`
   - `driver/driver.h`
   - `driver/cr3_memory.c`
   - `driver/cr3_memory.h`
   - `driver/ioctl_crypto.h`
4. Project properties:
   - **C/C++ → Preprocessor** → add `_KERNEL_MODE`
   - **Driver Settings → General** → Target OS Version = Windows 10+
   - **Inf2Cat** → No (no INF required for manual SCM load)
5. Build → output: `x64\Release\MyMemoryDriver.sys`
6. Sign with `signtool` (step 3) or run `build.ps1`

### Driver IOCTLs

| IOCTL | Code | Description |
|-------|------|-------------|
| `IOCTL_READ_MEMORY` | 0x800 | Encrypted `MEMORY_READ_REQUEST` in, encrypted bytes out |
| `IOCTL_PING` | 0x801 | Returns `MM_PING_MAGIC` (`0x4D4D454D`), version `2` |
| `IOCTL_HANDSHAKE` | 0x802 | Client sends 32-bit key; driver returns `key ^ 0x12345678` |
| `IOCTL_WRITE_MEMORY` | 0x803 | Encrypted `MEMORY_WRITE_REQUEST` + payload in |

Device path: `\\.\MyMemoryDriver`

**Session flow:** `IOCTL_HANDSHAKE` must succeed before read/write IOCTLs. All read/write payloads are XOR-encrypted with the session key. The key rotates every 1000 messages (driver and client stay in sync).

**Memory access:** Reads and writes use CR3 page-table switching (`ReadMemoryByCR3` / `WriteMemoryByCR3`) instead of `MmCopyVirtualMemory`.

---

## 5. Build the unified Launcher

`Launcher` is a single Windows GUI executable that replaces the old `loader.exe` and `client.exe`. It includes:

- BYOVD driver loading (manual map + SCM fallback)
- `NtAddAtom` kernel execution primitive
- PUBG ESP overlay and AI aim assist client

It is included in `PUBG-Memory-Visualization.sln` and built by `build.ps1`.

Manual setup (if not using the solution):

1. Open `Launcher\Launcher.vcxproj` or create a new **Windows Desktop Application (x64)** project named `Launcher`.
2. Add the sources and headers from:
   - `Launcher\`
   - `client\`
   - `client\ai_aimassist\`
3. Include directories:
   - `driver\`
   - `client\`
   - `client\ai_aimassist\`
   - `Launcher\imgui\`
   - `..\ai-aimassist-source\example_win32_directx11\misc\opencv2\include`
4. Library directories:
   - `Launcher\imgui\dxsdk\Lib\x64`
   - `..\ai-aimassist-source\example_win32_directx11\misc\opencv2\x64\vc16\lib`
5. Link: `d3d11.lib`, `dxgi.lib`, `dwmapi.lib`, `opencv_world470.lib`
6. C++ standard: **C++17** or later
7. Administrator manifest / `UACExecutionLevel = RequireAdministrator`

Output: `x64\Release\Launcher.exe`.

`opencv_world470.dll` is **delay-loaded**, so CLI `load` / `ping` / `unload` work without OpenCV or CUDA on `PATH`. The overlay still needs those DLLs next to the exe; `build.ps1` and the Launcher post-build copy them from `ai-aimassist-source` (see `scripts\copy_runtime_deps.ps1`). YOLO weights are copied if found on disk — they are not downloaded or committed.

Deploy next to exe:

```powershell
copy client\config.json.example config.json
```

Headless CLI commands:

```powershell
# Admin
x64\Release\Launcher.exe load C:\path\to\x64\Release\MyMemoryDriver.sys
x64\Release\Launcher.exe ping
x64\Release\Launcher.exe unload
```

GUI mode:

```powershell
x64\Release\Launcher.exe
```

---

## 6. Client overlay inside the Launcher

The old standalone `client.exe` project has been merged into `Launcher`. The `client\` sources are now compiled into the `Launcher` project and the overlay is launched from the **PUBG Client** panel in the GUI, or from the headless `Launcher.exe` CLI commands above.

---

## 7. Runtime flow

```
1. .\build.ps1 -Configuration Release     (Admin — build, sign, load, ping)
   — or manually —
   Launcher.exe load MyMemoryDriver.sys   (Admin, test signing on)
2. Launcher.exe ping                      (verifies ping + XOR handshake)
3. test_read.exe                          (optional Phase 1 memory tests)
4. Start target process / offline session
5. Launch Launcher.exe GUI                (load config, attach, launch overlay)
6. INSERT → menu | F1 → ESP | F2 → health bars
```

---

## 8. Pattern / offset workflow

Patterns in `config.json` are **examples** — update after every game patch.

1. Dump `TslGame.exe` in IDA / Ghidra
2. Find `UWorld` / view-matrix sigs
3. Paste into `pattern_uworld` / `pattern_view_matrix`
4. Or set `offset_uworld` / `offset_view_matrix` directly (RVA)
5. Tune UE4 chain offsets (`offset_level_actors`, etc.)

When scan succeeds, console prints resolved addresses.

---

## 9. Manual mapping

`manual_map.c` does **not** perform kernel manual mapping. That technique loads unsigned code while evading driver signature enforcement and is not part of this project.

Use instead:

- `LoadDriverViaServiceW()` in `manual_map.c`
- `Launcher.exe load …`
- `scripts/load_driver.ps1`

---

## 10. WinDbg kernel debugging

Use a **local VM** or second machine for kernel debugging. Do not enable kernel debug on your daily driver without understanding the security impact.

### Target VM (guest)

Admin command prompt:

```cmd
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
shutdown /r /t 0
```

For Hyper-V / VMware, map COM1 between host and guest per your hypervisor docs.

### Host debugger

1. Install **WinDbg Preview** (Microsoft Store) or Debugging Tools for Windows.
2. **File → Kernel Debug → COM** → set port/baud to match guest.
3. Set symbols before breaking:

   ```
   .sympath srv*c:\symbols*https://msdl.microsoft.com/download/symbols
   .reload
   ```

4. Load driver on guest (`build.ps1` or `Launcher.exe load`).
5. Break on entry:

   ```
   bu MyMemoryDriver!DriverEntry
   g
   ```

6. After break, inspect:

   ```
   lm m MyMemoryDriver
   !devobj \Device\MyMemoryDriver
   ```

Unload clears the breakpoint target — use `Launcher.exe unload` on guest to exercise `DriverUnload`.

---

## 11. DebugView (driver DbgPrint)

The driver emits minimal kernel debug output:

| Event | Message |
|-------|---------|
| Load | `[MyMemoryDriver] DriverEntry ok device=... symlink=...` |
| Unload | `[MyMemoryDriver] DriverUnload` |

### Setup

1. Download [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (Sysinternals).
2. Run **as Administrator**.
3. **Capture → Capture Kernel** (and enable **Enable Verbose Kernel Output** if needed).
4. Load/unload driver and filter for `MyMemoryDriver`.

If nothing appears, confirm test signing / driver actually started (`Launcher.exe ping`) and that kernel capture is enabled.

---

## 12. Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `577` / driver won't start | Unsigned `.sys`, test signing off, or test cert not trusted | Sign with `build.ps1` / `scripts\sign_driver.ps1`. Enable testsigning and reboot. Test Mode watermark does **not** load a `NotSigned` image. Import the test `.cer` to TrustedPublisher + Root. `Launcher.exe load` now fails (exit 1) if the service is not RUNNING. |
| `OpenSCManager` access denied | Not elevated | Run loader / `build.ps1` as Administrator |
| `CreateFile \\.\MyMemoryDriver` failed | Driver not loaded | `Launcher.exe ping` or `build.ps1` |
| `Process not found` | Game not running | Start target process first |
| `Pattern scan failed` | Stale sigs | Update patterns/offsets in config |
| LNK2019 ImGui symbols | Missing imgui `.cpp` files | Add all six ImGui sources |
| Overlay black / no draw | Wrong window title | Set `window_title` in config |
| Empty ESP list | Wrong UE4 struct offsets | Re-dump offsets for your build |
| `Steam not found` / `steam://` not registered | Steam not installed or not registered | Install Steam or run `steam.exe` once |
| `Game launch timeout` | PUBG did not start in time | Check `inject_launch_timeout_ms`; verify Steam is signed in |
| `Driver load failed` | Missing BYOVD driver or wrong provider | Place the correct `.sys` in `x64\Release\drivers\` and select matching provider |
| `Overlay failed to initialize` | Missing OpenCV or model weights | Ensure `opencv_world470.dll` and `runtime\yolov3-tiny.weights` are next to `Launcher.exe` |
| `IOCTL handshake failed` | Driver/client version mismatch or stale session | Rebuild both; `Launcher.exe unload` then reload |
| **`STATUS_ACCESS_DENIED` on read/write** | **Handshake skipped or session key desync** | Client must call `DriverSession::Open()` (ping + handshake) before reads. Run `Launcher.exe ping` to verify driver IOCTL path. If a raw `DeviceIoControl` read fails with Win32 error **5**, complete `IOCTL_HANDSHAKE` first. After a failed encrypted IOCTL, close the Launcher and reload the driver to reset session state. |
| Encrypted reads return garbage | Key desync after failed IOCTL | Restart client; reload driver to reset session |
| `build.ps1` WDK warning | WDK not installed or incomplete | Install WDK + VS extension (see below) |
| MSBuild driver failure | WDK toolset missing or wrong kit version | Repair VS + WDK; do not set `WindowsTargetPlatformVersion` to `10.0` |

### WDK install and `ntddk.h` (C1083)

If the driver project fails with:

```text
error C1083: Cannot open include file: 'ntddk.h': No such file or directory
```

the kernel-mode WDK headers are missing or the project is pointing at the wrong kit version.

#### 1. Verify what is installed

From PowerShell:

```powershell
# Kernel headers (ntddk.h) — need a version folder such as 10.0.28000.0
Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Include\*\km\ntddk.h"

# WDK MSBuild integration — modern WDK uses a versioned build folder
Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\build" -Recurse -Filter WindowsDriver.Common.props
```

You need **both**: `ntddk.h` under `Include\<version>\km\` and `WindowsDriver.Common.props` under `build\<version>\`.

#### 2. Install WDK (matches Visual Studio 2022)

1. Install **Visual Studio 2022** with **Desktop development with C++** (already required).
2. Download and run the **WDK installer** for your VS version:
   - [Download the Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
   - Use the WDK release that matches your Windows SDK / VS 2022 (e.g. WDK for Windows 11, version 24H2 or latest shown on that page).
3. In Visual Studio Installer → **Individual components**, ensure:
   - **Windows Driver Kit** (or **Windows 11 SDK** + WDK components as listed on the download page)
   - **MSVC v143 - VS 2022 C++ x64/x86 build tools**
4. Optional but recommended: Visual Studio → **Extensions** → search **Windows Driver Kit** and install the WDK VS extension if the installer offers it.

Reboot if the WDK installer requests it.

#### 3. Rebuild in Visual Studio

1. Open `PUBG-Memory-Visualization.sln`.
2. Confirm project **MyMemoryDriver** → Properties → **General**:
   - **Configuration Type**: Driver
   - **Platform Toolset**: `WindowsKernelModeDriver10.0`
   - **Target Platform Version**: latest installed (e.g. `10.0.28000.0`) — **not** bare `10.0`
3. **Rebuild** `MyMemoryDriver` (Release | x64).

Or from the repo root:

```powershell
.\build.ps1 -Configuration Release -SkipLoad -SkipSign
```

#### 4. If headers exist but build still fails

- Repair WDK from **Apps & features** → Windows Driver Kit → **Modify/Repair**.
- Run **Visual Studio Installer** → **Repair** on VS 2022.
- Ensure `MyMemoryDriver.vcxproj` does **not** hardcode `WindowsTargetPlatformVersion` to `10.0` (paths like `Include\10.0\km` do not exist on modern kits).

#### 5. Without WDK

This project cannot produce `MyMemoryDriver.sys` without the WDK. User-mode targets (`loader`, `test_read`, `client`) build with the normal VS C++ toolset only.

### Driver debug output

Attach kernel debugger (section 10) or use **DebugView** (section 11) for `DbgPrint` output on load/unload.

---

## 13. Project layout

```
PUBG-Memory-Visualization/
├── build.ps1               Automated build / sign / load / ping
├── build.md                This guide
├── ROADMAP.md              Project phases and status
├── test_plan.md            Phase 1 test plan
├── PUBG-Memory-Visualization.sln
├── MyMemoryDriver.vcxproj  WDM kernel driver
├── test_read.vcxproj       Memory read/write smoke tests
├── Launcher/               Unified GUI/CLI launcher (project: Launcher\Launcher.vcxproj)
│   ├── main.cpp            ImGui launcher window
│   ├── newstuff/           BYOVD driver loader + NtAddAtom execution
│   ├── client_panel.cpp    PUBG overlay panel wrapper
│   ├── inject_thread.cpp   One-click PUBG Steam inject flow
│   └── imgui/              Vendored Dear ImGui + DX11 backends
├── driver/
│   ├── driver.h          Shared IOCTL protocol
│   ├── driver.c          Kernel driver (CR3 read/write, encrypted IOCTL)
│   ├── cr3_memory.h/c    CR3 page-table memory access
│   ├── ioctl_crypto.h    Shared XOR session crypto
│   ├── WdkVersion.props  Auto-detect installed WDK kit version
│   ├── manual_map.h/c    SCM load helpers (not kernel manual map)
├── tests/
│   └── test_read.cpp     DriverSession smoke tests (self-process)
├── client/
│   ├── client.cpp        Main loop, entity gather, keybinds
│   ├── driver_comm.h/cpp Encrypted driver session (read/write)
│   ├── overlay.h/cpp     ImGui ESP (box, health, name, distance)
│   ├── pattern_scanner.* Signature scan + RIP resolve
│   ├── config.h/cpp      JSON config (no external deps)
│   └── config.json.example
├── scripts/
│   └── load_driver.ps1
└── x64/Release/            Build output (after build.ps1)
    ├── Launcher.exe
    ├── MyMemoryDriver.sys
    ├── test_read.exe
    ├── drivers/            BYOVD vulnerable drivers (gdrv, RTCore64, ...)
    ├── runtime/            YOLO/OpenCV assets (yolov3-tiny.cfg, weights, labels)
    └── opencv_world470.dll
```

---

## 14. One-click PUBG / Steam inject flow

The **PUBG Client → Inject** tab automates the entire flow:

1. Close any existing PUBG process (if configured).
2. Launch PUBG via Steam (`steam://rungameid/578080`).
3. Wait for the game window (`PUBG` by default).
4. Load `MyMemoryDriver.sys` with the BYOVD provider selected in the **Kernel Driver** panel.
5. Start the ESP/AI overlay thread in a separate window.

### Usage

1. Build the solution with `build.ps1` (or VS) and place the required BYOVD driver under `x64\Release\drivers\`.
2. Run `Launcher.exe` as Administrator.
3. Switch to the **PUBG Client** panel → **Inject** tab.
4. Click **Load config** to populate inject settings from `config.json`.
5. Adjust **Steam AppID**, **process names**, and **window title** if your game/client differ.
6. Click **Inject** and wait for the status log to show `Overlay active`.
7. Click **Stop / Detach** to stop the overlay and optionally terminate the game.

### What is configured in `config.json`

| Field | Default | Purpose |
|-------|---------|---------|
| `inject_steam_appid` | `578080` | PUBG Steam AppID |
| `inject_process_name` | `TslGame.exe` | Main game executable |
| `inject_alt_process_name` | `PUBG_BATTLEGROUNDS.exe` | Newer client executable |
| `inject_window_title` | `PUBG` | Window title substring to wait for |
| `inject_launch_timeout_ms` | `120000` | How long to wait for the game window |
| `inject_close_existing` | `true` | Terminate existing PUBG processes before launching |
| `inject_stop_terminates_game` | `true` | Stop / Detach also terminates the game process |
| `inject_driver_path` | `x64\Release\MyMemoryDriver.sys` | Driver path (relative to launcher exe) |

### Prerequisites for the inject flow

- Administrator UAC (the Launcher manifest already requires it).
- Steam installed and registered as the `steam://` protocol handler.
- The BYOVD driver matching the selected provider exists in `x64\Release\drivers\`.
- `MyMemoryDriver.sys` is next to `Launcher.exe` or in the configured `inject_driver_path`.
- `opencv_world470.dll` and `runtime\yolov3-tiny.weights` are present for AI aim assist.

## 15. Keybinds (default)

| Key | VK | Action |
|-----|-----|--------|
| INSERT | 45 | Toggle ImGui menu |
| F1 | 112 | Toggle ESP |
| F2 | 113 | Toggle health bars |

Override via `key_toggle_*` in `config.json`.
