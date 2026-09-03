# Phase 1 Test Plan — MyMemoryDriver

Structured manual and automated tests for the kernel driver, encrypted IOCTL session, and CR3 memory access. **Do not target BattlEye-protected games or live PUBG** — use self-process, Notepad, or other safe dummy targets only.

See also: [build.md](build.md) and the `build.ps1` workflow.

---

## Prerequisites

| Requirement | How to verify |
|-------------|---------------|
| **Windows 10/11 x64** | `systeminfo \| findstr /B /C:"OS Name"` |
| **Test signing enabled** | `bcdedit \| findstr testsigning` → `Yes` |
| **Visual Studio 2022 + WDK** | `build.ps1` locates MSBuild; WDK required for driver build |
| **Administrator** | Required to load/unload driver via SCM |
| **Built + signed driver** | `x64\Release\MyMemoryDriver.sys` exists |
| **Launcher built** | `x64\Release\Launcher.exe` exists |

### One-time setup

```powershell
# Admin — enable test signing (reboot required)
bcdedit /set testsigning on
shutdown /r /t 0
```

### Build and load (automated)

```powershell
# Admin PowerShell, repo root
.\build.ps1 -Configuration Release -RunTests
```

This builds driver + Launcher + `test_read`, signs the `.sys`, loads via SCM, runs `Launcher.exe ping`, and optionally runs memory tests.

---

## Test 1: XOR handshake + ping

**Goal:** Verify device is reachable, `IOCTL_PING` returns expected magic/version, and `IOCTL_HANDSHAKE` XOR mask (`0x12345678`) matches.

### Steps

1. Ensure driver is loaded (`build.ps1` or `Launcher.exe load <path.sys>`).
2. Run:

   ```powershell
   x64\Release\Launcher.exe ping
   ```

### Expected output

```
driver ok magic=0x4d4d454d version=2 handshake=ok
```

### Pass criteria

| Check | Pass | Fail |
|-------|------|------|
| Exit code | `0` | Non-zero (`2` = ping/handshake failure) |
| Magic | `0x4D4D454D` (`MMEM`) | Any other value |
| Version | `2` | Mismatch |
| Handshake | `handshake=ok` printed | `IOCTL handshake failed` |

### Fail actions

- `open device failed` → driver not loaded; run `Launcher.exe load`.
- `IOCTL handshake failed` → rebuild driver and Launcher; `Launcher.exe unload` then reload.

---

## Test 2: Read memory (safe target)

**Goal:** Encrypted `IOCTL_READ_MEMORY` returns correct bytes from a known address.

### Option A — `test_read.exe` (recommended)

```powershell
x64\Release\test_read.exe
```

Includes PE header read at own module base and encrypted round-trip on stack buffer.

### Option B — Notepad.exe module base

1. Start Notepad.
2. Note PID (Task Manager or `(Get-Process notepad).Id`).
3. Use `test_read`-style code or extend harness to read first 2 bytes at `notepad.exe` image base → expect `MZ` (`0x5A4D`).

### Pass criteria

| Check | Pass | Fail |
|-------|------|------|
| `DriverSession::Open()` | Succeeds (ping + handshake) | Returns false |
| Read size | Requested bytes returned | `DeviceIoControl` fails or short read |
| PE DOS signature | `0x5A4D` at module base | Other value |
| `test_read` output | `PASS: encrypted read round-trip` | `FAIL:` lines |

---

## Test 3: Write memory (safe target)

**Goal:** Encrypted `IOCTL_WRITE_MEMORY` modifies memory in **own process** or dedicated test harness only.

### Steps

1. Run `test_read.exe` (includes write test on a local `uint64_t` in the test process).

   ```powershell
   x64\Release\test_read.exe
   ```

2. Expected line:

   ```
   PASS: write + read round-trip at 0x...
   ```

### Pass criteria

| Check | Pass | Fail |
|-------|------|------|
| Write IOCTL | Returns success | `FAIL: encrypted write failed` |
| Local verification | Variable updated in-process | Unchanged |
| Read-back via driver | Matches written value | Mismatch |

**Do not** write to Notepad, games, or system processes unless you fully control the target and accept crash risk.

---

## Test 4: Encrypted read round-trip

**Goal:** Confirm client and driver stay in sync on XOR session key and rotation (`MM_KEY_ROTATE_INTERVAL = 1000`).

### Steps

1. `DriverSession::Open()` — handshake establishes session key.
2. Read 16 bytes from a stack buffer in the test process (`test_read.exe` Test 1).
3. Compare decrypted payload to known plaintext.

### Pass criteria

| Check | Pass | Fail |
|-------|------|------|
| Plaintext match | All bytes identical | Any byte differs |
| Without prior handshake | N/A (Open fails first) | Read returns garbage or `ACCESS_DENIED` |

### Session desync check (negative test)

1. Open device with raw `CreateFile` **without** handshake.
2. Issue `IOCTL_READ_MEMORY` → expect failure / `STATUS_ACCESS_DENIED` (Win32 error 5).

---

## Summary checklist

| # | Test | Command / tool | Pass indicator |
|---|------|----------------|----------------|
| 1 | Ping + handshake | `Launcher.exe ping` | `handshake=ok`, exit 0 |
| 2 | Read memory | `test_read.exe` | `PASS: encrypted read round-trip`, PE `MZ` |
| 3 | Write memory | `test_read.exe` | `PASS: write + read round-trip` |
| 4 | Encrypted round-trip | `test_read.exe` | No `FAIL:` lines; all `PASS:` |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `STATUS_ACCESS_DENIED` on read/write | Handshake not completed | Call `DriverSession::Open()` or run `Launcher.exe ping` first |
| Garbage after read | Session key desync | Close client, `Launcher.exe unload`, reload driver |
| sc start error `577` | Unsigned / invalid signature | Enable testsigning; run `build.ps1` signing step |
| `OpenSCManager` denied | Not elevated | Admin PowerShell |
| Driver load but no DebugView output | DbgPrint not captured | Run DebugView as Admin; enable Capture Kernel (see build.md) |

---

## Optional: unload after testing

```powershell
x64\Release\Launcher.exe unload
```
