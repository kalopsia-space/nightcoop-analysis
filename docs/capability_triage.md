# NightCoop.dll 0.1.0-beta.1 — capability triage

The pre-run malware triage of the client binary: what Windows/OS capabilities `NightCoop.dll`
does and does not use, established before running it. This is the detail behind the README's
"no malicious code" verdict. For the consolidated vulnerability audit with severities see
[`SECURITY_AUDIT.md`](SECURITY_AUDIT.md); for what the mod actually *does* as a game feature see
[`00_overview.md`](00_overview.md). The 0.1.1-beta.2 build was re-swept against all of the
"absent entirely" items below and is still clean — see [`6_changes_0.1.1-beta.2.md`](6_changes_0.1.1-beta.2.md).

## Package contents (0.1.0-beta.1)

| File | SHA-256 | Notes |
|---|---|---|
| `bin/x64/winmm.dll` | `22690f3ac5efbfa825b758028f114d0e7d83833160716f199c56056db01fc8be` | Identical to official RED4ext v1.30.0 |
| `red4ext/RED4ext.dll` | `59309a78a9606481d13f87e8fbf9ea9c0b735115389ded0295537180c9e52511` | Identical to official RED4ext v1.30.0 |
| `red4ext/LICENSE.txt` | `a0b08b28ae3931a5a41a1788aac6c7a391513bfc3599272021ea5b2c1af2f6f6` | Identical to official |
| `red4ext/THIRD_PARTY_LICENSES.txt` | `b49e3d32f961c21e0b15f4c9b11da9455d7c9905a457b1dfa88504f6592220ff` | Identical to official |
| `red4ext/plugins/NightCoop/NightCoop.dll` | `6d22c0c1b70a3d79df4127a273f9e33198583698300086cd4f8f3e9f9e48adb8` | The mod itself (analysed below) |

The RED4ext files were compared against [`red4ext-1.30.0.zip`](https://github.com/wopss/RED4ext/releases/tag/v1.30.0)
from the official GitHub release (asset digest `sha256:3a72225c…c0b0`). Because `winmm.dll` is a proxy
DLL the game loads automatically, this check matters most.

## NightCoop.dll overview

- PE32+ x64 DLL, unsigned, no PDB, no overlay, no embedded PE files.
- Compiled 2026-10-23 14:26:27 UTC, about 30 minutes before the announced open-beta release (18:00 MSK). The internal build ID is `a7c537d`, and an embedded source path is `F:\files\cyberpunk\nightcoop-port25\src\…`.
- Exports: `Main`, `Query`, `Supports`, `RegisterTypes`, `PostRegisterTypes`, `NightCoopAddonApi` (the standard RED4ext plugin interface plus an add-on API for a companion "NightReplay" plugin).
- 19,538 functions, all decompiled with Ghidra 12.1.2 (0 failures).

## Findings by capability

### Absent entirely

Each of these was searched for in the import table, in the strings, and across all 19,538 decompiled functions:

- Process creation: `CreateProcess`, `ShellExecute`, `WinExec`, `system()`.
- Injection: `WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`, `OpenProcess`, `SetWindowsHookEx`.
- HTTP or download APIs: WinHTTP, WinINet, `URLDownloadToFile`.
- Executable memory: no `VirtualAlloc`, and no `VirtualProtect` call with a `PAGE_EXECUTE_*` flag.
- API hiding: no PEB/TEB walking, no ROR13 or export-table hashing, no raw `syscall`.
- String obfuscation: no XOR-decode loops beyond normal crypto.
- Credential theft: no `CryptUnprotectData`, and no references to browsers, Discord, Telegram, wallets, tokens or cookies.
- Persistence: no registry writes, no Startup-folder GUIDs, no scheduled tasks.
- Environment snooping: no `getenv` of `USERNAME`, `APPDATA`, `USERPROFILE` and similar.

### Present, with what each one does

| Capability | Where | What it does |
|---|---|---|
| `VirtualProtect` | `FUN_18090f7b0` | 8-byte pointer-swap hook helper: set RW, write one pointer, restore the old protection. The other two call sites are C runtime code. |
| Registry | `FUN_1809f95c0` | Reads only `SYSTEM\CurrentControlSet\Control\LeapSecondInformation` (MSVC STL `<chrono>`). |
| `LoadLibrary` / `GetProcAddress` | 36 sites | Resolves `dbghelp!MiniDumpWriteDump/StackWalk64` (crash dumps), `RED4ext_ResolveAddress`, `ntdll!wine_get_version` (Wine detection), `REDGalaxy64!CloudStorage` (GOG cloud saves), `shell32!SHGetKnownFolderPath`, `kernel32!SetThreadDescription`, and ICU `ucal_*` (timezones). |
| Known folders | `FUN_180680a80` | Only `FOLDERID_SavedGames` → `CD Projekt Red\Cyberpunk 2077` (the game's save folder). |
| File writes | `FUN_18069a7a0`, `FUN_18090f820`, `FUN_180104670`, `FUN_1800f4640` | Atomic save writes (`.nightcoop.tmp` → `MoveFileExW`), its own config and state files, logs, crash minidumps. |
| Files read | — | Its own config (`switches.txt`, `hub.txt`, `servers.txt`, `name.txt`, …) and game saves (`sav.dat`). |
| Clipboard | `FUN_180897300` ← coop menu `FUN_1808a2e70` | Pasting and copying invite codes, nicknames and addresses. |
| Keyboard | 14 functions | Every one first checks `FUN_18060a2f0`: the foreground window's PID must equal the game's PID. Only specific hotkeys and menu text entry (`ToUnicodeEx` for typed characters) are polled. This is not a keylogger. |
| `SuspendThread` / `GetThreadContext` / `ReadProcessMemory` / Toolhelp | `FUN_1800f8ac0` and similar | In-process hang and crash reporter: stack walks and module lists written to local logs and minidumps. No upload path was found. |
| `TerminateProcess` | 5 sites | RED4ext SDK version-mismatch abort and CRT fatal-error paths. |
| `Main` | `0x1809eb920` | Logs the version, registers its types with RED4ext, and initialises about 150 game subsystems. No startup side effects beyond that. |

### Network

- All outbound traffic goes through a single `WSASendTo` call site (`FUN_180018cc0`), which is called by 10 netcode functions.
- **Lobby/relay hub:** `hub.nightcoop.net`. Its certificate is pinned and signed by the project.
- **STUN / NAT traversal:** `stun.l.google.com`, `stun.cloudflare.com`, `global.stun.twilio.com`, `stun.nextcloud.com`, and UPnP SSDP on `239.255.255.250:1900` (read-only `GetExternalIPAddress`; no `AddPortMapping`). These run only in the on-demand `NightCoopNetCheck` diagnostic.
- **Local-IP discovery:** a UDP `connect` to `8.8.8.8` and `2001:4860:4860::8888` (no payload sent).
- **Peer links:** X25519 key exchange with XChaCha20-Poly1305 (`net_crypto`).
- **Data shared:** game state, nickname, chat, and the host's save file, which is sent to partners by design. The hub and peers see your IP address.

### Minor notes (not malicious)

- No beta expiry: the only "it expired on {}" string belongs to the hub certificate check (`FUN_180041d80`).
- Phantom Liberty is enabled when its files are present, which skips the store ownership check (`GameServices` step).

## Limitations

- This is static analysis of decompiler output, not original source, and the mod was never executed.
- Indirect calls through game vtables and function pointers can't be followed fully by static analysis.
- The 69 MB of pseudocode was scanned with patterns, and every sensitive call site was hand-reviewed. Not every line was read.
- Server-side behaviour of `hub.nightcoop.net` is out of scope.
