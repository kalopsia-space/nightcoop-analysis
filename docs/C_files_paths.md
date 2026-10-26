# NightCoop — Audit C: Files, Paths, Config Parsers, Logs, Clipboard

Static analysis only. The DLL was never run. All strings/pseudocode treated as untrusted data.
Scope: path traversal / filename injection, config parsers, log injection, clipboard invite,
crash/hang/minidump/rtti/port-test/mod-saves filenames, and the high-value question of whether
signed blobs (hubs.ncl / locations.ncl) are verified before being trusted.

Base data dir = `SHGetKnownFolderPath(FOLDERID_SavedGames)\CD Projekt Red\Cyberpunk 2077`
(built in `FUN_180680a80`); plugin folder is next to the DLL.

## Findings table (most severe first)

| # | Severity | Function / string | Field | Reachability | Confidence |
|---|----------|-------------------|-------|--------------|------------|
| 1 | Low | `FUN_18004f2a0` log sink + fmt lines e.g. `"relay: hub rejected the join: {}"`, `"cannot resolve '{}'"` | Network/paste-sourced free-text logged verbatim | Refusal reason: pure network (malicious/compromised hub). Resolve host: needs user paste/typing | Plausible |
| 2 | Info (no bug found) | `FUN_180050e90` (hubs.ncl), `FUN_18008d180` (UDP locations answer) | Signed-blob parse vs verify order | Network (locations answer) / local file (hubs.ncl) | Plausible-clean |
| — | Clean | path construction, format strings, clipboard invite, crash/hang/minidump/session/rtti filenames | see "Clean surfaces" | — | Confirmed |

Overall: this is a security-conscious codebase. No high- or medium-severity reachable issue was
found in this scope. The only non-clean item is cosmetic/forensic log-line injection (Low).

---

## 1. LOW — Log-line injection via unsanitized network/paste strings

- Sink: all mod logging formats through a `fmt`-style `{}` formatter (`FUN_180030ae0` build +
  `FUN_18004f2a0` / log write). The argument bytes are written verbatim; there is no newline or
  control-character stripping on the path I traced.
- Network-controlled arguments that reach the log as free text:
  - `"relay: hub rejected the join: {}"` / `"relay: the hub's port {} did not answer{}"` — the
    rejection reason is a free string chosen by the hub (s8 ~16162–16166, 16206).
  - `"cannot resolve '{}'"`, `"connecting to {}:{}"` (s8 16142/16144) — host string from a pasted
    invite / typed address.
- Effect: a malicious or compromised hub (refusal reason) — or a crafted invite the user pastes —
  can embed `\n` or ANSI escapes and inject forged lines / terminal escapes into
  `nightcoop-session-<timestamp>.log`. No code execution; this is log-integrity / forensic-spoofing
  only, and `{}` is NOT a C format specifier so there is no format-string primitive here.
- Mitigating facts that cap severity: the client keys players in logs by **peer number**
  (`"peer {}"`, `"relay: joined session {} as hub peer {}"`), not by raw nickname, and the session
  code is a validated 6–7 char alphanumeric. So the usual "nickname in the log" vector is largely
  absent; the residual vector is the hub-chosen reason string and the paste host.
- Fix: strip CR/LF and non-printable bytes from network/paste strings before logging (the report
  notes the hub side already uses `AddressText` and avoids raw strings; mirror that on the client).

Confidence Plausible: I confirmed these strings are logged as fmt arguments; I did not find a
sanitizer on this path, but did not exhaustively prove one is absent for every call site.

---

## 2. Signed blobs — parse-vs-verify order (the high-value question)

Reference (`hub/repo/src/NetCrypto.hpp`, `HubRules.hpp`): `HubList`/`HubCert`/`Location` each have a
bounded `Read()` (static limits `kMaxEntries=64`, `kMaxRevoked=256`, `kMaxLabel=63`,
`HubCert::kMaxSize`, `kMaxLocations=16`, …) that is SEPARATE from `Verify()`. Policy comment:
"the client never takes a list unless a valid signature by a trusted root and a serial newer than
the held one."

DLL behaviour:
- `hubs.ncl`: `FUN_180050090` reads the whole file into a heap buffer (alloc `0x8028`), then
  `FUN_180050e90` (787 lines) parses + verifies. Attacker surface for the file itself is local
  (someone who can write `hubs.ncl` next to the DLL / in the data dir).
- Locations list: `FUN_18008d180` (849 lines) handles the UDP `NCloc!` answer — this is the
  network-reachable pre-verify parser (a rogue main server or MITM can send the bytes).

What I verified:
- The DLL parsers mirror the repo's bounded-Reader pattern: field reads are gated by a
  remaining-length check against the datagram/buffer (e.g. in `FUN_18008d180`:
  `if ((ulonglong)(*(longlong*)(param_1+0x118) - *(longlong*)(param_1+0x110)) < 0x300)` before
  consuming), and strings are built with length-guarded std::string ops (`FUN_18003a010` /
  `thunk_FUN_1809f0e70`), not fixed-size copies.
- Parse-before-verify DOES occur — it must, because the signature sits at the end of the blob and
  the structure has to be walked to locate it. But the parsed entries are not acted on / trusted
  (no hub connection, no file rewrite) until the EdDSA signature against the embedded project root
  key passes and the serial is newer (`"hub list ... is not taken"`, s8 16034/16084).
- I found no unbounded length field, no entry-count that is used before a cap, and no
  trust-before-verify use of entries.

Conclusion: no exploitable "signed-blob-parsed-before-verify" issue found. Residual risk (why
Plausible-clean, not Confirmed-clean): the 787/849-line decompiles are large and messy; I could not
individually prove every u16 length field in the pre-verify walk is bounded to the remaining
datagram size. If the dev wants certainty, the one place worth a targeted re-read is the
pre-verify length handling of proof / list-body in `FUN_18008d180` (the UDP path is the only
network-reachable pre-verify parser).

---

## Clean surfaces (stated explicitly)

**Path traversal / filename injection — CLEAN (Confirmed).**
Every filesystem path I traced is `<known-folder or plugin dir> + <static string literal>`, joined
by `FUN_180024650(dest, dir, literal)`. No peer-, hub-, or config-supplied string is used as a
filename or directory component:
- `host-world.dat`, `host-world.json` (`FUN_18063da50(&buf,"host-world.dat",0)` @05:22475/23115) —
  static. The downloaded host world save lands at this fixed name, not a network-chosen one.
- `/nightcoop-crash.log` (@00:202937), `nightcoop-hang-<time>.dmp` (@00:207908/207940),
  `nightcoop-session-%04d-%02d-%02d-%02d-%02d-%02d.log` (@00:38634) — constant or timestamp only.
- `rtti-names-{}.txt` — the `{}` is not a network/config string (build/version-derived debug dump),
  referenced via a `.data` pointer, never from a peer/hub string.
- Session code is validated by `IsCodeChar` (alphanumeric Crockford set, length 6 or 7,
  `HubRules.hpp:134-143`) — cannot contain `/ \ . : NUL`, so it is path-safe even where used.
- No per-player file is keyed by nickname; player state is keyed by peer number. mod-saves folder
  names come from scanning the game's own save directory (`mod-saves.txt` lists
  `kind folder sav.dat-size ...`), not from the network.
No `..`, drive-letter, NUL, trailing-dot, reserved-name (CON/PRN…), or ADS (`:`) injection point was
found because no untrusted string reaches a path.

**Format-string injection — CLEAN (Confirmed).**
There is no `printf`/`sprintf`/`swprintf`/`wsprintf`/`vsprintf`/`StringCchPrintf` call anywhere in
the pseudocode with a network/config string as the FORMAT argument. The only format-family call is a
single `FormatMessageA(0x1300, ...)` (@08:50217) used to render an OS `GetLastError()` code — the
format flags come from the system message table, not attacker data. All mod-level logging/UI text
uses `fmt`-style `{}` where runtime strings are arguments, never the format literal. A nickname or
reason containing `{}` is inert.

**Clipboard invite parse — CLEAN (Confirmed, memory-safety).**
`FUN_1808a5e50` (via coop menu `FUN_1808a2e70`) parses a pasted `CODE@host[:port][#fingerprint]`.
The apparent stack buffers (`local_128[104]`, `local_c0[16]`) are in fact std::string / struct
members populated by `FUN_180031380` (std::string copy-construct, dynamic/bounded) copied out of a
thread-local parse singleton (`FUN_1800a6ba0` reads `DAT_181eb2e68`), not fixed-size `memcpy`
targets. The fingerprint is validated to 16 base32 chars (`0-9 A-Z` without I/L/O/U, s8 16054).
Pasting attacker text only fills fields and may trigger a join attempt — no filesystem write, no
process exec, no path construction. No overflow found.

**Crash / hang / minidump / port-test / rtti-names filenames — CLEAN (Confirmed).**
All are timestamp- or constant-derived (above). The VEH crash handler `FUN_1800f4640` (installed by
`FUN_1800f4cc0` via `AddVectoredExceptionHandler`) writes to the fixed `nightcoop-crash.log`.
HangWatch (`FUN_1800fa240`) writes `nightcoop-hang-<time>.dmp`. None incorporate a network string.

**Config parsers (switches.txt / servers.txt / hub.txt / name.txt / markers.txt) — no injection into
paths; CLEAN for the path/format scope.**
These are line-oriented parsers with explicit bad-line handling (`"switches.txt: «{}» is not «name =
on|off», skipped"`). `name.txt` (nickname) is validated: letters/digits/space/`- _ .`, ≤16 chars,
≥1 alnum. `hub.txt` is imported into `servers.txt` as an address (host[:port]); addresses are parsed
to host+port, never used as a filename. `servers.txt` is game-written with its own header. No config
value becomes a path component. (I did not fuzz these for parser-internal memory bugs on overlong
lines — out of this audit's path/format focus — but found no bounded-copy sink taking a config line.)

---

## Key function → file map
- `FUN_180680a80` (known-folder base) — `05_180636ad0-18076adf0.c`
- `FUN_18069a7a0`, `FUN_180104670`, `FUN_1800f4640`, `FUN_18090f820` (file write primitives;
  take `LPCWSTR` filename built by caller, `CreateFileW`) — 05 / 00 / 00 / 07
- `FUN_180024650` (path = dir + literal) — `00_180001000-180139ee0.c:22500`
- `FUN_180050090`/`FUN_180050e90` (hubs.ncl load/verify), `FUN_18008d180`/`FUN_180098590`
  (locations answer) — all `00_180001000-180139ee0.c`
- `FUN_1808a5e50` (invite parse) / `FUN_1808a2e70` (coop menu) — `07_180898b60-1809c3af0.c`
- `FUN_180931af0` (mod-saves.txt), `FUN_1809c44f0`/`FUN_1809ead70` (switches.txt) — 07 / 08
