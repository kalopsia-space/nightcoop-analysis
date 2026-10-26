# Audit F — RCE, fuzzing & obfuscation review (0.1.1-beta.2)

A focused follow-up audit of `NightCoop.dll` **0.1.1-beta.2** (SHA-256
`9b07bb76…`) looking specifically for **remote code execution / memory
corruption** reachable from the network, for **obfuscated or hidden code**, and
an honest statement of **what this methodology would and would not catch**. It
builds on the general triage in [`capability_triage.md`](capability_triage.md),
the 0.1.0 deep-dives [A](A_net_deserializers.md)–[E](E_hub_server.md), and the
change analysis in [`6_changes_0.1.1-beta.2.md`](6_changes_0.1.1-beta.2.md).

**Bottom line: no RCE or memory-corruption bug found, and no obfuscated/packed/hidden code.**
The new reward surface is memory-safe by construction, the highest-risk
pre-existing parser (the `wire_zip` decompressor) survived both static review
and fuzzing, and the binary is plain, unobfuscated MSVC C++ with Control Flow
Guard enabled. Caveats and residual risk are stated at the end — they are real.

## Threat model

An attacker who can feed bytes to the client's deserializers: a **malicious
host**, a **malicious peer**, or a **man-in-the-middle on a direct-IP (hub-less)
session** (those are encrypted but unauthenticated). Hub-mediated sessions have
verified keys, so there the attacker is effectively the host/peer you chose to
play with.

## 1. New wire surface — the Rewards messages (safe by construction)

0.1.1-beta.2's only new attacker-reachable code is the reward message family
(`nc::rewards`). Receive path:

- **Dispatcher `FUN_180389570`** routes four subtypes (`*`, `+`, `,`, and the
  default `0xEE` → `RewardWord`). It takes the buffer as a `{start,end}` pair —
  the **actual decrypted byte range**, never a wire-claimed length — and every
  field read is guarded `cursor + size <= end`; the first failed check drops the
  message (fail-safe). Some subtypes additionally require the cursor to land
  exactly on `end`.
- **`RewardWord` handler `FUN_18039fd70`** parses a **fixed 22-byte** layout:
  `NCOP` magic (4) + type `0xEE` (1) + subtype (1) + an 8-byte id + two 4-byte
  fields. It **requires the length to equal exactly `0x16`** before any field
  read, so every read is in-bounds. Valid words go into a fixed-size struct
  pushed onto a **capacity-capped** queue (`< 0x4000`) under a lock. A stack
  canary is present. Malformed frames hit the rate-limited
  `rewards: a malformed word from peer {} ({} bytes)` log and return.

No variable-length field, no `memcpy` with a wire-controlled size, no
wire-controlled index. **No memory-safety issue.** The residual is logic/trust
only (a modified host/owner can enqueue bogus reward credit → cheating), which
is the pre-existing Low-severity owner-trust class in
[`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (#1, #6, #8).

## 2. Highest-risk pre-existing parser — the `wire_zip` decompressor

`wire_zip` (the `NCZQ` reliable-stream compression) is an LZ4-style block codec —
the classic out-of-bounds-write vector. Receive path:

- Frame router `FUN_18007ad60`: `NCPT`→control, `NCSQ`/`NCZQ`→`FUN_180079140`.
- Orchestrator `FUN_18006f4f0`: parses the block header, enforces the
  **per-block decompressed size ≤ `0x10000` (64 KiB)**, runs the decode, then
  **checksum-validates** the output (`FUN_180066330`). The caller caps total
  reassembly accumulation at **`0x800000` (8 MiB)**.
- Decode core **`FUN_180066cc0`** (the LZ77 expand).

### Static reading of the decode core
Every write is bounded:

- Output end is fixed at `uVar14 = base + outsize`, `outsize ≤ 0x10000`.
- Before each literal copy: `end - cur < len → abort` (output room) **and**
  `inlen - ip < len → abort` (input room).
- Match offset validated: `off == 0 || cur < off → abort` — a back-reference can
  never point before the buffer start (no underflow).
- Before each match copy: `end - cur < matchlen → abort`.
- Length-extension loops (`0xf`/`0xff`) are input-bounded (`inlen <= ip → abort`).
- At the end it requires `cur == end` exactly (produced precisely `outsize`).

### Fuzzing
The decode core was transcribed faithfully to C (see
[`../tools/fuzz/fuzz_wirezip.c`](../tools/fuzz/fuzz_wirezip.c)) and fuzzed under
**libFuzzer + AddressSanitizer + UBSan**, with the window buffer allocated to
exactly `base + outsize` so any OOB read/write faults immediately.

| | |
|---|---|
| Executions | **452,858** (~5,000 exec/s, 91 s) |
| Coverage | 59 edges / 244 features — **saturated early**, then minimized |
| Crashes / leaks / sanitizer errors | **0** |
| Hand-crafted branch seeds (literal run, `0xf/0xff` length extension, overlapping/RLE match, prior-window back-reference) | all **clean** |

Static reasoning and fuzzing agree: the decompressor is memory-safe. (It is
shared, unchanged 0.1.0 code, so this also reinforces the original audit.)

## 3. Obfuscation / packing / hidden-code sweep

The classic "mostly benign binary hiding a small encrypted payload" pattern is
absent. Nothing is obfuscated or packed:

| Check | Result |
|---|---|
| Section entropy | `.text` 6.42, `.rdata` 6.22 — normal compiled code (packed ≈ 8.0) |
| Section permissions | `.text` R+X, `.data` R+W — **no RWX**, no self-modifying region |
| Packer section names | none (no UPX/VMProtect/Themida/`.enc`) |
| Overlay (appended data) | **0 bytes** |
| Embedded PE/MZ payloads | **0** real executables (byte-coincidence `MZ`/`PE\0\0` only) |
| Runtime code decryption | none — no `VirtualAlloc`, no `PAGE_EXECUTE` `VirtualProtect`, no RWX |
| Import hiding | no ROR13/FNV/djb2 import hashing, no PEB/TEB walk, no `syscall`; `GetProcAddress` resolves APIs by **plaintext name** |
| TLS callbacks | 2, both **standard CRT** (`__dyn_tls_init` / `__dyn_tls_dtor` for C++ `thread_local`), CFG-guarded |
| Exploit mitigations | **Control Flow Guard enabled** — hardening, the opposite of obfuscation |
| String encryption | none — all strings are **cleartext** (hub host, crypto domains, ~250 switch names, the self-documenting hint strings the audit relied on) |

The one XOR-in-loop function the scanner flagged (`FUN_1802b0640`) contains
floating-point math and a game-object signature — a hash/mixing routine, not a
string decoder (verified by inspection, not full reversing).

## 4. What this methodology would and would not catch (residual risk)

This audit is **static plus one fuzzed parser**. It is strong in some dimensions
and shallow in others; the risk statement below is deliberately honest.

**Reliably caught (comprehensive passes over all ~20k functions / all sections):**
capability-based malware (process spawn, injection, download, credential theft,
persistence, keylogging), packing/encryption/obfuscation, and — importantly —
the client has **no download/exec/injection primitives** to add such behavior at
runtime without introducing APIs these passes would flag.

**Could be hidden from the depth of pass done here:**

1. **A planted, plausibly-deniable parser bug** (a subtle off-by-one usable by
   the dev's server/peer). We **read** the reward parser and **fuzzed** the
   decompressor, but did **not** read or fuzz every attacker-reachable parser
   (the NCSQ reassembler `FUN_18005d860`, the decompressed-stream framer
   `FUN_180066b20`, the save-splice path, and the ~150 other message types).
   This is the weakest spot in coverage.
2. **A dormant trigger** (time-bomb / magic-input). Static analysis can find the
   code, but only ~a dozen of 20k functions were read in depth; fuzzing won't
   reach a trigger without the trigger.
3. **Malice piggybacking on legitimate file/network features** — especially the
   world-file path that receives the host's save, writes it to disk and loads
   it. Not re-audited line-by-line in this build (relied on the module diff +
   Audit B).
4. **The server.** The hub is open source, but the dev runs the actual server,
   which can differ from the published source. Server-side behaviour is out of
   scope for client + published-hub analysis.

**Damage ceiling:** because the client has no download/exec primitives, even a
hidden backdoor is capability-limited — at worst it could corrupt/overwrite
files it can already reach (saves, its own directory), crash the game, or leak
data over the existing encrypted channel; it cannot silently run a second-stage
payload or install persistence without APIs the capability sweep would catch.
CFG + ASLR + no-RWX further raise the bar on weaponising any planted memory bug.

**To close the gaps** would require fuzzing every attacker-reachable parser,
reading the save-splice path line-by-line, and — the big one — **dynamic
analysis** (run in a VM, observe filesystem/network/syscalls, diff behaviour
across builds), since a dormant trigger or a modified server only reveals itself
at runtime.

## Limitations

Static analysis of decompiler output; the DLL was never executed. The fuzzing
exercised a **faithful transcription** of `FUN_180066cc0`, not the shipped bytes
(a found crash would be replayed against the real DLL via a Wine harness to
confirm; none was found). Coverage was targeted, not exhaustive.
