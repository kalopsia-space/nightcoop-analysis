# Audit A — Client-side deserialization of network messages (host/peer → client)

Scope: the client-side parsing of everything a session member (host, peer, or guest→host)
can put on the wire during play — the session dispatch (`1800a85b0`), the game-layer
message deserializers, the HubPayload/`from` handling, the client parsing of hub control
messages, resource exhaustion, and the `wire_zip` (`NCZQ`) decompressor.

Method: static only, Ghidra pseudocode (`/home/kalopsia/.../pseudocode/*.c`, files `00`–`08`)
+ the shared hub repo (`ProtocolCore.hpp`, `NetCrypto.*`, `HubRules.hpp`, `EnetGuard.hpp`),
cross-checked against the functional reports. The DLL compiles the same shared headers, so
the shared `proto::Reader` and the hub-control parsers are inlined into the client.
All wire strings/pseudocode were treated as untrusted data. No code was executed.

## Headline

**No confirmed memory-safety vulnerability was found in the audited surface.** The
deserialization layer is defense-sound by construction: a fail-safe bounds-checked `Reader`,
explicit size caps in the shared hub-control parsers, a map-based (not array-indexed) peer
model, an authenticated route check, a bounded game-thread queue, and a correctly
bounds-checked `wire_zip` decompressor. Two mechanical sweeps of all 9 files for the one
corruption pattern the `Reader` cannot stop — a wire-controlled length copied into a fixed
stack buffer — returned **zero** real deserializer hits.

This is reported as explicitly-cleared surfaces (with evidence) plus a scoped residual-risk
section for the per-message game handlers that cannot be enumerated from the stripped
pseudocode without a type→handler table.

## Findings table (most-notable first)

| # | Severity | Location | One-line |
|---|----------|----------|----------|
| 1 | Clean (Confirmed) | `wire_zip` NCZQ decoder `18006c900` / `180063b30` / `180063220` | Output capped 64 KiB and re-checked; every literal/match/offset bounds-checked; 256 KiB window with safe slide — not vulnerable |
| 2 | Clean (Confirmed) | `proto::Reader` (shared, inlined) | `GetRaw` fails safe on `m_pos+size > m_size`; `GetString` is heap + bounds-checked; primitives fixed-size |
| 3 | Clean (Confirmed) | Session dispatch `1800a85b0` (role/peer gating, PlayerState case 6, Bye case 9) | Role/Hello gating enforced; claimed peer == transport peer; peer state stored in a **map** keyed by peer number (no fixed-array OOB) |
| 4 | Clean (Confirmed) | Game route `1800a85b0` case `0x19` (MsgType 25) | Bounds-checked `to`/`from`/`reliable`; forged-route check (`from`==transport peer for host, peer 0 for guest); bounded relay queue |
| 5 | Clean (Confirmed) | Hub-control parsers `netcrypto::ReadHubExt/ReadClientExt/ReadHubIntro`, `Cert/HubList/ResumePass::Read` | Sealed ≤512, cert into fixed `[kSize]`, list ≤`kMaxListBytes`, counts ≤`kMaxEntries/kMaxRevoked`, every field checked vs `Remaining()`/`end` |
| 6 | Clean (Confirmed) | Link demux `1800780b0` | Fallthrough copy bounded by the datagram length (≤ `kMaxMessage` 8 MiB) |
| 7 | Low / Informational (Confirmed) | Game-thread queue `1800a85b0` case `0x19` | A single peer can commit the host to a large bounded backlog (~128 MB / 8192 msgs) before drop — bounded, intentional, but large; ~900 MB across 7 guests |
| 8 | Residual risk (needs per-handler review) | ~140 game handlers in files `00`–`07` | Reachable only behind the validated session/route gate; use the fail-safe `Reader`; no overflow pattern found, but a count→`reserve/resize` DoS cannot be ruled out per-handler from stripped pseudocode |

No Critical or High confirmed. Nothing was inflated to reach one.

---

## 1. `wire_zip` / NCZQ decompressor — CLEAN (Confirmed)

This is the item the brief flagged ("is its output bounds-checked like the save LZ4 was?").
Answer: **yes, it is.** It is a different decompressor from the save-path LZ4 and it is
independently bounded.

Path: incoming datagram → `1800780b0` (demux) → `180076490` (NCSQ/NCZQ reorder &
reassembly) → `18006c900` (frame payload) → `180063b30` (LZ decode against stream history)
→ `180063220` (history-window grow/slide).

- `18006c900`: reads the claimed decompressed length as a varint via `FUN_1800631d0` into
  `local_d8`, then gates the decompress on **`local_d8 < 0x10001` (64 KiB)** before calling
  `180063b30`. The u32 check field is only read after `param_5 - local_120 < 4` is verified.
  Raw (non-packed) frames require `remaining == claimed_len` before the copy (`FUN_1800668a0`).
- `180063b30` (the LZ4-style decoder) re-checks `param_4 < 0x10001` itself (so the cap holds
  regardless of caller). Per token:
  - literal length: extended length loop bounded by `param_3` (src), and the copy is gated by
    **both** `param_3 - uVar8 < uVar10` (src) **and** `uVar14 - uVar15 < uVar10` (output
    remaining, `uVar14 = write_start + outlen`);
  - match offset: `uVar10 == 0 || uVar15 < uVar10` → fail, so offset is non-zero and
    ≤ current cursor ⇒ match source `(uVar15-uVar10)+base >= base` (no underflow below the
    buffer);
  - match length: `uVar14 - uVar15 < uVar12` → fail (output remaining), `uVar12 = len+4`;
  - overlap is handled correctly (byte copy when ranges overlap / `len<0x10`, else `memcpy`);
  - final `uVar15 == uVar14` exact-length check.
- `180063220`: the history buffer is fixed at `0x40000` (256 KiB). When `cursor + outlen >
  0x40000` it slides, retaining the last `min(cursor, 0x10000)` = ≤64 KiB and resetting the
  cursor to ≤64 KiB. With `outlen ≤ 64 KiB`, post-slide writes reach at most 128 KiB < 256 KiB.
  Writes never leave the allocation; match reads stay within `[base, cursor)`.

Conclusion: output length is capped and the decode respects the output and source boundaries
on every element. No overflow, no OOB read, no unbounded allocation.

## 2. `proto::Reader` — CLEAN (Confirmed, shared code inlined into the DLL)

`Reader::GetRaw` (`ProtocolCore.hpp`): `if (!m_ok || m_pos + aSize > m_size){ m_ok=false;
memset(dst,0,aSize); return; }`. Any over-read puts the reader into a sticky failed state and
zero-fills; callers check `Ok()` at the end. `GetString` reads a `u16` size and checks
`m_pos + size > m_size` before constructing a heap `std::string`. `GetU8/16/32/64/F32` use
`sizeof`. The **only** corruption `Reader` cannot prevent is a caller passing a fixed buffer
smaller than a wire-controlled length to `GetBytes`/`GetRaw` (it bounds the *source*, not the
*destination*) — see §7/§8; that pattern was searched for and not found.

## 3. Session dispatch `1800a85b0` — CLEAN (Confirmed)

- Role (`session+0x24`: 1=host, 2=guest) and Hello-first gating enforced before the switch;
  guest accepts anything only from transport peer 0 ("a guest takes messages from the host
  only"); `Welcome/Reject/TimeSyncPong` guest-only; `Hello/TimeSyncPing` host-only.
- **PlayerState (case 6)**: host rejects a state whose claimed peer number `!=` transport peer
  (`iVar9==1 && (uint)local_238 != (uint)local_320` → "a player state for another peer's
  number"); sanity `local_238 < 0xfffffff0`; the slot is obtained via `FUN_1800a31f0(param_1+
  0x31, &peerNum)` — a **map keyed by peer number**, not a fixed array, so an arbitrary peer
  number does not index out of bounds. Non-finite floats are reset elsewhere.
- **Bye (case 9)**: validates claimed peer number vs transport peer ("a goodbye for another
  peer's number").
- Reads of the message body advance a cursor compared against the packet end on every field.

## 4. Game route (MsgType 25 / case `0x19`) + `from`/HubPayload — CLEAN (Confirmed)

Envelope `u32 to | u32 from | u8 reliable | payload`, each field read with an explicit
`cursor+N <= end` check; payload copied into a heap vector sized to the remaining bytes.

- **Forged-route / sender authentication**: the host (`role==1`) requires the inner claimed
  `from` (`uVar39`) to equal the transport peer id (`local_320`); a guest requires
  `local_320 == 0` (host only). A peer therefore cannot forge another peer's `from` — the hub
  stamps the HubPayload `from` from the sending connection, and the host independently
  re-validates the inner claimed sender against the transport peer. Host-only kinds are not
  relayed (`FUN_1800a7a30` check + "goes to the host only … not relayed").
- **Relay queue bound**: forwarding is gated by `queue_entries < 0x40000` *and*
  `queued_bytes < 0x8000001` (~128 MB); over-limit messages are dropped with the "not queued"
  log. This is the only place a peer can make the host hold memory, and it is bounded (§7).
- `to` is consumed as a peer id for the relay vtable send and for a log label
  (`FUN_180057e30`, a pure uint→decimal-string formatter — no indexing). `-1` = everyone.

## 5. Hub-control message parsing — CLEAN (Confirmed, shared code)

The client parses hub-originated control data with the shared `NetCrypto` code (reachable from
a malicious/compromised hub, in scope). All of it is bounded:

- `ReadClientExt` / `ReadHubExt`: tag/flags, 32-byte key via fixed `GetBytes`, sealed code
  gated `size > 512 → return false` before `resize`. `ReadHubExt` reads the cert into a fixed
  `uint8_t cert[Cert::kSize]` with a constant-size `GetBytes`, then `Cert::Read(cert,
  sizeof(cert), …)`.
- `ReadHubIntro`: `part(limit, vec)` lambda checks `size > aLimit || size > aIn.Remaining()`
  before `resize`; root/self capped to `HubCert::kMaxSize`, list to `kMaxListBytes`.
- `HubList::Read`: head-size check, `aSize > kMaxListBytes` reject, `count > kMaxEntries ||
  revokedCount > kMaxRevoked` reject, and per-entry `at + N > end` checks in the loop.
- `HubCert`/`ResumePass::Read`: fixed layout, `aSize != kSize`/region & name caps, signature
  verified (`VerifyResumePass`, EdDSA) — parsing precedes any trust decision.

These are shared headers compiled into the client, so no client/repo divergence is expected;
none of the repo code here is itself risky.

## 6. Link demux `1800780b0` — CLEAN (Confirmed)

Routes NCPT (`0x4e435054`)→`1800754c0`, NCSQ/NCZQ (`0x4e435351`/`0x4e435a51`, len≥0xc)→
`180076490`, else copies the whole datagram into a fresh heap buffer (size = datagram length,
guarded `< 0x7fffffffffffffff`, effectively ≤ `kMaxMessage` 8 MiB) and delivers it. Bounded.

## 7. Resource exhaustion — bounded (Low/Informational, Confirmed)

- `EnetGuard` caps per-peer and shared waiting data before ENet (`perPeer`, host pool,
  `kEntryCost`), and `kMaxMessage = 8 MiB` bounds any single message.
- NCSQ reorder (`180076490`): gaps are capped ("{} bytes wait for a gap to fill — dropping
  more") and the reliable backlog has a dead-link cutoff ("{} MB … the link is dead").
- NCZQ history is the fixed 256 KiB window (§1).
- The game-thread relay queue (§4) lets one peer commit the host to ~128 MB / 8192 messages
  before drop — **bounded** and intentional ("loading or a flood"), but worth noting it is a
  per-peer figure (≈900 MB across the default 7 guests) a flooding member can pin. Not a
  memory-safety bug.

## 8. Fixed-buffer / overflow sweep — negative result (Confirmed)

The one pattern `Reader` cannot stop is `GetBytes(fixedBuf, wireLen)` / a copy of a
wire-controlled length into a fixed stack buffer. Two sweeps of all 9 files:
- receiver functions (those checking the `NCOP` magic `0x4e434f50`) with a variable-length
  copy into an `au/ac/abStack` array → **0**;
- all functions, any `memcpy`/copy-helper into an `au/ac/abStack` array with a variable last
  argument → **12 hits**, all verified non-deserializers (Ghidra stack-cookie scratch,
  `std::string` SSO buffers, a crypto/hex key formatter `180695cf0`, and the script API
  `NightCoopAddonApi` `180934380`).

No wire-length-into-fixed-buffer overflow exists in the parse paths.

## Residual risk / recommended follow-up (honest scope limit)

The ~140 per-message game handlers (MsgTypes 18–227, spread across files `00`–`07`) are
dispatched via a handler table, not an in-pseudocode `switch`, so they cannot be exhaustively
enumerated from the stripped decompile. They are reachable **only** after the validated
session + route gate (authenticated session member, correct role, `from`==transport peer),
and they consume the same fail-safe `Reader`. The overflow sweep (§8) covered them and found
nothing. The one pattern not fully provable from the stripped code is a **count→allocation
DoS**: a handler that reads a `u16/u32` count and calls a vector `reserve/resize`
(`FUN_180052ff0` / `FUN_180054100`) multiplied by an element size *before* the per-element
`Reader` reads fail, without a `Remaining()` cap. The shared code consistently caps such
counts and `EnetGuard` bounds a message to 8 MiB, so the realistic worst case is a bounded
tens-of-MB allocation per message; a multiply-by-element-size blow-up to `bad_alloc` is the
only way this becomes a crash. I found no confirmed instance. Recommended check with symbols:
grep handler bodies for a `reserve/resize` whose argument derives from a `GetU16/GetU32`
without a preceding comparison to `Remaining()`/packet size, and confirm every entity/record
handle read from the wire is resolved through a map/validated lookup rather than an array
index (the Cyberpunk net-id/TweakDBID deref path was not individually traced per handler).

## Reachability summary

Everything in §§3–8 is reachable by an ordinary authenticated session member (host, guest, or
peer) with no extra privilege; §5 is additionally reachable by the hub the client connects to.
The auth boundary (role gating + `from`==transport-peer route check) is intact, so a peer
cannot impersonate another peer or inject host-only messages as a guest.
