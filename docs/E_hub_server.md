# NightCoop HUB SERVER — defensive security audit (E)

Source: commit `6b694a6` "0.1.0". Scope: `tools/hub/main.cpp`, `src/HubServer.*`, `src/NetCrypto.*`,
`src/ProtocolCore.hpp`, `src/HubRules.hpp`, `src/HubCookie.hpp`, `src/EnetGuard.hpp`. Monocypher 4.0.2 primitive
assumed correct (usage audited). ENet (5a9c537f) reasoned about, not present.

Threat model: unauthenticated remote attacker sending arbitrary / source-spoofed UDP; plus a malicious client that
completes the ENet handshake. ~300 players, 1 core / 512 MB; must not be crashable, trivially DoS-able, or leak/corrupt
one session's traffic into another.

## Verdict

This is an unusually **defensive, well-engineered** codebase. I found **no confirmed memory-safety bug, no
cross-session traffic leak, and no remotely-triggerable crash.** All the hard parts the prompt asked about — the
amplification bound, cookie forgery/replay, the Reader, the stale-ENet-slot fix, resume hijack/replay, routing
isolation, guard integer accounting — are correct. The findings below are **resource-exhaustion / DoS ceilings and
reflection**, mostly Low–Medium, all bounded, several operator-tunable. The headline is #1 (outbound queue has no
aggregate pool) and #2 (connectionless flood not covered by the per-turn budget).

## Findings (most severe first)

| # | Sev | File:line | Flaw | Reach | Confidence |
|---|-----|-----------|------|-------|-----------|
| 1 | Medium | HubServer.cpp:106-139,539; HubServer.hpp:215 | Outbound ENet queue is capped **per-recipient only** (`maxQueuedBytes`); no aggregate/per-thread pool. `maxClients × maxQueuedBytes` (default 64×32 MiB = **2 GiB**) exceeds the 512 MiB–1 GiB target → OOM | authed client(s) | Plausible |
| 2 | Medium | HubServer.cpp:542-588,694-745; HubServer.hpp:218 | Per-turn `serviceBudgetMs` guards only the **event loop**, not the intercept path. A connectionless flood (SipHash + `sendto` per datagram, 4 MiB socket buffer drained per turn) can pin the entry thread | unauth remote | Plausible |
| 3 | Low | HubServer.cpp:710,725 | Sub-1× UDP **reflection**: cookie-tell (12 B) and loc-tell are sent to the (spoofable) source address. De-amplifying (reply ≤ request) so useless for amplification, but the hub emits a packet to any spoofed victim per ask | unauth remote | Confirmed |
| 4 | Low | HubServer.hpp:353; HubServer.cpp:1003-1022,1356 | `Session::nextId` (u32) wrap → a guest assigned id 0 would be treated as **host** in `Route` (impersonation). Needs ~2³² joins in one session; resume path is clamped (`ResumeNextId` ≤ 2²⁴) so it cannot be forced | authed client | Plausible (not practically reachable) |
| 5 | Low | HubServer.cpp:906-944; :1254-1281 | Sealed-join / resume cost an X25519 each; the crypto runs **before** the per-address fail counter is incremented, so an attacker pays up to `joinFailsPerMinute` X25519 ops / address / minute. Bounded, but the gate is post-crypto | authed-ish | Confirmed |

### 1 — Outbound queue: per-recipient cap, no aggregate pool (Medium)
`SendTo` (HubServer.cpp:115-127) tracks bytes queued to each recipient in `m_queued[index]` and closes a recipient
once its own counter would exceed `maxQueuedBytes`. There is **no sum/pool check** across recipients, unlike the
inbound `EnetGuard` which has `budget.pool`/`guardPoolBytes` (HubServer.cpp:400). Peak per recipient ≈ `maxQueuedBytes`
(the packet that would exceed it is dropped, not queued), so the aggregate ceiling is `maxClients × maxQueuedBytes`.
With defaults (64 slots × 32 MiB) that is ~2 GiB, far above the stated 512 MiB–1 GiB budget. Attack: one malicious
host + colluding guest bots that connect but never ACK; the host relays up to 4×8 MiB payloads to each guest
(inbound passes `EnetGuard` because delivered-in-order bytes are not "waiting"), so ~16 guests × 32 MiB ≈ 512 MiB
transient from a single session; filling all 64 slots → OOM on a 512 MiB box. Fix: give the outbound queue a global /
per-thread pool mirroring `EnetGuard` (e.g. sum of `m_queued` capped), and/or lower the default `maxQueuedBytes` so
`maxClients × maxQueuedBytes` fits the memory target.

### 2 — Connectionless flood not bounded by the service budget (Medium)
`serviceBudgetMs` only breaks the `while (result>0)` event loop (HubServer.cpp:576). The `Intercept` → `OnDatagram`
work (loc-ask / cookie-ask parse + `enet_socket_send` reply, or `EnetGuard::Judge`) runs inside ENet's receive drain,
which empties the socket buffer (default `socketReceiveBytes` 4 MiB → ~170k 24-byte asks). A sustained
`kAskMagic`/`kLocAskMagic` flood forces a SipHash + a `sendto` syscall per datagram, which can keep the entry thread
(thread 0) busy for the whole turn, delaying real traffic and new joins. Mitigations that make this only Medium: cost
per packet is cheap (SipHash, precomputed signatures — **no asymmetric crypto on the spoofable path**), the kernel
socket buffer throttles, and sessions live on other shard threads/ports that keep relaying while the entry port is
pinned. Consider rate-limiting intercept replies or counting intercept time toward the budget.

### 4 / 5 — detail
#4: `const uint32_t id = session.nextId++;` then `Route` treats `aFromId==0` as the host (HubServer.cpp:1003). If
`nextId` ever wraps to 0 a guest becomes "host". Unreachable in practice (join requires a full handshake; `maxGuests`
forces churn; the only attacker-controlled write to `nextId` is `HubResumeSession`, clamped to [1, 2²⁴] by
`ResumeNextId`). Still worth a one-line guard (`if (nextId==0) nextId=1`) or rejecting wrap.
#5: In `Resume`, `createsPerMinute` is checked first but only counts *successful* resumes, so a stream of bad passes
passes that gate and reaches `LookAtResume` (one X25519) before `AddJoinFail` increments; same shape in the sealed-join
path. Net cost is still bounded by `joinFailsPerMinute` (12) per address because the counter is shared and closes the
connection past the limit — so this is a hardening note, not a vuln.

## Mitigations confirmed correct (credit)

- **Reader (`ProtocolCore.hpp:257-361`)** — every read bounds-checks `m_pos + size > m_size`; on failure it latches
  `m_ok=false`, zero-fills, and all later reads return 0. Attacker sizes are u8/u16/u32, so `m_pos + size` cannot
  overflow `size_t` on 64-bit. `GetString` re-checks before copy. Safe.
- **Amplification bound holds for every connectionless branch.** Cookie: ask ≥ 24 B (`kAskSize`), reply fixed 12 B.
  Locations: `MakeLocTell(tell, aSize)` (HubRules.hpp:849-859) drops the list if it won't fit and returns `{}` if even
  the keyed status answer exceeds the request size → the hub sends nothing rather than a larger reply. `HubIntro` /
  `HubAddrQuery` are **post-handshake** (source-validated reliable ENet), not a spoofable amplification vector.
- **Cookie design (`HubCookie.hpp`)** — SipHash-2-4 over IP|port|bucket, current+previous bucket (32–64 s), never
  zero, reply sent only to the real source. Forged addresses can't learn their cookie; replay is address-bound. The
  `Pressure` fallback (half the slots may be taken by cookieless CONNECTs under flood) is documented and
  operator-overridable (`--cookie always`).
- **Stale ENet-slot fix is complete.** Repeated `HubCreateSession`/`HubJoinSession`/`HubResumeSession` from a peer
  already in `m_clients` are ignored (HubServer.cpp:1129, 1242, 882). `DropClient` removes the peer from both
  `session.guests` and `m_clients`; a departing host erases the whole session and moves guests to `m_idle`. ENet's
  DISCONNECT-before-slot-reuse ordering is relied on correctly; `CloseClient` uses `disconnect_now` (no late event).
- **Routing isolation (`Route`, HubServer.cpp:991-1022)** — a guest (`fromId!=0`) can only reach the host; guest→guest
  and guest-broadcast are dropped, so a guest cannot forge host messages (`Reject`/`Welcome`) to another guest. Host
  `to` is looked up only within its own `session.guests`. No cross-session path.
- **`EnetGuard` inbound accounting** — mirrors ENet's parse without writing; per-peer + guaranteed-share + shared pool;
  `m_poolUsed` invariant maintained by `SetHeld` so `m_poolUsed - Above(slot.held)` cannot underflow; slot index is
  bounded by `peerCount`; worst case fails safe (drop), never crashes. Pre-auth connections get no fragments.
- **Crypto glue** — `SealBox`/`OpenBox`/`SealBytes`/`OpenBytes` bound all lengths, bind direction+length in AEAD
  associated data (answer can't pass for request, nor one box-direction for another), cap sealed input at 512 B
  (`ReadClientExt`) / 1024 B (`kMaxBoxBytes`). `HubCert::Read`/`HubList::Read`/`Cert::Read`/`ResumePass::Read` are
  fully bounds-checked with explicit `end = size-64`, count caps, and `at != end` trailing-byte rejection.
- **Resume cannot hijack or replay a session.** `JudgeResume` requires opened-under-the-named-key + this hub's
  signature + same key + same protocol + not expired + within ±120 s clock skew + code not live. The sealed request
  rides inside the established transport encryption, so an on-path attacker never sees the blob; replay within the
  skew window is refused as `Live` once the code is taken. Clock-skew window is tight and two-sided.
- **`MakeCode`** uses `std::random_device` per character (not mt19937), with a look-alike-free alphabet; collisions
  re-rolled against the shared shard directory. Codes from the network are `ValidCode`-filtered before any lookup or
  log line.
- **Key-file handling (`main.cpp`)** — secrets written only to a new `O_EXCL`/`0600` file with `fchmod`+`fsync`,
  never overwritten; wide-permission warning on load; 4 KiB read cap; buffers wiped; `--sign-key-credential` name is
  checked for path traversal; all numeric args `std::clamp`ed; shard count clamped 1..64. `BuildIntro`/`BuildLocations`
  treat a malicious/half-written file as "keep previous / run without it", never crashing.

## Notes / non-issues checked
- No asymmetric crypto on the pre-connection (spoofable) path — the key anti-DoS property, and it holds.
- `PacketGone` underflow-safe (`*count -= min(count,len)`); `m_queued` storage is stable for the host's lifetime and
  cleared only after `enet_host_destroy` frees packets. No UAF across Service turns.
- `HubAddressBook` growth is swept (>1024 → drop >60 s entries); keyed by real (connected) peer address, so spoofing
  can't bloat it.
- `CloseIdle`/`DropClient`/`CloseOverflow` all snapshot-then-mutate or operate on a different map while iterating; the
  `CloseOverflow` round loop is bounded by `peerCount`. No iterator invalidation.
