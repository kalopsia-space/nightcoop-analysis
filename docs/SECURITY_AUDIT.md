# NightCoop — security audit

Static audit of the client `NightCoop.dll` 0.1.0-beta.1 (build `a7c537d`) and the open-source hub server ([Twenfys/nightcoop-hub](https://github.com/Twenfys/nightcoop-hub) @ `6b694a6`). Nothing was run. All inputs (strings, pseudocode, config) were treated as data. Per-surface detail is in [`A_net_deserializers.md`](A_net_deserializers.md), [`B_save_splice_loot.md`](B_save_splice_loot.md), [`C_files_paths.md`](C_files_paths.md), [`D_crypto_auth.md`](D_crypto_auth.md), [`E_hub_server.md`](E_hub_server.md).

## Verdict

**No critical or high-severity issue, and no memory-safety vulnerability, was found on any surface.** This is a security-conscious codebase: the wire readers are bounds-checked and fail safe, every file path is built from fixed names, the cryptography is assembled correctly, and the hub — the one internet-facing component — is the most hardened part of all.

The real issues are an **integrity flaw in item trading** (a modified client can dupe/create items), a **structural trust concentration** in the hub signing key, a handful of **bounded denial-of-service ceilings**, and the **two already-known limitations** (unauthenticated direct-IP play; evadable kick-bans). None of these let an attacker run code on your machine or read your encrypted game traffic.

Scope caveat: static analysis of decompiler output, not source. The client dispatches ~140 game-message handlers through a table that can't be fully enumerated from the stripped binary; they sit behind the validated session/role gate and use the fail-safe reader, but each was not traced line by line.

## Findings, ranked

| # | Severity | Component | Issue | Reachability | Confidence |
|---|----------|-----------|-------|--------------|------------|
| 1 | Medium | Client — item trade | Item dupe / arbitrary-item creation: host grants on the sender's self-reported debit and sender-chosen item id; possession + unique/quest checks are client-side only | Modified client + a 2nd colluding account | Confirmed |
| 2 | Medium | Trust model | A hub holding its signing key can silently MITM every session it vouches (hub acts as the CA; no out-of-band key confirmation) | Hub operator, or anyone who leaks a hub key | Confirmed (by design) |
| 3 | Medium | Hub server | Outbound ENet queue capped per-recipient (32 MiB) but not globally → up to ~2 GiB, over the 512 MiB–1 GiB budget → OOM | Authed client(s) / non-acking bots | Plausible |
| 4 | Medium | Hub server | `serviceBudgetMs` doesn't cover the connectionless intercept path → a datagram flood can pin the entry thread | Unauth remote | Plausible |
| 5 | Medium | Trust model | This build has no root CA / hub list (`kRootKey` all-zero), so the pinned project-hub key has **no revocation path**; a key leak needs a new DLL to fix | Operational | Confirmed |
| 6 | Low–Med | Client — crypto | Direct-IP sessions encrypted but **unauthenticated** → network MITM via key substitution (hub direct paths are authenticated) | Opt-in IP play on a hostile network | Confirmed (known) |
| 7 | Low–Med | Client | Kick-ban keyed on a self-generated client id → restart to evade; per-session | Any kicked player | Confirmed (known) |
| 8 | Low | Client — loot | A malicious NPC-owner can misreport mirror loot / grant arbitrary records for its own mirrors | Modified client | Plausible |
| 9 | Low | Client — stats | TeamBuild "best of everybody" trusts peer-reported build/level for shared skill checks → skill-check cheat | Modified client | Confirmed (by design) |
| 10 | Low | Client / hub | Resource growth: item-offer spam grows the host ledger; big game-message relay backlog (~128 MB/peer); replayed resume request can contend for a session slot after a hub restart | Session member | Plausible/Confirmed |
| 11 | Low | Client — logging | Network/pasted strings logged verbatim → newline/ANSI injection into the log file (not a format-string bug; `{}` is type-safe) | Malicious hub (reason) / user paste | Confirmed |
| 12 | Low | Hub server | Sub-1× UDP reflection off the cookie/location replies (de-amplifying, so useless for amplification) | Unauth remote | Confirmed |
| 13 | Low | Hub server | `Session::nextId` u32 wrap could assign guest id 0 (= host) — needs ~2³² joins; resume path clamps to 2²⁴, so not practically reachable | Authed client | Plausible (not reachable) |

## The two that matter most

### 1. Item dupe / arbitrary-item creation (Medium, confirmed)

Item trades use a host ledger (offer → debit → grant → ack). But the host can't see remote inventories, so it delegates the debit to the **sender's own client** and grants on the sender's self-reported success flag and sender-chosen `TweakDBID`. The host gate (`FUN_1803610f0`) enforces host role, a valid non-self recipient, item id ≠ 0, quantity 1–9999, and binds the giver id to the sending connection — but performs **no possession check and no unique/quest-item refusal** (those run only client-side, in `RemoveLocal`/`GiveLocal`). I verified the gate directly: it records the transfer and proceeds with none of those checks.

A modified giver can therefore report a debit it never performed, for any item id and quantity up to 9999, and the host will grant it to a colluding recipient (self-grant is blocked, so a second account is needed). Granted items persist into the campaign on return. Impact is economy/integrity only — no memory corruption.

**Fix:** validate possession and tradeable/unique status **host-side** before granting; log debit/grant mismatches.

### 2. The hub is a certificate authority (Medium, structural)

The "the hub never sees your game" property is a *passive* guarantee. Because the hub signs each peer's session key, a hub that holds its signing key can mint a certificate over its **own** substituted key with the correct role/session/peer/validity, and both sides' strict checks pass — a silent full MITM of any session it vouches. There is no out-of-band key confirmation. So the confidentiality of a verified session equals trust in that hub's key operator, and a leak of the official `kHubSignKey` would allow silent interception until a new DLL ships (no revocation in this build — finding 5).

This is inherent to the hub-as-CA design, not a bug, but it should be stated plainly: **play through hubs whose operator you trust.** For the official hub that's the project; for a self-hosted hub it's whoever runs it.

## What is demonstrably sound (credit where due)

- **Wire parsing.** The shared `proto::Reader` bounds-checks every read, latches a failure, and zero-fills — the client and hub share it. Two mechanical sweeps of all 9 pseudocode files for the one bug the reader can't stop (a wire-controlled length copied into a fixed buffer) returned zero real hits.
- **Both decompressors.** The save-file LZ4 (`FUN_1800bf2d0`) and the live `wire_zip`/NCZQ decoder check every literal, match and offset against both source and destination bounds and cap their output. These are the usual home of save/stream RCEs; here they're clean.
- **The save container and node tree.** VASC/FZLC/EDON parsing caps chunk count (≤512), per-chunk and total decompressed size, node count (≤1,000,000) and name length (≤512), and validates every node's offset+size against the buffer. The ~249 inner node readers re-check each inner count/offset against the field window.
- **File paths.** Every path is a fixed data/plugin directory plus a string literal or a numeric counter. No peer nickname, session code or save content ever becomes a path component — no traversal, no arbitrary write. Session codes are validated to the 6/7-char alphabet.
- **No format-string primitive.** The mod uses C++ `std::format` with compile-time literal format strings; there are no `printf`-family calls with a network string as the format. (Independently verified.)
- **Crypto glue.** Per-message counter + per-direction key + per-link random salt → no nonce reuse (the documented anti-reuse rationale is actually enforced); correct sliding replay window; counter overflow fails closed; certificates bind key ↔ session ↔ role ↔ peer ↔ time; downgrade attempts (strip HubIntro, DNS spoof) become refusals because the project hub is decided from the pinned key first; all-zero root key fails closed with no bypass; RNG failure fails closed where it matters; Monocypher tag/signature compares are constant-time and small-order/zero points are rejected.
- **Signed blobs verified before trust.** `hubs.ncl` / location lists are parsed with bounded readers but not acted upon until the EdDSA signature against a trusted root passes.
- **The hub server.** No memory-safety bug, no cross-session traffic leak, no remotely triggerable crash. The amplification bound holds on every connectionless branch (reply ≤ request), connection cookies resist forgery and replay and are address-bound, routing is isolated (a guest can't forge "from host" or reach another session), the stale-ENet-slot reuse bug is fixed, resume passes can't be forged or used to hijack a live session, and key files are created with `O_EXCL`/`0600`. Its findings are DoS ceilings only.

## Recommended fixes, by priority

1. **Item trade (finding 1):** add host-side possession and tradeable/unique validation; log mismatches. This is the one issue that affects honest players sharing a session.
2. **Hub key custody (findings 2, 5):** document the trust model for players; plan a root-CA + revocation path (the code already supports it — `kRootKey` is just unset in this build) so a leaked hub key can be revoked without a client rebuild.
3. **Hub DoS (findings 3, 4):** give the outbound queue a global/per-thread pool like the inbound `EnetGuard` (or lower `maxQueuedBytes` so `maxClients × maxQueuedBytes` fits the memory budget), and rate-limit or budget the connectionless intercept path.
4. **Harden the known limits (6, 7):** warn before loading a save from / joining a direct-IP host you haven't played with; consider binding kick-bans to something sturdier than a self-generated id.
5. **Lower-priority (8–13):** owner-reported loot validation, per-peer caps on offers/ledger entries, sanitising network strings before logging, and a `nextId` wrap guard.

## Residual / not fully cleared

- The ~140 individual game-message handlers: a bounded count→allocation DoS inside one can't be ruled out from the stripped decompile (the shared code caps counts and messages are limited to 8 MiB, so the realistic worst case is a bounded tens-of-MB allocation). If symbols become available, grep handler bodies for `reserve`/`resize` sized from a wire `GetU16`/`GetU32` without a `Remaining()` check, and confirm every wire-read entity/record handle is resolved through a validated map lookup rather than an array index.
- The per-node content parsers were judged from the 12 largest readers plus two automated sweeps, not a line-by-line read of all 249.
- The game's own CDPR save loader receives the spliced save and is attacker-reachable, but it's out of scope and not the mod author's code.
