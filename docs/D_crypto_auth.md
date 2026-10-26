# NightCoop — crypto / authentication / logic audit (D)

Scope: logic and cryptographic flaws in the shared net-crypto code (compiled into both the
open-source hub and the client DLL) and the client-only glue. Memory safety is out of scope.
Static analysis only. Primary source: `hub/repo/src/{NetCrypto.hpp,NetCrypto.cpp,HubRules.hpp,
HubCookie.hpp,ProtocolCore.hpp}` + Monocypher 4.0.2. Client glue confirmed against
`pseudocode/*.c` strings (`dll/s8.txt`) and report `reports/1_network_session.md`.

Build fact that colours everything below: in `HubRules.hpp` the project-hub **old keys are set**
(`kHubSignKey` L31, `kHubBoxKey` L34) but the **project root is all-zero**
(`kRootKey{}` L109, `kRootKeyBackup{}` L112) and `kSeedHubList=""` (L126). So this build has a
pinned project-hub key but **no root CA, no hub list, no revocation list**.

---

## Findings (ranked)

| # | Severity | Confidence | Area | One line |
|---|----------|-----------|------|----------|
| 1 | High (trust-model) | Confirmed | E2E vs hub | A hub holding the signing key can actively MITM every link through it by signing substituted keys — undetectable. A *passive* hub cannot read. |
| 2 | Medium (operational) | Confirmed | Identity | No-root build → the pinned project-hub key has **no revocation path**; if `kHubSignKey`/`kHubBoxKey` leak, only a new DLL build fixes it. |
| 3 | Medium | Confirmed (documented) | Direct IP | Direct-IP sessions are encrypted but unauthenticated → full network-MITM key substitution. Hybrid direct paths are NOT affected. |
| 4 | Low–Med | Confirmed (documented) | Ban | Kick-ban keyed on a self-generated, unauthenticated 64-bit client id → restart evades; per-session only. |
| 5 | Low | Plausible | Resume | A captured `HubResumeSession` can be replayed within the ±120 s skew window to contend for the session slot after a hub restart (DoS of the host's reclaim). Cannot break E2E — replayer lacks the host key's secret. |
| 6 | Low (def-in-depth) | Confirmed | RNG/tag | Client never rejects an all-zero `session` tag in a Cert; it trusts the hub's RNG. No concrete client-side break. |
| 7 | Low | Confirmed | Punching | Forged `HubAddrSeen` only mis-points hole-punching; the direct link still needs the sealed hello under hub-vouched keys + session tag, so no unauthenticated peer is injected. |

Everything else examined (nonce construction, per-link salt, replay window, strict cert checks,
pinning, root-zero handling, RNG fail-closed paths, constant-time, small-order points, resume-pass
binding, SipHash cookie, box sealing) is **sound** — see §"What is sound".

---

## 1. Can the hub / a network MITM read or tamper? (audit area 1)

**Passive hub: NO (sound).** Link keys come from `DeriveLinkKeys` (NetCrypto.cpp L2412-2428):
`BLAKE2b-512` keyed with the **X25519 shared secret** over `"NightCoop transport 1" | hostKey |
guestKey | hostSalt | guestSalt`. The hub knows neither party's X25519 secret, so it can never
derive the link keys, regardless of the fact that it *signs* the public keys (signing ≠ knowing the
secret). HubPayload is relayed opaquely. A passive/honest-but-curious hub genuinely cannot read.

**Network MITM without the hub key, Vouched hub: NO (sound).** See §2 (strict cert checks).

**Active hub holding the signing key: YES — undetectable active MITM (Finding 1, by design).**
The sole authentication root is the hub's EdDSA signature on peers' keys. The hub generates those
signatures, so a malicious hub can mint a Cert over *its own* MITM key `K` with the correct
`role`, `session` tag, `hubPeer`, and validity, send it in the guest's `CryptoHello`, and run
X25519 with the real guest separately. The host's strict checks (OnHello L2466-2505) all pass
because every field is hub-controlled and the signature verifies under `kHubSignKey`. There is no
out-of-band key confirmation, TOFU, or SAS anywhere (the hybrid direct hello reuses the same
hub-vouched link keys, so it is not an independent channel). **Consequence:** "end to end, the hub
never sees content" is true only for a *passive* hub; the confidentiality of a Vouched session is
exactly as trustworthy as the operator of that hub's signing key. This is inherent to the
hub-as-CA model, not an implementation bug, but it must be stated plainly in the verdict: a
compromise of `kHubSignKey` = silent full MITM of all project-hub sessions.

### Nonce construction (sound)
`Link::Seal` (L2327-2354) / `Link::Open` (L2356-2388): nonce = `counter(8 LE) | dir(1) | zero(15)`,
24-byte XChaCha20-Poly1305. The 9-byte header `kSealMark|counter` is the AEAD associated data, so
the counter is authenticated (a MITM cannot shift the replay window). For a given key the only
varying field is the per-message `counter`; directions use **separate keys** (`m_tx`/`m_rx`) *and*
distinct `dir` bytes, so a nonce cannot repeat across directions. `m_txNext` starts at 1 and `Seal`
refuses at `0` and `UINT64_MAX` (L2332), so overflow is fail-closed (link must reconnect) and no
nonce ever repeats after any failure.

Counter reset to 1 on every `Link::Begin` (L2228) is **safe** because the key is fresh every Begin:
`m_salt` is re-randomised per link (L2242) and feeds `DeriveLinkKeys`, so two links with identical
X25519 keys still get different link keys and never share a counter→nonce.

### Per-link salt rationale (actually enforced — sound)
The header's anti-nonce-reuse argument (NetCrypto.hpp L84-93) is implemented: the host uses one
X25519 pair for all links, but `Begin` generates a fresh random `m_salt` per link and `Derive`
(L2390-2410) passes the host's own salt into `DeriveLinkKeys`. So even though the hub signs *any*
key a guest submits, a guest substituting another guest's public key gets **different** link keys
(different host salt) → no cross-link nonce reuse on the host. The salt from the partner is
unauthenticated, but tampering with it only makes the two sides derive different keys → the link
fails to open (DoS), it cannot force a reuse because the anti-reuse property rides on the *host's
own* locally-random salt.

### Replay window (sound)
`ReplayWindow::Fresh`/`Mark` (L2042-2079): counter 0 rejected; `>m_top` fresh; `m_top-c ≥ 4096`
too-old rejected; else per-bit check. `Mark` slides correctly — on a jump ≥ window it `fill(0)`s,
otherwise it clears exactly the newly-entering slots (whose prior occupants are now outside the
window and rejected by the age test anyway). One window per link/direction, reset per Begin with a
fresh key, so cross-link/cross-path replays can't decrypt. A single window is shared by the hub and
direct paths (same link keys), which is correct — marked counters block replay across paths.

---

## 2. Signature / identity checks (audit area 2)

**Strict link auth (OnHello L2466-2505) — sound.** When a link is strict (project hub, crypto on),
the host/guest requires: own cert verifies under the hub key and matches own key/role/(peer);
partner has a cert; partner cert verifies under the **hub we are talking to** (`HubSign()`, i.e. the
pinned old key / root cert / fingerprinted key — not a build-wide key); `cert.key == sent key`;
`cert.role == partner`; `cert.session == own.session`; `cert.hubPeer` matches the expected peer
(guest-id for the host, 0 for the guest); and freshness within `kCertSkewSec`=300 s. This binds the
partner's key to the exact session+role+peer and blocks a network MITM and cross-session/cross-peer
cert replay. A guest therefore cannot spoof another guest's peer id at the link layer, and the
session-layer route check enforces it at the game layer too (`dll/s8.txt:16818` "game message with
forged route: transport peer …, claimed sender …").

**`JudgeHub`/`PolicyFor`/`Decide`/`Apply` (L1243-1256, 1321-1453, 1891-1939) — sound, fail-closed.**
- `Open` → Unvouched (encrypted, unauthenticated) — the documented IP/own-name case.
- `Pinned` (project hub): root cert path needs a trusted root; with none it falls through to the
  pinned old key → Vouched (sign+box). Correct.
- `Chain` (*.nightcoop.net): requires a root cert; with no root → **Refused** (fail-closed).
- `Fingerprint`: self-cert path (fingerprint must equal `Fingerprint(self.sign)` **and** the
  self-cert must verify under its own key and not be revoked) works without a root. Sound.

**`kRootKey` all-zero does NOT create a bypass (sound).** `TrustedRoots()` (L1006-1016) filters out
zero keys; `IsTrustedRoot` (L1025-1029) additionally rejects a zero key and returns false when the
set is empty; `rootOk` (L1345-1366) gates every root-cert acceptance on `IsTrustedRoot(issuer)`;
`TakeList` (L1059-1069) gates hub-list acceptance the same way. So no attacker can forge a
zero-issuer root cert or list — the all-zero root means "no root", handled as refusal, never as
accept.

**Downgrade / strip-HubIntro (sound).** For the project hub in this (no-root) build,
`Reset` computes `m_needsIntro = false` (L1883) and calls `Decide(nullptr)` immediately, so the
verdict is **Vouched by the pinned key before any HubIntro arrives** — a MITM stripping HubIntro
cannot downgrade it. The pinned box key is used to seal the code (`m_seal`, Apply L1937). DNS
spoofing of `hub.nightcoop.net` to an attacker server still yields policy Pinned (keyed on *name*):
the attacker cannot produce certs under `kHubSignKey`, so links are **Refused** — downgrade attempts
degrade to DoS, never to an authenticated-looking compromise. `kHelloRefuse`/plain-by-timeout paths
(OnHello L2451-2459, Tick L2626-2648, Incoming Waiting L2554-2561) all go to **Refused** under
strict, never silently Plain.

**Name/validity/revocation enforcement.** Name (`Names`), notBefore/notAfter (±`kCertClockSlackSec`
=2 d), and revocation are all checked client-side in `rootOk` (L1354-1362). *But* revocation depends
on a root-signed `HubList`, which is never accepted in a no-root build → **Finding 2**: the pinned
project-hub key cannot be revoked without shipping a new DLL. Operational, medium.

---

## 3. Other spoof/replay vectors (audit area 3)

- **(a) Direct-IP MITM — Finding 3, documented.** `Begin` sets `m_strict = Strict() && viaHub`
  (L2222); direct connections have `viaHub=false` → never strict → certs ignored → classic
  unauthenticated-DH MITM by anyone on-path. Confined to the explicit "Host/Join by IP" mode; the
  UI labels it "Encrypted, not verified". Hybrid hub sessions' direct paths are authenticated (the
  direct hello must open under the existing hub-vouched link keys + session tag;
  `dll/s8.txt:16363-16369`). Severity medium (needs network position, opt-in mode).
- **(b) Kick-ban evasion — Finding 4, documented.** Ban key is the self-generated
  `rand()^clock` 64-bit client id (`dll/s8.txt:16721/16798`); restart → new id → re-admitted;
  ban is per-session only. Weak by design.
- **Guest spoofing another peer id in a payload — blocked.** Host validates claimed `from` ==
  transport peer (`dll/s8.txt:16818`), and link-layer certs bind `hubPeer`. Sound.
- **Resume replay / cookie reuse / HubAddrSeen — Findings 5 and 7** (below / above). No
  authenticated-peer injection results from any of them.

---

## 4. Resume pass & connection cookie (audit area 4)

**Resume pass binding (hub-side JudgeResume + LookAtResume) — sound.** `LookAtResume`
(NetCrypto.cpp L1778-1795): the request is sealed to the hub box (`OpenFromClient`, dir
`kBoxResumeToHub`), the pass inside carries this hub's EdDSA signature (`VerifyResumePass`
L1772-1776), `sameKey` = `pass.hostKey == clientKey`, `sameProtocol`, and times/skew.
`JudgeResume` (HubRules.hpp L1073-1085) orders checks so a stranger learns nothing (Bad → Expired →
Stale → Live → Full). A stranger cannot forge a pass (hub signature) nor resume a live session.

**Finding 5 — resume request replay (low).** The anti-replay is only (i) the ±`kResumeSkewSec`=120 s
check on the host-reported `askedSec` and (ii) the live-session check — there is no per-request
nonce and no binding to the source address. A MITM who captures a host's `HubResumeSession` can
replay the raw bytes within ~120 s after a hub restart to win the race for the session slot and deny
the real host its reclaim. It is **not** a confidentiality/integrity break: the replayed key is the
host's public key, which the hub then signs, but the replayer lacks the host's X25519 secret, so it
cannot derive link keys with any joining guest. Impact = narrow DoS during a restart window.
Client side: the host only stores and re-presents the pass; the binding is validated by the hub, so
there is nothing for the client to mis-validate.

**SipHash connection cookie (HubCookie.hpp L49-108) — sound for its purpose.** Pure anti-slot-
exhaustion for spoofed UDP source addresses. The cookie = SipHash-2-4(secret, ip|port|bucket)
folded to 32 bits, **never zero** (`cookie?cookie:1`), valid for the current + previous 32 s bucket.
It is only ever sent to the real address (`OnDatagram` checks `receivedAddress`), so a source-
spoofer never learns it; a blind forgery is 2⁻³² with no oracle, and a single hit buys one slot —
acceptable for a DoS mitigation. The 16-byte secret never leaves the hub. No replay/skew abuse of
consequence (the window is deliberate, bounded to 64 s).

---

## 5. RNG (audit area 5) — fail-closed where it matters (sound)

`Random` (L340-395): BCryptGenRandom → rand_s fallback (Wine) / getrandom / getentropy, returns
false on hard failure. Call sites handle failure safely:
- `Begin` salt failure → link **Refused** (L2242-2247, fail-closed; plain not allowed through the
  project hub).
- `SealBox`/`SealBytes`/root seal nonce failure → return empty (fail-closed).
- `Local::Reset` X25519 failure → `m_on=false` → the whole connection goes unencrypted *locally*
  (L1852-1857). Through the project hub this is fine: the strict partner **refuses** an unencrypted
  side (OnHello L2451-2456), so the outcome is a failed session, not a silent insecure one. RNG
  failure is not remotely inducible, so there is no network-triggered downgrade.

**Finding 6 (def-in-depth, low).** The "session signature mark is zero" guard is a *hub* log; the
client has no equivalent string (`dll/s8.txt` has none) and OnHello checks `cert.session ==
own.session` but never `!= 0`. If a hub's RNG failed and emitted a zero session tag, the client
would accept it. No concrete client break (certs still need the real hub signature; the per-session
X25519 keys still bind), but rejecting an all-zero tag would be cheap defence-in-depth.

---

## 6. Monocypher usage (audit area 6) — sound

- **Tag / signature verification is constant-time:** all AEAD opens go through `crypto_aead_unlock`
  and all signatures through `crypto_eddsa_check` (Monocypher, constant-time). No hand-rolled MAC or
  tag compare exists.
- **The only secret-dependent comparison is `IsZero` on the X25519 shared secret** (L435-441): it
  OR-accumulates all bytes with **no early-out**, so it is effectively constant-time. Every other
  comparison (`cert.key != …`, `cert.session != …`, fingerprint strings, `memcmp(hostKey,…)` in
  resume, `HubList::Revoked` find) is over **public** values; their early-outs leak nothing secret.
- **Small-order / all-zero points handled:** `Local::Shared` (L1971-1977) and the hub's
  `OpenCode`/`SealCode`/`SealForClient`/`OpenFromClient` (L1739,1755,1804,1821) all run
  `crypto_x25519` then reject an all-zero shared secret via `IsZero` — the recommended Monocypher
  pattern that catches the low-order points. `OnHello` additionally rejects an all-zero partner
  public key (L2460-2464) before deriving.
- **Box sealing** (`SealBox`/`SealBytes` L190-233): fresh 24-byte **random** XChaCha nonce per seal
  (large nonce space, one-shot), with direction+length as associated data so a reply can't pass for
  a request nor one direction for the other. Sound.
- Root key seal uses Argon2id(64 MiB,3) + XChaCha with domain-separated AD binding the public key
  (L794-831) — sound.

---

## What is sound (for the final verdict)

Against a **passive hub** and a **network MITM without the hub key**, the E2E design holds:
keyed-BLAKE2b KDF over a bound transcript; non-repeating XChaCha nonces (per-message counter +
per-direction key + per-link random salt, overflow fail-closed); a correct replay window; strict
EdDSA cert checks binding key↔session↔role↔peer↔time; name-pinning that turns DNS/strip-HubIntro
downgrades into refusals; fail-closed RNG at the security-critical sites; constant-time primitives
and small-order-point rejection; a well-bound resume pass and a fit-for-purpose SipHash cookie.
The all-zero `kRootKey` is handled fail-closed and creates **no** bypass.

## True breaks vs accepted limitations

- **Accepted, documented limitations:** direct-IP MITM (Finding 3) and kick-ban restart-evasion
  (Finding 4). Neither affects authenticated hub play.
- **Inherent trust-model property to surface (Finding 1):** "the hub never sees content" is a
  *passive* guarantee; a hub that holds the signing key can actively MITM undetectably. Pair with
  **Finding 2**: in a no-root build the pinned key is unrevocable without a rebuild — so a leak of
  `kHubSignKey` is catastrophic and unrecoverable in-field.
- **Minor real issues:** resume-request replay DoS window (Finding 5), missing zero-session-tag
  guard (Finding 6), forged-HubAddrSeen punch misdirection (Finding 7).
- **No nonce-reuse, key-substitution-on-vouched-links, downgrade-to-authenticated, or root-bypass
  break was found.**
