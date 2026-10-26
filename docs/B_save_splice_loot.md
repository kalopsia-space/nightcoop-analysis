# Audit B — Save Splice, Transfer Framing, Loot Ledger

Defensive static-only audit of NightCoop (Cyberpunk 2077 co-op mod, RED4ext DLL).
Threat model: a malicious **host** sends a crafted `sav.dat`/world messages to a joining **guest**;
a malicious **guest** sends crafted world/item/loot messages to the **host**. No auth gate on the bytes.

Scope covered: (1) node-content parsers + splice (`SpliceWorld`/`AdoptSession`/`MergeCampaign`, `nc::savefile`),
(2) `sav.dat` transfer framing (WorldWant/WorldFile/WorldStatus/WorldReload), (3) guest-side splice→write→load
path building, (4) item/loot ledger integrity, (5) TeamBuild/BuildStats.

Already cleared per brief and not re-audited: FZLC container `FUN_1800bf580`, LZ4 `FUN_1800bf2d0`,
EDON node-table reader (count ≤1e6, name ≤512, each node offset+size validated in-buffer). This audit starts above those.

Pseudocode: `/home/kalopsia/nightcoop-re/nightcoop-analysis/pseudocode/*.c`.
Key load-bearing claims below were independently re-read and verified against the decompiled code (marked **[verified]**).

---

## Findings (most severe first)

| # | Severity | Confidence | Function(s) | Issue |
|---|----------|-----------|-------------|-------|
| 1 | **Medium** | Confirmed | `FUN_1803610f0`, `FUN_180361550`, `FUN_180361fa0`, `FUN_1803633d0`, `FUN_180362ca0` | Item **dupe / arbitrary-item injection**: possession + unique/quest refusal are client-side only; host grants on sender's self-reported debit success and sender-chosen item id. |
| 2 | Low | Confirmed | `FUN_180674fb0`, `FUN_180694780`, `FUN_18069a7a0` | Bounded RAM/disk **DoS**: a host can force a guest to allocate+zero-fill and write up to ~128 MiB (×2 across reassembly + write buffers). Transient; 128 MiB cap is enforced. |
| 3 | Low | Plausible | `FUN_180362ca0` + ledger maps `DAT_181f12af8`/`DAT_181f12b20`/`DAT_181f12b60` | Unbounded ledger/dedup-set growth: a guest spams Offer(38); no per-peer transaction cap observed → memory-growth DoS on the host. |
| 4 | Low | Plausible | WorldLoot `180368200…180382a70`, `FUN_18036fca0` | WorldLoot owner-authority is **per-NPC/distributed**, not host-only. A malicious owner can misreport its mirror loot or grant arbitrary item records to peers looting its mirrors. Gameplay desync; impact confined to attacker's mirrors. |
| 5 | Low | Confirmed (by-design) | `FUN_180754f30` (`FUN_1807543b0` = install only) | TeamBuild "best of everybody" trusts peer-reported build/level/street-cred for shared skill checks → skill-check cheat. Values used in max/compare only, never as index or size. |

**No Critical or High finding.** The parser, transfer-framing, path-building, and loot-routing surfaces are deliberately
written as if the peer is adversarial and held up to scrutiny.

---

## Finding 1 — Item dupe / arbitrary-item injection (Medium, Confirmed)

**Where.** LootSync handshake Offer(38)→Debit(39)→Grant(40)→Ack(41).
- Host offer gate `FUN_1803610f0`; giver entry `FUN_180361fa0` ("inventory: transfer {:#x} requested for peer {}").
- Sender debit `FUN_180361550` / `RemoveLocal` `FUN_1803633d0` ("RemoveItem said {}, {} -> {}").
- Host ledger `FUN_180362ca0` ("inventory: host: transfer {:#x} complete").
- Recipient grant apply `FUN_180362920` → `GiveLocal` `FUN_1803626f0` (GiveItem).

**The gap.** The host arbitrates *routing* but cannot inspect a remote guest's inventory, so it **delegates the
debit to the sender's own client** and sends the Grant only after the sender self-reports debit success. Two things
are trusted from the (potentially modified) sender:
1. the **debit-success flag** reported by the sender (`ItemTransferStatus`, byte `param_2[9]`), and
2. the **item record (TweakDBID)** the sender chose at offer time (`param_2[2]`).

The unique/quest-item refusal and the "do you actually own this" check both live on the sender's client
(giver entry `FUN_180361fa0` / `RemoveLocal`), **not on the host**. A modified sender reports debit success without
removing anything and names an arbitrary item id; the host then grants that item to the recipient. Net result: an
item is **created** (dupe) and can be an **arbitrary record** (e.g. an iconic/legendary never owned), quantity up to 9999.

**Verified host-side offer gate** `FUN_1803610f0` (lines 165665-165668) — what the host *does* enforce:
```
if (((((*(int *)(lVar3 + 0x24) == 1)          // we are the host
  && (*param_2 != 0))                          // tx id != 0
  && ((uint)param_2[1] != 0xffffffff))         // recipient valid
  && ((param_2[2] != 0 && ((int)param_2[4] - 1U < 9999))))  // item!=0, qty in [1,9999]
  && (((uint)param_2[1] != param_1             // recipient != sender (no self-grant)
  && ((cVar2 = FUN_180363000(), cVar2 != '\0'
  && (*param_2 >> 0x20 == (ulonglong)param_1))))))  // tx-high == sender id (no impersonation)
```
These block zero/negative/overflow quantity, self-grant, and giver-id spoofing — but there is **no possession check
and no uniqueness/tradeable check** on the host.

**Precondition / reachability.** Self-grant is blocked (recipient≠sender), so the attacker needs a **second or
colluding account** as recipient. Two modified clients on the normal co-op channel → reliable dupe / arbitrary-item
grant. Granted items persist into the campaign through the return/splice merge. No RCE; integrity/economy/quest-state only.

**Note on honest path.** On an *unmodified* sender, `RemoveLocal` `FUN_1803633d0` verifies local count ≥ qty and that
the removed delta equals qty before reporting success, so a *failed* grant loses the item rather than duping it. The
bug is specifically that this check is on the attacker-controlled side.

**Fix.** Validate possession and tradeable/unique-ness **host-side** (TweakDB tag check against the sender's
server-visible inventory where available), rate-limit and log debit/grant mismatches.

---

## Finding 2 — Bounded transfer RAM/disk DoS (Low, Confirmed)

The host→guest `sav.dat` is sent as a **properly bounds-checked chunk stream**, and there IS a total-size cap, so this
is bounded, not unbounded.

**Verified cap** in WorldFile chunk handler `FUN_180674fb0` (lines 51506-51508):
```
if (((((*param_1 != 0) && ((byte)(cVar8 - 1U) < 2)) && ((byte)(cVar10 - 1U) < 5)) &&
    ((param_1[2] - 1U < 0x8000000 && (uVar2 < 0x8001)))) &&       // totalSize<=128MiB, chunkLen<=32KiB
    (((uint)param_1[6] + uVar5 <= (ulonglong)(uint)param_1[2]     // offset+chunkLen <= totalSize
      && (uVar5 <= param_2[1] - uVar1)) ...                       // chunkLen <= remaining msg bytes
```
Every field read in this handler is preceded by a cursor bound check (`if ((ulonglong)param_2[1] < uVar1) goto ...`),
and the payload copy at line 51518 (`FUN_180a2c510(uVar7, param_2[2]+*param_2, uVar2)`) is gated by
`param_2[2] + uVar5 <= param_2[1]` at 51517. Cross-chunk consistency (totalSize + playthrough) and
`offset+chunkLen ≤ buffer` are re-checked in `FUN_180694780` before the write.

**Residual DoS.** A malicious host can still declare `totalSize` near 128 MiB and make the joining guest allocate +
zero-fill that buffer (reassembly) and then write the full buffer to disk via `FUN_18069a7a0`. `FUN_18069a7a0`
itself has **no** cap — it writes `param_3` bytes in a 16 MiB chunk loop:
```
for (; bVar3 = true, param_3 != 0; param_3 = param_3 - uVar9) {  // line 83763
  uVar9 = param_3 & 0xffffffff;
  if (0x1000000 < param_3) uVar9 = 0x1000000;                    // 16 MiB chunk
  WriteFile(hFile, param_2, (DWORD)uVar9, &local_84, 0);
}
... MoveFileExW(pWVar7, param_1, 9);                             // atomic rename into place
```
— but the buffer reaching it is bounded to 128 MiB upstream, so the worst case is ~128 MiB RAM + ~128 MiB transient
disk per transfer (fork estimate ~2×128 MiB counting reassembly + write buffers). Transient and the guest opted into
the host and can disconnect. **Severity Low.** Optional hardening: lower the WorldFile cap toward a realistic
save ceiling (a real save is a few MiB; 128 MiB is generous) and bound disk use of `.nightcoop.tmp`/campaign-copy.

> Reconciliation note: an earlier pass flagged this as "no cap / up to ~1 GB (Medium)" by reading only the uncapped
> `FUN_18069a7a0`. The 128 MiB cap in `FUN_180674fb0` (verified above) makes the correct rating **Low**.

---

## Finding 3 — Unbounded ledger growth (Low, Plausible)

Host transaction ledger map `DAT_181f12af8` and sender/recipient dedup sets (`DAT_181f12b20`, `DAT_181f12b60`) grow
one entry per transaction in `FUN_180362ca0`; no per-peer transaction cap was observed. A guest spamming
ItemTransferOffer(38) can grow host memory. Memory-growth DoS only; no corruption. Fix: per-peer rate/entry cap and
TTL eviction of completed/abandoned transactions.

---

## Finding 4 — WorldLoot distributed owner-authority (Low, Plausible)

WorldLoot is **owner-authoritative per NPC**, not host-only. The owning client arbitrates takes from its mirror drops
(`FUN_18036fca0`: "granted" / "denied, it is not here any more") and takers trust the owner's `LootTakeResult(44)`.
A malicious owner can therefore grant item records of its choosing to peers who loot *its* mirrors, or misreport
"already taken". Impact is confined to players looting the attacker's mirrors; arbitration is serial on the owner's
game thread, so no cross-mirror double-grant. Gameplay desync, not memory safety.

---

## Finding 5 — TeamBuild trusts peer stats (Low, Confirmed by-design)

`FUN_180754f30` (BuildStats) implements "checks of our V's build count the best of everybody in the host's world"
(switch `build_checks_any`, default on) by aggregating peer-reported build score / level / street-cred into a
max/compare for shared attribute checks. A peer can inflate its reported score to pass skill checks for the group —
a gameplay cheat, no security impact. The peer values are only compared/maxed, **never used as an array index or
allocation size**. `FUN_1807543b0` is just the RTTI hook install (`RPGManager.GetBuildScore`), no net parsing.

---

## Clean surfaces (with evidence)

**Scope 1 — node-content parsers & splice: clean to examined depth; no memory-safety bug.**
- The `nc::savefile` readers (range `1800c0c50…1800e7500`, ~249 functions) navigate the already-validated EDON node
  tree via name lookups (`FUN_1800ccec0` find-child-by-name, `FUN_1800cb010`, `FUN_1800ca960`, `FUN_1800ccf80`) and
  re-check every inner count/offset against the pre-validated field-window `size`:
  - **[verified]** `FUN_1800ca960` line 167039: `if (uVar12 + uVar17 * 4 + 4 <= (ulonglong)local_c8[1])`
    (offset + count*4 + 4 ≤ fieldSize), preceded by `if ((ulonglong)local_c8[1] < uVar12 + 4)` at 167028, with vector
    growth overflow guards at 167056 (`0x3fffffffffffffff - (uVar5>>1) < uVar5`) and 167076 (`uVar5 + 0x27 <= uVar5`).
  - Root-descriptor check "the root's descriptors run past it" → `count*8+2 <= size`; blob-size strict equality in the
    stat/character readers `FUN_1800e3220`/`FUN_1800e4ca0` (`*(uint*)(blob+4)+8 != uVar` → reject).
- Two automated sweeps over the range found **zero** raw-length `memcpy`/`memmove`/`memset` (copies use container
  `end−begin` sizes = safe heap growth) and **zero** wire-value-indexed fixed stack arrays.
- The fastTravel reader `FUN_1800d0710` and NodeRef handling operate on the parsed tree, and handle a missing node
  with an explicit error ("the session's save has no FastTravelSystem", "our campaign's FastTravelSystem: ...") rather
  than a null deref.
- `SpliceWorld` `FUN_180650940` (orchestrator, 3045 lines, 126 callees) / `AdoptSession`+`MergeCampaign`
  (`FUN_1807146c0`/`FUN_18071b510`/`FUN_180725d40`) delegate to these readers and gate on parse status
  ("the spliced save does not parse: "). No count-from-host-save sizes a guest-side fixed array.
  Caveat: the 12 largest parsers were read in full; smaller helpers were sampled, with uniform discipline.

**Scope 2 — transfer framing structure: clean, Confirmed.** See Finding 2 — `FUN_180674fb0`/`FUN_180694780` fully
bounds-check totalSize (≤128 MiB), chunkLen (≤32 KiB), offset+len ≤ totalSize, and len ≤ remaining message, with
cursor bounds on every field read. World-handoff control messages are framed with a magic (`0x4e434f50` "NCOP") and
length guards.

**Scope 3 — path building: clean, Confirmed.** Every guest-side write path is a fixed literal or mod-generated
counter: `"ManualSave-"` + a local integer, `"host-world.dat"`/`.json`, `"delta.bin"`, `"state.txt"`, `"times.txt"`,
`"copy.txt"`, `"sav.dat"`, `".nightcoop.tmp"`, and the `MoveFileExW` target in `FUN_18069a7a0`. **No** path component
is taken from save contents, peer nickname, session code, or any wire string → no traversal / arbitrary-write / load
of attacker-chosen paths. Cloud download is header-gated (`FUN_1806a5880`: "the downloaded sav.dat is not a save of
this game version (no VASC/FZLC header)").

**Scope 4 — loot routing authority: sound, non-forgeable.**
- **[verified]** Debit(0x27)/Grant(0x28) are honored only when the source peer id == 0 (host) and the local node is a
  guest — `FUN_180361b60`/`FUN_180361550` (`if ((param_1==0) && (*(int*)(FUN_1800a6b20()+0x24)!=1))`). A guest cannot
  forge a host-origin command to another guest.
- **[verified]** Offer gate `FUN_1803610f0` binds giver to the authenticated transport peer id
  (`*param_2 >> 0x20 == param_1`), requires host role, non-self valid recipient, item≠0, qty∈[1,9999] — see Finding 1.
- Grant apply `FUN_180362920` runs only if the message recipient id == own id. The host ledger `FUN_180362ca0` is a
  per-tx state machine keyed on the full 8-byte tx id and verifies the reporting peer is the expected sender/recipient,
  so a third peer cannot advance another's transaction. Tx-id low bits are peer-chosen but high dword is forced to the
  sender id; dedup prevents replay.
- The residual integrity gap is Finding 1 (client-side possession/uniqueness), not a routing/forgery flaw.
- A `net_guard`-family layer additionally validates npc/combat/vehicle messages (`FUN_1803378d0`, `FUN_180322410`).

---

## Cross-reference (corroboration, out of primary scope)

The reconstructed **hub/relay** server source in the session scratchpad (`scratchpad/hub/repo/src/EnetGuard.hpp`) documents
a project-wide receive cap `kMaxMessage = 8 MiB` ("the largest message any receiver accepts") enforced before ENet
allocates. This is the separate relay component, not the client DLL, but it corroborates that the project designs around
a bounded message size; the DLL's own 128 MiB WorldFile cap (Finding 2) is the authoritative client-side bound.

---

## Residual risk / limits of this pass

- Static only; no dynamic confirmation of the dupe (Finding 1) — rated Confirmed on the basis that the host-side checks
  provably omit possession/uniqueness and the debit runs on the sender.
- Parser discipline judged uniform from the 12 largest readers + two automated sweeps; a line-by-line read of all 249
  savefile functions was not performed.
- Transport-level trust (that peer id 0 really is the host, ENet reliable-channel limits) is the net layer, out of this
  audit's scope; Finding 4/1 authority assumptions depend on it.
