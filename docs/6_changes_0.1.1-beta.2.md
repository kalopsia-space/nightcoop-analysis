# What changed in NightCoop 0.1.1-beta.2

A diff-focused writeup of the second open-beta build, **0.1.1-beta.2**, against the
**0.1.0-beta.1** build analysed in the rest of this repo. It covers only what moved;
everything described in [`00_overview.md`](00_overview.md) and the per-area writeups
([1](1_network_session.md)–[5](5_lifecycle_world.md)) still holds unless noted here.

## The two builds

| | 0.1.0-beta.1 | 0.1.1-beta.2 |
|---|---|---|
| `NightCoop.dll` SHA-256 | `6d22c0c1b70a3d79df4127a273f9e33198583698300086cd4f8f3e9f9e48adb8` | `9b07bb769013ef4a9f91b1b547ffb4929d5845ac63383892e3151895281e40bc` |
| Size | 15,649,280 | 16,116,736 (+457 KB, +3%) |
| Compiled (UTC, from PE header) | 2026-10-23 14:26:27 | 2026-10-24 15:16:20 |
| Source tree (embedded) | `F:\files\cyberpunk\nightcoop-port25\src\` | same |
| Exports | `Main`, `Query`, `Supports`, `RegisterTypes`, `PostRegisterTypes`, `NightCoopAddonApi` | same |

**Only `NightCoop.dll` changed.** The three bundled RED4ext files
(`bin/x64/winmm.dll`, `red4ext/RED4ext.dll`, and the two licence texts) are **byte-for-byte
identical** to 0.1.0-beta.1, which were already verified against the official RED4ext v1.30.0
release. So the loader/proxy chain carries no new trust and did not need re-checking beyond the
hash compare.

Verdict is unchanged: **no malicious code.** The new code is more co-op game logic — a rewards
system and some lag/scene catch-up tuning — and adds no process creation, injection, HTTP/download,
executable-memory, persistence, or credential-access capability. Every "absent entirely" item from
the [README](../README.md) was re-swept against the new binary and is still absent.

## Summary of changes

The build is dominated by one new module, `Rewards.cpp` (namespace `nc::rewards`), plus smaller
tuning to lag handling and the "led" scene flow. Attribution below is by comparing the symbol /
string sets of the two binaries; a token is called **new** only when it is absent from the
0.1.0-beta.1 binary and present in 0.1.1-beta.2.

| Area | New in 0.1.1-beta.2 | Nature |
|---|---|---|
| **Rewards** | module `nc::rewards` / `Rewards.cpp`, wire message `RewardWord`, script fn `NightCoopCatchUp`, world rules `reward_own_kills`, `reward_partner_defeat`, `reward_quests_shared` | new co-op feature |
| **Lag handling** | world rule `lag_catchup` | new tuning |
| **"Led" scene flow** | `skip_land_choice`, `led_wait_room` | refinement of the existing led-story path |
| Iconic-item tracking | many `*_owned` switch tokens (e.g. `katana_saburo_owned`, `liberty_dex_owned`) | supporting data for `reward_quests_shared` |

Things that look new but are **not** — already present in 0.1.0-beta.1, so not attributable to this
build: shared scanner tags (`npc_tags`, `npc_tags_join`), NPC look-at (`animLookAtRequest`,
`AddCombatLookAt`), zone catch-up (`skip_zone_catchup`, `catchup_max_m`), `DisableKillReward`.

## 1. The Rewards system (`nc::rewards`)

This is the headline change. Before this build, co-op players shared the world and the story but
each player's XP, bounty (eddies), and quest rewards were whatever their own game happened to grant.
0.1.1-beta.2 adds an explicit rewards layer so that combat credit and quest rewards track the co-op
reality rather than each machine's isolated view. It is three independent world rules, all of which
grant rewards **locally through the game's own `RPGManager.GiveReward` path** — the wire only carries
small "credit" words, never items or currency directly.

### `reward_own_kills` — your kills reward you
Each machine computes the combat reward (bounty, level/combat experience) for the NPCs **it owns and
neutralizes** and gives it to its own player, as the game normally would. When a partner neutralizes
an NPC your machine does not own, your machine queues nothing for you (`reward_own_kills; … hit(s)
so far`). So kill XP/bounty is settled on the machine that owns the NPC; it is not transferred over
the wire. Sub-switches seen: `reward_own_kills:bounty`, `reward_own_kills:damage`.

### `reward_partner_defeat` — credit for a partner's takedown of your NPC
When an NPC is "neutralized without death" by a **partner's body** (the puppet copy of the remote
player), the owner machine emits a `RewardWord` telling that partner "the reward is theirs"
(`reward_partner_defeat:sent`). On the partner's machine, their own copy of that NPC then rewards
**their** player exactly as the game rewards whoever performed the takedown
(`reward_partner_defeat:rewarded`). If the owner has no local copy to credit, it records "no word".
The grant still happens locally on the recipient; the word only carries the fact "peer N's body
neutralized NPC X".

### `reward_quests_shared` — the host's quest rewards reach the guests
Quest-node rewards (what the game's quest graph hands out via `RPGManager.GiveReward` at a node) are
shared from the host to the guests. The host's quest node grants locally, then sends a numbered word
(`word #N`, `reward_quests_shared:sent`); each guest applies it to their V
(`reward_quests_shared:granted`) **but never twice**:

- if the guest's own quest node already gave that reward, or gives it later, the shared word is a
  no-op for it (`own_skipped`, "our own node gave it to our V already", "our V has it already by the
  host's word: not given twice");
- a session-wide **reward ledger** reconciles "owed by the host's word but not yet met by our own
  node" against "given by our own node but not yet met by the host's word", and is **cleared when
  the player leaves the host's world**;
- **once-only items stay per-player and are never shared**: "iconic weapons, shards, recipes,
  keycards, perma rewards" are each player's own — taken from a corpse they stay with the others,
  and lying in the world before the session they are "neither shared nor emptied". This preserves
  the unique-item rule the 0.1.0 audit already documented (unique items can't be transferred).

`NightCoopCatchUp` is the script-callable entry that lets a guest reconcile against the host's
accumulated quest-reward words (e.g. for a late joiner or after a host skip).

### Security of the rewards layer
- **Trust model is unchanged.** `reward_quests_shared` honours **only the host's word** ("by the
  host's word", "no word of the host for it yet"). `RewardWord` from a non-host peer carries only
  partner-defeat credit, which the recipient applies to *its own* player via the normal game path —
  a peer cannot use it to grant rewards to someone else.
- **Bounds-checked parsing.** `RewardWord` is read through the same shared, fail-safe `proto::Reader`
  as every other message; a bad frame is rejected with `rewards: a malformed word from peer {}
  ({} bytes)` rather than parsed unsafely. The two-sweep check from
  [Audit A](A_net_deserializers.md) (wire-controlled length into a fixed buffer) was repeated over
  the new `nc::rewards` code and found no such pattern.
- **Residual risk is the pre-existing one.** A *modified host* can over-report quest-reward words,
  and a *modified NPC-owner* can misreport a partner-defeat word — both are instances of the
  owner/host-authored-message trust the [security summary](SECURITY_AUDIT.md) already lists as
  Low-severity (items #1 item-dupe and #8 owner-reported loot). The new feature widens that existing
  surface by one message type; it does **not** introduce a client-to-client grant primitive, because
  the dedup ledger and the "once-only items are never shared" rule block the obvious duplication
  path.

## 2. `lag_catchup` — world catch-up after long frames

A new world rule: after a long (stalled) frame, **your** world is advanced at ×1.25 to catch back up,
while the remote partner's body keeps its own time ("our world catches up x1.25 after long frames
(lag_catchup), theirs does not: the body keeps their own time"). It is latched at load — "lag_catchup
is off until the game restarts" — so toggling it mid-session has no effect until relaunch. This is a
smoothing/tuning rule with no network-trust implications; it only changes local time scaling.

## 3. "Led" scene-flow refinements

Two smaller additions to the existing host-led story path (see [4_story_world.md](4_story_world.md)):

- **`skip_land_choice`** — handling for when a fast-forwarding guest lands directly on a dialogue
  **choice window**: the decided option is applied at the window, and the instrumentation counts
  "sent / heard / caught up / lines passed / at our window". The embedded dev note is dated
  "23.10 evening", i.e. right around the 0.1.0 cut.
- **`led_wait_room`** — a wait-room gate in the led flow (holding peers until the shared scene is
  ready), alongside the pre-existing `led_peer_sweep` / `led_quiet_budget` tuning.

These refine catch-up/skip behaviour that already existed; they don't change the vote/authority model
for dialogue (strict majority, 60 s host-wins timeout).

## What did not change

- **Loader / RED4ext scaffolding** — byte-identical (see table above).
- **Transport, crypto, hub protocol** — same `NCOP`/`NCSQ`/`NCZQ` framing, same X25519 +
  XChaCha20-Poly1305 link crypto, same hub sign/box keys and domain strings. The protocol version is
  recorded below.
- **Save sharing, item ledger, loot ownership** — unchanged except that the rewards ledger now sits
  alongside the item ledger.
- **Absent capabilities** — the full "absent entirely" sweep (process creation, injection,
  HTTP/download, exec memory, persistence, credential theft, env snooping) is still clean on the new
  binary.

## Analysis facts (from the 0.1.1-beta.2 decompile)

- Protocol version: **128** — unchanged from 0.1.0-beta.1. The `RewardWord` message type was added
  within the existing type space without bumping the version (the Hello still advertises `0x80`), so
  the two builds remain wire-compatible at the handshake level.
- Functions decompiled: **20,041** (Ghidra 12.1.2, 0 hard failures; the 0.1.0 dump had 19,538).
- Pseudocode for this build is in [`../pseudocode-0.1.1-beta.2/`](../pseudocode-0.1.1-beta.2/), split
  by address range in the same ~8 MB-per-file format as the 0.1.0 dump in `../pseudocode/`.

## Limitations

Same as the parent analysis: this is static review of decompiler output and strings; the DLL was not
run. Feature attribution here is by binary string/symbol diff, so a change that reuses an existing
symbol without adding a new one would not show up as "new". Switch semantics are read from the
binary's own self-documenting hint strings, which describe behaviour but not every default.
