# NightCoop: combat, NPCs, damage, vehicles and police

Static analysis of `NightCoop.dll` (Ghidra pseudocode plus raw strings). The DLL was never run.
Addresses are function entry points in the pseudocode (`//==== <addr>`). Quoted text is the DLL's own log or help
strings. Message names come from the hub repo's `src/ProtocolCore.hpp` `MsgType` enum.

Notes on method and confidence:
- The mod logs a great deal, in long English sentences, and keeps a change history inside its strings ("as before
  16.10", "(21.10 night)", commit hashes like `d39a19b`, `0f021e3`). Most behaviour below comes straight from those
  strings. Where the text is my interpretation, I mark it *inferred*.
- Most switch defaults were read from the DLL's initialised `.data` section without running anything. Each name was
  matched to the `bool*` its setter picks (for example `FUN_1803378d0`: `memcmp(name,"guest_npc_off")` →
  `pcVar20 = &DAT_180dc0009`), and then the initial byte was read. A switch is "1" when that byte is 1. Values in
  `.bss` are 0 at load.
- Module attribution uses the embedded `src\<Module>.cpp` assert paths plus each function's position next to them.

---

## 0. Message vocabulary (combat, NPCs, vehicles)

From `ProtocolCore.hpp`. All of these names also appear in the DLL's name table at `1800b4910`.

| id | name | used for (from DLL evidence) |
|---|---|---|
| 18/19 | HitClaim / HitResult | attacker's damage claim on an NPC → the owner applies it and replies with the outcome |
| 20/21/22 | NpcSpawn / NpcSnapshot / NpcDespawn | an owner announces, streams and removes a shared NPC |
| 23/35 | NpcAnim / NpcAnimWant | animation-graph input stream for copies; a copy asks for a "full state" |
| 24 | NpcGrenade | grenades held or thrown by NPCs (visual grenade on the copies) |
| 26/27/28 | NpcHandoff / NpcHandoffAck / NpcClaim | ownership transfer of an NPC |
| 32 | PlayerHit | an NPC owned by one peer hits another peer's player body (forwarded damage) |
| 36 | NpcDead | NPC death table (accepted from the host only) |
| 37 | NpcLookAt | look-at targets of NPCs |
| 47/48 | PlayerRevive / DownedNotice | help-up and downed state |
| 60–65 | VehicleSpawn/State/Despawn/Seat/Handover/Hit | vehicle replication |
| 91 | NpcTakeRequest | "npcs asked for by a partner's grapple or carry" |
| 92 | PlayerCarry | body on the shoulder or in the arms |
| 98 | NpcDefeat | defeated (non-lethal) NPC state |
| 99 | PlayerGrenade | a player's grenade |
| 116/117 | NpcOwnActors / NpcAppearances | scene actors each side keeps; owner's look |
| 123 | VehicleSceneSeat | seats in quest-scene vehicles |
| 124/125/126 | PvpRules / PvpHit / PvpResult | PvP |
| 129/130/131 | Destruction / DeviceBlast / PlayerBlast | destructibles, barrels and explosive devices |
| 132 | VehicleDamage | dents and flat tyres on mirrors |
| 134 | RideAlong | a guest riding in the host's car |
| 135 | ChallengeRules | "tougher enemies" |
| 136 | NpcShot | each NPC weapon `Fire`, so copies fire visibly |
| 140 / 162 | HackSync / HackIcon | quickhacks and upload mappins |
| 155/168 | CrowdEachHold / CrowdWalkersCover | crowd streaming observers and the walker ball |
| 165 | VehicleRemote | `car_remote` (remote-controlling a car) |
| 167 | AvSound | AV sound events |
| 171 | BlackwallNpc | Blackwall casts |
| 176 | PoliceFight | `police_fight_partner` |
| 177 | VehicleAutopilotEnd | ends of autopilot paths |
| 181/190/214 | CarsWord / SenseWord / TurretWord | crowd cars, NPC senses, turrets |
| 197 | NpcAction | e.g. "the body part of the attacker's hit shape (NpcAction 197)" |
| 213 | NpcCarHit | our car hit a partner's NPC |
| 220 | NpcTag | scanner tags |
| 227 | VehicleRole | quest-car role key, sent before the spawn |

**Input validation** (`net_input_checks` = 1, global `DAT_180d82980`, help text at `1803378d0`): "messages an
unmodified build never sends are refused: a spawn whose record is not a character (npc) or a vehicle, an attack
record of another class, a hit by an npc or a vehicle another peer owns, npc deaths not from the host, a vehicle
handover naming the wrong owner, a hit claim without damage…".

Examples:
- `180322410`: "net input: refused PlayerHit from {} for NPC {:#x} owned elsewhere" and "refused NpcDead from non-host peer".
- `180228420`: "refused HitClaim from {} with healthPct {}".
- `1803cc180`: "refused VehicleHit … owned elsewhere".
- `1803cce60`: "refused NpcCarHit".

`net_entity_caps` refuses "a peer's new npc over 2048 or new vehicle over 192".

---

## 1. NPC ownership and authority

### 1.1 Model: one owner simulates, everyone else shows a copy

Every shared NPC has exactly one **owner** machine. The owner runs the NPC's real AI, health and damage pipeline.
Each other machine shows a **copy** (also called a "puppet" or "mirror") that is under "direct control": "game
components off", placed by snapshots and animated from the owner's graph stream.

- `1802df450`: "copy of net id {:#010x} is in the world, taking it under direct control".
- `18021a3f0`: "the ai of the copy {:#x} does not tick here — its owner's npc leads it (its stream and snapshots)" (`copy_ai_off`).

NPCs are identified by a 32-bit **net id**. Because both machines load the same save and world, most NPCs exist on
both sides independently, as **twins**. NightCoop pairs them instead of always spawning new copies:
- `1802ff8b0`: "by its community key and record, the only one of them here and there, {:.1f} m apart (…key_unique_pair…)".
- `1802ff8b0`: "a puppet in place of the leader's copy (host first)".
- Our local twin is then turned into the owner's puppet. If no twin matches, a copy is spawned from `NpcSpawn`
  (`180262b10`: "copy of net id … registered with population").
- The copy is dressed in the owner's look (`18032fd30`: "dressed in the owner's look '{}' (ours was '{}', try {} of {})").

`1803103c0` lists the roles an NPC can have: "own idle npc / own active npc / our stand-in / own crowd / copy of npc /
copy of crowd / puppet (our body) / puppet (our stand-in)".

### 1.2 Who owns what by default: the host leads

- **The host is the "leader".** It owns idle and crowd NPCs in the shared area. `guest_npc_off` = 1 (`1803378d0`
  help): "a guest near the host keeps no npc of its own: no twin and no puppet of the host's npc, the host's copy
  stands and ours is removed at once".
  - Exceptions it keeps: "actors of our scenes, vendors, the dead, npcs we share, police of our wanted level, npcs the
    game brought back". These are listed with reasons in `180313a60`.
  - `180300c50`: "guest_npc_off: the crowd at once, others in 2 s, within 100 m of the host".
- `host_first` = 1: "in the shared area a follower shares no npc the leader has: our body under the leader's copy
  becomes its puppet at once, our active npc near the leader waits up to 3 s for the leader's spawn".
- **Far apart, each side runs its own crowd.** `180308ac0`: "peer {} went {:.0f} m away, they run their own crowd
  now" and "we lead the crowd here and share ours with them".
- **Distance-based handoff for active NPCs.** Defaults read from `.data`, printed by `180339420` (setter for
  `NightCoopNpcOwnersRadius`):

  | parameter | global | default |
  |---|---|---|
  | interest radius | `DAT_180dbff20` | 150 m |
  | "give away past" | `DAT_180dbff24` | 70 m |
  | "take within" | `DAT_180dbff28` | 100 m |
  | `handoff_margin` | `DAT_180dbff30` | 15 m |
  | animation stream: up to N NPCs | `DAT_180dbff38` | 400 |
  | animation stream: within | `DAT_180dbff34` | 150 m of a partner |
  | `share_limit` | `DAT_180dbff48` | 400 |
  | `leader_limit` | `DAT_180dc013c` | 400 |
  | `orphan` (abandon after owner quiet) | `DAT_180dbff40` | 3500 ms, range 0.5–30 s |

  - Handoff margin help: "a partner takes our npc over only when it is nearer to it than we are by the margin (…15 m)".
  - Share limit: "up to {} npcs are shared at once, the nearest to the other players (400 since 11.10…)".
- **Combat leadership of companions** (`companion_combat_lead` = 1, `18032afc0`, `180330f00`): "a companion of the
  host's world (FollowerRole, like Jackie) is led by the machine whose player is in combat"; "both players are in
  combat: the lower number leads"; "nobody is in combat: the host leads them". `companion_lead_hold` = 1: a change
  needs "4 s in a row" because "the players' combat flickers".
- **Scene actors.** "an actor of our own live scene is ours at any scene tier" (`180339e40`). Each machine plays its
  own quest scenes: "our npc … (an actor of a quest scene the host plays too, each plays its own)" (`18032fd30`).

### 1.3 Handoff protocol (NpcHandoff, NpcHandoffAck, NpcClaim)

1. **Offer.** `180303900` and `180314b90`: "offering net id {:#010x} to peer {}: it is {:.0f} m from us and {:.0f} m from them".
2. **Ack or refuse.** `180314fb0`:
   - "peer {} took net id {:#010x} (entity {:#x} on its side)", then "our npc {:#x} is now a puppet of peer {}".
   - "peer {} did not take net id {:#010x} (reason {})".
   - Timeout at `180303900`: "peer {} never answered about net id".
3. **Receiver side.** `1803159c0`: "took net id … (entity …) from peer {}" or "offered net id …, but we have no body for it".
4. **Claim, the reverse direction.** `1803154c0`: "peer {} claimed net id {:#010x} and we gave it up".
   - `180318b00` refuses: "peer {} asked for net id …, but it is not ours / … it is dead here / … its body is gone".
   - Grapples and takedowns trigger such asks: "a partner took it into a grapple or takedown" (`18033c160`).
5. **Simultaneous claims.** `180316fc0`: "npc {:#x} was claimed by peer {} too (their state {}, ours {}); we give it
   up (our net id … -> theirs …)".
6. **Stale-message guards** (both default 1):
   - `handoff_stale`: "while a handover of an npc waits for the ACK its old owner sends no spawn of it, and the new
     owner ignores the old owner's spawn of it for 6 s".
   - `handoff_purge`: drop queued old-owner messages, because "a spawn among them made a second body".
7. **Abandoned NPCs.** `180304990`: "owner {} of net id … went quiet; peer {} is closer, it takes it". After the
   quiet period (`orphan`, 3.5 s), "a heard owner in our world only loses the copy, a quiet one in our world keeps it
   standing up to {} s, the leader's idle npcs wait, copies created by us are removed" (`180339420`).
8. **Unsharing.** `180324990`:
   - "net id … calmed down; the leader runs the idle npcs here, stopped sharing it".
   - "net id … is {:.0f} m from the other players, stopped sharing it".
9. **Stand-ins.** When a handoff leaves us with our former NPC as a stand-in, `lived_copy_goes` removes it "once
   nobody leads it and it is calm" (`180334350`).
10. **Debug.** `NightCoopNpcHandoff(Int32,Int32)` forces a handoff. The handler `FUN_1809d35c0` reaches `18030d300`
    ("npc owners: net id {:#010x} is not ours").

### 1.4 Driving copies: snapshots, animation stream, smoothing, pose blend

**Snapshots** (`NpcSnapshot`). Tunables and history are in `1802d54e0`:
- Owners send "every npc we own … 20 times a second".
- `owner_lod`: "npcs we own farther than 60 m from every partner and calm send snapshots and graph inputs 5 times a second".
- `owner_lod_view`: unseen calm NPCs send 10 times a second.
- The per-copy LOD table at `1802750d0`: "close fight 30 Hz / near 20 Hz / seen from afar 10 Hz / far 10 Hz /
  unseen 10 Hz / far, unseen and still 4 Hz".
- Change-only sending: "an npc snapshot goes when it changed (then twice more, and every 0.5 s while it stands)".
  `1802783c0` reports the skip rate: "{} skipped as unchanged = {:.0f}%".

**Interpolation.**
- The copy is shown at a delay behind the newest snapshot: "the copy shows the original {} ms in the past on top of
  the network delay".
- The path is "along a Hermite curve through the owner's snapshots (speed continuous, no overshoot)", replacing
  "straight from snapshot to snapshot (as d39a19b)".
- Since 16.10 a copy can run past the newest snapshot by a forecast: "shown past the newest snapshot (a forecast)"
  (`1802a3b40`), limited to "not longer than the partner's show delay".
- Big jumps: `snap_jump` (`1802acd50`) "the copy goes there at once, not flown across".
- If the root does not move, the copy is teleported: "the root transform does not reach the world … placing by
  teleport instead" (`18027c870`).
- `copy_time_owner`: "a copy's graph runs at the real pace of the owner's npc … a slowed world here does not slow
  copies". This is relevant for Sandevistan and slowdown.

**Animation stream** (`NpcAnim`, `NpcAnimWant`):
- The owner taps its NPC's animation-graph inputs and sends them. The copy's graph receives the same inputs.
- The copy asks for a "full state" when it is out of sync (`18027a6f0` lists inputs and features).
- Copy-side filters handle workspot oddities: "workspot graph input 'inCover' forced to zero", "stanceState Cover
  forced to Crouch" (`18026a930`, `18027c870`).
- `NightCoopNpcMirrorKey(name, mode)` chooses per input: "is mirrored and blocked like any other input / … no longer
  applied to the copy / the copy keeps its own" (`1802d4b00`).

**Pose sanity** (`18027c870`):
- T-pose detector: "net id … is in a T-pose (hands {:.2f} m apart, {:.2f} m above the hips)", "out of the T-pose after {} ms".
- Pose check: "is in the owner's pose again after {} ms" (`18026e310`).

**NpcSmooth** (`180346470`, `180347790`, `18034ac70`) measures quality and changes nothing:
- "copies near our camera are measured, a summary every 10 s".
- It logs teleports and hand jumps: "teleport: net=… step_m=…", "hand30: …", and jerk/teleport percentiles at `180349410`.

**NpcPoseBlend** (`180209110` "pose fix: npc copies pose blend (anim job threads)"; `180209330`, `18020b710`):
- "a jump of a copy's pose (announced or found) blends out over the blend time": "inertialized over {:.0f} ms (npc_pose_blend)".
- A reference-pose output (the rig's bind pose, that is a T-pose) "shows its last good pose" and "asks the owner's full state at once".
- Switches: `npc_pose_ms` and `npc_pose_radius` ("copies within {:.0f} m of our player are under the pose rule").
- It hooks the engine's animation job threads.

**Look-ats** (`NpcLookAt`): `1802abe40` "look-at '{}' from peer {}: target …"; capped per body part (`lookat_cap`).
**Hands and weapons** are mirrored into slots: `1802b47c0` "weapon … placed in slot".

### 1.5 Despawn, missing bodies, workspots

- Despawn: `18027af10` "copy of net id … despawned", "released back to the game".
- Missing from EntitySystem (`1802aff50`): "npc … temporarily missing from EntitySystem; keeping source and copy for
  {} ms" and then "stayed missing … the copy goes too".
- Lost body: "a lost body is told to partners at once, their copy hides until it comes back or goes".
- Calm NPCs in workspots (benches, bars) are held for partners up to 60 s while out of the owner's world (`1802783c0`).
  "a calm workspot of it goes to partners as any calm one", and a vehicle seat is not treated as a workspot (18.10).
- World unload: "{} copy(-ies) forgotten, the world is unloading" (`18028ff80`).

### 1.6 Death, defeat, ragdolls

- **Who decides death.** The owner. "npc copies: npc … died, the copy dies too" (`1802aff50`). The death table
  (`NpcDead`) is host-only (`180322410`).
  - `dead_identity` = 1: "a death at the host kills ours only if it is the same person (record and key)".
  - `dead_list_world` = 1: "the host sends its whole list to a partner who comes into its world".
  - `dead_no_puppet` = 1: "our dead npc is never made a puppet of the owner's living one (its health would be set back up)".
- **How the copy dies** (`1802997b0`, `1802c6de0`, `180272d60`, `180297700`):
  - It waits for the owner's death animation, which arrives in the graph stream. Then "a death animation by hit data
    (NormalDeathTask), as its owner's npc", or a ragdoll ("WithoutHitDataDeathTask").
  - `death_hit_data`: the copy dies by its own AI using the owner's hit data.
  - In a vehicle seat: "the death in its vehicle seat (VehicleNPCDeathData)"; "a passenger in combat: out of its
    seat, a RagdollVehicle ragdoll (seat_corpse)".
  - The reward goes to whoever landed the hit: "by our player (reward is ours)".
- **Prediction.** "a copy killed by our player's claim falls at once, the others wait 250 ms for the owner's death
  animation (11.10)". `predict_lethal_only` = 1: "predicted only by a lethal finishing hit; a non-lethal one leaves it
  to the owner". "a predicted death is not undone once the owner has said the npc is gone".
- **Defeat** (`NpcDefeat`): the copy "stays down while its owner's npc lies defeated (health at its pool's limit)".
  Claims stop at "the defeat limit (0.10%), our Kill finished it (TryFinish)" (`18023ce70`).
- **Ragdolls** (`1802a5610`, `1802cb1f0`): with `ragdoll_owner`, "the copy goes down with it", "gets up with it".
  `ragdoll_fall_witness` logs drift: "lies by its owner's npc 1.5 s: the copy fell {:.2f} m, the owner's npc {:.2f} m".
- **Takedowns and disposals.** "an npc gone from our world right after our player's takedown or carry dies for
  partners too". A disposed body "is hidden for good here once it dies".
- **Corpses.** "goes 30 s after its death even from a shoulder (as before 12.10)"; "is not removed while our player
  or a partner's body carries it".

### 1.7 Crowds, population and traffic (PopulationView, NpcOwners)

- **The host is the crowd leader.**
  - It raises its population limit: "while we lead the crowd the population limit is raised up to max(2 x the game's
    limit, {}) plus our copies".
  - Copies count as "always there": they "enter over the limit and push our own out, never pushed themselves"
    (`180332be0`).
  - `leader_room_combat` and `leader_room_wanted` = 1 keep this room during combat or a wanted level.
- **Walker ball** (stage 2, 18.10; `180356a10`, all `crowd_walkers_*` = 1, `crowd_cars_gate` = 1):
  - "a walker of the host does not enter the world where a partner sees it and the host's camera does not".
  - "a guest's own walker never enters inside the host's walker ball".
  - "the host shares its walkers within 130 m of a covered partner".
  - Leftover guest pedestrians go "out of our view and far" (`crowd_walkers_leftover`, `180300c50`).
- **crowd_each** (`18035d480`, `18035fc80`, all parts = 1):
  - "the host holds a second loaded area (a streaming observer of its game) at the body of every far partner".
  - It creates "our anchor NightCoopHost … in the game's streaming list".
  - It is bounded by memory and by the engine's "frame of five" observers.
  - This lets the host simulate NPCs around a distant guest.
- **Partner circles and view** (`1803561e0`, `180356410`):
  - "circles around the partners are added to the game's keep circles".
  - "an npc in the world a partner sees is seen for the host's game too" (`partner_view`).
  - NPCs are therefore not culled as unseen just because the host is not looking.
- **Removal diagnostics.** `PopulationView` hooks entity removal and classifies callers: "the crowd, unseen by the
  host…", "pushed out at the population limit", "RemoveEntity by a plugin (ours)" (`180351f20`, `18034c3a0`).
- **Traffic** (`1804316c0`, global `DAT_180dc3572` = 1): "traffic and parked crowd cars: shared by the leader, ours
  removed in the leader's circle". The alternative is "not shared, each side keeps its own".
  - `1803ca680`: "a crowd car the owner stopped sharing is removed here".
  - `crowd_cars_reach` and `crowd_reuse_remove` handle crowd-pool id reuse: "its number was removed less than 30 s
    ago with another car".

### 1.8 Making partners real targets (NpcTargets)

NPCs on the owner's machine must fight the partner's body (a remote `PlayerPuppet`). NightCoop patches the engine and
scripts so that body counts as a player:
- `1801b9710`: "partner bodies are engine players at level {}". Modes: "plain npcs, threat raised by our hook /
  player-controlled bit / … peer and sense type Player". `NightCoopPartnerAsPlayer(Int32)` sets the level.
- Threat hook (`1801a86f0`, `1801a5360`): "no hooking API; partner bodies keep a low threat".
  `body_threat`: "fighting near our npcs in combat is in their threats as their squad knows a player".
- Visibility and stealth (`1801b94e0`, `1801b9190`, `1801a0040`): "the partner body … is detected by npcs x{:.2f}
  (their stat Visibility …)", crouch handling, optical camo.
- Security zones (`1801b1d40`, `1801b6230`): "its devices and the agents of its system are told it crossed in".
- Script patches in `RemotePlayers` (`1801f4270`) make hostility pairwise, not group-wide:
  - "hostility from a hit goes to the attacking player only, not to the whole player group".
  - "an npc fighting the partner does not start detecting our player unless it is hostile to us".
  - "a copy of an npc that fights us at its owner is in combat with us (nameplates, police)".
- Debug commands: `NightCoopThreats` (`LAB_1809e67a0`) and `NightCoopSenses` (`LAB_1809e4970`). The senses dump is at
  `1801ad4d0` ("senses: npc … high {} … top threat {} of {}").
- NPC tags: scanner tags are synced (`NpcTag`, `18098bd60`), and "the host sends the shared tags to a player coming into its world".

---

## 2. Damage model

### 2.1 Principle: the NPC's owner is authoritative; the attacker sends claims

When you hit an NPC that someone else owns, you are hitting its copy. NightCoop's `DamageTap` hooks the game's damage
pipeline:
- `18020f6a0`: "pipeline call hook", "stat pool change hook".
- Hooked stages are listed in the strings: `ProcessArmor`, `ProcessEvasion`, `DealDamages`, and others.

It intercepts the health write on the copy and converts it into a **HitClaim** for the owner:
- `180212a40` marks each pool write "CLAIMED" or "SUPPRESSED"; "not ours to claim, the owner's world decides".
- `180238360` sends: "damage claim: #{} {:.2f}% on net id … -> peer {}, attack {:#x} type {}, {} flag(s)".

**The claim is a percentage of the NPC's health** (`healthPct`), not HP. An empty claim is refused.

Owner side (`18022ee70`, `180230a90`, `1802379c0`):
- "claim #{} on net id …: {:.2f}% as a hit from their body". The owner re-queues the hit (`QueueHitEvent`) with the
  partner's body as instigator, so its own AI, reactions and quest logic see a real hit.
- Fallback: "{:.2f}% written directly".
- Errors: "no such npc of ours", "the target is dead (claim_dead_tail)", "the game does not let it die yet",
  "killed by their body on retry".
- Hit reactions are rebuilt to match the game's `EvaluateHit` (`18023ce70`, `18023ed50`, `claim_game_path`):
  thresholds, twitch/impact/stagger choice, hit direction, melee side, hit-shape zone, hit timer and combo reset.
  `led_partner_hit` makes a partner's hit count "for the quests too: its TargetHitEvent to our player".

**HitResult** reports the outcome to the attacker. Stats at `1802292c0`: "owner applied {} as hits + {} directly + {}
zero-damage … predicted deaths {} ({} undone) … outcomes: delivered {}".

Special cases:
- `claim_instant_kill` = 1 (`18021a1d0`): an instant-kill or ForceKill hit on a copy "is a finishing claim of 100% to its owner".
- `claim_kill_flag`: a lethal claim marks the copy "just killed or defeated" in the same hit, so on-kill effects fire
  on the attacker ("the Byakko katana, perks").
- `twin_claims` = 1 (`18021b1a0`): damage on our twin of a partner's NPC "is written here and goes to its owner as a claim too".
- Quickhack status damage waits for the status to be present: "the claim waits for it (up to {} ms…)" (`18023e4d0`).

**Loopback test mode.** `NightCoopDamageLoopback(Bool)` (`18023fa80`; `.bss`, so default off): "hits on NPCs
become claims that land 50-150 ms later". Single-player testing of the claim path.

### 2.2 Damage to players from NPCs: forwarded hits

The NPC's AI runs only on its owner. When it shoots a partner's body on the owner machine, the hit is forwarded to
that partner (`PlayerHit`):
- `1802394a0`: "damage forward: hit #{} on the body of peer {} from {:#x} (net id …), attack {:#x}".
- The victim applies it through its own pipeline, with its own armour, perks and difficulty (`180243e20`): "attack …
  queued on us, {} ms after it landed there". If there is no local copy of the attacker: "no copy of the attacker
  here, dropped". `victim_own_body` instead builds the hit "from our own body of that npc".
- Copies on the victim's machine do not deal real damage:
  - `copy_hits_forwarded_only` = 1 (`18021a530`): "a copy's own shot at our player … dropped".
  - `RemotePlayers` patch: "a copy's AI fires no real shots of its own: the owner's npc fires".
- **NpcShot** gives visible shooting: "fires at partners too: the owner sends each Fire of its weapon in the stream,
  the copy fires by it (18.10)". The copy fires blanks: "copies fire blanks (flash and sound)" (`1802d54e0`).
  `1802cbe10` traces where the visible bullet goes.
- The owner forces NPC fire at a partner's body through the game's `AI_ShootAt`/`CreateStaticPositionProvider`
  (`18028d330`). Fragile: "the game's AI_ShootAt … are not as in 2.31".
- Car hits on a partner's body: "a car hit is the partner's to take, on their machine: ours on their body goes to
  them (VehicleHit)" (`1801f4270`, `1803fb710`).

### 2.3 Gates, suppression and caps (debug switches)

All of these are `.bss`, so off by default:
- `NightCoopDamageGate(Bool)` (`18021aba0`): "gate ON, hits from doubles are dropped". Doubles are local stand-ins
  and copies.
- `NightCoopDamageSuppress(Bool)` (`18021b0c0`): "NPC health is not written inside the pipeline".
- `NightCoopDamageStage(Bool)` and `NightCoopDamageReplay` toggle pipeline-stage capture. "damage scope: on, the next
  10 pipelines and 20 pool writes inside them go to the log" (`18021ada0`).
- `NightCoopDamageLog(Int32)`: "the next {} hit(s) go to the log" (`18021ac50`).
- `NightCoopDamageStatus`: the summary at `18021*`/`180212a40`, e.g. "seen {} (pass {}, drop {}), from doubles {},
  into doubles {} (forwarded {}, friendly fire dropped {})".
- **Damage cap** for debug-spawned enemies (`18021a640`, `180212a40`, `180450d50`): "hits on the player from {:#x}
  take at most {:.0f} HP". Police spawned for a peer are exempt: "its hits are not capped".
- `copy_ai_off`: copies' AI does not tick. `av_ai_off` does the same for AV mirrors.
- `hack_body_dot_off`: a partner's DoT on bodies is not written locally ("its damage came by their claims").

### 2.4 Grenades and explosions

- NPC grenades (`NpcGrenade`; `180284910`, `1802a49b0`, `1802c7bb0`, `1802dc620`):
  - The copy holds a visual grenade in the same hand slot and "the visual grenade flies by the owner's points".
  - `grenade_attack`: "a visual grenade explodes by its own attack (fire, push; its hits are dropped here)". The
    blast is cosmetic locally; real damage comes from the owner.
  - The visual grenade "lives 4 s after its blast".
- Player grenades (`PlayerGrenade`) and PvP grenade damage appear in the PvP reference: "frag grenade on hard {}"
  (`1809203a0`).
- Explosive barrels and devices (`Barrels`; `180835bc0`, `180837230`, `1808375f0`, `DeviceBlast`): "an explosive
  device blown by one player blows up for everybody, damage only at the blower's — on others' NPCs by claims".
  On the other side, it "explodes here without damage (blast, sound, push; damage is the peer's)".

### 2.5 Quickhacks, Blackwall and hack icons

- **HackSync** (`18096edc0`, `180975290`, `180974ec0`, `1809714e0`). Options: `hack_npc_sync`, `hack_npc_visual`,
  `hack_body_dot_off`, `hack_pvp`, `hack_npc_on_partner`, `hack_status_first`, `hack_log`.
  - "quickhacks on the partners' npc copies go to the npc's owner (hack_npc_sync), on our own npcs to the partners'
    copies for the look (hack_npc_visual)".
  - "the partner's body is a quickhack target in pvp (hack_pvp)". The victim sees "Your partner is uploading a
    quickhack to you", "Your antivirus stopped the partner's quickhack".
  - "the quickhack wheel lists the hacks of an ordinary npc (Character.Gun_NPC_Base)" (`180973840`).
- **HackIcon** (`180982120`, `180983d00`): our upload progress is shown on partners' screens "as the game's upload
  mappin over the same target", in a yellow variant of the blue style. `NightCoopHackStatus` (`LAB_1809ccac0`).
- **Blackwall** (`18098eb00`, `180990b30`, `1809919c0`; `BlackwallNpc`):
  - A cast on a partner's copy goes to the owner and "puts the same statuses on their npc".
  - `blackwall_kill_claim`: "our ForceKill on a copy … sends the owner a finishing claim".
  - The caster's body plays NPC taunt clips as a stand-in gesture, because "the body's TPP graph has no clip of the player's FPP gesture".

### 2.6 PvP (`Pvp.cpp`, `DamageClaims`, `DamageTap`)

- **Off by default and host-controlled.** "pvp: installed — off until the host turns it on (NightCoopPvp(true) or the
  co-op menu)"; "only the host switches PvP". Rules are broadcast as `PvpRules` with a revision number (`18091ede0`).
- **Settings** (`NightCoopPvpSet(name, value)`, `180922a70`): `mult`, `ranged`, `melee`, `explosion`, `dot`, `hack`,
  `crit`, `status`, `head`, `cap`, `dot_cap`, `level_step`, `level_cap`, plus per-weapon-class multipliers.
  - Weapon classes: pistol, smg, rifle, lmg, shotgun, sniper, smart, tech, blade, knife, blunt, fists, mantis,
    monowire, explosive, quickhack, other.
  - Ranges: multipliers 0..10; `cap` 1..100 % of the victim's full health per hit; `dot_cap` 0.1..100 % per tick;
    `level_step` 0..0.2; `level_cap` 0..0.9.
  - `1809203a0` prints a reference of "hits to put a player down".
- **Flow.**
  - The attacker computes the hit against the partner's body: crit, headshot, falloff, attack-vs-players multiplier
    (`18023acb0`). It sends **PvpHit**.
  - The victim's machine applies it through its own pipeline, with its defence, armour and overshield (`180244e90`,
    `180231880`): "our player loses {:.2f}% of health from peer {}'s {} (… cap {:.0f}% per …)" (`180212a40`).
  - The pipeline is split so nothing is counted twice: "the attacker's stages skip at the victim, the body's defense,
    stealth and the attack's multiplier vs players skip at the attacker" (`18020ee80`).
  - **PvpResult** returns hit markers and dealt %.
  - Refusal reasons (`180243120`): "already down / pvp is off there / no body of ours there / failed there".
- **No PvP deaths.** "pvp: peer {} is down after our hit" (`18022e190`); "they are down: no finishing, help-up with F
  as before" (`180921dd0`). A PvP down goes into the normal Downed state, with the notice "beat you in PvP".
- `pvp_hostile`: the partner's body becomes an enemy for "target filters, crosshair, smart lock, the dash at an enemy".
- `pvp_leap_reach`: a melee leap targets the near side of the body's blocker capsule (`180922fb0`).

### 2.7 Challenge mode ("Tougher enemies")

- **Host-only, levels 0..3**: off / seasoned ("the next tier's skills") / hardened ("…, AI one step up") / elite
  ("two tiers of skills, AI two steps up"), plus "custom".
  - Set via the co-op menu or `NightCoopChallenge(Int32)`. `NightCoopChallengeSet(name, Int32)` takes `ai_step` and `skill tiers`.
  - The level is persisted in `challenge.txt` next to the plugin.
  - Sent as `ChallengeRules` (`180927730`, `180928ef0`).
- **Mechanism.**
  - NPCs get ability packages from higher tiers of their TweakDB family via `GameplayLogicPackageSystem.ApplyPackage`
    / `RemovePackage`: "challenge: record {:#x} is {} ({} higher tier(s) of its family in TweakDB)". Abilities listed
    include `CanUseGrenades`, `HasSandevistan`, `HasKerenzikov`, `CanBlindQuickHack`, and others.
  - The AI difficulty step works by redirecting script reads of difficulty: "{} of {} function(s) read the difficulty
    through us" (`180926c00`, `DifficultyForAi`).

---

## 3. Downed and revive

`Downed.cpp`. Enabled by default: global `DAT_180e94050` = 1, `1805bd740` "falling instead of dying in co-op is {}".

- **Falling instead of dying.** A script patch `GoDown` replaces death with a down state.
  - It sets immortality and adds "Mortal overrides" (`1805bb4d0`). When quest god-mode overrides hide immortality,
    "it is put as an override too (as the game's Second Heart)" (`down_immortal_override`).
  - Exceptions: "resurrection is forbidden here — the game's own death" and "the player's own Second Heart gets them up".
- **While down.**
  - Hint: "You are dying — a partner next to you can help you up (F). Hold T to pass out and come to in a safe place".
  - The phone and notification actions are held back (`1805bbbb0`, `1805bd640`), but "holding T answers" an incoming call.
  - Damage over time is removed. The camera is restored after rising (`1805bc3d0`, `1805bda70`).
- **Help-up.**
  - The helper side (`1805b99d0`) shows "Hold F to help up", checking "in reach / too far / not looking at them / we
    are in a vehicle". It sends `PlayerRevive`.
  - The receiver (`1805b1380`): "downed: PlayerRevive from peer {} taken ({:.1f} m from us)" and shows "Your partner helped you up".
  - The helper sees "You helped up" (`1805badb0`).
  - State is broadcast with `DownedNotice`.
- **Passing out.**
  - Holding T, read directly with `GetAsyncKeyState(0x54)` or through the game's `OpenChatBox` (`1805b9380`), gives
    "we passed out".
  - You come to "in a safe place" back along your trail (`1805b4120`; `down_pass_in_place` changes this).
  - While the host loads a save, T does not pass you out: "you will wake up in its world".
- **Everyone down.** "everyone is down (no load of the host's save); a partner can help us up, T to pass out". The
  co-op never forces a game-over reload.
- **Debug and status.** `NightCoopDowned` and `NightCoopDownedShield` are gameplay tag/status names used with the
  engine's tag functions, not script commands. The status line at `1805b1ad0` counts "downs {} (in pvp {}), help
  prompts {} (F held {}), helped up {}, … passed out {}".
- A co-op fall does not switch the target tracker off: "its combat state ends as in the game" (`1801b95f0`).

---

## 4. Police and wanted level

- **One police authority: the host** (`police_host_only` = 1, global `DAT_180dc3ce0`; mode text at `18045fc30`):
  "it alone sets the police; a guest's units, chase cars and AV on its ask while its wanted level is the higher".
  - Script patches in `1801f4270` make it work:
    - "a guest's wanted level sets no police here: its ask for a unit goes to the host".
    - "a guest sets no chase vehicles / roadblocks / AV of its own".
    - "the host's own system sets no police while a guest's higher wanted level leads: one squad".
  - Host handling of a guest's request is at `18045c1e0`. Responses include "set, hostile to its body", "refused (it
    does not lead, not level 5, or its AV is here already)", "its squad is full", and "the place is too near or too
    far from its body".
  - The units' search behaviour mirrors star state: "lose its exact place and search, as in the single game / know where it is".
- **Spawning for a guest** (`Enemies.cpp`/`PoliceHost.cpp`):
  - Chase cars: `1804419b0` "chase car … of peer {} is told to chase its body (AIVehicleChaseCommand)".
  - Units: `180447f60` "unit … of peer {} is in combat {} ms after it came into the world".
  - AV via `PreventionSpawnSystem.RequestAVSpawnAtLocation` (`18044b420`).
  - Car placement respects the guest's view: "out of that guest's view … (police_car_partner_view)" (`180455ba0`).
  - `police_car_unseen` keeps cars until no one sees them.
- **No cross-contamination of wanted levels** (`1801f4270`):
  - "the partner's damage does not raise the local wanted level".
  - "a kill by the partner's body does not raise the local wanted level".
  - "a witness nearer to the partner's body does not call the police on the local player".
  - `police_sees`: "police starts detecting a wanted partner's body without asking the host's prevention system".
- **PoliceFight** (`police_fight_partner`; `18045e570` sent, `1804577a0` taken): when our police NPC targets a
  partner's body "and we are not wanted — it is their fight: told them, their wanted level gets the police's combat
  start as in the game" (`CombatStartedRequestToPreventionSystem`).
- **Car hits on a partner's NPCs** (`NpcCarHit`, `1803cce60`):
  - The NPC's owner reports "our car net id … hit its npc" with speed and damage %.
  - Our wanted level then gets "the kill (CheckIfPreventionShouldReact) / the damage (SendDamageRequestToPreventionSystem)".
  - Kill thresholds come from TweakDB `AIGeneralSettings.vehicleHitKillThreshold` / `vehicleHitCrowdKillThreshold` (`1803fb440`).
- `own_police` (`1803378d0` help): "police of our wanted level … is shared at once near the leader, never handed to a
  partner and never taken for a partner's npc of the same record".
- `NightCoopWanted(Bool)` (`FUN_1809e9560` → `18044d0a0`) toggles the prevention system with
  `TogglePreventionSystem(sourceName "NightCoop")`: "enemies: police {} (source 'NightCoop')". `NightCoopPolice` is a
  string in `180452560` alongside `AITargetTrackerComponent`, *inferred* to be a source or tag name, not a script command.
- World handoff: "a police chase in the host's world we return from {}" (`return_drop_chase`, `18068faf0`).

---

## 5. Vehicles (`Vehicles.cpp`, the largest module in scope)

- **Ownership follows the driver.**
  - A shared vehicle has a home peer and a current owner. The owner simulates physics; others show a kinematic **mirror**.
  - `1803a4aa0`: "net id …: peer {} drives it now, ours is a mirror".
  - `1803a52d0`: "net id …: we drive it now (was peer {}, home peer {})".
  - `1803ab9c0`: "we took the wheel from peer {}".
  - `1803cb660` (`VehicleHandover`): "peer took the wheel / returned home to us / the owner's player drives it".
  - `claim_wait_driver`: "the wheel is not asked for (they would refuse); it is ours when they get up".
- **What gets shared** (`1803b1190`): "our vehicle {:#x} is shared ({}record …; reasons {:#x}, nearest partner {:.0f} m)".
  - Categories: taxi, player vehicle, crowd, static, quest cars.
  - Unshared when "nobody needs it" or "it left our world".
- **Mirror placement.** Snapshot interpolation with a show delay. `NightCoopVehiclePlacement(String)` options:
  `delay_smooth`, `delay_raw`, `smooth`; "the mirrors' show delay follows the owner's lag at most 1 % of the clock" (`180430740`).
  - Placement happens "in the frame by its own dt (stage before the physics)".
  - Guards against the local game moving mirrors: `mirror_autopilot_guard`, `mirror_bit_guard` (kinematic bit 0x100),
    `mirror_game_teleport`, `mirror_move_cap`.
- **Car contacts.** `car_contact_physics` (`180427450`, `1803adc30`): a mirror is "released to physics for the
  contact" when your car hits it, and goes "back on their owner's track" later.
- **Seats for partners** (`1803ba190`, `1803eebe0`, `180415530`, `1803d5b40`):
  - A partner's body is mounted into the matching seat with the seat clip. Entry and exit are animated, and seats are
    switched with `switch_seat`.
  - `seat_share`: "one player shown per seat".
  - `back_seats` = 1: back doors are opened for a second or third player. Quest-locked back doors are handled with
    `back_seats_quest_coop`.
  - Quests seat guests: "our share of the host's seats by our number (guests {})… (ride_guest_back_rank)".
  - **RideAlong**: "F at the wheel caught as a vote…, cars yielded to the host, the host refused a guest's wheel" (`18040d6d0`).
  - NPC copies sit in mirrors through "NightCoop's seat workspot" (`1803bc8e0`). `NightCoopVehicleSeats(String)`
    sets the seat pose for npc copies, bodies, or both (`1804312b0`).
  - Low-level mounting goes through `IMountingFacility.Mount` / `MountingRequest` (`1803c47d0`, `1803e4400`).
- **Quest and scene cars** (`1803fd690`, `1803d04d0`, `180410c40`). Both machines spawn their own copy from the same
  save, and NightCoop matches them by "id, record and place", by role (`scene_car_role`, `VehicleRole`: "the community
  key of the car or of the npcs in its seats"), or by `quest_car_readopt`.
  - "the quest car's wheel is the host's only (a guest does not take it…)" (`180430e40`).
  - Autopilot ends are synced (`VehicleAutopilotEnd`, `1803c9b20`).
- **Damage.** `car_damage` = 1 (`18042d6e0`, global `DAT_180dc386c`): "mirrors take the owner's dents and flat tire"
  (`VehicleDamage`). `1803c8ac0` and `180436520` check that the code layout matches 2.31 and otherwise skip
  ("does NOT match the code: car damage is not read here").
- **Car hits** on bodies and on NPCs: see 2.2 and section 4. `car_hit_own_ride` / `car_hit_left_ride` suppress hits
  from the car the victim sits in or just left (`18040d900`).
- **Orphans and remote control.**
  - `car_keep` = 1: a car whose owner stopped sharing it "stood here as an orphan for 120 s" unless you are in it (`1803da730`).
  - `car_remote` (`VehicleRemote`): "our player remote-controls the mirror… we drive it now, as with the wheel taken" (`1803abcd0`).
- **Extras.**
  - Radio share (`radio_share`, `18042b240`).
  - AVs: `av_share`, `av_cloak`, `av_sound`, `av_ai_off` (`1804145b0`, `1803e0dd0`, `18041dfb0`).
  - Steering-wheel hands for a partner at the wheel (`steer_feed`).
  - Johnny is re-shown in cars (`18040cfe0`).
  - World handoff copies cars obtained in a session into your own campaign garage (`18065f3e0`).
- **Defaults** read from the `NightCoopVehicle*` option table (`18042d7d0`): `seat_share`, `car_keep`,
  `car_keep_sight`, `av_share`, `av_cloak`, `av_sound`, `back_seats`, `car_remote`, `radio_share`, `scene_cars_share`,
  `quest_car_readopt`, `seat_corpse`, `steer_feed`, `mirror_bit_guard`, `crowd_cars_reach` = 1. `car_predict` and
  `copy_window_open` = 0.
- **Script commands.** `NightCoopVehicles(Bool)` turns the module on or off ("off (mirrors removed, our vehicles have
  physics again)"). `NightCoopVehicleTraffic(Bool)`. `NightCoopVehicleStatus` / `NightCoopVehicleDump` (dump format
  at `1803c27e0`).

---

## 6. Destruction, barrels, carrying bodies

- **Destruction** (`Destruction.cpp`; `18081c220`, `18082bc10`, `1808249c0`, `180829d60`; msg `Destruction`):
  - It polls "the destruction registry … like the save gathers it (2 Hz)" and sends "words" about broken objects.
  - Kinds: baked node or component, instanced node, owned component or node.
  - The peer reproduces each break:
    - chunk fields on live physics proxies;
    - masks written into records of unloaded objects ("it streams in broken");
    - the game's own part break for road signs and fences;
    - the fracture field (`FE_Erase`) or the impulse queue for instanced props such as barriers, crates and concrete blocks.
  - `TriggerDestruction` is replaced by the field it would apply when the component lacks `FF_TriggerDestructionEvent`.
  - Options (`NightCoopDestructionSet(name,bool)`): destruction, destruction_apply, _log, _mask_watch, _by_registry,
    _unseen, _chunks, _persist, _baked, _baked_drawn, _futile_trigger, _foliage, _near_match, plus
    `destruction_instanced` (off; "the fallback for a word without hits").
  - Every path is gated on "the 2.31 code". On a mismatch the feature is not applied.
- **Barrels**: see 2.4. "explodes here with its damage on our NPCs and player" only when blown by our player;
  otherwise there is no damage locally (`180835bc0`).
- **BodyCarry** (`PlayerCarry`; `180509a30`, `180510f40`, `180512220`, `1805106e0`, `1805108b0`):
  - "our player picks up entity … (net id …)". The partner shows the body on our body's shoulder, or a quest carry
    double "in our body's arms".
  - `carry_per_peer`: "two partners carrying at once each keep theirs".
  - `carry_look`: the double "wears the look the carrier names".
  - Disposal: "goes to partners as 'dispose' … their copy plays its half and is hidden for good".
  - Put-down: "entity … put where the partner left it ({:.1f} m off)".
  - Carried bodies are excluded from the owners' scan (21.10).

---

## 7. Script-callable debug functions in scope

Registered in `PostRegisterTypes` `1809ec910` through `FUN_1809beb60(name, handler, "String", args)`. All return a
String. Handlers marshal to the game thread through `FUN_1809c04e0`.

| function | args | handler | what it does (evidence) |
|---|---|---|---|
| NightCoopNpcMirror | Int32 npc# | 1809d39d0 | mirror a local NPC as a test copy: "mirroring npc #{} … under direct control, offset {:.1f} m, delay {} ms" (`1802a1c30`) |
| NightCoopNpcMirrorStop | – | 1809d4590 | stop: "stopped sharing {} npc after {} snapshot(s)" |
| NightCoopNpcMirrorSet | String, Float | 1809d4090 | tunables "offset, delay, interp, wire, record, log, effects, riders, bodyloss, bodylossdelay, backcheck, gamedeath, despawnleft, lived_copy_goes" |
| NightCoopNpcMirrorAi | Bool | 1809d3a90 | "combat mirror for copies: PuppetState.HighLevel {}; local threat injection" (`1802a1750`) |
| NightCoopNpcMirrorKey | String, Int32 | 1809d3d70 | per-input mirror, block or keep (`1802d4b00`) |
| NightCoopNpcMirrorStatus | – | 1809d4460 | copy statistics (`1802783c0`) |
| NightCoopNpcOwners / …Dump | – | 1809d46c0 / 1809d46e0 | owners table (`18030b280`) |
| NightCoopNpcOwnersOn | Bool | 1809d4920 | "sharing npcs is off; stopped sharing {} and released {}" (`1803373c0`) |
| NightCoopNpcOwnersRadius | String, Float | 1809d4af0 | interest, handoff_margin, orphan, share_limit, leader_limit, partner_circle, partner_view, crowd_each_on/max, crowd_walkers_max, stream(s) (`180339420`) |
| NightCoopNpcOwnersSet | String, Bool | 1809d4e30 | ~60 boolean rules (`1803378d0`) |
| NightCoopNpcHandoff | Int32, Int32 | 1809d35c0 | force a handoff of net id to peer |
| NightCoopNpcCrowd | Bool | 1809d3220 | crowd "local on every machine / shared by the leader" (`180337320`) |
| NightCoopNpcList / NpcDump(Int32) / NpcClear | – | 1809d38a0 / 1809d33f0 / 1809d30f0 | combatant registry (`18024c920`, `18024ac00`, `18024a950`) |
| NightCoopEnemy | String record, Float | 1809cbe80 | spawn a hostile NPC "{:.0f} m ahead", hits capped (`18044ea20`) |
| NightCoopEnemyClear / EnemyStatus | – | 1809cbfa0 / 1809cc2f0 | `1804433e0`, `180443cf0` |
| NightCoopThreats / NightCoopSenses | – | 1809e67a0 / 1809e4970 | threat and senses dumps (`1801a5360`, `1801ad4d0`) |
| NightCoopPartnerAsPlayer | Int32 | 1809d5150 | engine-player level for partner bodies (`1801b9710`) |
| NightCoopBodyHitShapes | String | 1809c92a0 | partner body hit shapes |
| NightCoopDamageLog / Gate / Status / Loopback / Replay / Stage / Suppress | Int32 / Bool / – / Bool / – / Bool / Bool | 1809ca3b0 / ca1e0 / cac10 / ca580 / ca910 / caa40 / caeb0 | section 2.3 |
| NightCoopPvp / PvpSet / PvpStatus | Bool / String, Float / – | 1809d95e0 / d97c0 / d9b00 | section 2.6, host only |
| NightCoopChallenge / ChallengeSet / ChallengeStatus | Int32 / String, Int32 / – | 1809c99c0 / c9c50 / c9f70 | section 2.7 |
| NightCoopHackStatus | – | 1809ccac0 | section 2.5 |
| NightCoopDestructionSet / DestructionStatus | String, Bool / – | 1809cb080 / cb4e0 | section 6 |
| NightCoopWanted | Bool | 1809e9560 | toggles the prevention system (police) with source "NightCoop" |
| NightCoopVehicles / VehicleTraffic / VehiclePlacement / VehicleSeats / VehicleStatus / VehicleDump | Bool / Bool / String / String / – / – | 1809e9390 / e91c0 / e8a90 / e8d90 / e9090 / e8960 | section 5 |

Strings that look like commands but are not registered here:
- `NightCoopDowned`, `NightCoopDownedShield`: gameplay tags or statuses.
- `NightCoopPolice` (see section 4).
- `NightCoopCopyHit`, `NightCoopPvp`: tags or flags on attacks, next to the damage-pipeline stage names.
- `NightCoopVehicleMirror` (`1804304f0`).
- `NightCoopMirrorSlowdown`, `NightCoopSlowdownValue`, `NightCoopPuppetDrive`: outside this scope.

### Notable switch defaults (read from `.data`)

- **NpcOwners** (`1803378d0`): `guest_npc_off`, `guest_npc_off_quest`, `guest_npc_off_story`, `guest_npc_off_riders`,
  `host_first`, `handoff_stale`, `handoff_purge`, `companion_combat_lead`, `companion_lead_hold`, `dead_identity`,
  `dead_no_puppet`, `dead_list_world`, `leader_room`, `leader_room_combat`, `leader_room_wanted`, `takedown_adopt`,
  `scene_down_keep`, `own_swap_unseen`, `twin_refind`, `player_not_npc`, `key_unique_pair` = **1**.
  `scene_entry_remove` and `companion_host` = **0**. `net_input_checks` = 1.
- **Crowd**: all `crowd_walkers_*`, `crowd_cars_gate`, and `crowd_each_*` parts = 1. Traffic shared by the leader = 1.
- **Damage**: `copy_hits_forwarded_only`, `twin_claims`, `claim_instant_kill`, `predict_lethal_only` = 1. Gate,
  suppress and loopback = 0 (`.bss`).
- **Police**: `police_host_only` = 1. A sibling flag `DAT_180dc3ce6` (*inferred* to be the chase-car/AV redirect) = 1.
- **Downed** enabled = 1. **PvP** off until the host enables it. **Challenge** off unless `challenge.txt` says otherwise.
- Numeric NpcOwners defaults are in the table in 1.2.

---

## 8. Surprising design choices

1. **Pairing twins instead of a host-spawned world.** Both machines load the same save, so the mod matches its own
   locally spawned NPC to the owner's by community key, record, place and look, then turns it into a puppet. It
   spawns network copies only when no twin exists. Much of NpcOwners is dispute resolution for this: host_first,
   late_body_yields, story_namesake, twin_refind, dressing the twin "in the owner's look", and "a guest keeps no npc of
   its own".
2. **Claims are percentages, applied as real hits.** The owner re-queues `QueueHitEvent` with the partner's body as
   instigator, so AI, reactions, quests and on-kill perks behave natively. Large amounts of code rebuild
   `EvaluateHit` reaction details (thresholds, hit timer, combo reset, zones) for remote hits.
3. **PvP splits the damage pipeline between machines** (attacker stages vs victim stages), with per-hit percentage
   caps. PvP never kills; it downs.
4. **One police squad.** The host's prevention system runs police for the guest with the higher wanted level, with
   many script redirects of spawn calls.
5. **The host runs streaming observers at distant guests** (`crowd_each`, an anchor "NightCoopHost" inserted into the
   engine's streaming list), so it can own NPCs far from its own camera.
6. **Engine-level hacks pinned to game version 2.31.** Many features check exact code layouts and turn themselves off
   on a mismatch: "not the 2.31 code", "does NOT match the code", "(2.31: +0x260)", hooks of `sub_5F7600`,
   `ForceMoveTo`. The pose blend runs on animation job threads.
7. **Raw keyboard polling.** Pass-out reads `GetAsyncKeyState('T')` directly, alongside the game's OpenChatBox.
8. **Development history is kept in the code.** Nearly every rule can be switched back to "as before <date>" behaviour
   by a named switch, and logs are full of "witness" counters (`ragdoll_fall_witness`, `release_jump_witness`,
   `tbh_witness`, `car_pair_witness`).

## 9. Limitations the logs admit

- Copies drift and fall into T-poses; the mod has detectors and resync for them ("is in a T-pose", "the root transform
  does not reach the world … placing by teleport", "JUMPED {:.2f} m in a frame (release_jump_witness)").
- Ragdolls differ between machines (`ragdoll_fall_witness`). "the death by hit data chose a ragdoll … as the game does".
- Hits without a local copy of the attacker are dropped ("no copy of the attacker here, dropped").
- The owner can refuse a lethal claim: "the game does not let it die yet", "the game never let it die".
- Two-copy problems with quest NPCs and cars: "a spawn among them made a second body", "two mirrors inside each
  other", "a removed actor lost its lines at Lizzie's" (why `scene_entry_remove` is off).
- Population and memory limits: "no room: memory or crowd_each_max", "the ball would grow past its limit", "the
  walkers' desired would pass the cap". The engine allows five streaming observers.
- Fallbacks when a game API is not found: "PhoneSystem not found", "AI_ShootAt did not run", "the gameDifficulty
  enum … not found: the AI step does nothing", "car damage is not read here".
- Client-side caps (2048 NPCs, 192 vehicles per peer) and the "refused" checks are the mod's own anti-forgery layer.
  There is no stronger authority than the host and the owner.
