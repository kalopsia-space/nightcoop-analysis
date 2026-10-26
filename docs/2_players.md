# NightCoop.dll: how the remote partner (avatar) is represented and replicated

Static analysis only (Ghidra pseudocode + raw strings). Evidence notation:
- `fn 0x1805…`: a function address in the pseudocode (`//==== <addr>`). Module labels come from `__FUNCSIG__` strings or the
  nearest module-path string. Where several modules sit next to each other the label can be off.
- `str#N`: line N of `dll/s8.txt`. Many long log strings are **not** inlined in the pseudocode. In `.rdata` they sit in
  per-module blocks next to each module's `src\<Module>.cpp` path, so the line number shows which module a string belongs to.
- Wire numbers come from the hub repo `src/ProtocolCore.hpp` (protocol `kVersion = 128`, magic `'NCOP'`).

The binary is written for game build **2.31**. Hooks check bytes against "the known 2.31 code" and stay off when the
code differs (e.g. str#17767, #18439, #18660, #42949). There are notes for 2.4+ (Glamdoc, akimbo) and 2.5 (`psm_weapon_25`). Many
switches are documented with dated "as before 21.10" texts, so the log strings read like a change log.

---

## 0. Big picture

| Layer | Module(s) | What it does |
|---|---|---|
| Sampling the local player | PlayerBridge (`fn 0x180521310` `playerbridge::Tick`), AnimTap | Reads position, yaw, camera pitch, weapons, the PlayerStateMachine blackboard and the anim-graph inputs of our player |
| Wire | net core (`fn 0x1800af570` sender, `fn 0x1800b5160` serializer, `fn 0x1800a85b0` receiver) | `PlayerState`(6) at 30 Hz, `PlayerAnim`(29)/`PlayerAnimWant`(30) anim stream, `PlayerCustomization`(33), `PlayerAnimSetup`(34), `PlayerLook`(31), `PlayerFx`(138), `CyberwareLook`(210), `PlayerCarry`(92), `PlayerWorkspot`(90), `PlayerGrenade`(99), `PlayerBlast`(131) |
| Body lifecycle | Puppets (`fn 0x18055c310` `puppets::Tick`, `fn 0x180562290` `UsePlayerBody`), BodyBuilder, RemotePlayers | Spawns a transient entity per peer from the player's own template, builds it as a remote `PlayerPuppet`, dresses it and removes it later |
| Animation | AnimMirror, "pose fix" (in the RemotePlayers block), TPP layer/legs/melee (in the SandevistanGhosts block, `fn 0x180499030`…`0x1804c3c90`) | Replays the partner's first-person anim-graph stream on the body, then corrects it with NPC third-person clip layers |
| Look | PartnerLook, Wardrobe, CyberwareLook, GenderPairs (quest side) | Customization state, clothes, gender, Johnny replacer, arm chrome palette |
| FX | PlayerFx, WeaponSound, SandevistanTrail/Streak/Ghosts, ImplantSphere | World effects, blank-shot sounds, Sandevistan visuals, a local time-dilation "sphere" |
| Physics/hit | BodyBuilder, SolidBodies, PhysicsPush, BodyHitShapes | Blocker capsules, item pusher, cloth, hit representations (PvP vs PvE) |
| UI | PlayerMarkers, Hud | World/minimap markers with name and distance, the mod's own status line |
| Camera | FppCameraGuard | Stops a partner body's seat workspot from taking over our first-person camera. **There is no third-person camera feature.** All the "Tpp" features are about how the partner's body looks |

---

## 1. Spawning and removing the partner body

### 1.1 Which entity

- **Default: the player's own template, as a remote `PlayerPuppet`.** `fn 0x180562290` (`nc::puppets::UsePlayerBody(bool)`)
  picks `Character.Player_Puppet_Base` and its `_inline0/_inline1` flats (`fn 0x180532170`, `fn 0x18054bf00`). It logs
  "puppets: player-graph bodies ON from the player's own template ({} V, '{}')". The templates are
  `ep1\characters\entities\player\player_wa|ma_fpp_ep1.ent`, or `base\…\player_wa|ma_fpp.ent` without Phantom Liberty (str#28859-28862).
  - Switch `body_no_dlc`: "a partner's body is built from the player's template of this machine" vs. "from the Phantom
    Liberty template always" (str#29545-29548).
- **Fallback: the cutscene V template.** `player_wa|ma_tpp_cutscene.ent` (`Character.TPP_Player_Cutscene_Female|Male_inline0`).
  `NightCoopRemoteTemplate(Bool)` chooses "the player's own template (player_[wa|ma]_fpp_ep1.ent, a full player)" vs "the
  cutscene V template with a PlayerPuppet root" (str#19900-19903).
- **Legacy default record: `Character.Panam`.** It is the initial value of the writable record string
  (`s_Character_Panam_180e938b8`, used in `fn 0x180562290`). The early puppet prototype spawned an NPC record, and
  `NightCoopPuppetRecord(String)` / `NightCoopPuppetTemplate(String,String)` can still set any record.
- **Puppet vs NPC switch.** `NightCoopRemotePlayer(Bool)` → `fn 0x1801f22a0`. ON: "partner bodies built from now on are
  PlayerPuppets". OFF: "new bodies will be npcs again, but {} remote player(s) are still in the world" (str#19893-19897).
  When built as an NPC: "body builder: entity {:#x} is built as the game's npc, {} component(s) kept off" (str#18049).
- **Spawning mechanics.** TweakDB records are cloned at runtime: "tweak: record '{}' created as a copy of '{}' … template '{}'",
  with names `NightCoop.{}_{:016x}`, plus gender records with `.initial = true` (str#28814-28846). The record is
  spawned as a transient entity: "GetNextTransientID returned an empty id", "puppets: peer {} registered with population
  system", "RegisterEntity failed for peer {}" (str#29021-29035). An entity-build hook (`ExtractComponentsJob hook`,
  str#18083) runs BodyBuilder on the entity *before* it attaches.

### 1.2 BodyBuilder: what is changed on the entity
(Strings str#17990-18157. Main builder `fn 0x1801649c0`, about 1080 lines. The partner-body pass is in `fn 0x180157c30`.)

- "body builder: entity {:#x} assembled on the player graph: root {}, {} animation sets ({} from extensions), … graph
  table {}, {} measuring slot(s)". The animation setup is copied from the local player (`entAnimationSetupExtensionComponent`,
  `AnimGraphResourceContainer`, `player_tpp_head`). Security-camera animation sets on `player_tpp_head` are dropped. The
  `isTPP` tag is toggled with `NightCoopBodyTpp(Bool)`: "the next body is built {} the isTPP tag".
- Partner-body pass: "{} impostor(s) told the copy is done, {} component(s) added (npc senses and hits, or the body
  controller for the skin), {} trigger activator(s) off, {} customization part(s) no longer hidden in first person, {}
  attachment slot option(s) no longer mo[ve items to the FPP weapon plane]".
- It copies or creates `senseVisibleObjectComponent` so NPCs can see the partner. Warning text: "no senseVisibleObject could
  be made; npcs will not see the partner".
- It copies `HitPhysicalQueryMesh` ("npc attacks will miss the partner" if missing) and adds a
  `gameuiCharacterCustomizationBodyController` named **`NightCoopBodyController`** ("no skin under their clothes" if missing).
- It adds two blocker capsules **`NightCoopSolidBody` / `NightCoopSolidBodyLow`** (preset "Player Blocker", switched off
  until SolidBodies turns one on) and an item pusher **`NightCoopPushBody`** (type Player, collides with
  items/destructibles) (str#18139, #18145).
- It hides shadow-only meshes (`HideShadowMeshes`) and resets render planes back to the scene plane, away from the "first-person
  weapon" plane (`SceneRenderPlanes`, `SendScenePlaneEvent` with `enteventsSetPlaneSetting`; Puppets str#29395-29416).
- **Remote-player component strip list** (RemotePlayers, str#19904-19925). These components are kept off a remote
  PlayerPuppet: `vehicleCameraManagerComponent`, `vehicleTPPCameraComponent`, `entSoundListenerComponent`,
  `WidgetHudComponent`, `WidgetMenuComponent`, `gamestateMachineComponent`, `gamePlayerCommandConsumerComponent`,
  `vehicleGarageComponent`, `gameComponentsStateSaveComponent`, `gamePlayerTierComponent`, `gamePlayerMappinComponent`,
  `gameBreachFinderComponent`, `gameTargetingActivatorComponent`, `gameVisionActivatorComponent`,
  `gameScanningActivatorComponent`, `InspectionComponent`, `DisarmComponent`, `DEBUG_VisualizerComponent`,
  `gameAudioEmitterComponent`, `senseSensorObjectComponent`, `WeaponPositionComponent`,
  `vehicleVisualCustomizationComponent`. `OnRequestComponents` is wrapped: "the inherited components plus the player's
  aim point; no player or vehicle cameras" (`fn 0x1801e7840`).
- **Third-person view on.** `nc::remoteplayers::OnBodyReady` (`fn 0x1801e6cc0`) queues `gameActivateTPPRepresentationEvent`
  on `gameTPPRepresentationComponent`: "third-person view on (ActivateTPPRepresentationEvent queued)". Cutscene template
  bodies have "no TPPRepresentation".

### 1.3 Script callbacks of PlayerPuppet that are cut for remote bodies
RemotePlayers wraps the player's scripted callbacks so the remote PlayerPuppet does not act like a second local player
(str#19716-19759). Examples:
- `OnStatusEffectApplied` and `OnStatusEffectRemoved`: "status effects touch the local UI, and Kill/Death tags would kill the body here".
- `OnTargetNeutraliziedEvent`: "the partner's kills give no experience to the local player".
- `UpdateLootInteraction`: "the partner's corpse is not lootable: its items are copies of their gear".
- `OnItemAddedToSlot` and similar: "the partner's clothes do not edit the local equipment data".
- `OnItemAddedToInventory` and similar: "no facts, journal, weight or hotkeys of the local player".
- `OnBeingTargetByLaserSight`: no sniper laser on our screen.
- `OnCarHitPlayer`: "a car hit is the partner's to take … (VehicleHit)".
- `OnDamageReceived`, `SendDamageRequestToPreventionSystem`, `CheckIfPreventionShouldReact`: partner damage does not raise the local wanted level.
- Death: "base death only; no player autosave or telemetry".

On top of this, about 30 AI script call sites are redirected to "the nearest player"
(`fn 0x1801d5550` "{} of {} player lookups redirected to the nearest player", `fn 0x1801e5690` `NearestPlayerTo`). This
covers crowd fear, perception, police and car-chase conditions (`body_vehicle_target`, `simple_combat_partner`, `partner_aim_fear`,
`police_game_path`, …). That is NPC-behaviour territory and is only noted here.

### 1.4 Spawn and lifecycle rules (Puppets, `fn 0x18055c310` Tick, str#29295-29440)
- "puppets: peer {} joined, spawning a body". The body waits for the peer's look: "waiting for their look before creating
  their body", and after a timeout "look did not come in {} s, creating their body anyway". It also waits for our world to run:
  "a body made in a stopped world gets dressed before its third-person head and stays without a face".
- **Veil.** `body_veil`, from `OnGameAttached`: the body stays hidden (game visibility source 14, dissolve kind 7) until its TPP head,
  face, items and hair have streamed in. It is then shown with the game's dissolve. There is a safety timeout (str#29249-29276, #29577).
  `fn 0x1805567d0`, `fn 0x1805643a0`.
- Face watchdog: "body lost its face … NightCoop does not remove components, the game did". It recreates the body up to N tries
  (str#29390-29431).
- **Distance cull.** "puppets: peer {} is {:.0f} m away, their body is removed until they come closer" (`fn 0x18055c310`).
- **Death.** "peer {} died: their body remains as a corpse until they respawn". "Down in a vehicle seat: their body stays in the
  seat of our copy of the vehicle … (help them up at the car: hold F next to the seat)". Revive: "gets up where they lay
  (second heart or revive): their body is revived, not recreated".
- Stuck guard: "body is stuck {:.0f} m from the partner for {} ms, it will be created again" (`fn 0x18053b5d0`).
- A look change recreates the body: "look changed, their body is created again to wear it".
- **Removal.** "peer {} left, despawning". A body in a seat workspot is removed only "after the game lets the workspot go"
  (str#29215-29224, #29469). It uses the population's dissolve despawn (`sub_97B800`, `enteventsSetDissolveVisibility`, str#29231-29239).
  Despawn is verified with "entity {:#x} STILL IN WORLD after despawn". Plans for bodies that never attached are dropped on a world
  change (`body_prepare_forget`).
- Hidden cases (Streak and Solid strings list them): a scene places them, VR training double, a braindance, NCART, a lift
  cab, a quest vehicle, a workspot, or they "play as another".

### 1.5 Johnny / replacers
- `replacer_body`: "a partner who plays as Johnny is shown here as Johnny: the photo mode's Johnny on our player's rig,
  moved by their stream (needs our own player male: our V or Johnny)". The entity is
  `base\characters\entities\player\photo_mode\johnny_photomode.ent` (`fn 0x180540ab0`), with appearances
  `silverhand_default`, `johnny_silverhand_replacer`, `silverhand_clean_2020`, `silverhand_wounded…`, `silverhand_riot`,
  `__q101_bomb_bag`, `__q108_arasaka_tower`, plus parts `hh_050_ma__johnny` and `a0_001_ma_arms__silverhand` (str#28883-29013).
  Off means "as before 18.10: a partner who plays as another is hidden here".
- BodyBuilder: "entity {:#x} is a partner who plays as Johnny: built from the photo mode's Johnny (an npc template)". Its
  visible object is forced on so NPCs see him (`replacer_body_seen`). BodyHitShapes gives it the NPC `HitRepresentation`
  "as the cutscene V's" (`hit_rep_add`, `fn 0x18016ce50`).
- `replacer_equip`: when both play the same replacer, we put on the weapon the partner holds, because "its equipment comes
  with our own save's scripted systems".

### 1.6 Gender
- Puppets: "peer {} is {}: body of their gender on their rig and animation sets". If their rig or record is not ready, "the body
  is of our gender and their look will not fit". `body_gender_live`: bodies of the other gender use their own rig.
- PartnerLook receives the partner's rig and animation sets (`PlayerAnimSetup`): "partner look: peer {} rig {:#x} and {} animation set(s)
  arrived, rig loading" (send side `fn 0x1801919f0`).
- Female bodies get male-only NPC clips (two-gun akimbo) "by rotations only, its own bone lengths kept"
  (`akimbo_clips_female`).
- GenderPairs (str#37288-37311) is a **quest-graph** feature, not an avatar feature: "a partner's branch node, fact or journal entry of the
  other side is the same step as its pair here". Male-V and female-V quest branches are treated as equivalent.

---

## 2. What player state is sent, and how it is applied

### 2.1 PlayerState (MsgType 6), 30 Hz
- `playerbridge::Tick(float)` (`fn 0x180521310`) adds up frame time against `DAT_180b66cdc = 0.0333…` (read from the DLL's .rdata),
  so the local state is sampled at **30 Hz**. Velocity is computed as delta/dt and zeroed when above `200.0` m/s (`DAT_180abd288`).
- The network thread sender `fn 0x1800af570` writes `'NCOP' | 6 | struct` when a "dirty" flag is set. It stamps the sample with the
  shared (host-synced) clock and sends on channel 0 (unreliable).
- Serializer `fn 0x1800b5160`, about 103 bytes:
  - u32 peer
  - 6×f32: position xyz, yaw, camera pitch, and one more
  - u64 time
  - u16
  - 3×u8
  - u32
  - u64: right-hand weapon ItemID
  - 5×u32/f32 (velocity and other values)
  - 13×u8 flags/states
  - u32
  - 2×u8
  - u64: left-hand weapon ItemID
  - u32
  - u8

  The flags carry the PlayerStateMachine blackboard values: "player bridge blackboard: locomotion={} upperBody={} weapon={}
  dilation={} vehicle={} combat={} vitals={}" (`fn 0x18051f0d0`). Also included: magazine ammo, melee/leap/body-slam
  ("player bridge motion and melee: detailed={} meleeWeapon={} meleeLeap={} bodySlam={}"), optical camo, the quest fist fight
  restriction, and our stat Visibility ("partners' npcs see our body with it").
- The receiver `fn 0x1800a85b0` checks the data: "a player state for another peer's number", "a number that is not finite came"
  (str#16814-16816).
- A script entry `NightCoopSubmit(Float x,y,z,yaw,pitch)` (`fn 0x1809e65d0`) can also submit a state, for scripts and tests.
- **Second weapon (2.4+ akimbo).** "two weapons (2.4+): our second weapon goes to partners, theirs is put in the left hand of their
  body here (slot WeaponLeft)" (`akimbo_body`, `akimbo_fire`).

### 2.2 Applying the state to the body (Puppets, `nc::RemoteSample`)
Per-sample appliers: `ApplyStance` `fn 0x180536c70`, `ApplyWeapon` `fn 0x180537680`, `PlaceWeapon` `fn 0x180549fc0`,
`PlaceLeftWeapon` `fn 0x180549020`, `ApplyDilation` `fn 0x1805364e0`, `MoveTo` `fn 0x180547930`, `EnsurePolicy`/`PolicyAdvance`
`fn 0x18053dad0`/`0x18054c400`, `ShootForward` `fn 0x18055aec0`.

- **Drive modes.** `NightCoopPuppetMode(String)`: "ai, teleport, direct, policy". AI uses `AIMoveToCommand`/`AIRotateToCommand`.
  Policy uses `movePoliciesComponent`. Direct uses root-transform placement.
  - `NightCoopPuppetPlacer(String)`: "teleport, transform".
  - `NightCoopPuppetDrive(Bool)`: "prepared for direct drive, movers off: {}, CanLocomotion opened: {}".
  - Fallbacks: "move policy unavailable, falling back to teleport", "peer {} is {:.1f} m behind, teleporting from …".
- **Smoothing.** "its place goes from {} to {}: {:.2f} m apart, eased over ~0.3 s" or "set at once (a move, not a seam)". The source
  is "our cab's frame" (a lift), "the vehicle seat" or "their snapshots" (str#29166-29172).
  - `body_root_keep`: a body the game moves off our root transform gets "who holds it: mover, motion planner, the game's
    workspot, mounted by the game" logged, and is put back under the transform without teleporting.
- **Locomotion** is fed to the graph as anim features: "peer {} locomotion -> style {} action {} at {:.2f} m/s, direction {:.0f} deg".
- **Weapons.** The weapon is given and attached in `AttachmentSlots.WeaponRight/Left`.
  - `body_weapon_npc`: the weapon is set up as an NPC weapon (third-person VFX set, ExitShoot when the partner stops firing).
  - `body_weapon_reload_fx`: EnterReload/ExitReload on the body's weapon.
  - `grenade_follow_slot`: a grenade stays in the right hand.
  - Firing: "peer {} fires real rounds (the local player is excluded from hits)", or falls back to effects (`AI_ShootForwards`,
    `AddObjectToIgnoreCollisionWith`). `NightCoopPuppetBullets(Bool)` toggles real rounds, `NightCoopPuppetFire(Bool)` toggles effects.
- **Time dilation.** "peer {} uses an implant, the body ignores world slowdown", and later "follows world time again". During a scene
  fast-forward that runs only here, the body keeps its own time (str#29149-29157).

### 2.3 Animation stream: AnimTap → PlayerAnim(29) → AnimMirror
- **AnimTap** (str#17596-17670; Install `nc::animtap::Install`) hooks `entAnimationControllerComponent` input writes on the watched
  player graphs: `player_ranged`, `player_melee`, `player_vehicle`, `player_locomotion`, `player_inspection`, `player_interaction`,
  `player_carrying`, `player_adhoc` (`.animgraph`).
  - It records features, floats, ints, bools, vectors, quaternions, events, wrappers and attach/detach. Debug output:
    "tap: [{}] feature '{}' <{}> x{} ({} changed, {:.1f}/s)".
  - The same tap feeds NPC copies (loco_seed, owner_poll_lean).
  - `NightCoopAnimTap(Int32 seconds)` records. `NightCoopAnimProbe()` runs a probe.
- **Mirror.** "mirror: body {} repeats partner {}'s animation stream, {} ms behind plus its network lag" (`fn 0x18013ce50`). There is a
  fixed number of body slots: "mirror: all {} body slots are taken: partner {} gets no animation stream".
  - Full state: "mirror: sent partner {} the full state of your {} ({} + {} input(s))" (`fn 0x180148140`). A late or desynced body
    asks for it with `PlayerAnimWant`(30).
  - Status: "mirror: partner {} stream: {} batch(es), {} input(s), {} full state(s), {} undecodable, {} dropped".
- **Design choice.** The partner body runs the *player's own first-person graph* (BodyBuilder "assembled on the player graph"). It replays the
  remote player's raw graph inputs, rather than mapping state to NPC animations. The rest of the system works around the gaps this leaves
  (§2.4).
- **Vehicle handling in the mirror** (str#17676-17983):
  - TPPRepresentation branch edges: `tpp_game_edge`, `tpp_edge_hold`, `tpp_edge_new_body`, `branch_with_vehicle`.
  - `seat_graph_hold` keeps "in the vehicle" until the body's own exit clip starts.
  - `seat_wrap_body` keeps the local seat's wrappers.
  - `steer_feed`: the hands follow the steering wheel via `VehiclePassenger.inputLR`.
  - Driver combat uses the graph's `ProceduralDriverCombatData` "aimed by their camera".
  - `seat_combat_entering`: the window clips start at the partner's `isEnteringCombat`.
  - Other mirrored state: AdHoc gestures (Blackwall cast: the left arm plays the NPC gesture clip), PlayerVitals/StatusEffect knockdowns,
    and a `graph_ref_release` "kick" (a StatusEffect pulse) when the graph falls into the rig's reference T-pose.
- **LOD.** "mirror: the full view (pose fix and clip layers) goes to the nearest {} bod(ies)" ("(default under Wine)" vs "(default)"), so
  the default depends on Proton/Wine detection via `wine_get_version`. Farther bodies "keep only the animation stream (no clip layers:
  first-person poses)".
- Debug functions:
  - `NightCoopMirrorDump()`, `NightCoopMirrorBodies(Int32)`
  - `NightCoopMirrorSpine(String)`: "graph, rigid or tpp"
  - `NightCoopMirrorFloat/Bool(String,…)`, `NightCoopMirrorFloatClear`: override graph inputs "on top of your stream"
  - `NightCoopMirrorSlowdown(Bool)`
  - `NightCoopAnimEvent/Input/Feature/Duration/Wrapper` and `NightCoopPuppetAnim/Graph(Bool)`: the "lab:" pushers (str#29493-29505)

### 2.4 Fixing a first-person graph on a third-person body
- **Pose fix** (RemotePlayers block, str#20003-20079; `fn 0x180200fe0` "correcting the pose", `fn 0x180200af0` mode). This is a hook on
  the graph write-back on the anim job threads.
  - Modes: "off, proportions, ik or lowready".
  - Parameters: lean, leanRun, yawLimit, roll, chestLevel, headLevel, bob, weaponForward, lowAngle, lowBack, seatHeadLook.
  - Corpse and seated bodies use the graph's own pose. In a seat "its head turns to the partner's look (seatHeadLook)".
  - `reference_pose_witness` logs T-poses that are shown or hidden.
- **TPP layer** (upper body): NPC clips are layered on the body by weapon class, e.g.
  `base\animations\npc\gameplay\{rig}\corpo\{weapon}\…_action_combat.anims` and `ma_gang_handgundual_action_combat.anims` for akimbo.
  - "tpp layer: {} rig mapped onto the body rig: {} upper-body bone(s) …".
  - `reload_by_weapon` matches the reload pace to the weapon's reload time.
  - In cars: seat combat clips (`base\animations\vehicle\{}\…`), `seat_grip`, with phases startup/loop/recover/reload/recoil.
  - `NightCoopTpp(Bool)` → `fn 0x1804abbc0` ("tpp layer on/off"). Also `NightCoopTppStatus`, `NightCoopTppClip(path,clip)`,
    `NightCoopTppProbe(path,clip,t)` (samples bones: "tpp probe: T=(…) R=(…)"), and `NightCoopTppSet(name,val)` with names yaw,
    chestPitch, chestShare, headPitch, idleFollow, recoil, reloadRate, seatGrip.
- **TPP legs.** Lower-body locomotion from NPC clips (`gang_unarmed_locomotion_*`, `corpo_smg_locomotion_*`).
  - `kneel_fit` makes the body kneel in a partner's sunk workspot. `vehicle_flag_watch` is also part of it.
  - `NightCoopTppLegs(Bool)`, `…LegsStatus`, `…LegsStyle("auto"|"relaxed"|"combat")`, and `…LegsSet` with names lockRange, rateMin,
    rateMax, smooth, jumps, headPitch, style, combatHold, sideChest, steps, rateBack, kneel.
- **TPP melee.** Melee attack clips are mapped from NPC katana/knife/blunt/strongarms/mantis sets (melee_combo_*, melee_heavy_*,
  deflect_*). Also: hit reactions `add_body_hit_*_upperbody`, a Blackwall gesture reach (`blackwall_body_reach`), and consumable
  (`tpp_injector_01_armed`) and bike clips (`fn 0x1804bfce0`).
  - `NightCoopTppMelee(Bool)`, `…MeleeStatus`, `…MeleeSet` with names twist, tilt, chestShare, rate, consumableSeat, relaxMoveAside.
- In short, "TPP" here means **third-person animation of the partner's body**. It is not a camera mode.

### 2.5 Vehicle seating of the avatar
- Bodies are put into the seat workspot of our mirror of the vehicle (VehicleSeat 63). Logs: "peer {} body in net id {:#010x} {}: in the
  seat workspot … hips {:.2f} m above the root, vehicle graph {}"; "switches seats {} -> {} with the seat clip (switch_seat)"; door
  and exit clips (`door_body_seat`); `seat_share` "one player shown per seat"; `body_seat_hold` (Vehicles block str#24897-26026).
- `body_car_aim`: while we shoot from a vehicle, a partner body in it that is under our sight is hidden with its hit shapes off, so our
  shots go through it, and it gets `BaseStatusEffect.IgnoreWeaponSafe` so our weapon is not lowered.
  - `body_aim_only` hides it only while aiming or shooting. `body_aim_contour` uses a camera ray against capsules on the bones.
    `body_aim_fade` uses the game's dissolve (str#29282-29295, #29553-29567).
  - `hidden_body_no_safe` does the same for bodies hidden by scenes.

### 2.6 Echo twin (solo test)
`NightCoopEcho(Bool)`, `NightCoopEchoDelay(Int32 ms)`, `NightCoopEchoOffset(Float m)` and `NightCoopEchoStatus` spawn a local twin of our own
player. The twin replays our own stream after a delay with a sideways offset: "echo: the twin is live, {} ms behind you, {:.1f} m to your right"
(`fn 0x1805663f0`). The twin can wear a different look (`NightCoopLookTest`) and get a marker.

---

## 3. Look, equipment and FX replication

### 3.1 Customization: PartnerLook (PlayerCustomization 33, PlayerAnimSetup 34)
- `ReadOwn(nc::proto::PlayerCustomization&)` serializes `gameuiCharacterCustomizationState`: head groups, perspective info, parts,
  morphs and tags ("{} groups, {} parts, {} tags, {} bytes"). It is sent as "partner look: our look is {}: sending it to partners".
  Receive: "peer {} look arrived". Size limits: "refused customization exceeding PlayerCustomization::Write bounds".
- **How a body gets someone else's face.** The game resolves customization through *one* global character customization
  system (our V). PartnerLook hooks `GetState`/`GetState(isMale)`/`GetPreviousState` at several call sites
  (`exe+0x961a61`, `exe+0x2aa7549`, `exe+0xaac79a`, …; str#18464-18484). Inside a partner body's scope each call is answered with that
  peer's state: "partner look: {} of body {:#x} paints with the look of peer {}".
  - `look_entity_scope` attributes parts to their owning entity (EntityID +0x28/+0x38 in jobs). It can be turned off
    in `switches.txt` at start.
  - `look_other_gender`: a part of the other gender asking outside any scope gets "the look of the only partner body of that gender".
  - `look_world_reset`.
  - Debug output shows symptoms of mis-scoping: "{} hairstyles on at once", "{} skin tones on one body".
- **Own gender and the menu doll.** `own_gender_sync`, `own_gender_settled`, `own_doll_gender`, `doll_rebuild`, `doll_rebuild_arrival`. In the
  host's world our V's `gamePuppetPS.gender` comes from the host's save. NightCoop calls `gamePuppetPS::SetGender` (or writes the
  field) so "the menu doll, the TPP view and the body controllers" match our body (str#18578-18640).
- Debug: `NightCoopLook()` and `NightCoopLookTest(String,String)` (echo double look swap: "echo double gets our look with '{}' -> '{}'").

### 3.2 Clothes: Wardrobe and Puppets (PlayerLook 31)
- "wardrobe: local look: {} V, censored {}, genitals {}, arms {:#x}, clothes:{}". Read via `EquipmentSystem`, `GetVisualItemInSlot`, `IsBuildCensored`,
  `ShouldShowGenitals` (`fn 0x180518850`). Sent as "puppets: your look ({} item(s)) goes to partners". Received as "peer {} look
  received: {} V, {} item(s)".
- Applied with `GivePreviewItemByItemID`/`CreatePreviewItemID` into slots `AttachmentSlots.TppHead/Head/Eyes/Chest/Torso/Legs/Feet/Outfit`.
  Dressing waits for the third-person head ("clothes put on before it leave the body without a face").
- `wardrobe_arms_tpp` changes arm items `'&FPP' -> '&TPP'`. `body_no_dlc` skips items whose record this machine lacks.
- Debug: `NightCoopPuppetDress()`, `NightCoopPuppetGive(String,Bool)`, `NightCoopPuppetAppearance(String)`,
  `NightCoopPuppetVisuals(Bool)`, `NightCoopPuppetComponent(s)/ComponentClass`.

### 3.3 Cyberware look (CyberwareLook 210)
"our Glamdoc arms chrome is read every 2 s and sent to partners". The style rides the customization state; the palette is separate.
The game allows one Glamdoc palette per scene, so with `cw_palette_borrow` our scene borrows the partners' palette
(`SetCustomizationParameters`) only if our V wears none, and restores it with `RestoreCyberwareCustomization(false)` (str#18749-18837). Options:
`cw_look`, `cw_palette_borrow`.

### 3.4 Effects
- **PlayerFx (138).** World effects drawn by our player's effect nodes (`VisualEffect`, `VisualEffectAtInstigator`, `GroundSlamEffects`,
  `VisualEffectAtPosition`, `EffectScriptContext.SpawnEffect`) are captured and sent. Partners show them with
  `gameFxSystem.SpawnEffect`: "picture and sound, no damage". Examples: arm launcher, rockets, explosive rounds, ground slams,
  landings, ricochets. Options: `fx_mirror`, `fx_grenades` (grenades off by default to avoid double blasts), `fx_log`. Debug:
  `NightCoopFxStatus()`.
- **WeaponSound.** A hook (`sub_9D69DC`, `gameWeaponAudio`) lets a *blank* shot of a partner body or NPC copy play the weapon's
  shot sound. The mode comes from the weapon record's primary trigger mode (FullAuto → 'automatic', otherwise 'single';
  `shot_mode`). Toggle: `NightCoopNpcMirrorSet("shot_sound", 0)` (str#42938-42983).
- **Sandevistan.**
  - SandevistanTrail: Smasher's dash ribbons `ch_npc_sandevistan_trail_left/right.effect` and Oda's echo loop
    `ch_oda_sandevistan_loop.effect` are added as `entEffectDesc` to the body's `entEffectSpawnerComponent` at build time. They run
    while the partner's implant is active, with spacing by body or world time and caps on live ribbons.
  - SandevistanStreak: a spawned entity (`NightCoop.SandevistanStreak`, named `NightCoopStreak_{}_{}`) of mesh segments that draws a
    neon, laser or hologram trail. Palettes: Kabuki_Green, rey02_red, CHA_Purple, JPN_Blue, JT_toxic_yellow. Self mode: "always behind
    you / behind you while your implant runs".
  - SandevistanGhosts: up to N afterimage entities (`NightCoopGhost_{}`) whose skeletons copy the body's pose each frame (a pose table
    on the anim threads). They use a loot-highlight or cloak material as a silhouette or overlay.
  - Debug: `NightCoopSandevistanTrail(Bool)`, `NightCoopSandevistanTrailSet(name,val)` with names ribbons, echo, period, max, life,
    clock, list, streak, self, look, color, segments, lines, length, width, taper, height, age, fade, mask, palette, graph, and
    `NightCoopSandevistanTest(x,y,z)`.
- **ImplantSphere: time dilation is local.** "implant sphere: the implant acts only inside the spheres" vs "on the whole world, as in
  the game". A sphere (`fx_basic_sphere.mesh`, `holo_blue_glitch`, dust `e_dust_motes_and_thick_dust_strong.effect`) is spawned
  around the implant user. People inside are slowed, people outside are "freed" (given their own time) (`fn 0x18046a430`, str#26857-26917).
  Debug: `NightCoopSandevistanSphere(Int32)`, `…Radius(Float)`, `…Zone(Bool)`, `…Dust(Bool)`. This is how one player's Sandevistan
  avoids slowing the other player's whole world.
- **TeamBuild** (BuildStats 141), in scope only loosely: attribute, level and street-cred checks count "the best of everybody in the host's
  world" via a wrap on `RPGManager.GetBuildScore` and native `questStat_ConditionType`/`questStreetCredTier_ConditionType`. Switches:
  `build_checks_any`, `build_checks_native`.

---

## 4. Collision, physics, hit shapes, markers

### 4.1 SolidBodies
- Modes: `NightCoopSolidBodies("pvp"|"on"|"off"|"status")`. "pvp" means "partner bodies are solid for our player only while the host has PvP
  on" (str#42589-42699).
- The body's `NightCoopSolidBody` capsule (or `…Low` when crouching or sliding) is toggled through `entIComponent.Toggle`.
- It is turned off for: a teleport or catching up, standing on top of the body, being "deep inside our player", a vehicle, scenes, lifts,
  downed state ("a lying body is stepped over, and the revive prompt stays reachable"), connection loss, and VR doubles. It comes back
  "solid again once apart".
- It checks that the physics proxy is at the body (`CreatePhysicalBodyInterface`): "its capsule stands {:.2f} m off the body (a stale place)".

### 4.2 PhysicsPush
- `blast_push`: our grenade explosions (a wrap on `BaseGrenade.Detonate`) are sent (PlayerBlast). Partners call `SpawnPhysicalImpulse`
  "without damage".
- `body_push`: the body's `NightCoopPushBody` capsule (Player collision type) pushes items and breaks glass.
- `body_cloth`: the world cloth query group finds partner bodies "as it finds our player's character controller: curtains and flags
  swing off them".
- Collision group bits are read from the game presets and sanity-checked ("PlayerBlocker 0x4000"). Option names: blast_push, body_push,
  body_cloth, physics_log (str#39318-39440).

### 4.3 BodyHitShapes (PvP vs PvE)
- Modes: `NightCoopBodyHitShapes("npc"|"always"|"player"|"add_on"|"add_off"|"status")`.
- Bodies carry both the player's three boxes (the head box sits on the FPP camera bone) and the NPC set from
  `base\characters\base_entities\npc_base\npc_base.hitrepresentation` (head, torso, arms and legs with hit zones). They also get a
  small sphere where NPCs aim (`NightCoopAim`).
  - **Mode npc**: the NPC set is live while the host has PvP on and the player's boxes otherwise.
  - **Mode always**: the NPC set is always live.
  - **Mode player**: the 03.10 behaviour, boxes only.
- Switching uses the game's `gamehitRepresentationEventsToggleHitShapeEvent` (str#18184-18373; `fn 0x18016ce50`).
- `body_car_aim` removes all hit shapes while the body is hidden under our sight from our vehicle.

### 4.4 Markers, nameplates, HUD
- **PlayerMarkers.** An ink canvas `NightCoopPlayerMarkers` in the HUD window holds one `NightCoopPlayerMarker` per peer. Each shows the
  name (from `NightCoopName(String)`) and the distance in metres, uses `ProjectPoint` with the camera axes, and clamps to the screen edge.
- Map pins use `RegisterMappinWithObject` with `Mappins.CPO_RemotePlayerMappinDefinition` / `CPO_RemotePlayerVariant` on the body, and
  `MinimapPOIMappinController` with the `codex_character` icon from `mappin_icons.inkatlas` (`fn 0x18058f960`; str#29847-30031).
- Settings file `markers.txt` ("# NightCoop: player markers (1 on, 0 off)"; `fn 0x180591360`/`0x180591d40`). Console:
  `NightCoopMarkers("on"|"off"|"world"|"map"|"world on|off"|"map on|off"|"echo"|"status")`. Option `markers_profile_scripted`.
- Markers are hidden in menus, scenes or dialogue, when not in one world, or when there is no body.
- **Hud.** Mod messages go to a quiet `NightCoopStatusLine` at the left of the HUD, or to the top centre or the middle of the screen.
  Placement: `NightCoopHudPlace(left%, top%, size, width%)`. Keys: `hud_left`, `hud_layers`, `hud_center`, `hud_quiet`, `hud_wait_delay`,
  `hud_forced_witness`. It also fixes Cyrillic fonts for partners' texts.

---

## 5. Camera

- **No third-person camera** for the local player was found. The only TPP camera string is the component
  `vehicleTPPCameraComponent`, which is *stripped* from remote bodies.
- **FppCameraGuard** (str#18374-18462). This hooks the seat workspot camera action (`PlayerUseWorkspot`) start and end. Each patch site is checked against
  the 2.31 bytes and the fields it writes (+0x464 seat mode, +0x474, +0x4BC, +0x4D0, +0x4D4, [+0x360]+0xC1/+0xEC). When a partner body
  (built as a PlayerPuppet) sits down, its seat action could take *our* `gameFPPCameraComponent`. With `fpp_camera_foreign`, "another live
  entity's camera (our player's) in the seat action of a partner's body or an npc is taken out, what the start wrote into it put back". An
  ownerless camera is also taken out (the "exe+0x520F84 crash after VR"). Switches: `fpp_camera_guard`, `fpp_camera_foreign` (both via
  `NightCoopQuestSet`). It also reports "the body of peer {} has a first-person camera among its components" (BodyBuilder builds without one).

---

## 6. Game classes, functions and script entry points used

**RTTI classes and functions named in strings** (selection):
- Puppet and AI: `PlayerPuppet`, `PlayerPuppetPS`, `gamePuppetPS::SetGender`, `ScriptedPuppet`, `AIMoveToCommand`, `AIRotateToCommand`,
  `AIPositionSpec::SetWorldPosition`, `movePoliciesComponent` (`SetDestinationPosition`, `SetIgnoreNavigation`, `SetMovementType`…),
  `entAnimInputSetterAnimFeature`, `entAnimExternalEvent`, `IPlacedComponent::SetTransform` (found by signature),
  `gameweaponObject::TriggerWeaponEffects`, `gameweaponeventsShootEvent`, `SetWeaponOwner`, `AI_ShootForwards`,
  `gameeventsResurrectEvent`, `enteventsSetDissolveVisibility`, `enteventsSetVisibility`.
- Visuals: `gameTPPRepresentationComponent`, `gameActivateTPPRepresentationEvent`, `gameuiCharacterCustomizationSystem`,
  `gameuiCharacterCustomizationBodyController`, `gameCyberwareCustomizationSystem`, `EquipmentSystem`, `gameHitRepresentationComponent`,
  `entColliderComponent` / `physicsColliderCapsule`, `senseVisibleObjectComponent`, `entEffectSpawnerComponent`,
  `entRenderOverlayEvent`, `entMorphTargetManagerComponent`, `gameFxSystem`, `gameEffectSystem`, `gamemappinsMappinSystem`,
  `gameFPPCameraComponent`, `AnimFeature_VehicleData` / `VehiclePassenger` / `ProceduralDriverCombatData` / `StatusEffect`.
- PlayerBridge: `PlayerStateMachineDef` blackboard fields (Locomotion, LocomotionDetailed, UpperBody, Weapon, RightWeapon, LeftWeapon,
  MeleeWeapon, CombatGadget, Combat, Vehicle, TimeDilation, Vitals), `MagazineAmmoCount`, `OpticalCamoIsActive`, `GetPlayer`,
  `GetLocalInstanced`.
- **Engine internals**: hooks by exe RVA from an "address library", with byte checks. Examples: menu doll `sub_AC8294`, TPPRepresentation
  `sub_9FE5F4 -> sub_1841748, sub_A414A4`, weapon audio `sub_9D69DC`, population despawn `sub_97B800`.

**Script-callable functions related to this scope** (registered in `PostRegisterTypes` `fn 0x1809ec910`. Each wrapper forwards to a
module function, e.g. `NightCoopTpp`→`fn 0x1804abbc0`, `NightCoopRemotePlayer`→`fn 0x1801f22a0`, `NightCoopScriptPlayer`→`fn 0x1801ba1f0`
`npctargets::SetScriptPlayer`, `NightCoopPartnerAsPlayer`→`fn 0x1801b9710`):

| Group | Functions (signature) |
|---|---|
| Puppets | `NightCoopPuppets()`, `PuppetsEnable(Bool)`, `PuppetTest(F,F,F)`, `PuppetClear()`, `PuppetRecord(S)`, `PuppetTemplate(S,S)`, `PuppetMode(S)`, `PuppetPlacer(S)`, `PuppetDrive(Bool)`, `PuppetAnim(Bool)`, `PuppetGraph(Bool)`, `PuppetBody(Bool)`, `PuppetFire(Bool)`, `PuppetBullets(Bool)`, `PuppetComponent(S,Bool)`, `PuppetComponents()`, `PuppetComponentClass(S,Bool)`, `PuppetVisuals(Bool)`, `PuppetDress()`, `PuppetGive(S,Bool)`, `PuppetAppearance(S)` |
| Remote/identity | `NightCoopRemotePlayer(Bool)`, `NightCoopRemoteTemplate(Bool)`, `NightCoopRemoteInfo(Int32)`, `NightCoopScriptPlayer(Bool)` (whether `GameObject.IsPlayer` is true for bodies), `NightCoopPartnerAsPlayer(Int32)` (engine-player level: "plain npcs", "player-controlled bit", "bit, peer and sense type Player"), `NightCoopName(S)`, `NightCoopSubmit(F×5)` |
| Anim | `NightCoopAnimTap(I)`, `AnimProbe()`, `AnimEvent(S)`, `AnimInput(S,S,S)`, `AnimFeature(S,S,S)`, `AnimDuration(S)`, `AnimWrapper(S,F)`, `MirrorDump()`, `MirrorBodies(I)`, `MirrorSpine(S)`, `MirrorFloat(S,F)`, `MirrorFloatClear(S)`, `MirrorBool(S,Bool)`, `MirrorSlowdown(Bool)`, `BodyTpp(Bool)` |
| TPP | `NightCoopTpp(Bool)`, `TppStatus()`, `TppProbe(S,S,F)`, `TppClip(S,S)`, `TppSet(S,F)`, `TppLegs(Bool)`, `TppLegsStatus()`, `TppLegsSet(S,F)`, `TppLegsStyle(S)`, `TppMelee(Bool)`, `TppMeleeStatus()`, `TppMeleeSet(S,F)` |
| Look | `NightCoopLook()`, `NightCoopLookTest(S,S)` |
| FX | `NightCoopFxStatus()`, `NightCoopSandevistanTrail(Bool)`, `…TrailSet(S,F)`, `…Test(F,F,F)`, `…Sphere(I)`, `…Radius(F)`, `…Zone(Bool)`, `…Dust(Bool)` |
| Physics/hit | `NightCoopSolidBodies(S)`, `NightCoopBodyHitShapes(S)` (PhysicsPush options go through the option setter, see §7) |
| UI | `NightCoopMarkers(S)`, `NightCoopHudPlace(F,F,F,F)` |
| Echo | `NightCoopEcho(Bool)`, `EchoDelay(I)`, `EchoOffset(F)`, `EchoStatus()` |

Names that look like functions but are **not**: `NightCoopSolidBody`, `NightCoopSolidBodyLow`, `NightCoopPushBody`, `NightCoopBodyController`,
`NightCoopAim` and `NightCoopGhostMorphs` are component or slot names. `NightCoopPlayerMarker(s)` and `NightCoopStatusLine` are ink widget
names. `NightCoopGhost_{}`, `NightCoopStreak_{}_{}` and `NightCoop.Sandevistan*` are entity or record names. `NightCoopBody` is a forced-visibility source.

---

## 7. Switches (names seen; `switches.txt` "name = on|off", or `NightCoopQuestSet(name,bool)`)

Defaults are mostly **not** readable from strings. The texts describe ON versus "as before <date>". Where a default is
visible it is noted below.

- **Bodies (Puppets).** body_veil, body_root_keep, body_weapon_npc, body_weapon_reload_fx, body_car_aim, body_aim_only,
  body_aim_contour, body_aim_fade, hidden_body_no_safe, body_prepare_forget, body_no_dlc, body_gender_live, replacer_body,
  replacer_body_seen, replacer_equip, grenade_follow_slot, reload_by_weapon, down_immortal_override.
- **Hit shapes.** hit_rep_add (`NightCoopBodyHitShapes("add_on"|"add_off")`).
- **Look.** look_entity_scope (only at start, from switches.txt), look_other_gender, look_world_reset, own_gender_sync,
  own_gender_settled, own_doll_gender, doll_rebuild, doll_rebuild_arrival; wardrobe_arms_tpp; cw_look, cw_palette_borrow.
- **PlayerBridge.** psm_weapon_25, akimbo_body, akimbo_fire, akimbo_clips, akimbo_clips_female.
- **Mirror.** tpp_game_edge, tpp_edge_hold, tpp_edge_new_body, branch_with_vehicle, seat_graph_hold, seat_wrap_body,
  seat_combat_entering, steer_feed, graph_ref_release, body_weapon_npc. Full-view body count: the default differs under Wine.
- **TPP.** reload_by_weapon, seat_grip, akimbo_clips(_female), kneel_fit, vehicle_flag_watch, blackwall_body_reach.
- **NPC targets for bodies.** body_stealth, body_visibility, body_crouch_point, body_tbh_effectors, body_anim_offscreen, body_fist_fight.
- **RemotePlayers AI.** body_vehicle_target, simple_combat_partner, partner_aim_fear, body_blame_friends, upload_body_no_lock,
  hostile_restore_on_leak_only, hostile_burst_quiet, copy_own_reactions_off, police_* (out of scope).
- **FX.** fx_mirror, fx_grenades, fx_log; shot_sound and shot_mode (`NightCoopNpcMirrorSet`); Sandevistan trail/streak/ghost settings
  (§3.4).
- **Physics.** blast_push, body_push, body_cloth, physics_log. SolidBodies mode pvp/on/off.
- **Camera.** fpp_camera_guard, fpp_camera_foreign.
- **HUD and markers.** hud_left, hud_layers, hud_center, hud_quiet, hud_wait_delay, hud_forced_witness; markers.txt;
  markers_profile_scripted.
- **TeamBuild.** build_checks_any (shown as on, "NightCoopQuestSet("build_checks_any", false) — our V's own"), build_checks_native.

---

## 8. Surprising or notable design choices

1. **The partner is a second `PlayerPuppet`, not an NPC.** It is built from the local player's own `.ent` template, with about 20
   player-only components stripped, dozens of player script callbacks cut, and about 30 AI call sites redirected to the "nearest player".
   An NPC-record mode (legacy default `Character.Panam`) still exists behind `NightCoopRemotePlayer(false)`.
2. **The animation replicates raw anim-graph inputs** of the player's first-person graphs (AnimTap → AnimMirror) and replays them on a
   body running the same graph. The gaps (no third-person upper body, T-poses, seats) are then patched with NPC clip layers (TPP
   layer/legs/melee) and a pose-fix hook on the anim job threads. This is the single largest subsystem.
3. **Faces and clothes come from hooks on the global customization system.** `GetState` calls are re-answered per entity at hard-coded
   2.31 RVAs, because the game assumes there is only one V. Two partners of the same gender, or a gender mismatch, needed special rules
   (`look_other_gender`, menu-doll rebuild).
4. **Sandevistan is localised.** World time dilation is limited to a sphere around the user (ImplantSphere), and the partner's body ignores
   our world slowdown. Visual trails are made from Smasher/Oda boss effects, custom streak meshes and pose-copied ghost entities.
5. **There is no third-person camera.** Everything named "Tpp" is about the partner's body. The only camera code (FppCameraGuard) protects our
   FPP camera from being taken over by a partner body's seat workspot. That workaround follows from making bodies real PlayerPuppets.
6. **Hit shapes depend on PvP.** Bodies carry both the player's boxes and the NPC hit representation, swapped live with the game's toggle event
   when the host turns PvP on. Solid collision also defaults to "pvp" semantics.
7. **The state rate is fixed at 30 Hz.** There is no delta compression of PlayerState. Bodies are eased (~0.3 s) or teleported, a stuck body is
   recreated, and bodies far away are despawned rather than LOD-ed. Clip layers are LOD-ed to the "nearest N".
8. **Wine/Proton-specific defaults** (`wine_get_version`) for the mirror's full-view count and the Sandevistan streak.
9. **There is a lot of self-diagnostics.** Most features log "witness" counters and "as before <commit/date>" fallbacks, and several hooks verify
   code bytes or RTTI layouts and disable themselves on mismatch.
