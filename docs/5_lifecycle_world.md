# NightCoop.dll: plugin lifecycle, world and save sharing, inventory and loot, infrastructure

Scope: build `a7c537d` (built "Oct 23 2026 17:26:20", protocol 128). This is static analysis of the Ghidra pseudocode and string tables only. The DLL was never run. Quoted strings are the mod's own log and description texts. Addresses are `FUN_…` entry points in the pseudocode.

Notation: "host" means session role 1 and "guest" means role 2. The session state object comes from `FUN_1800a6b20()`: `+0x28` is "session active" and `+0x24` is the role. This was confirmed in `FUN_18090a640`/`FUN_18090c8c0`, where role 1 maps to "host" and role 2 to "guest".

---

## 1. Startup and hooking

### 1.1 RED4ext exports

| Export | Addr | What it does |
|---|---|---|
| `Query` | `1809f0140` | Fills in PluginInfo: name and author both `L"NightCoop"`, version field `0x10000`, SDK 1. **Runtime version = the file version of the detected game exe.** If the exe is unknown, it reports the 2.5 entry (index 1) anyway, so RED4ext never refuses to load the mod; the mod then decides for itself whether to go passive (see below). |
| `Supports` | `18003c4a0` | `return 1` (always supported). |
| `Main` | `1809eb920` | Load/unload (described below). |
| `RegisterTypes` | `1809f01f0` | Registers the `NightCoop` RTTI class. |
| `PostRegisterTypes` | `1809ec910` | Registers about 240 global script natives, `NightCoopHost`, `NightCoopJoin`, … `NightCoopProbeResource` (full list in §1.5). |
| `NightCoopAddonApi` | `180934380` | Add-on API for the "NightReplay" companion plugin (§1.6). |

### 1.2 Game version gate

- Supported exe file versions are hard-coded in a table at `0x180a997b8`, matched in `FUN_1800fa170`:
  - **"2.31" = exe 3.0.80.51928**
  - **"2.5" = exe 3.0.88.46235**

  Both entries have their "full mode" flag set.
- `FUN_1809e9b60` decides passive or full mode:
  - Any other exe → **PASSIVE**: "the mod's port to it is not finished: PASSIVE, no hooks and no types, only the RTTI names file is written (port-test.txt next to the dll forces the full mode)".
  - In passive mode, `Main` only calls `gameapi::InstallNamesOnly` (`1801143c0`). That writes `rtti-names-<ver>.txt` ("# NightCoop: RTTI names of this game build (tools/names/check_names.py)", `180117140`). On unload it logs "NightCoop unloaded (passive on game {})".
- The code is written against 2.31. Hundreds of hooks check their target bytes first ("is the known 2.31 code" / "{} differs from 2.31 at +{:#x} (want {})"). Support for 2.5 is partial:
  - `Main` warns "the save splice runs on 2.5 with its node formats not checked on 2.5 saves yet (save_splice_25 = off in switches.txt turns it off)".
  - Several features log "FAILED (not the 2.5 code)".
- Main log lines: "NightCoop loading, protocol version {}, build {} ({})" and "game version {} (exe {}.{}.{}.{}){}".

### 1.3 Main load sequence (`1809eb920`, reason 0)

**Early setup:**
1. `FUN_180900250`: autotest detection. It checks for the marker `autotest\enabled` (which may contain `until=`) or the `-nightcoopautotest` command-line argument, and sets up inbox/outbox.
2. Plugin folder path: `FUN_1809c79c0`.
3. Log setup: `FUN_180036410`, `FUN_180034d10`.
4. Crash handler: `FUN_1800f4cc0` installs `AddVectoredExceptionHandler(1, FUN_1800f4640)` and opens `nightcoop-crash.log`.
5. Hub list: `FUN_180050090` loads `hubs.ncl`.
6. SDK logger bridge (a lambda).
7. Version log lines.
8. Passive check.

**Full mode:**
- `FUN_18059cf70`: Phantom Liberty start-mode handling (§6.2).
- `RegisterTypes` / `PostRegisterTypes` are registered through the RTTI system (two code paths depending on the version table).
- Then about 95 `Install` calls in this order (names come from each function's `__FUNCSIG__`):
  1. **Core:**
     - `180107f20` game loop: "game loop installed (Running state)". It registers a RED4ext game state; there is a fallback, "SDK has no gameStates API; game thread unavailable".
     - `180114220` `gameapi::Install`.
     - `1800fa240` HangWatch (dbghelp `MiniDumpWriteDump`/`StackWalk64`, thread "NightCoop hang watch").
     - `180902f00` AutoTest.
     - `180913f70` IntroSkip (`skip_intro.txt`).
  2. **Animation and bodies:** AnimTap `18012d0f0`, `180160790`, FppCamGuard `180179ee0`, look_entity_scope (`1809ea110` reads switches.txt), PartnerLook `180188ba0`, CyberwareLook `180196c10`, NpcTargets `1801a86f0`, RemotePlayers `1801e2280`, `1801fdee0`, DamageTap `180216220`, `18034fd60`, `18035bd70`, `1804657d0`.
  3. **Combat and NPCs:** DamageClaims `18022c570`, Pvp `180921140`, Challenge `1809298b0`, NpcCopies `180296900`, NpcOwners `18030e990`.
  4. **Loot:** LootSync `180362f90`, WorldLoot `180371c10`.
  5. **Session:** `1803d7550`, SessionFlow `18059ced0` ("session flow installed"), Downed `1805b3d00`, `1805d3df0` (QuestSync), DialogVote `18060c700`, **WorldHandoff `1806602e0`**, CoopMenu `1808a82b0`, Hud `180576450`, PlayerMarkers `18058aa10`, `1806cd660`.
  6. **Story and world sync:** StoryPeers `1806f5710`, StoryPull `1806fa030`, LiftSync `180711640`, DoorSync `18072c560`, DeviceSync `180745db0`, **TeamBuild `1807543b0`**, `180760120` (scene pauses), PhoneSync `18077aa30`, SmsReply `1807825d0`, **Wine entity guard `180787a90`**, QuestClock `18078d2f0`, `1807a74b0`, `1807d2ec0`, `1807fddb0`, `18080a160`, Braindance `180939740`, BdGhosts `18094e800`, `180964ba0`, Destruction `18081c220`, Barrels `180833f80`, PhysicsPush `18083bbd0`, PlayerFx `18096a910`, HackSync `180972340`, HackIcon `18097c840`, NpcTags `180988930`, BlackwallSync `18098fb80`, Promo `18099a0f0`, PhotoCopies `1809b08c0`, **WorldLoad `180846230`**, StoryHold `180850830`, QuestRide `18086b670`.
  7. **NPC behaviour and visuals:** Enemies `180445060`, PoliceHost `18045e3f0`, ImplantSphere `180469a70`, SandevistanStreak `18047e000`, SandevistanGhosts `18048b3c0`, TPP layer clips `180499860`, `1804a80c0`, `1804b49c0`, `1804c47a0`, workspot `1804e1810`, WorkspotDevice `1804fc760`, BodyCarry `18050ba90`, PlayerBridge `18051da90`, Puppets `180540310`, WeaponSound `180934b50`, SolidBodies `180919180`, BodyHitShapes `180171350`, Echo `180566240`.
  8. **Last:** **Addon `180933310`**, AnimMirror `180143760`, **WorldRules `18087a1f0`** ("world rules installed"), **MenuBackground `180875190`** ("menu background installed").
- Then a deferred lambda (`FUN_1801087d0`).

**Unload (reason 1)** runs about 85 matching shutdown functions in reverse groups. The exit path logs "log: the last {} min before the exit {}" and "run (exit_skip_statics is off…)" or "skipped (the game is in quick_exit…)".

Altogether `Main` makes about 180 subsystem calls (about 95 installs plus about 85 shutdowns). That is the "~150 subsystems" from the earlier audit.

### 1.4 How it hooks the game

- **Addresses:**
  - The bundled RED4ext SDK `RelocFunc` resolves address-library hashes through `RED4ext.dll!RED4ext_ResolveAddress` (`180115830`). An unknown hash produces the stock fatal dialog and `TerminateProcess` ("The mod has encountered a critical error while trying to resolve an address hash…", `180115f20`).
  - Many hooks use **hard-coded per-version RVAs** instead. Example: `180787a90` takes `exe base + table[ver]` from `0x180c02b90`, `memcmp`s 0x11 bytes of the expected code, then calls `sdk->hooking->Attach(handle, target, detour, &orig)` (`(**(param_1+0x10))(…)`).
  - Log strings name the offsets directly, e.g. "GetCameraLocation … (2.5 exe+0x2e50ed4 / 2.31 exe+0x28c1428)" and "the splash's SetState hooked at exe+{:#x}".
- **Native function detours:** RED4ext hooking Attach (for example `npctargets::DetourSetThreat`). When the SDK lacks a hooking API, a feature is disabled with "no hooking API in the SDK".
- **Script bytecode patching (ScriptPatch, `1801c9690`/`1801c9d20`/`1801cc940`/`1801cb130`).** Script functions are found by `Class.Function` name (`FindScriptedAllImpl`, `BuildKnownFunctions`). There are two operations:
  - *Wrap*: a new body with a native **guard prologue** that returns Bool ("script patch '{}': {}; prologue {}"). The guard can short-circuit the original.
  - *Redirect*: calls of X inside a script body are pointed at a native in a free native slot ("{} call(s) of {} now go to {} ({} param(s) skipped)").

  Both are reversible: "restored: {}" (`1801cc940`).
- **Pointer swap:** the `VirtualProtect` 8-byte swap helper `18090f7b0` is used **only by AutoTest** (`180902f00`/`180903430`). AutoTest hooks `shell32!SHGetKnownFolderPath` and patches the game's IAT slot, so that "Saved Games" points to `autotest\profile\Saved Games` (save isolation for the test stand: "SHGetKnownFolderPath hooked … the game's import slot patched too").
- **GameApi** (`180113780`, `180114220`):
  - Lookup of classes, functions and fields by RTTI or script name, with diagnostics ("no class '{}' (by RTTI or script name)", "the field is '{}' (RTTI names of script fields have no m_)"). Lookups by name are counted per call site.
  - `call_type_guard` refuses to call a member function on an object of a foreign class ("the game calls it only on {} objects: {} (call_type_guard)").
  - `call_unbound_guard` refuses an object-less call to a member that has no static implementation ("the interpreter crashes on it without an object").
- **GameSystems (`nc::gamesys`)** wraps game systems: `FindEntity`, `ItemInSlot`, `SlottedItems`, `StatValue`, `HealthPercent`/`SetHealthPercent`, `SetGodMode`, `Apply/Has/RemoveStatusEffect`, `ToggleComponents`, `PreventionSystemObject`, `DynamicSpawnRegistered`.

### 1.5 Game scripts patched (ScriptPatch targets, collected from install call sites)

| Module | Wrapped or redirected script functions |
|---|---|
| WorldRules (`180876b10`, `180877350`) | `TimeDilationHelper.SetTimeDilationWithProfile`, `TimeDilationFocusModeDecisions.EnterCondition` (scanner slow-mo), `TutorialPopupGameController.PauseGame`, `PauseMenuBackgroundGameController.OnInitialize/OnUninitialize`, `ShardNotificationController.PauseGameState/OnUninitialize` (redirects of `inkISystemRequestsHandler.PauseGame/UnpauseGame`) |
| SessionFlow (`180598be0`, `18059a400`) | `gameuiInGameMenuGameController.OnInitialize/OnSavingComplete`, `FastTravelSystem.OnRestored`, **`GameTimeUtils.CanPlayerTimeSkip`**, `SingleplayerMenuGameController.*` (OnInitialize, HandleMenuItemActivate, OnSaveMetadataReady, OnSavesForLoadReady), `LoadGameMenuGameController.*`, `DeathMenuGameController.HandleMenuItemActivate`, `EngagementScreenGameController.OnInitialize`, `gameuiPreGameMenuGameController.OnInitialize`, `characterCreationSummaryMenu.OnOutroComplete`, `gameuiSaveHandlingController.PreSpawnInitialLoadingScreen` |
| CoopMenu (`1808890e0`, `1808fb3a0`) | Pause and main menu item lists (`ShouldAllowExitGameMenuItem`, `OnMenuItemActivated`, `AddMenuItem`, `Clear`), `LoadGameMenuGameController.LoadGame`, `LoadListItem.IsCloud`, character creation (`ExpansionNewGame.*`, `CharacterCreationBackstorySelectionMenu.*`, `DifficultySelectionMenu.*`, `characterCreationSummaryMenu.*`, `characterCreationLifePathBtn.*`), `ScenesFastForward*` |
| MenuBackground (`180873250`) | `gameuiWorldMapMenuGameController.OnInitialize/OnUninitialize` |
| WorldLoot (`180368530`, `1801cab50`) | `gameItemDropObject.OnGameAttached`, `DropAction.CompleteAction`, `ScriptedPuppet.DropHeldItems`, `LootingGameController.OnUpdateData`, `MinimapStealthMappinController.FadeOut`, `NPCPuppet.OnIncapacitated`, redirect `RPGManager.ForceItemTier` |
| TeamBuild | redirect `RPGManager.GetBuildScore`; fields of `questStat_ConditionType`, `questStreetCredTier_ConditionType` |
| QuestSync (`1805f07e0`) | `FastTravelSystem.PerformFastTravel`, `DataTerm.TeleportToExitNode`, `DropPointControllerPS.OnDepositQuestItems`, `ComputerInkGameController.ResolveQuestInfo` |
| Downed (`1805aee90`, `1801cb130`) | `DeathDecisions.EnterCondition`, `DeathDecisionsWithResurrection.ToResurrect`, `ResurrectDecisions.ToDeath`, `HighLevelTransition.SetIsResurrectionAllowedBasedOnState`, `PlayerPuppet.OnInteraction`, `PhoneSystem.OnUsePhone`, `FastTravelSystem.IsFastTravelEnabled`, `ScriptedPuppet.SetSenseObjectType` |
| Others | `DialogHub*/dialogWidgetGameController.*` (dialog vote), `PhoneSystem.OnPickupPhone`, `MessengerDialogViewController.ActivateReply`, `LiftDevice.OnLiftStartDelayEvent`, `PreventionSystem.*`, `FocusModeTaggingSystem.*`, `QuickHackMappinController.UpdateView`, `ExplosiveDevice.StartExplosionPipeline`, `BaseGrenade.Detonate`, `Device.OnDeath`, `SecurityTurret.*`, `gameuiMinimap/WorldMappinsContainerController.CreateMappinUIProfile`, `HUDProgressBarController`, `OnscreenMessageGameController`, `EquipmentSystemPlayerData.EquipItem`, `HighLevelTransition.*DeathAnim*`, `PlayerGameplayRestrictions.RequestFists`, `AICondition.Check`, `StimBroadcasterComponent.SendDrirectStimuliToTarget`, … |

Script natives registered in `PostRegisterTypes` include, in this report's scope: `NightCoopGiveItem`, `NightCoopInventoryStatus`, `NightCoopLootStatus`, `NightCoopSessionStatus`, `NightCoopToHost`, `NightCoopPreSessionSave`, `NightCoopTravelScreen`, `NightCoopHostWorld`, `NightCoopCampaign`, `NightCoopWorld`, `NightCoopNoPause`, `NightCoopBlockPause`, `NightCoopPauseSource`, `NightCoopLiveMenuBackground`, `NightCoopMirrorSlowdown`, `NightCoopSlowdownValue`, `NightCoopQuestSet`, `NightCoopStorySet`, `NightCoopLogSave`, `NightCoopAutoTest`, `NightCoopAddonStatus`, `NightCoopNetStats`, `NightCoopFrames`, and many more.

Some `NightCoop*` names are **not** natives:
- `NightCoopNewGame`, `NightCoopPanel`, `NightCoopHint`, `NightCoopChoice`, `NightCoopServer`, `NightCoopKick` are coop-menu ink widget names (`1808918d0`).
- `NightCoopLoadHold`, `NightCoopMenuHold`, `NightCoopTravel` are pause or restriction **reason names** (§4).

### 1.6 Add-on API (`NightCoopAddonApi`, `180934380`)

- Signature: `void* NightCoopAddonApi(int iface)`.
- Only **interface version 2** is served. Any other version logs "refused (this NightCoop has {}: the add-on is from another release, update both)" and returns null.
- The returned table (built in `180933c40`) holds:
  - `{u32 size=0x220, u32 iface=2, u32 protocol=0x80, char* build="a7c537d", 66 function pointers}`.
- Attach and detach are logged ("addon: '{}' attached (interface {}, protocol {})", "an add-on asked for interface {} and was refused (… NightReplay says why: NightReplayStatus())").

What the entries do, identified by their callees:

| Group | What the entries do |
|---|---|
| Logging and HUD | Log into nightcoop.log (`1809305e0`), localized text, HUD status lines show/clear (`180932170`, `180932290`, `1809323a0`) |
| Session | Session state and role (`1809326f0`, `180932070`, `180931730`, `1809317f0`), peer list and names (`180931420`, `180931200`, `180931450`), shared game seconds (`1809320b0`) |
| Player | Local player handle and position (`18092f3d0`), look and wardrobe read (`180930940`) |
| Saves and travel | **`SaveNow`** (`180931990`: "saving is locked now (combat, a scene?)"), **`LoadSaveIndex`** (`1809304f0`), **`LoadContinue`** (`1809303f0`), **`GotoMainMenuNow`** (`18092f2a0`), **`TeleportLocal`** (`180932690`), mod saves listing (`180931af0`: reads `mod-saves.txt`, campaign/baseline), directory listing (`1809306a0`) |
| Replay helpers | Puppet "player body" (`1809326d0`), anim features and item-in-slot readers (`18092ff60`, `18092f420`, `18092fa90`), NPC copy despawn (`18092f220`), entity lookup (`180930840`), door sync (`18092f1e0`), partner look (`18092eac0`) |

Taken together, this is what an external replay recorder or player needs: record sessions, then drive puppet bodies, travel and loads. Strings such as "into our replay recording too" and "puppets: peer {} body is a player of a replay" confirm the purpose.

---

## 2. How a session starts, world-wise

### 2.1 The guest plays in the host's world with its own character, via save splicing

Modules: WorldHandoff (`nc::worldhandoff`, `18063d6c0…18069d280`), `nc::savesplice` (`SpliceWorld`, `MergeCampaign`, `AdoptSession`; save parser `nc::savefile` `1800c0c50…1800e7500`), and SessionFlow.

1. **Pre-session save (guest).**
   - `NightCoopPreSessionSave` / `PreSessionSave` makes "a new save before the session". This save becomes "our campaign until the return".
   - With no world loaded, the log says "joining without a pre-session save: the main menu has no world to save".
   - The answer has a 15 s timeout ("no answer about the pre-session save in 15 s").
2. **WorldWant (80).** The guest logs "asking the host for its world ({})" (`18064d930`).
3. **The host snapshots its world** (`180686890`).
   - It requests a ManualSave (`sessionflow::RequestManualSave`). Possible outcomes: "saving stayed locked (combat or a scene)", "the save failed".
   - Then it reads `sav.dat` into memory: "a save for {} guest(s), its bytes are in memory now", "our save {} ({} bytes) goes to {} peer(s)".
   - `1806586f0`: "peer {} wants our world ({}, their world #{})".
4. **WorldFile (81).** The host sends `sav.dat` ("our world ({}, {} bytes) is sent to peer {}", `1806811b0`).
   - When the host itself loads a save, it sends the save **ahead**. Guests build theirs while the host loads: "{} ({} bytes, playthrough {}, …) goes to {} partner(s) ahead of our load: their save is built on it while we load, and loads once our world is up from it".
   - This is the **WorldReload (95)** path: "reloads: sent ahead {}, confirmed {}, another save {}, cancelled {}, partners told".
5. **The guest builds a spliced save** (`180650940`, 3045 lines; `1806997d0` "Building the save: the host's world + your character").
   - `savesplice::SpliceWorld` keeps the host's world nodes (quests, facts, world state) and grafts in the guest's character from its own last save: "the entry build: the host's world with our character (the game loads it now)".
   - Stats can be taken "by owner": "the player's and items' from the character, npcs' and objects' from the world" (`splice_stats_by_owner`).
   - Other carried state: life path ("the same choice options and scene branches by the life path as the host's"), UI state, and garage cars ("The garage in the host's world is yours: you call your own cars").
   - The guest's stash and quest items depend on a switch: "our character with its quest items, stash and per-player facts" vs. "only our character (07.10): no own quest items, an empty stash".
   - Validation: "the spliced save does not parse: ".
   - Cloud downloads are checked for a header: "the downloaded sav.dat is not a save of this game version (no VASC/FZLC header)" (`1806a5880`).
   - Old saves: an older-version lobby save is first "loaded, saved anew by our game" to raise its version.
   - Working files in the session folder: `host-world.dat`, `host-world.json`, `delta.bin`, `state.txt` ("led_brought_items: {} item record(s) our character brought into the host's world"), `times.txt`, `copy.txt`.
6. **The write is atomic** (`18069a7a0`). The new save folder (`ManualSave-N`, "the game's list does not see it") is written to `*.nightcoop.tmp` and then moved into place with `MoveFileExW`. `18069b500`: "written over {} ({} bytes, {} ms{})", with screenshot.png and metadata put back.
7. **The guest loads it. WorldStatus (82)** reports progress back: "{} is loading your world" / " is in your world" / "peer {} could not load our world: {}".
   - The host re-checks: "the host's world {} is up from the save sent ahead" / "the host's world did not come up from the save it sent ahead".
   - Saving inside the host's world produces saves carrying a **host mark** (`nightcoop_host_world`). Those saves are not treated as the guest's own campaign.
8. **WorldLoad (120)** (WorldLoad module `180845c90`): "transition #{} went after {:.1f} s".
   - It covers loading-screen transitions inside the host's world.
   - "loading screens in the host's world end at everybody together" (switch `load_hold`) vs. "end at each machine on its own".

**Where it applies:** GOG / cross-progression cloud saves are supported (`1806a3140`: `REDGalaxy64.dll!redgalaxy::api::CloudStorage()`, vt+0x30 GetFile). A cloud-only pick is downloaded into a local folder (`.nightcoop-cloud-`, switch `cloud_fetch`).

### 2.2 What happens to the guest's own save and character

- The guest's campaign is protected:
  - "campaign_copy": the mod copies the campaign to `campaign-copy`, with `.new`/`.old` rotation and verification ("sav.dat of the copy is not whole").
  - Technical saves are hidden in `saves-archive` at the next start ("only hides technical saves of NightCoop", `player_saves_visible`).
  - `mod-saves.txt` lists mod saves as "kind folder sav.dat-size sav.dat-time [retired]".
- Character identity is checked by a seed (`character_check`: "our character in the session: seed {:08x}"). `campaign_recover` falls back to "the newest save of our character" if the pre-session save is gone.
- **The return after the session** (`18064b060`, `18064c1c0`, `180655680`) asks the player in the co-op menu, then saves, merges (`savesplice::MergeCampaign`) and loads. The player chooses one of:
  - **Keep own world** (`return_ask`/`return_own_world`): "You are in your campaign: your world as it was; the character keeps the session's progress, money and items".
  - **Carry the session's world**: "The session's world is your campaign now: quests and decisions as in the session, your fast travel points are added; your former save is in …", with the stash merged ("stash: the campaign's {} item(s) … put in the session's stash").

  Session cars go to the garage ("cars got in a session go to our campaign's garage").
- **TeamBuild / BuildStats (141)** (`1807543b0`, `180754f30`):
  - It redirects `RPGManager.GetBuildScore` and reads `questStat_ConditionType` / `questStreetCredTier_ConditionType`.
  - Effect: "checks of our V's build (a dialog option's or a scene's attribute check, level, street cred) count the best of everybody in the host's world".
  - Switch `build_checks_any`, default on.

### 2.3 Shared new game and the host-world lobby

- The host starts a new game. Guests follow into their own character creation:
  - "lobby (guest): into the character creation of the host's new game (start #{})".
  - The host's hovers and choices are mirrored with `CreationHover` (114), and `LobbyStart` (113) starts the run.
  - Start: "the shared new game start #{} goes for everybody at the shared time {} (in {} ms, the slowest link rtt {} ms)".
  - WorldRules holds the start until every world goes: "world rules: the start of the shared new game … is held here (not every world goes yet)".
- `NightCoopHostWorld` / `NightCoopCampaign` / `NightCoopWorld` are status and selection natives for the "host's world" campaign. A save of the shared new game is "your character, the host's world" and "stays our campaign, no return after the session".
- Lobby switches include `lobby_index_load`, `lobby_shared_saves`, `lobby_take_any`, `lobby_fresh_index`, `own_save_reuse`, `death_menu_host_world`.

### 2.4 Loading and menu holds (WorldRules)

- `NightCoopLoadHold` (`18087fc60`) is a pause reason. It holds the world while a partner is still in the transition into the host's world:
  - "a loading screen in the host's world is over here, not yet at every partner in the transition".
  - It is re-checked every 1 s and released with "the game of world #{} goes (its loading screen is over, {:.1f} s after the arrival)".
  - Variant: "the in-world loading hold … stands the world by time dilation 0 too" vs. "is the pause flag only".
- `NightCoopMenuHold` (`18087fea0`): when "every player of the session in the world is in a menu", the world pauses. It is lifted when "not everyone is in a menu any more" or "our window closed".

---

## 3. Inventory and loot

### 3.1 Item transfer between players (LootSync, `180361d50…180364490`)

The host keeps a **ledger**. The exchange is a four-step handshake:

| Step | Message | Log string |
|---|---|---|
| Offer | ItemTransferOffer (38): the sender asks to give | "inventory: transfer {:#x}: offering {} x '{}' to peer {}" |
| Debit | ItemTransferDebit (39): the host accepts and tells the sender to remove the item | `RemoveLocal` `1803633d0` via `gameTransactionSystem.RemoveItem` |
| Grant | ItemTransferGrant (40): the host tells the recipient to add it | `GiveLocal` `1803626f0` via `GiveItem` |
| Ack | ItemTransferAck (41) | "inventory: host: transfer {:#x} complete" |

- Failure paths are explicit:
  - "the recipient refused … after the sender gave it away"
  - "abandoned after the debit … is lost"
  - "peer {} did not answer for {} s"
- Unique items are refused ("unique items do not go this way").
- The script entry point is `NightCoopGiveItem` (recipient, item record, quantity) → "inventory: transfer {:#x} requested for peer {}" (`180361fa0`). The status native is `NightCoopInventoryStatus`.
- There is **no separate money transfer**: no eddies-specific code or strings were found. Money travels with the character (spliced in, kept on return: "level, perks, money, items").

### 3.2 World loot (WorldLoot, `180368200…180382a70`): owner-authoritative, mirrored

- Loot of an NPC belongs to the machine that **owns** the NPC. Corpses and drops are **shared** (`ShareDrop`, `SpawnMirrorDrop`): other players see **mirror** containers or drops.
  - Mirror lifecycle strings: "mirror of {} {:#010x} (peer {}) now holds …", "… emptied", "… let go: the owner no longer sees it".
- Taking from a mirror is a request to the owner. **LootState (42) / LootTake (43) / LootTakeResult (44)**:
  - "world loot: peer {} says {} x {:#x} from {} {:#010x} was already taken".
  - Takes are rolled back if denied ("takes asked {} (ours {}, rolled back {}, waiting {}), others' takes granted {}, denied {}").
- Result: containers and corpses are effectively **shared, first come first served**, arbitrated by the owner.
- Exceptions, from the switch descriptions in `18037dfc0`:
  - `loot_personal`: "what the game gives once (iconic weapons, shards, recipes, keycards, perma rewards) is every player's own: taken from a corpse or an npc's drop it stays with the others; lying in the world before us it is neither shared nor emptied". With it off: "such items are one for everybody".
  - `loot_twins`: our twin of a partner's NPC makes no loot of its own; the owner's loot comes onto it.
  - `loot_incap`: corpses are shared even when the death was not seen.
  - `loot_world_death`: a drop next to an unshared fresh death "is the world's loot (the host decides)".
  - `loot_spawn_near`: mirror drops spawn within 55 m (old value 80 m).
  - `loot_corpse_marker`: the minimap corpse marker is held until the loot lands.
  - `loot_force_tier`: mirrored container items get the owner's tier via `RPGManager.ForceItemTier`.
- Status native: `NightCoopLootStatus`.

---

## 4. World rules in co-op (WorldRules, `180876260…180884220`)

`18087d060` resolves `gameTimeSystem` (`IsPausedState`, `SetPausedState`, `SetTimeDilation`, …). `18087e360` is the pause controller.

- **No solo pause.**
  - Menus that try to pause are blocked: "world rules: the game tried to stop time for '{}', lifted" (`18087b4d0`).
  - The world pauses only when **everyone in the world is in the pause menu** ("everyone in the world is in the pause menu", `180881bb0`).
  - Optionally full-screen windows count too: "a full-screen window (inventory, map, shop, ripperdoc) counts as a menu for the pause of all".
  - Pause release and re-lock is watchdogged: "the game is still paused {} ms after our UnpauseGame … and nobody holds it". There is also a physics-backlog guard: the pause is briefly lifted so the engine flushes physics ("past {} it crashes, 03.10 21:45").
- **Tutorial popups** do not pause in co-op (`tutorial_pause_wrap`): "a tutorial popup does not pause the game in co-op (its PauseGame is held by our wrap)".
- **Scanner slow-motion** is suppressed ("the scanner would slow the world down"; wraps `TimeDilationFocusModeDecisions.EnterCondition`).
- **Sandevistan / time-dilation implants** are mirrored by radius:
  - "a partner's implant now slows those within {:.0f} m".
  - Your own implant slows your player ("own implant slows the world to {:.2f}").
  - `NightCoopMirrorSlowdown`, `NightCoopSandevistanRadius`.
- **Photo mode** is off in a co-op session through the `GameplayRestriction.NoPhotoMode` status effect ("photo mode is off for the co-op session", `18087a500`), unless `photo_together` is on. `PhotoTogether` (209) then syncs it ("in photo mode (the partner's word)").
- **Time skip / sleeping:** `GameTimeUtils.CanPlayerTimeSkip` is wrapped (`180599770`, guard `18059cb50`). The guard fires for **guests** (role 2), so only the host can skip time. Game time is the host's: the `GameClock` (46) message and `SharedTimeMs` ("clock sent {} / applied {}").
- **Fast travel / teleports:** `NightCoopTravel` is a restriction or effect tag applied by `sessionflow::TeleportLocal` (`1805aa990`/`1805aaf70`) while the mod moves the player. `NightCoopTravelScreen` shows the travel loading screen. QuestSync guards `FastTravelSystem.PerformFastTravel` and `DataTerm.TeleportToExitNode` (`1805d1b00`), and fast travel in the host's world is personal ("our own fast travel: nobody joins it").
- **Menu background** (MenuBackground, `180872da0…180875280`): the game normally freezes the world picture behind full-screen menus. In co-op the world keeps running and is shown live ("the live background behind full-screen menus in co-op is now {}", `NightCoopLiveMenuBackground`). Blur re-requests are handled ("a popup took the blur off under the menu").
- **Story hold:** "the story's wait for partners coming into the host's world" (quests suspended until partners arrive).
- Natives: `NightCoopNoPause`, `NightCoopBlockPause`, `NightCoopPauseSource` ("could not lift pause; … Use NightCoopPauseSource("name")").

---

## 5. Config files, switches, logs

All files live next to the DLL (`red4ext\plugins\NightCoop\`) unless stated otherwise.

| File | Purpose (evidence) |
|---|---|
| `switches.txt` | Startup switches, one `name = on\|off` per line. `#` starts a comment. Bad lines: "switches.txt: «{}» is not «name = on\|off», skipped". Totals: "switches.txt: {} switch(es) applied" (`1809ead70`/`1809c44f0`; `1809ea110` checks one switch at start, e.g. `look_entity_scope`). |
| `hub.txt` | "names the server for the next session" (`host[:port]`). With `hub_file` off: "hub.txt is not read: sessions go through the project's hubs". It is imported into servers.txt as "the own server" (`180045360`, `18008d180`). |
| `servers.txt` | The player's own server list for the server picker (`180097230`). |
| `locations.ncl` | Cached hub locations "from the main server with their ping … kept from the last run" (`180098590`). |
| `hubs.ncl` | Signed hub list ("NightCoop hub list 1"), checked against the embedded project root key (`180050e90`). |
| `name.txt` | Nickname ("coop menu: our nickname is '{}' (name.txt)", `18088c0c0`). |
| `skip_intro.txt` | Intro-skip preference (`180913f70`/`180915370`). |
| `promo.txt`, `markers.txt`, `challenge.txt` | Promo-scene mode, saved player map markers, challenge rules (`18099f090`, `180591d40`, `18092d120`). |
| `port-test.txt` | Forces full mode on an unknown game version. |
| `no-phantom-liberty.txt`, `.off.txt`, `.starting` | The "start without PL" mark and its crash-safe start marker (§6.2). |
| `rtti-names-<ver>.txt` | RTTI name dump (passive mode / tools). |
| Session working files | `host-world.dat`/`.json`, `delta.bin`, `state.txt`, `times.txt`, `copy.txt`, `mod-saves.txt`; save folders `campaign-copy[.new/.old]`, `lobby-backup`, `saves-archive`, `bad-save` |
| `autotest\` | `enabled` (may hold `until=`), `inbox`/`outbox`, `handoff`, `ready.txt`, `heartbeat.txt`, `saves.txt`, `copies.txt`, `profile\Saved Games\…`, `logs\` |

**Switch system.**
- `NightCoop*Set(key, value)` natives take a string key. Each family dispatches to its module's setter, which compares the key with `memcmp` against known names and logs the change: `QuestSet`, `NpcOwnersSet`, `RideSet`, `NpcMirrorSet`, `DestructionSet`, `StorySet`, `PvpSet`, `ChallengeSet`, `PoseFixSet`, `Tpp*Set`, `SandevistanTrailSet`.
- The big dispatcher for `QuestSet` is `1809da250` (about 5000 lines). Some switches are matched by FNV-1a hash.
- Several switches "go to the partners" so that all machines agree ("at every machine: the switch goes to the partners").
- The autotest command `set mirror|ride|owners|radius <name> <value>` does the same as the console.
- About 557 distinct key strings appear in `memcmp` calls; the list is in `scratchpad/w5/switchkeys.txt`.

Switches in scope, with defaults where the text states them (`QuestSet("x", false)` in a hint means the default is on):

| Area | Switches |
|---|---|
| World and saves | `handoff` (on; "the world handoff is off (NightCoopQuestSet("handoff", true))" when off), `campaign_return`, `campaign_copy`, `campaign_recover`, `character_check`, `save_splice_25` (on for 2.5, can be turned off), `splice_stats_by_owner`, `cloud_fetch`, `lobby_*`, `own_save_reuse`, `death_menu_host_world`, `reload_wait_game_start`, `all_down_last_save`, `player_saves_visible`, `return_own_world`, `return_drop_chase`, `sessionstash` |
| Loot | `loot_personal`, `loot_twins`, `loot_incap`, `loot_world_death`, `loot_spawn_near`, `loot_corpse_marker`, `loot_force_tier` |
| Rules | `load_hold` (on), `story_hold` (on), `tutorial_pause_wrap`, `photo_together`, `stand_unhack` (on), `build_checks_any` (on), `sms_any` (on) |
| Infra | `hang_watch` (on), `hang_dump` (**off**: "a dump from inside the process crashed the game 11.10"), `hang_threads` (on), `hang_test` (off), `slow_frames` (on), `frame_witness` (on), `fullscreen_hint` (on), `log_hide_ips`, `skip_intro`, `no_pl_mark`, `net_guard` (on), `hub_file`, `hub_pick`, `hub_picker`, `hub_resume`, `hub_cookie`, `hub_chain`, `look_entity_scope` (on; switches.txt only), `call_type_guard` |

**Logs** (`1800350e0`, `180036ae0`):
- Location: `nightcoop.log` in the plugin folder.
- Rotation: at start the previous log is renamed to `nightcoop-session-YYYY-MM-DD-HH-MM-SS.log` using its own last-write time.
- Line format: `[time] [level] message` (levels include `warn `). A rate limiter logs "log: {} line(s) dropped in the last second".
- `log_hide_ips` masks IP addresses.
- `NightCoopLogSave` / `logsave` write "the last 5 min of the log".
- Hang and crash snapshots go to `logs\nightcoop-last-*.log`. On exit it logs "log: the last {} min before the exit {}".

**Crash reporter** (`1800f4cc0`, handler `1800f4640`):
- A first-chance vectored exception handler that reacts only to fatal codes: AV, in-page error, illegal instruction, divide-by-zero, stack overflow, heap corruption `0xC0000374`, fast-fail `0xC0000409`, and similar.
- It writes to `nightcoop-crash.log`: "[hh:mm:ss.mmm] %s (0x%08lx) in thread %lu, game started …; the game's own crash handler runs next", then the faulting address with module+offset, "reading/writing/executing 0x…", registers, and a stack.
- It also dumps "NightCoop: the last %u s of the log before the crash" to `logs\nightcoop-last-…-crash.log`.
- It then returns so the game's own crash handler runs. A minidump is written only by HangWatch, and only with `hang_dump` on.

---

## 6. Expiry, Phantom Liberty, platforms, Wine

### 6.1 Beta expiry: the earlier audit's note does not hold

- The only "it expired on {} (this computer's date is {})" string is in **`FUN_180041d80`, the hub certificate validator**. It sits alongside "it is valid from {} (check the date)", "it is not a root certificate", and "it is signed by a key that is not the project's root".
- It checks the validity window of hub certificates signed by "NightCoop root key 1", with about 2 days (`0x2a300` s) of tolerance for clock skew.
- No hard-coded build-expiry date or time-bomb comparison was found:
  - No epoch constants in the 2026–2027 range are compared against the clock.
  - There are no "beta over" strings.
- In practice, if the project stops issuing hub certificates, or its signed hub list (`hubs.ncl`) or peer keys ("the hub's signature on the partner's key is out of date (issued {}, until {}, …)") lapse, online play through the official hubs stops. That is not a local kill switch. A `hub.txt` own server with a fingerprint still works.
- The only other date-limited item is the AutoTest marker `enabled` with `until=`.

### 6.2 Phantom Liberty

The mod can start the game **without PL** so a guest who lacks it can join. Strings: "lobby (host): {} (peer {}) has no Phantom Liberty", "restart without Phantom Liberty for {}", "cannot join a world with Phantom Liberty".

- **Mechanism** (`18059cf70`, `1805a1090`):
  1. A mark file `no-phantom-liberty.txt` is written.
  2. On the next start, the game's EP1 files check is hooked ("no-PL start: the game checks the files of Phantom Liberty (entry EP1)"). The result is "Phantom Liberty is not enabled, TweakDB is tweakdb.bin, the ep1 archives are not mounted, saves are of the base game".
  3. A `.starting` marker detects a start that crashed ("the previous start without Phantom Liberty did not reach the main menu"), so the next start goes as usual.
  4. The mark is cleared via the mod menu or `NightCoopQuestSet("no_pl_mark", false)`.
- **The ownership note:** when turning PL back on without a restart, "the game's own check of its files marks it owned (as the GameServices step without the platform's accounting)".
  - This means a re-enable trusts file presence rather than the store entitlement check.
  - It only re-enables content that is already installed; nothing is downloaded.
  - Related engine sites named in the strings: `sub_638500` (IsAdditionalContentEnabled), `sub_E60C3C` (ep1 archives "mounted only when installed and owned").

### 6.3 GOG and Steam

- There is no Steam-specific code: no steam_api, no SteamID.
- There is GOG Galaxy **cloud save (cross-progression)** support through `REDGalaxy64.dll!redgalaxy::api::CloudStorage` (`1806a3140`). It downloads cloud-only saves picked in the lobby, or as the host's world, into a local folder.
  - Failure strings: "CloudStorage() is null (the game's cloud is off or not signed in)".
- REDGalaxy64 ships with every store version of the game, so this works anywhere the player is signed into GOG cross-progression.

### 6.4 Wine and Proton

`ntdll!wine_get_version` is probed in five places. Under Wine:

- **Crash workaround:** `180787a90` installs a hook only under Wine, the "entity guard". It skips an expired weak entity in the transform-update job ("Wine crash at exe+6F012F"; "verified weak-entity transform update protection on Wine {}"). The hook target is a per-version hard-coded RVA, verified with a 17-byte memcmp.
- **Visual defaults** change:
  - Sandevistan ghosts and streak (`18048b3c0`, `18047e000` via `180498190`/`180484070`): "(defaults under Wine)".
  - Implant sphere (`180478500` callers).
  - Partner-body seat animation branch (`180150b70`, used by AnimMirror `180142650…`): "(default under Wine)".
- **Hang diagnostics** account for wineserver stalls ("other threads stood as long (the system or Wine; under Wine the wineserver)"; "under wine it may not work").

---

## 7. HangWatch and FrameWitness

HangWatch (`1800fa240` install, `1800fd570` frame analysis, `180102170` options):

- A watchdog thread ("NightCoop hang watch") monitors the game thread.
  - If the game thread "has not come back for {:.1f} s while the world was running", it logs the game thread's stack (StackWalk64, or return addresses only if StackWalk64 is unavailable).
  - With `hang_threads` it also logs the other threads' stacks: each thread is suspended "only for a copy of its context and stack top" (`SuspendThread`/`GetThreadContext`/`ReadProcessMemory` on its own process).
  - It saves the last minutes of the log to `logs\nightcoop-last-…-hang.log`.
  - It writes `logs\nightcoop-hang-….dmp` only if `hang_dump` is on.
- **Slow frames:** "the stack of a frame longer than 100 ms is sampled, a line every 10 s".
- **FrameWitness (msg 208):**
  - Trigger: "a game frame of 500 ms and longer is named in the log (its cause: our tick, a window switch, a loading screen, the whole process, the game's work; the window mode; stack samples inside it) and told the partners".
  - Rate limit: at most 30 words per 60 s ("not told (too often)").
  - Payload (serializer `180104420`): version byte, u16 frame milliseconds, cause code (1 = Alt+Tab, 2 = loading screen, 3 = our tick, 4 = whole process stood, else the game's work), flags (front or background, minimized, world stands), window mode (Windowed / Borderless / Fullscreen), a few u16 timing fields, and **a short text of at most 240 bytes**. From its construction the text appears to be a human-readable cause summary; it may include the names of sampled stack frames.
  - Partners log "frame witness: peer {}'s game window {}{}, window mode {}".
  - `fullscreen_hint` shows a hint when Alt+Tab in Fullscreen causes long frames ("Borderless instead of Fullscreen").
  - The word goes only to session peers, through the normal encrypted peer channel (`FUN_1800af3d0` broadcast).

---

## 8. Telemetry

**None found.** No data goes anywhere other than peers, the hub/relay (`hub.nightcoop.net` or your own `hub.txt`/`servers.txt`) and the STUN/UPnP endpoints already listed in the security audit.

- Crash logs, hang logs, minidumps and RTTI dumps are written locally only. The strings point the user to local tools ("python tools/dmp.py <dump>", "tools/symres.py").
- Of the diagnostics, only FrameWitness (above) and the "heartbeat"/net-stats counters go to partners.
- The GOG cloud access is a read (GetFile) of the user's own cloud saves through the game's own Galaxy library. No upload path was found.

---

### Caveats

- The format strings of many log lines are passed by pointer, so function-to-string attribution sometimes comes from neighbouring functions.
- Switch defaults are inferred from the descriptive hint strings.
- The FrameWitness text contents and the exact pre-session save trigger order were inferred from structure rather than traced byte by byte.
- The WorldStatus/WorldReload message layouts were not decoded.
