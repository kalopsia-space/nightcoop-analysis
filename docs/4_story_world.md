# NightCoop.dll: story, quests, scenes, dialogue and world-interaction sync

Static analysis only. Sources:
- Ghidra pseudocode, with function addresses given as `0x18...`.
- The raw string table, cited as `s8:<line>` from `dll/s8.txt`. Many log strings contain an em-dash, and Ghidra does not inline those, so they appear only in the string table.
- The hub repo's `ProtocolCore.hpp`, used for message names.
- Initial values of switch flags, read from the `.data` section of the shipped `NightCoop.dll`. That DLL was extracted from the zip into the scratchpad and never run.

All quoted text is the mod's own log or UI wording. Dates such as "17.10" or "21.10 evening" are the developer's changelog markers, and they are embedded in the strings. Short commit hashes such as `e8dd6f5` and `3e31158` appear the same way. Together they show this build dates from about 23 Oct.

---

## 0. Executive summary

- **The host is authoritative, but the guest's game still runs its own copy of the quest graph.** The current design is called the **"led story"**: the story is *led* by the host (step "4b" in the strings). The meaning of "LED" in the module names `LedPause`, `LedOutcome`, `LedStoryWhy`, `led_*`, `led_calls` and so on is simply the past tense of *to lead*. It is not a light.
  - The guest's quest graph is not overwritten. Instead, every point where it would make its own decision is intercepted and driven by the host. That covers pauses/conditions, instant checks, switches, random rolls, choices, and finishing of nodes that wait. Facts and journal entries written by the host's graph are then only **checked** on the guest.
  - The older "mirror" mode is kept as a fallback: snapshots plus copying of host facts and journal entries.
- **Scene gating** (`SceneGate`, `StoryPeers`) holds quest talks until every player in the host's world is at the NPC. The host decides, and a gate opens at one **shared network time** for everybody.
  - Walking away from the speakers stops the talk for everybody.
  - The host can hold End to start without the partners.
- **Skipping is not voted.** One player's fast-forward or cutscene cancel drags the others to the same point (`SceneSkip`). A skip waits while a partner at the same point may not skip.
- **Dialogue choices are voted.**
  - Each voter presses in their own native choice window; the options are matched by scene IDs.
  - A choice is decided by a strict majority (`voters/2+1`, so both players must agree with 2 players). On timeout, the host's vote decides, otherwise the most votes.
  - The default timeout is **60 s**; 0 means wait forever.
  - The winning option is applied at a shared timestamp on every machine, by replaying a key press into the game's own window.
- **Phone, SMS and braindance**
  - Holocalls are committed by the host and replayed on guests.
  - SMS replies: the first reply from anyone counts and is executed by the host.
  - Braindance has one timeline led by the host. Guest buttons are only requests to the host; everyone flies and picks a layer freely; exiting needs a vote. Partners appear as coloured "ghosts" or hologram cones.
- **World interactions**
  - Doors, lifts and devices are host-kept state that every copy follows.
  - Quest lifts wait for everyone, and there is one cab per lift for everybody.
  - Random quest nodes roll the same number on every machine, from a seed built out of the host's world id, the hour of the shared clock, the graph, the node and the roll index.
- **Time and pause**
  - The guest's in-game clock is set to the host's (`GameClock`, SessionFlow).
  - Quest real-time delays are lock-stepped (`QuestClock`).
  - Menus do **not** pause the world in co-op (`NightCoopNoPause`, default on). The game really pauses only when *every* player is in the pause menu, or in some menu if `windows_pause_all` is on.
- **Huge switch surface.** `NightCoopQuestSet(name, bool)` takes about 253 named switches (handler `0x1809da250`). Many are kill-switches for fixes dated 04.10–23.10, so this is a very actively patched beta.

---

## 1. Quest state: authority, replication, following the host

### 1.1 Roles
- **Host.** Every game runs its own quest graph, but the host's graph is the reference.
  - A guest follows the host only while the guest is in the **host's world**: it joined from the host's save, or the "shared new game" (`sharednew`) started on both machines.
  - Outside the host's world (main menu, own save) nothing is applied, and incoming host changes are dropped or deferred: "quests: we are {} – the host's facts and journal are not for this world ({} change(s) dropped…)" (s8:31599).
- **The shared new game.** Both machines start a new game together: "the shared new game: the same world by its very start, no snapshot (changes go as they come)" (s8:31363).
- **Joining a running game.** The host writes a save for the joiner ("the host saves for a joining partner – the save goes first"). The joiner loads it while `StoryHold` freezes the story for everyone (see §6.3).

### 1.2 Facts and journal replication (QuestSync; messages QuestFacts=70, QuestJournal=71, QuestWant=73)
- **Snapshots** are sent on join and on each new world. The guest asks: "quests: our world #{} is here – asking the host for its facts and journal" (s8:31521).
  - The host sends "facts snapshot #{} – {} fact(s) to peer(s) {}" (s8:31348) and "journal snapshot #{} – {} active/finished entr(ies)…" (s8:31352).
  - A world change during a snapshot triggers another one (switch `want_new_world`).
- **Incremental changes**: "quests: sent {} fact(s) and {} journal entr(ies) to {} partner(s)" (s8:31341). On the guest they are logged as "quests: host facts applied ({} changed here, {} already equal)" (`0x1805e0e50`).
- **Facts that are never shared.** The DLL embeds a long list of facts that stay per-player (s8:31060–31280):
  - VR tutorial flags (`q000_vr_*`);
  - `*_tutorial_seen`;
  - `gmpl_*` combat counters, `wanted_level`, metro display;
  - holocall setup facts.
- **Journal guard and cleanup.**
  - If the host's journal snapshot lacks entries that the guest's own quest just set, those entries are kept ("we are ahead").
  - Otherwise, entries the host lacks are set inactive: "quests: our journal checked against the host's – {} entr(ies) of {} active/finished here set inactive (the host does not have them)" (s8:31515).
- **Objective tracking.** The guest tracks the host's objective: "quests: tracking the host's objective {:#010x}" (`0x1805f1870`).
- **Quest-item drop points** (`quest_item_deposit`, `deposit_hand_over`; msg QuestItemDeposit=175):
  - A guest's deposit sends its fact to the host, so "the job counts for everybody".
  - The other players' copies of the deposited item are removed too (s8:31546–31575).
- **Documents read** (`document_read_shared`; msg DocumentRead=187): "our player read a document in a computer – the fact it set ({}) goes to the host: the job counts for everybody" (s8:31577ff; `0x1805e4f90`, `0x1805e7fc0`).
- **Build checks** (BuildStats=141, `build_checks_any`/`build_checks_native`): the attribute, level and street-cred checks of dialogue options use "the best of everybody in the host's world".

### 1.3 The led story (LedPause and LedOutcome; messages LedPause=128, StoryTrace=127, LedStoryWhy=203)
This is the core mechanism. The summary string reads: "no guessing: in step is a scene both of us run, nothing falls behind, the facts and journal the host's quest graph wrote are only checked here" (s8:~38200). It has four parts.

**1. Pauses (conditions).** Quest pause nodes are classified by condition class:
- step 2a: FactsDB, Journal, Time, System, Content;
- step 2b: Trigger, Distance, Object, Character, Entity, Spawner, Vehicle, Senses, Scene, Stats, Payment, UI, Logical;
- logged as "led pause: condition classes …" (`0x1807da010`).

Each class gets a policy:
- **The host decides.** Facts, journal, time, calls and world/NPC conditions are held on the guest until the host's word, then "released at the host's moment t={}".
- **Any one of us.** Sitting at the wheel, "connected" to a device, a braindance layer step, and the player's interaction, scan, inspection or tag ("whoever did it leads").
- **The team.** "in combat" fires when anyone fights; "not in combat" fires only when nobody fights.
- **Each player's own (personal).** Own-V gender, body or life path ("rule 6"), stats, input, own tutorials, the phone interruption graph, vendor scenes.

The host tallies held nodes: "the host tallies the votes of held nodes every {} ms" (s8:38212). The per-peer feature bits are exchanged: "led pause: peer {} has led pauses {}, led policies {} …" (`0x1807d0700`).

**2. Outcomes, choices, rounds and finishing** (LedOutcome):
- "the guest's instant checks, switches, random nodes and choices go by the host's exits" (s8:38670).
- `led_rounds_wait`: a guest check waits up to `rounds_wait_s` (0.3–5 s) for the host's exit of the same round.
- `led_finish`: guest nodes the host already passed are force-finished `finish_s` seconds after the host's time. Separate timers exist: `finish_move_s`, `finish_equip_s`, `finish_npc_s`.

**3. Random nodes** (RandomSync, `led_random_one` and `led_random_quest`, §5.6).

**4. Fallback.** When graph-check mismatches accumulate:
- "led pause: the led story FALLBACK – the led story goes off at every machine until our world changes (the guessing and the facts / journal mirror work as before step 4)" (s8:38207).
- The on-screen text is "Story: the led graph does not hold – the old mirror is on".
- The guest sends the host its reasons ("led_story_why"; msg LedStoryWhy) so that the host's log records them: "led story: peer {} FELL BACK from the led story" (s8:37866).
- The led story re-arms after a quiet period with no mismatches.

### 1.4 StoryTrace: divergence detection
- Quest nodes "that decide or wait are traced (the host sends its trace, the guest compares)".
- Graph keys must be stable across machines. The game's own path hash differs between machines, so graphs are keyed "by the root quest" (`story_stable_keys`).
- On divergence: "story trace: DIVERGED (the first in this world) … the host passed {} -> '{}' {:.1f} s ago, not here" (s8:37031).
- Then "story alarm: RAISED – our story diverged from the host's … nothing loads by itself" (s8:37078), with an on-screen red line (`story_alarm_hud`).
- **Excluded from comparison**: own-V forks (gender, body or life-path branches), tutorial graphs (`own_tutorials`), the phone-interruption graph, and polling loops that change more than N times a minute.
- **Time while the world stands still** (a pause or a load) does not count toward the alarm (`live_alarm_world`).
- Main functions: `0x1807a23c0` (1398 lines) and `0x1807b2e10`; the summary is at `0x1807a0f40`.

### 1.5 StoryPull, StoryPeers, StoryHold (messages StoryPull=87, StoryHold=153)
- **Pulling the story to the host (guest, PageDown or `NightCoopStoryPull()`):**
  - First press, a **live pull**: "our waiting nodes the host passed in this round go by its exit, finished the way the game finishes them" (s8:38804ff).
  - Second press within a minute: "by a fresh save of the host's world" (`live_pull_save`). Text shown: "The story diverged from the host's – hold PageDown to pull to it: its save loads, your character stays".
- **Calling a partner over** (StoryPull):
  - "who moves the story first leads: the others are called – told where to go; a move only by their own key, PageUp held for a second" (s8:35037).
  - There is also "The host calls you over" and a menu move-to-host. The console fallback is `NightCoopToHost()`.
  - Moves are refused in VR training ("in the VR training every player runs their own course") and when players are in different places (a flashback).
- **Who the story waits for** (StoryPeers):
  - "the story waits only for partners in the host's world; the host starts without them by holding End, in the co-op menu or `NightCoopGoAlone()`" (s8:34866). Status is reported by `0x1806f4d10`.
- **StoryHold**:
  - While a partner loads into the host's world, the host suspends the quests system the way the game's world loader does ("questQuestsSystem vt+0x1D8… the flag +0x1AF"). Quests, calls and quest timers wait, but players can still move.
  - If a host quest scene is talking, the hold becomes a full pause.
  - Limits: at most 90 s, or End to go without them. The hold is released for everybody "at the shared time" (`0x180852080`; s8:39664).
- **QuestRide (msg 84) and teleports (QuestTeleport=77)**:
  - Host quest rides are offered to partners as seats in the host's vehicle ("The host rides by the quest, your seat … walk up to its door and press F").
  - There is a special "Ride with Jackie" mode: "the host takes the wheel, the others ride seeing through their eyes, without control" (`0x1808627b0`, `0x18085b4a0`).
  - Host teleports by a quest or fast travel are **not forced** on guests. Partners nearby follow; far ones get "The host moved on by a quest – NightCoopToHost() to join" (s8:31443–31468).

### 1.6 NightCoopQuestResync
- It is registered at `PostRegisterTypes 0x1809ec910` as `NightCoopQuestResync`, with the short alias `QuestResync` (`LAB_1809da000`, which is not decompiled).
- The adjacent strings show what it does. On a guest it requests a full snapshot ("quests: asking the host for a full snapshot", s8:31704). On the host it queues one for every partner ("quests: full snapshot queued for every partner", s8:31705).
- With no session it reports "quests: not in a session".

---

## 2. Scenes and cutscenes

### 2.1 Scene classification
- Scenes are classified by the category tag in their scene file (`scnSceneResource.sceneCategoryTag`).
- Each class is then shared in one of three ways: "shared like a quest: everybody at the NPC, choices by vote", "shared: the host leads it", or "local to each player" (s8:31303–31330).
- Special cases:
  - **Vendor scenes** that start a quest are promoted to quest scenes (`quest_vendor`).
  - Scenes whose entries are all **phone calls** are shared like calls (`led_calls`).
  - Background or ambient scenes, and scenes loaded from a save that never "went by an entry", are not shared.
- Messages: QuestScene=72 announces scene starts and ends; SceneGate=83 and SceneGateGo=115.

### 2.2 SceneGate: waiting for everyone at the NPC
- The gates are the scene graph's own "player in zone" and "came up / looks at" pause nodes, hooked through "pause node (SceneGate + LedPause)" (s8 near 34500).
- A gate is held until every partner in the host's world is at their own gate. Then "the host opens {:#018x} for everybody at the shared time {} (in {} ms, the slowest link {} ms)" (s8:34727).
- UI texts: "Waiting at the NPC for …", "Your partner waits for you at the NPC – walk up: the talk starts for everybody at once", "The story waits for you: follow your partner".
- **Walking away**: "a talk of a quest scene stops for everybody when one of them walks away from its speakers and goes on once everybody is back" (`talk_away_all`, s8:34589).
- **Exceptions** follow game logic:
  - Pauses followed by doors, a lift, a move or a place check are "each player's own … nobody is pushed through (a door locks only behind the one who walked away)".
  - "any one" gates open for everybody when one player arrives.
  - VR-course phase pauses are each player's own.
  - Quest "walls" (prefab variants) close behind each player individually (`zone_walls`).
  - Sprint shortcuts into timed parts are disabled while a partner is in the world (`gate_shortcuts`).
- **Own-V forks.** Gender, body or life-path branches are not compared, and a common delay after the branches waits for the partner still in theirs (QuestClock §6.2).
- **A known limitation is shown to players**: "The talk has not started? Step a few metres away from the NPC and come back" (s8:34672).
- A partner's status is logged as "scene gate: peer {} is {} scene… ({:.0f} m from us)" (`0x1806c0ca0`).
- **The design was rewritten.** An older gate/barrier design was abandoned: "quests: gate and barrier are gone (23.09) – a scene node answered 'running' without its scene is never woken again and its quest signal is lost in saves" (s8:31699). Since then the led policies have taken over many gates; "off by default since ledgates: the old gates of SceneGate hold zones, distances and looks" (`led_policies`=0).

### 2.3 SceneSkip: fast-forward and cutscene skips (msgs SceneSkip=89, SceneLineSkip=118, SceneCutSkip=119, SceneSkipHere=121)
- **Not a vote.**
  - "the scene system's fast forward found – a skip by one player brings everybody to the place of the scene where it landed" (s8:36091).
  - Lines are identified "by places" in the scene. Partners behind "catch up now", fast-forwarding until a line starts that the skipper has not had.
  - Cutscene cancels: "we skip the cutscene of scene {} (node {}: the player's 'cancel') – the partners skip it at that node too: at once, or when theirs comes" (s8:36387).
- **A veto by state.**
  - "peer {} may not skip now ({}) in our scene … a skip of our player waits: the game gives it only if everybody at this place may" (s8:36431).
  - Reasons a player may not skip: combat, scene tier 5, a moving car, a lift, a call (`FastForwardUnavailableEvents`).
- **The skip kind is the host's**: "the skip kind here is the host's: {} (our own setting {} is overridden while we play with them)".
- **Walks between sections** while catching up a partner run the world 10x faster through a named time dilation (`NightCoopSkipWalk` is the dilation reason name, `0x180768510` and `0x180773a50`, not a script function; switch `skip_walk`).
- **Visuals.** A lot of code exists only to show the skip glitch effect and sound to partners, as the presser sees them (`skip_look_*`). Strings note "no glitch then, by the user's word of 16.10".

### 2.4 ScenePose (msg NpcScenePose)
- When an NPC is driven by a scene animation that is not in its replicated graph stream (the mixer slot), its owner streams the raw pose to partners who show it as a copy: "its pose goes to them every {} ms (scene_pose)" (s8:28499; `0x180503f50`).
- `NightCoopScenePose` is a CName (FNV-1a-hashed at `0x180502380`), not a script function.

### 2.5 SceneText and subtitles (msg DialogLine=78)
- Subtitles of the host's scene are relayed to partners **by localisation key**, so each player reads their own language: "a line of the host's scene is not shown – no text of ours ({}), the host's is {} and ours {}: only our language goes on our screen" (s8:31983).
- **The host's raw text is never shown**: "(the host's text is never shown)".
- SceneText reads `.scene` files to map choice nodes and option keys: "scene text: scene {} read: {} choice node(s), {} en-us/pl-pl string(s)" (s8:32612; `0x180638a30`, `0x18063bf00`).
- **Limitation**: only en-us and pl-pl strings are embedded ("are not embedded (only en-us and pl-pl are)"). Cutscene lines are timed to each player's voice-over language.

### 2.6 Partner bodies inside scenes
- Partner bodies are hidden while a scene places your player on their spot or both share one spawn point: "the body of peer {} stands inside our player (one spawn point for both) – hidden until one of us steps away" (s8:31512–31534).
- In the shared new game, no partner bodies appear until the first scene releases the player.
- Seats are shared one player per seat (`seat_share`).

### 2.7 IntroSkip
- Skips the startup logos, warnings and intro cinematic by driving the splash controller to `after_skip_pressed` (`0x180911230`, `0x180912240`).
- **Default off** (`skip_intro`=0): "NightCoopQuestSet("skip_intro", true) turns it on from the next start" (s8:42566).
- Unrelated to co-op sync.

---

## 3. Dialogue choices: ballot, vote, tally (DialogVote; msgs DialogBallot=74, DialogVote=75, DialogTally=76, DialogGather=79)

### 3.1 Flow
1. **Ballot.** When a voted choice hub appears, the host opens a ballot: "dialog vote #{} opened: '{}' in scene {} (hub flags {}), voters [{}] (needed {})" (`0x18060ec60`).
   - Options are keyed by scene IDs (`scnChoiceHubPartId`, screenplay option IDs) so that partners match them in their own window.
   - If there are no IDs, matching falls back to "kind, title".
2. **Voters.**
   - **Who votes**: partners in the host's world, near the NPC.
   - **Important scenes** "wait for everybody at the NPC" (DialogGather; UI text "All players must come to the NPC").
   - **Players who are far away** see "You are far from the dialog – those nearby vote" (s8:31850).
   - **Calls**: "a call: nobody has to stand by".
   - **Partners riding in their own copy of the quest vehicle** vote wherever they are.
3. **Voting happens in each player's own native window.**
   - Arrows and F work as normal; a press is intercepted and held as a vote.
   - Window overlays show "VOTED N OF K – M NEEDED TO DECIDE", "PARTNER CHOSE", "WAITING FOR THE HOST".
   - If the host's choice is not open locally, it is drawn into the guest's dialog window: "The host's choice: up/down arrows and F to vote".
   - If the dialogs differ, the guest is told "Your dialog differs – vote with NightCoopQuestVote(number)" (s8:32245).
4. **The decision rule.**
   - `needed = voters/2 + 1` (`0x18060ec60`: `(uVar13 >> 1) + 1`; `0x180608340`). This is a strict majority, so with 2 players both must agree.
   - On timeout the result is "the host's vote" if the host has voted, otherwise "the most votes" (`0x18061e360`).
   - If the game's own choice timer is about to expire, the current leader goes at once: "the timer must not run out at one of us while we wait for another" (s8:32048).
5. **Applying the result.**
   - "option {} goes for everybody at the shared time {}".
   - The decided option is applied by **replaying a press** through the game's InteractionManager.
   - It scrolls the selection to the decided row if needed (`vote_decided_scroll`, `vote_host_scroll`).
   - It verifies that the game selected it, retrying up to 3 times (`vote_apply_verify`).
   - Logged as "dialog vote #{}: applied at the shared time {} ({:+} ms against it)" (`0x18061c310`).
   - In led-story mode the choice node also takes the host's exit (`led_choices`), so a guest without the option ("You do not have the option the host chose") still follows the host's branch.

### 3.2 Special cases
- **Personal windows** (shop, ripperdoc, wardrobe, mirror) are never voted: "it goes to the game alone, the partner's scene stays at the choice (trade_personal)" (s8:32279).
- **Action choices** (a single option, such as 'Exit' in a car) open a vote only on a press. Condition-fired options are held until the shared moment (`vote_trigger_hold`, `led_trigger_hold`).
- **A guest's press before the host opens the choice** is held, labelled as a vote, and re-sent every 5 s (`vote_want_keep`). A guest "does not start it without the host"; the older behaviour was "press again to start without the host".

### 3.3 Timeouts and script API
- `NightCoopQuestVoteTimeout(int)` goes through `0x1809e2020`, then `0x18062ac50`.
  - It sets `DAT_180e94744`; values `<=0` mean "(wait forever)".
  - **The initial value is 60 s** (.data `3c000000`).
- `NightCoopQuestVote(n)` goes through `0x1809e1e50`, then `0x180602990` ("dialog vote: option 1..{}"). It votes from the console, "counted in the next frame".
- Both are marshalled onto the game thread through `FUN_1809c0020`.

---

## 4. Phone, SMS, braindance, photo mode, documents

### 4.1 PhoneSync (msg PhoneSync=133)
- "generic phone hooks ready – any contact, shared dial and answer" (s8:36592).
- The host **commits** each call ("phone sync: committed #{} call {} '{}' action {} phase {} by peer {}", `0x180778a80`). Guests replay it ("played #{} …", `0x18077f760`).
- Calls are shared only in the host's world (`phone_same_world`, since 12.10).
- **Phone interruption** (`phone_interrupt_any`, default on): "any one of us in combat, wanted 3+, without a phone, in a cinematic, under water or in a braindance – the team's". The call breaks off for everyone at once.
- **A known bug is acknowledged**: "it stays stuck: every next holocall here waits for a free line (a load resets it)". A `stuck_line_witness` diagnostic was added.

### 4.2 SmsReply (msg SmsReply=142)
- `sms_any` (default on): "a reply in a phone chat from anybody in the host's world: the host does it as the game does, the first one counts for everybody" (s8:36739).
- A guest's reply is sent to the host, which performs it and returns it through the journal sync. A second reply is dropped: "the question was answered already (a partner's reply came first)".

### 4.3 Braindance (msgs Braindance=137, BraindanceSource=157, BraindanceGhost=149, BraindanceClue=150)
- **Model**: "one timeline for everybody – the host leads, a guest's buttons are asks; everybody flies and picks the layer on their own; exit by a vote" (s8:43155).
- **The tape is matched on the recording's own timeline**, so voice-over length differences do not matter (`bd_tape_source`, 17.10).
  - The guest jumps to the host's frame when it slips: "the same frame by a jump to {:.2f} s at x{:.0f}".
  - The host's stops, turns and resets are reproduced exactly so that scene sockets fire everywhere (`bd_tape_exact`).
- **Exit**: "Leaving the braindance: your vote is in – everybody leaves at once when the others press exit too" (s8:43140).
- **Clues** (`bd_clue_any`, default on): "a focus clue … found by anyone goes at everybody by the game's own path (its condition done, the choice woken: the clue on the timeline, 'inspected', facts, the journal)" (s8:43458; `0x180966b50`, `0x180964600`).
- **Layer and view quest steps**, such as "switch to the audio layer", can be done by anyone (`bd_steps_any`).
- **Ghosts and avatars** (`bd_ghosts`, default on):
  - Each player's braindance camera is streamed to the others.
  - A flying partner is drawn as a coloured 2D icon plus name in the HUD layer, or as a 3D hologram cone in their colour (`BraindanceAvatars` builds a custom material, `0x18095d560`).
  - A partner "looking first person" shows as their name at the eyes of the recorded NPC, with an edge list for up to 7 others (s8:43296).

### 4.4 Photo mode
- **Photo together** (WorldRules, msg PhotoTogether=209, switch `photo_together`): "photo mode is allowed in co-op; one enters it – everybody in the host's world enters it too (the game's TogglePhotoMode request), one leaves – everybody leaves; each game stands in its own photo mode" (s8:40453).
  - When off, photo mode is disabled in co-op through the `NoPhotoMode` restriction, as before 22.10.
- **PhotoCopies** (`NightCoopPhoto`):
  - Spawns up to 2 "V copies" in photo mode, wearing a **remembered partner's look and outfit**. Partner looks are cached on disk by gender: "play once with a {} partner (their look is remembered by itself)".
  - Poses can be cycled, and there is a scripted camera "fly-around" orbit.
  - Usage: `NightCoopPhoto("status|add [1|2]|remove [1|2]|pose 1|2 next|prev|N|orbit [s] [deg]|stop|on|off")` (`0x1809abba0`; s8:44530).
  - Off by default per the hint "off (NightCoopQuestSet("photo_copies", true))".

### 4.5 Documents read
See §1.2 (`document_read_shared`, DocumentRead=187). The fact set by reading a computer document is forwarded to the host, so quest objectives count for everybody.

### 4.6 Promo (`NightCoopPromo`, msg PromoScene=172)
This is a scripted **marketing or trailer scene**, not gameplay sync:
- one player "casts" Cerberus' Blackwall (q305) at the partner;
- the victim falls to their knees through the `death_hacked` clip, with no real damage;
- a Johnny hallucination stands in place of the partner's body, with arms crossed in his workspot;
- the partner helps the victim up;
- a melee "punch of the scene" knocks out (s8:44117ff; `0x1809986c0`, `0x180995b30`).

It is enabled with `NightCoopPromo("on")` or the co-op menu. `NightCoopPromoKnees` is an internal name (a graph or effect reason), not a script function.

---

## 5. World interactions

### 5.1 DoorSync (msg DoorSync=88; `0x18072e240`, `0x180737fe0`)
- "a door is the same for everybody: open, locked, sealed – the host keeps it, every copy follows; a door closes by itself only when nobody is at it" (s8:35638).
- **Quest-driven door steps are reconciled with the led story.**
  - If a partner's quest opens a door ahead of the local quest, it stays open for this player until their own quest makes the step (`doors_open_behind`, `doors_ahead*`).
  - If a partner's quest shut it, it is held open if this player has not come through (`doors_own_shut`, `doors_shut_behind`).
- Partner bodies trigger doors on approach (`doors_bodies`). Doors are moved only when settled (`doors_settled`).

### 5.2 LiftSync (msgs LiftSync=86, LiftRide=97; `0x180711640`)
- "who is in which cab, the quest lift waits for everybody in the host's world, cabs leave in step for those inside" (s8:35288).
- `lift_one_cab`: "the host's departures move every copy (inside or outside), a guest's own departure asks the host".
- `lift_host_time`: the guest uses the host's travel time. `lift_speed_hold` and `lift_same_trip` are related fixes.
- Bodies and NPCs riding are placed in the cab's frame so they do not jitter. A named example is `#q000_first_elevator`.

### 5.3 DeviceSync (msg DeviceSync=139; `0x180745db0`)
- "cameras, turrets, traps, terminals, access points and the like are the same for everybody: a player's action with a device is done at the host as the game does it, the host's device state reaches every copy" (s8:35940).
- Turrets are host-led: a guest's turret releases the guest's player if the host's same turret is calm (`turret_host_led`).
- Device skill checks, deaths and replays have sub-switches (`devices_*`).

### 5.4 Workspots (WorkspotLayer, WorkspotDevice; msgs PlayerWorkspot=90, NpcWorkspot=93)
- **WorkspotLayer is mostly NPC-copy fidelity.** A copy ("twin") of another machine's NPC sits, leans or exits its workspot when the owner's NPC does.
  - Dozens of tuning switches exist: `twin_exit_on_time`, `exit_run`, `copy_reseat_wait`, `native_start_near`, `held_inputs_open` and others.
  - Lag statistics are logged: "exit lag over 10 s … late by median {} ms".
- **Sync animations** of players (grapples, takedowns, finishers, body disposal into freezers) carry the partner's target and the device's half of the animation (`sync_device`, `sync_grappled`, `sync_takes_copy`).
- **Crash guard**: "the end of AI workspots checks that the actor is still a readable entity (06.10 18:36 crash at exe+0x81C513)" (`NightCoopRideSet("workspot_end_guard", false)`).
- **WorkspotDevice** spawns local workspot devices for copies. WorkspotProps hands a copy the props container of the local spot (dumbbells, grill, barbell), "as an npc of the community gets it from its spot" (s8:28487; `0x1804fc110`).
- **Player sitting and leaning** on remote bodies is rendered in PlayerBridge/"tpp legs" (other report). `NightCoopWorkspot` is an internal CName (`0x18015ca30`, `0x1809a3b90`), not a registered script function.

### 5.5 Echo (`NightCoopEcho`, `NightCoopEchoDelay`, `NightCoopEchoOffset`, `NightCoopEchoStatus`)
- A **solo test harness**: it spawns a puppet "twin" of the local player replayed from local history with a delay and a lateral offset. "echo: the twin is live, {} ms behind you, {:.1f} m to your right" (s8:29595; `0x1805663f0`, `0x1805662d0`).
- Used to test puppet sync without a partner.

### 5.6 RandomSync and determinism
- The randomness is not globally deterministic. Only **quest** random nodes are seeded identically:
  - `led_random_one`, for quest **scene** random nodes: "rolls with one number at every machine (the host's world, the hour of the shared clock, the scene graph, the node, its roll in the scene's run)" (s8:38646).
  - `led_random_quest`, for `questRandomizerNodeDefinition` (TV and radio, open-world events, story branches): "the hour of the shared clock, the graph, the node, its roll in that hour" (s8:38759; summary `0x180809810`).
- Mismatches are logged ("our seeded roll #{} went '{}', the host's '{}' … the roll index or the world key differ"). In that case the guest takes the host's exit through LedOutcome, so the seed is a first line of defence and the host's exit is the authority.
- Both switches are on by default.

---

## 6. Time and pause

### 6.1 Game clock, time of day (SessionFlow, msg GameClock=46)
- The host's in-game time is applied to guests with `gameTimeSystem.SetGameTimeBySeconds`: "session flow: our clock was {:+.0f} game s off the host's – set to theirs" (s8:30325).
- `clock_same_world` (default on): "a guest takes the host's clock in the host's world only (12.10)".
- Separately, there is a **shared network time** (`NightCoopSharedTimeMs`; "initial clock offset {} ms", "clock: the host's time moved by {} ms at once"). Every "at the shared time T" event in this report uses it: gate openings, vote applies, hold releases.

### 6.2 QuestClock (msg QuestClock=94)
- This is **not** time of day. It is a lock-step for quest **real-time delay** nodes: "a realtime delay that starts here runs as in the game, but its end waits until the same node has started at the partners (at most {} ms and never longer than itself)" (s8:36835).
- **VR training stages** become barriers: "a stage goes on when every partner in VR is through it, at everybody in the same moment" (s8:36872).
- The common delay after own-V branches waits for the partner (`clock_own_branch`). Main function `0x18078d2f0`.

### 6.3 Pausing (WorldRules; `NightCoopNoPause`, `NightCoopBlockPause`, `NightCoopPauseSource`)
- **Normal menus do not pause the world in co-op.**
  - "world rules: a menu asked to pause the game – the world keeps running in co-op" (s8:40281).
  - The scanner slow-down, menu time-stop profiles and tutorial popups are also blocked "in co-op" (`tutorial_pause_wrap`).
- **A real pause needs everyone.**
  - "every player of the session in the world is in the pause menu (for {} ms) – the game is paused for real" (s8:40345). This is done with PauseGame plus SetPausedState.
  - With `windows_pause_all`, full-screen windows (inventory, map, shop) count too, using time dilation 0, "as the game does for a shop in a single game".
- **Engine pause race conditions are worked around.** The logs say "an UnpauseGame before it is lost and the world stays paused – 04.10 00:27:51", and the code waits before unpausing or re-pausing.
- **Forced pauses** are used for the start of the shared new game, loading screens in the host's world (WorldLoad: "whoever is out first waits paused until the place is up for everybody", `load_hold`), and StoryHold full pauses.
- **The script functions** (`PostRegisterTypes 0x1809ec910`):
  - `NightCoopNoPause(bool) -> bool` (`0x1809d3020`) goes to `0x180881d90`. It sets `DAT_180e976d8` and logs "world rules: keeping the world running on pause is now {}". **The initial value is 1, so it is on.**
  - `NightCoopBlockPause() -> bool` (`0x1809c9280`) goes to `0x1808829a0`. It returns true when in a session, `NoPause` is on, and `FUN_18051da80()` (probably "in co-op/connected") holds. It is likely used by redscript patches to decide whether to suppress a pause.
  - `NightCoopPauseSource(String)` (`0x1809d5450`) goes to `0x1808820a0`. It sets the pause source name by hand ("world rules: pause source set to '{}'"), as a fallback when "could not lift pause; none of the candidate source names worked. Use NightCoopPauseSource("name") if you know it." (s8:40244).

---

## 7. Script-callable functions in scope (registered in `PostRegisterTypes` 0x1809ec910)

Each function is registered under its full `NightCoop*` name. Most also have a short alias such as `QuestSet` or `QuestVote`.

| Function | Handler | Purpose |
|---|---|---|
| `NightCoopQuestSet(String)` | `0x1809da130` → `0x1809da250` | Global switch setter: ~253 names (all modules, not only quests). The value is a bool given in the same string. |
| `NightCoopQuestStatus()` / `NightCoopQuestDump()` / `NightCoopQuests(String)` | `LAB_1809e0a10` / `LAB_1809d9d70` / `0x1809e21f0` | Status and dumps of quest sync: scenes, facts, journal. |
| `NightCoopQuestResync()` | `LAB_1809da000` | Full facts/journal snapshot (§1.6). |
| `NightCoopQuestVote(int)` | `0x1809e1e50` → `0x180602990` | Vote option n from the console. |
| `NightCoopQuestVoteTimeout(int)` | `0x1809e2020` → `0x18062ac50` | Vote timeout in s (default 60; 0 = forever). |
| `NightCoopStorySet(String)` | `0x1809e5800` → `0x1809e5920` | Numeric story settings: `finish_s`, `rounds_wait_s`, `finish_move_s`, `finish_equip_s`, `finish_npc_s`, plus `story live` options (`live_pull`, `live_pull_save`, `live_pull_empty_save`, `live_finish_*`, `live_alarm_world`, `live_stuck_host_pass`). |
| `NightCoopStoryPull()` | `LAB_1809e56d0` | Same as PageDown: live pull, then pull by the host's save. |
| `NightCoopStoryStatus()` | `LAB_1809e5c40` | Story trace and alarm status. |
| `NightCoopGoAlone()` | `LAB_1809cc980` | Host only: start without waiting partners (same as holding End). |
| `NightCoopToHost()` | `LAB_1809e68d0` | Teleport to the host (session flow). |
| `NightCoopRide()` / `NightCoopRideSet()` / `NightCoopRideStatus()` | `LAB_1809e2c50`, `0x1809e2d80`, `LAB_1809e30a0` | Quest rides and workspot guard switches. |
| `NightCoopNoPause(bool)` / `NightCoopBlockPause()` / `NightCoopPauseSource(String)` | §6.3 | Pause control. |
| `NightCoopEcho(bool)` / `NightCoopEchoDelay(int)` / `NightCoopEchoOffset(float)` / `NightCoopEchoStatus()` | `0x1809cbae0` / `0x1809cbbb0` / `0x1809cbc80` / `LAB_1809cbd50` | Solo twin test. |
| `NightCoopPhoto(String)` | `0x1809d56e0` | Photo copies and fly-around. |
| `NightCoopPromo(String)` | `0x1809d6e30` | Promo scene on/off. |
| `NightCoopSharedTimeMs()` (alias) | `0x1809e5130` | Shared network clock. |

**Not script functions**, although the brief listed some of them: `NightCoopChoice`, `NightCoopHint`, `NightCoopPanel` and `NightCoopNewGame` are UI widget or style names (`0x1808918d0`). `NightCoopSkipWalk` is a time-dilation reason. `NightCoopScenePose`, `NightCoopWorkspot`, `NightCoopPromoKnees`, `NightCoopPhotoCopy` and `NightCoopBraindanceGhost*` are internal CNames or widget names.

**Hotkeys** (from the UI strings):
- PageUp held about 1 s: move to the partner who leads.
- PageDown held: pull the story to the host.
- End held (host): start without the partners.
- F: vote or ready.

### 7.1 Relevant switches and defaults
The default is the initial `.data` byte of the first flag each setter writes. This is a heuristic; it is confirmed where the strings agree (`led_policies`=0 "off by default", `skip_intro`=0).

- **On (1)**:
  - Scene, skip and story: `scene_gate`, `skips`, `skip_walk`, `skip_zone_catchup`, `skip_pull_timed`, `pulls`, `behind_gate_hint`, `story_names`, `story_trace`, `story_alarm`, `story_alarm_behind`, `quest_clock`, `story_hold`, `story_hold_scene_full`, `story_hold_led_ready`, `load_hold`, `quest_items`.
  - Led story: `led_pauses`, `led_world`, `led_looks`, `led_phase_zones`, `led_scenes`, `led_outcomes`, `led_choices`, `led_finish`, `led_rounds_wait`, `led_trigger_hold`, `led_random_one`, `led_random_quest`, `led_story`, `led_calls`, `zone_walls`, `story_stable_keys`, `story_scene_owner`, `own_tutorials`, `story_own_branch`.
  - Phone and SMS: `sms_any`, `phone_same_world`, `phone_talking_fact`, `phone_interrupts_own`, `phone_interrupt_any`.
  - Clock: `clock_same_world`, `clock_held_match`.
  - Doors, lifts and devices: `doors` and all `doors_*`, `lifts` and all `lift_*`, `devices`.
  - Braindance: `bd_timeline`, `bd_exit_vote`, `bd_tape_exact`, `bd_tape_source`, `bd_led`, `bd_steps_any`, `bd_ghosts`, `bd_clue_any`, `bd_actors_own`.
  - Build checks: `build_checks_native`.
- **Off (0)**: `led_policies`, `skip_intro`.
- **Not read** (inline or `.bss`): `photo_together`, `windows_pause_all`, `bd_ghost_3d`, `led_story_auto`, `led_wait_strict` and others.
  - The strings word `led_story_auto` as an opt-out ("NightCoopQuestSet("led_story_auto", false) – no fallback"), which suggests it is on.
  - `photo_together` and `photo_copies`/`photo_orbit` are worded as opt-ins.
- The full name list is in `0x1809da250`. The `quests:` options are listed in s8:31701; the `story live:` options in s8:38824.

---

## 8. Surprising design choices and admitted limitations

1. **The guest runs the whole story itself.** This is not state streaming: each machine executes the quest graph, and NightCoop intercepts every decision point (pauses, checks, randoms, choices, node finishes) to make the guest follow the host's exits. That keeps the native scenes, lines and animations on each machine, but requires stable graph keys and a big zoo of per-condition policies (§1.3). When it fails, it falls back to the older fact/journal mirror ("Story: the led graph does not hold – the old mirror is on").
2. **Divergence is accepted, and there are manual recovery tools.** The story trace raises a "story alarm" and the player must press PageDown; "nothing loads by itself". The second-level fix is reloading the host's fresh save "your character stays".
3. **Native UI is reused for voting.** Votes are cast in each player's own choice window, and the result is applied by **synthesising a key press** into the game's InteractionManager, with retries and scrolling. There is a lot of fragility handling (`vote_slip_select`, `vote_pending_rehub`, `vote_apply_verify`, "F FAILED (the choice window is not known to the scene: matched the old way)").
4. **Majority of 2 means both.** With two players every voted choice needs agreement, until the 60 s timeout hands the decision to the host's vote.
5. **Skips are not democratic.** One player can fast-forward everybody. The only brake is that a skip waits while a partner at the same point is in a state where the game forbids skipping.
6. **Subtitles are relayed by key, and only two languages are embedded.** The host's text is never shown, so if a partner's language is missing from the scene file, nothing is shown. Only en-us and pl-pl strings are embedded.
7. **There is a lot of special-casing of specific content**:
   - the VR tutorial (q000), where each runs their own course and stages are barriers;
   - "Ride with Jackie";
   - `#q000_first_elevator`;
   - "corpo, Jenkins' office: the trigger in the middle of the corridor";
   - "Lizzie's" and "Kirk and Big Joe in The Street Kid" (vote fixes dated 14.10);
   - "the guest's q001 blockade stood until the end of the ride" (08.10 evening).
8. **The code is tied to game version 2.31.** Many hooks check fixed exe offsets and vtable slots and degrade to "as in the game" if those do not match. Examples: "is NOT where 2.31 has it – it goes as in the game", "the splash controller is not the 2.31 one", and questQuestsSystem `vt+0x1D8/0x1E0`.
9. **Pause semantics change**: in co-op the world never pauses for one player's menus or tutorials. The logs admit several engine pause and unpause races, and work around them with timed waits.
10. **Known issues are written into the logs or the UI**:
    - a stuck holocall line until reload;
    - "The talk has not started? Step a few metres away from the NPC and come back";
    - gate nodes "never passed for a player" if reflection is incomplete;
    - a workspot-end crash (`exe+0x81C513`) guarded by a check;
    - time lost to long frames: "scenes, quest rides and delays here go that much later than at a partner with short frames".
11. **Joining relies on the host's save.** The joiner loads a save the host writes for them, and the whole host world freezes its quest system (StoryHold) for up to 90 s while they load.
12. **Every change ships with a kill-switch.** Nearly every behaviour change carries a dated switch that restores the old behaviour ("as before 17.10"), and many strings say "set it alike on every machine". A mismatch between machines is therefore a likely source of bugs.
