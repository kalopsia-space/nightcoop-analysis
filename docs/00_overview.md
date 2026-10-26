# NightCoop: how the whole thing works

This combines the official open-source hub server ([Twenfys/nightcoop-hub](https://github.com/Twenfys/nightcoop-hub), commit `6b694a6`, "0.1.0") with a static analysis of the closed client `NightCoop.dll` 0.1.0-beta.1 (build `a7c537d`). Details per area are in the other files in this folder:

| File | Area |
|---|---|
| [`1_network_session.md`](1_network_session.md) | transports, direct path, session layer, hub client, co-op menu |
| [`2_players.md`](2_players.md) | the partner's avatar: body, state, animation, look, effects, hit shapes |
| [`3_combat_npcs_vehicles.md`](3_combat_npcs_vehicles.md) | NPC ownership, damage, downed/revive, PvP, police, vehicles, destruction |
| [`4_story_world.md`](4_story_world.md) | quest "led" mode, scenes, dialogue votes, phone, braindance, doors/lifts, time and pause |
| [`5_lifecycle_world.md`](5_lifecycle_world.md) | startup and hooking, save sharing, items/loot, world rules, config files, Add-on API |
| [`6_changes_0.1.1-beta.2.md`](6_changes_0.1.1-beta.2.md) | what changed in build 0.1.1-beta.2: the co-op Rewards system, lag catch-up, diff from 0.1.0-beta.1 |

Focused security work is in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (summary), [`capability_triage.md`](capability_triage.md) (pre-run malware triage of the DLL), and the audits [`A_net_deserializers.md`](A_net_deserializers.md), [`B_save_splice_loot.md`](B_save_splice_loot.md), [`C_files_paths.md`](C_files_paths.md), [`D_crypto_auth.md`](D_crypto_auth.md), [`E_hub_server.md`](E_hub_server.md), and [`F_rce_fuzzing_0.1.1-beta.2.md`](F_rce_fuzzing_0.1.1-beta.2.md) (RCE/fuzzing/obfuscation review of 0.1.1-beta.2).

## The hub matches this client

The hub repo is the real counterpart of this DLL build, not just something similar:

- The DLL contains the exact hub signing key (`kHubSignKey`, at file offset `0xa91d90`) and box key (`kHubBoxKey`, at `0xa91db0`) from `src/HubRules.hpp`.
- The DLL contains every crypto domain string from the repo ("NightCoop transport 1", "…hub identity 1", "…resume pass 1", "…hub locations 1", "…hub list 1").
- The DLL has the same pass and location-ping magics, and the same code alphabet `ABCDEFGHJKMNPQRSTUVWXYZ23456789`.
- `src/ProtocolCore.hpp`, `HubRules.hpp`, `NetCrypto.hpp`, `HubCookie.hpp` and `EnetGuard.hpp` are shared source: they compile into both the hub and the DLL. So the repo publishes the full wire format, including the numbers of all ~150 game message types (protocol version **128**), even though the game logic itself is closed.

## The architecture

```
 Guest PC (NightCoop.dll)                Hub (nightcoop_hub, Linux)               Host PC (NightCoop.dll)
 ───────────────────────                 ──────────────────────────               ──────────────────────
 own quest graph, "led" ── HubPayload ─▶  relays sealed envelopes  ◀─ HubPayload ── authoritative world/story
 own player (authoritative)              session codes, rate limits               NPCs near host, police,
 NPCs it owns (by distance)              signs peers' X25519 keys                 item ledger, clock
          ▲                              tells each its public IP                        ▲
          └────────────── direct UDP path (hole-punched, same keys) ────────────────────┘
```

- **Star topology.** The host is the authority and relays between guests. A session has the host plus up to 7 guests. Guests accept messages only from the host, and the host drops messages whose sender is forged.
- **Transport.** ENet over UDP. Every message starts with `NCOP` + type. The default `HybridTransport` keeps a hub link and opens a direct path whenever it can. It switches to direct when direct RTT ≤ hub RTT + 10 ms, and back to the hub if direct is more than 30 ms slower for 5 s or goes silent. A numbered reliable stream (`NCSQ`), with a home-made LZ77 `wire_zip` (`NCZQ`), survives path switches.
- **End-to-end encryption.** Each host–guest link does X25519, derives keys with BLAKE2b over a transcript with salts, and seals every message with XChaCha20-Poly1305 (25 bytes overhead, replay window 4096). The hub signs each peer's key for the session (EdDSA). When the hub has been verified, a link with a bad signature or no encryption is refused. The hub sees only addresses, sizes and timing.

## What the hub does (open source, fully read)

- **Codes.** Hands out 6-character session codes from the system RNG. A 7-character code adds a hub "letter": `e.hub.nightcoop.net`. Codes are kept in memory only.
- **Relay.** Relays `HubPayload [to/from][opaque bytes]` and never parses the game traffic. It enforces that one connection belongs to one session in one role.
- **NAT help.** Answers `HubAddrQuery` with the address it sees the client at; the client uses that for hole punching.
- **Threads.** Runs one thread per core, each on its own port (47810+). The entry port 47800 sends a client to its session's thread with `HubRedirect`.
- **Abuse limits:**
  - SipHash connection passes ("cookies") that stop CONNECT floods from forged addresses.
  - Per-address limits: 12 creations and 12 failed joins per minute, then it stops answering (this stops code guessing).
  - A pre-ENet queue guard, queue caps, and an idle timeout of 30 s.
  - Answers are never longer than the request, so the hub can't be used to amplify traffic.
- **Identity.** Each hub has an EdDSA signing key and an X25519 "box" key, in `hub-sign.key`. Clients check a hub in one of three ways:
  - the official hub by the key built into the client (*pinned*);
  - a `*.nightcoop.net` hub by a project root certificate (*chain*; the root key is still all zeros in this build);
  - your own server by a 16-character Crockford fingerprint, as in `host#XXXX-XXXX-XXXX-XXXX`.

  With a verified hub, the session code travels sealed to the hub's box key.
- **Resume after restart.** The host holds a signed resume pass (valid 12 h). After a hub restart the host reclaims the same code within 90 s and guests rejoin with their old peer numbers.
- **Server picker.** Clients ping hubs with connectionless datagrams and get back the hub's state, load and a signed location list. They pick the lowest RTT.
- **Owner tools.** `--gen-root-key`, `--issue-cert`, `--sign-list`, `--locations`, and stats every 5 minutes.

## What the client does (closed, from the pseudocode)

**Loading.** It is a RED4ext plugin. `Query` always reports itself compatible. Two game builds are hard-coded: 2.31 (exe 3.0.80.51928) and partly 2.5 (3.0.88.46235). On any other exe it stays passive and only dumps RTTI names. `Main` installs about 95 subsystems. Hooks are RED4ext `Attach` calls at addresses found by hash or per-version offset, each checked against the expected bytes first. On top of that, `ScriptPatch` reroutes many game script functions through native checks.

**Starting a session (world sharing).**
1. The guest makes a pre-session save and asks for the host's world (`WorldWant`).
2. The host saves and sends its `sav.dat` (`WorldFile`).
3. The guest splices **its own character** from its last save into the **host's world**, writes it atomically (`.nightcoop.tmp` → `MoveFileExW`), loads it, and reports back (`WorldStatus`).
4. When it returns to solo play, the player chooses: keep their own world (and keep the level, money and items gained in co-op), or carry the session's world. Backups protect the original campaign.

**The partner's body.** A second `PlayerPuppet` is spawned from the player's own template, with player-only components removed and NPC senses and hit shapes added. About 30 AI call sites are redirected to "the nearest player".
- State (`PlayerState`, ~103 bytes, unreliable) is sent at a fixed 30 Hz and eased over about 0.3 s, or teleported.
- Animation works by capturing the raw inputs of the partner's first-person anim graph (`AnimTap` → `PlayerAnim`) and replaying them on the body (`AnimMirror`). NPC clips fill the gaps a first-person graph has (legs, aim, reload, melee).
- Looks are copied by answering the game's customization system separately for each body; clothes, cyberware and Johnny are handled too. Sandevistan ribbons, ghosts and slow-down limited to a sphere around the user, markers and minimap pins are all custom.

**NPCs and combat.**
- **Ownership.** Each NPC has one owner machine that runs the real AI. Since both machines load the same save, each machine's own copy of an NPC is paired with the other's ("twins") and turned into a puppet driven by snapshots (20 Hz; less when far away) and anim inputs.
- **Handoff.** Ownership moves by distance: given away past 70 m, taken within 100 m, through a NpcHandoff → Ack → Claim exchange.
- **Damage.** Hitting someone else's NPC sends a `HitClaim` (a percentage of health) to the owner. The owner re-queues it as a real hit from your body, so quests, perks and AI react normally.
- **PvP and downed.** PvP is off by default and set by the host; it downs players and never kills them. Instead of dying you are *downed*: a partner holds F to revive you, and you hold T to pass out and wake somewhere safe.
- **Police and vehicles.** Police are run by the host for whoever has the higher wanted level. Vehicles are owned by their driver and mirrored kinematically for everyone else; passengers get proper seat animations.

**Story ("led" = led by the host).**
- **Quests.** Every guest still runs its own quest graph. At every decision point (pauses, checks, switches, random rolls, choices) it takes the host's result. A StoryTrace compare raises a "story alarm" when the two drift; PageDown pulls to the host, and pressing it again loads the host's save.
- **Scenes.** SceneGate holds a quest conversation until everyone is there, then starts it at a shared time for all.
- **Dialogue.** Choices are **voted** in each player's own choice window: a strict majority wins, with a 60 s timeout after which the host's pick wins. Skips are not voted: one player's skip pulls everyone along.
- **Shared world.** Doors, lifts, devices, phone calls, SMS, braindances (led by the host), photo mode and documents are all shared. Quest random rolls are seeded from the host's world.
- **Time and pause.** The clock is the host's and only the host can skip time. Menus don't pause the world; it pauses only when **every** player is in the pause menu.

**Items.** Item transfers go through a ledger on the host (offer → debit → grant → ack), and unique items can't be transferred. Loot belongs to whoever owns the NPC, and `loot_personal` makes one-time items per-player. Dialogue stat checks use the best stats of anyone in the session.

**Config and tooling.**
- **Config files.** All live next to the DLL: `switches.txt` (`name = on|off`, about 250–550 named switches, also settable live via `NightCoopQuestSet`), `servers.txt`, `hub.txt` (old), `name.txt`, `markers.txt`, `hubs.ncl` and `locations.ncl`.
- **Script functions.** About 250 `NightCoop*` functions, callable from CET or redscript, mostly for debugging.
- **NightReplay API.** `NightCoopAddonApi(2)` gives the NightReplay plugin a table of 66 functions.
- **Diagnostics.** HangWatch logs stuck threads, writing minidumps only if `hang_dump` is on. FrameWitness (msg 208) tells partners about frames of 500 ms or longer.
- **Platforms.** GOG cloud saves work through `REDGalaxy64`, and Wine/Proton gets its own crash guard and defaults. The game can restart without Phantom Liberty so that a guest who doesn't own it can join.

## Corrections to the earlier security README

- **There is no beta expiry.** The only "it expired on {}" string is in the hub *certificate* check, which allows about 2 days of clock difference. There is no kill switch in the client. An expired official certificate would only block the official hubs; your own server would still work.
- **UPnP doesn't open ports.** The DLL has `M-SEARCH` and `GetExternalIPAddress`, but no `AddPortMapping`. SSDP/UPnP, STUN and the IPv6 probe all run only in the on-demand `NightCoopNetCheck` diagnostic, not during normal play. Hole punching relies on the address the hub reports.

## Privacy and security notes

- The hub and your peers see your IP address. The host's save is sent to guests by design.
- IPs are written to the mod's log by default (`log_hide_ips` is off), so be careful when sharing logs.
- A **direct-IP** session (no hub) is encrypted but has no key verification, so a man-in-the-middle could read it. A hub session, including its direct path, has verified keys.
- Kick bans use a client id the client generates itself on each launch, so a kicked player can get back in by restarting.
- A self-hosted hub without a fingerprint shows "encrypted, not verified": always give players the fingerprint with the address.
- No telemetry was found; logs and dumps stay on your machine.

## Limits of this analysis

All of this is static: it comes from decompiler output and strings, and the DLL was never run. Many switch defaults are inferred, either from initial data or from hint strings. Some functions are assigned to modules by their position in the binary. Much of the code checks the exact bytes of game 2.31 and switches itself off on other versions.
