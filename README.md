# NightCoop — security analysis & reverse-engineering notes

> An independent, from-the-binaries study of **NightCoop**, a closed-source Cyberpunk 2077
> co-op mod built on RED4ext. Everything here was reconstructed by static reverse engineering
> of the shipped DLLs — before running the mod — and cross-checked against the mod's
> open-source hub server.

### ✅ Verdict: no malicious code

The bundled RED4ext files are genuine (byte-identical to the official v1.30.0 release), and
nothing in `NightCoop.dll` steals data, persists, downloads or runs payloads, hides APIs, or
touches anything unrelated to the game. Two builds have been analysed — **0.1.0-beta.1** and
**0.1.1-beta.2** — and both are clean.

What it *is*: a peer-to-peer co-op layer (star topology, host-authoritative) that shares one
player's world and story with up to seven partners over an end-to-end-encrypted transport,
relayed by a lobby hub at `hub.nightcoop.net`. The full mechanism is documented below.

---

## Start here

| If you want… | Go to |
|---|---|
| The one-page tour of how co-op works | [Overview](docs/00_overview.md) |
| The security bottom line (findings + severities) | [Security audit summary](docs/SECURITY_AUDIT.md) |
| Proof the DLL isn't doing anything nasty | [Capability triage](docs/capability_triage.md) |
| What's new in the latest build | [0.1.1-beta.2 changes](docs/6_changes_0.1.1-beta.2.md) |
| A specific subsystem | the [functional writeups](#functional-analysis) below |

## Documentation

All writeups live in [`docs/`](docs/).

#### Functional analysis

- [**Overview** — how the whole thing works](docs/00_overview.md) — architecture, hub ↔ client, the full feature tour
- [1 · Networking & session layer](docs/1_network_session.md) — transports, direct path, session layer, hub client, co-op menu
- [2 · The remote partner (avatar)](docs/2_players.md) — body, state, animation, look, effects, hit shapes
- [3 · Combat, NPCs, vehicles & police](docs/3_combat_npcs_vehicles.md) — NPC ownership, damage, downed/revive, PvP, vehicles, destruction
- [4 · Story, quests & world sync](docs/4_story_world.md) — quest "led" mode, scenes, dialogue votes, phone, braindance, time and pause
- [5 · Lifecycle, saves, loot & infrastructure](docs/5_lifecycle_world.md) — startup/hooking, save sharing, items/loot, world rules, config files, Add-on API
- [6 · What changed in 0.1.1-beta.2](docs/6_changes_0.1.1-beta.2.md) — the Rewards system, lag catch-up, and the diff from 0.1.0-beta.1

#### Security

- [**Security audit** — summary](docs/SECURITY_AUDIT.md) — consolidated findings and severities (no critical/high)
- [Capability triage](docs/capability_triage.md) — the pre-run malware triage behind the "no malicious code" verdict
- [Audit A · Network-message deserialization](docs/A_net_deserializers.md) — host/peer → client parsing
- [Audit B · Save splice, transfer framing, loot ledger](docs/B_save_splice_loot.md)
- [Audit C · Files, paths, config parsers, logs, clipboard](docs/C_files_paths.md)
- [Audit D · Crypto / authentication / logic](docs/D_crypto_auth.md)
- [Audit E · Hub server (defensive)](docs/E_hub_server.md)
- [Audit F · RCE, fuzzing & obfuscation review (0.1.1-beta.2)](docs/F_rce_fuzzing_0.1.1-beta.2.md) — reward-message & decompressor memory safety, a libFuzzer run, a packing/obfuscation sweep, and an honest residual-risk statement

## What was analysed

Two shipped packages. Only `NightCoop.dll` differs between them; the three RED4ext files are
byte-identical across both builds and to the official [RED4ext v1.30.0](https://github.com/wopss/RED4ext/releases/tag/v1.30.0).

| Build | `NightCoop.dll` SHA-256 | Compiled (UTC) | Size |
|---|---|---|---|
| 0.1.0-beta.1 | `6d22c0c1b70a3d79df4127a273f9e33198583698300086cd4f8f3e9f9e48adb8` | 2026-10-23 14:26 | 15.6 MB |
| 0.1.1-beta.2 | `9b07bb769013ef4a9f91b1b547ffb4929d5845ac63383892e3151895281e40bc` | 2026-10-24 15:16 | 16.1 MB |

Per-file hashes and the RED4ext comparison are in the [capability triage](docs/capability_triage.md).

## Key findings at a glance

- **Clean binary.** No process creation, injection, HTTP/download, executable memory, API hiding,
  string obfuscation, credential theft, persistence, or environment snooping — searched across all
  ~20k decompiled functions. [→ triage](docs/capability_triage.md)
- **The capabilities it *does* use are game-shaped:** reads/writes the game's save folder and its own
  config, crash minidumps, clipboard for invite codes, and PID-gated hotkeys (not a keylogger).
- **Networking is encrypted and hub-mediated.** Peer links use X25519 + XChaCha20-Poly1305; the hub
  (`hub.nightcoop.net`) is pinned. No critical or high-severity issue, and no memory-safety bug, on
  any surface. [→ audit summary](docs/SECURITY_AUDIT.md)
- **Privacy to know about:** the host's save is sent to guests by design, and the hub and peers see
  your IP. Direct-IP (hub-less) sessions are encrypted but unauthenticated.
- **0.1.1-beta.2 adds** a co-op Rewards system (kills/quest rewards shared through the game's own
  grant path) plus lag/scene catch-up tuning — no new capabilities. [→ changes](docs/6_changes_0.1.1-beta.2.md)

## Repository layout

```
docs/                       The writeups indexed above (functional analysis + security audits)
pseudocode/                 Ghidra decompilation of NightCoop.dll 0.1.0-beta.1, split by address range (~8 MB/file)
pseudocode-0.1.1-beta.2/    Ghidra decompilation of NightCoop.dll 0.1.1-beta.2 (same format)
tools/                      DumpAll.java — Ghidra headless script that decompiles every function
                            scan.py      — API-usage and malware-pattern scan over the pseudocode
                            show.py      — print matching lines (with context) from chosen functions
                            xref.py      — IAT call-site finder over objdump output, resolving string arguments
                            fuzz/        — libFuzzer harnesses for attacker-reachable parsers (see Audit F)
```

> `pseudocode/` is decompiler output of a third-party closed-source binary, kept for reference.

### Reproducing

```sh
analyzeHeadless /tmp/proj nightcoop -import NightCoop.dll -scriptPath tools \
  -postScript DumpAll.java all.c -deleteProject
python3 -I tools/scan.py all.c
python3 -I tools/show.py all.c 18090f7b0,18060a2f0      # dump specific functions

objdump -d --no-show-raw-insn -M intel NightCoop.dll > dis.txt
python3 -I tools/xref.py NightCoop.dll dis.txt RegOpenKeyExW,LoadLibraryW 14 5
```

## Scope & limitations

Static analysis of decompiler output and strings — the mod was never executed. Indirect calls
through game vtables can't be fully followed; sensitive call sites were hand-reviewed but not every
line of the ~69 MB pseudocode was read; and the server-side behaviour of `hub.nightcoop.net` is out
of scope. Details per writeup.
