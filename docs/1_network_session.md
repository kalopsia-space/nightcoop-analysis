# NightCoop client: networking and session layer

Static analysis of `NightCoop.dll` (build `a7c537d`): Ghidra pseudocode, raw strings, and the shared headers from the open-source hub repo (`ProtocolCore.hpp`, `HubRules.hpp`, `NetCrypto.hpp`, `EnetGuard.hpp`). Nothing was executed.

The networking modules have no embedded `src\*.cpp` paths, because only modules that use the assert/`ResolveApi` macro embed one. Functions here are named by their log strings. Ghidra often prints a log string as a bare pointer (`local_138 = 0x180a9a8d0`) or through a RIP-relative `lea`, not inline. To find them I mapped every `.rdata` string to its VA and scanned `.text` for RIP-relative references (helpers: `scratchpad/tools/fs2.py`, `lea.py`, `strmap.py`).

Notation: `FUN_` addresses are function entry points. Quotes are log or UI strings, shortened.

---

## 0. Summary

- **Three transports, chosen per session** in `1800b0330` (session start):
  - **Direct** (`FUN_180055970`, ENet listen/connect, "transport"): used by `NightCoopHost(port)` / `NightCoopJoin(addr,port)` and "Host by IP / Join by IP".
  - **Relay** (`FUN_18005b5e0`, "relay: …"): a hub session with the direct path off.
  - **Hybrid** (`FUN_180067610`, "hybrid: …"): a hub session with the direct path on. This is the **default** (`session+0x608 = 1` in ctor `1800a1650`; toggled by `NightCoopHubDirect(bool)`).
  - Log: "session: through the hub {}:{} with the direct path (the hub is the meeting point and the fallback)" vs "session: through the hub {}:{}, relay only".
- **Hybrid** keeps one UDP socket for both the hub and the peer. It learns its public address from the hub (`HubAddrSeen`), not from STUN. It exchanges candidates through the hub, hole-punches for 5 s, and opens a second ENet connection authenticated by a session tag and a "direct hello" sealed with the hub-vouched link keys. Traffic then **moves between the direct path and the hub by measured RTT, with hysteresis**. A NightCoop reliable stream layered on top (`NCSQ`/`NCZQ` frames, `NCPT` control) survives path switches, and resends unconfirmed messages on the new path.
- **STUN, UPnP and IPv6 probing are used only by the on-demand `NightCoopNetCheck`** diagnostic, never for connecting.
- **Session layer** (`1800a85b0`, the message dispatcher): a star topology with the host as authority and relay.
  - `Hello` carries protocol **128**, a random client id, the nickname and the game version.
  - Up to **7 guests** by default.
  - Kick bans the client id for the rest of the session.
  - Peers can return after a drop, and a session can come back after a hub restart (`hub_resume`).
- **Hub client**:
  - The server picker pings locations, picks the nearest open one, and supports lettered hubs (7-char codes).
  - State lives in `servers.txt`, `hub.txt`, `locations.ncl`, `hubs.ncl` and `name.txt`.
  - Invite format is `CODE@address[:port][#FINGERPRINT]`.
  - Fingerprint UX: "Verified" vs "Encrypted, not verified".

---

## 1. Transports

### 1.1 Transport selection (`FUN_1800b0330`)

```
if hub session (param_7) && session.hubDirect (+0x608)      -> HybridTransport  (new 0x3a60, FUN_180067610)
else if hub session                                          -> RelayTransport   (new 0x478,  FUN_18005b5e0)
else (direct IP host/join)                                   -> ENet transport   (new 0x290,  FUN_180055970)
```
- Max guests: `if (param_6 == 0) param_6 = 7;`, stored at `session+0x368` (the ctor also sets `= 7`). Host log `1800ad5f0`: "session: the host is up — up to {} guest(s) ({} players with the host); with all of them here one more is refused at its Hello («the session is full»), a guest we still wait for gives its place to a new one".
- "session already running; stop it first".
- **Which hub is used** (same function):
  1. `hub.txt` next to the DLL, when `hub_file` is on: "session: hub.txt next to the dll names the server {}:{} — the session goes there instead of the project's hub (hub_file)".
  2. For a join, a 7-char code whose first letter names a hub: "session: the code {} starts with the hub letter {} — joining session {} on the hub {}:{}".
  3. The server picker (`hub_picker`): "session: the server picker sends the join {} to {} {} — …", and for hosts "…sends the host's session to {} {}" (`18008b9e0`).
  4. Without the picker, `hub_pick` (`1800ab8b0`): "session: the nearest hub of the project is {} … its code starts with {}". Fallback is `hub.nightcoop.net:47800` ("as before 22.10").
- Default port everywhere is `0xbab8` = **47800** (direct host/join, hub, NetCheck).

### 1.2 Direct ENet transport ("transport", `FUN_180055970` / `180057760` / `1800563b0`)

- `enet_host_create(addr, peers, **2 channels**, …)`. Logs: "listening on port {}, up to {} peers; links {}" and "connecting to {}:{}".
- Link security log: "encrypted without authentication (a direct connection: no hub to vouch for the keys)" or "NOT encrypted (net_crypto off)".
- Guest reconnects on its own: "reconnecting to {}:{} (attempt {}, next in {} s)" (network thread `1800b2640`).
- `EnetGuard` (shared with the hub) filters datagrams before ENet: "transport: a datagram from {} is dropped before ENet: … the pool holds {} MB …; NightCoopQuestSet("net_guard", false)".

### 1.3 RelayTransport ("relay: …", `18005b5e0`, main handler `18005d120`, connect `18005c220`)

- ENet client to the hub. Handles `HubRedirect` ("relay: the hub sends us to its port {} — the session lives in that thread of the hub"), `HubIntro` and cookies.
- Logs: "relay: session code {}", "relay: joined session {} as hub peer {}", "relay: hub rejected the join: {}".
- Payloads from a hub peer with no crypto link are dropped: "a payload from hub peer {} that has no link here — dropped (encryption is on)".
- Hub resume (host side) is in `18005bcd0`; see §3.5.

### 1.4 HybridTransport ("hybrid: …", ctor `180067610`, connect `18006bdc0`)

**Socket.** "hybrid: socket 0.0.0.0:{} — one socket for the hub and the direct path for the whole session". `SIO_UDP_CONNRESET` is turned off (`18006df60`). Every datagram passes a pre-ENet guard ("a datagram from {} is dropped before ENet"). Because one socket talks to both, the address the hub sees is a usable NAT mapping for punching.

**Own address and candidates.**
- `HubAddrQuery`/`HubAddrSeen` give the public address: "hybrid: the hub sees us as {}".
- LAN candidates come from `180073e40`:
  1. A UDP socket `connect()`ed to **8.8.8.8:53** (no data is sent), then `getsockname` gives the default-route IP.
  2. `WSAIoctl(SIO_ADDRESS_LIST_QUERY 0x48000016)` adds interface addresses.
  3. Only private or CGNAT IPv4 is kept (10/8, 172.16/12, 192.168/16, 100.64/10), at most 3.
- If neither source works: "no address to offer (no LAN interface and the hub did not tell ours)".

**Path protocol handshake (`NCPT` kind 1, `18007be20` → handler `1800754c0`).**
- Each side sends `NCPT|01|01|flags|u64 tag`. The flags say whether the direct path is allowed and whether zip is supported.
- Logs: "hybrid: peer {} speaks the path protocol (v{}, direct path {}) — reliable messages go numbered from now on" and "hybrid: peer {} understands zipped frames — reliable messages to it go in one zipped frame per network turn".
- Older or relay-only peers: "does not speak the path protocol (relay-only or an older NightCoop) — it stays on the hub".

**Direct attempt (guest initiates, `18007d550` / host side `180072f00`).**
1. The guest sends `NCPT` kind 2 (offer) **through the hub only** (the handler checks `param_5 == 1`, i.e. "came via hub"): "hybrid: direct attempt {} ({:08x}): offering {} candidate(s) to the host: {}".
2. The host answers with kind 3 (its candidates) or kind 4 (refusal: "the host has the direct path off" / "the host is busy with other direct attempts"): "hybrid: peer {} offers {} candidate(s) (attempt {:08x}): {}; answering with {}; punching for 5 s".
3. Both sides punch: "hybrid: {} {} answered the punch after {} ms".
4. The guest opens an ENet connection: "hybrid: direct connect to {} {} with the session tag". The host checks it (`180077be0`): "a guest takes no direct connections", "no session tag", "wrong session tag".
5. The first message on the new connection is a **direct hello sealed with the existing hub-vouched link keys** (`1800781b0`). Possible refusals: "its sealed hello opens with the keys of no link that tries a direct path", "an unencrypted hello for an encrypted link", "its hello is sealed with another link's keys", "wrong session tag in its hello".
6. Success: "hybrid: direct path to the host is up via {} {} ({} ms from the offer)". A NAT-hairpin or LAN path is reported as "Direct connection with your partner (local network)".

**Timeouts and retries.**
- Per-step timeouts: "the host did not answer the offer in 3 s", "no candidate answered the punch in 5 s", "the direct connection did not open in 3 s", "no direct connection came in 12 s", "sent no hello in 3 s".
- Retries: "failed: {} ({} of {}); next in {} s". The status shows `failed({}/5)`. After 5 in a row: "giving up after {} attempts in a row — staying on the hub, next try in {} min".
- After a loss, re-attempt timing depends on how many losses happened recently: "a new direct attempt to peer {} in {} s ({} loss(es) in 5 min)".

**Path choice (`18006b180`).** Kind 6/7 are per-path pings and pongs. The RTTs are kept at `link+0x1e0` (direct) and `+0x1c0` (hub).
- Moving to direct requires `rtt_direct <= rtt_hub + 10 ms`. Before the hub has been measured: "{:.1f} ms, the hub is not measured yet".
- Going back to the hub happens when:
  - the direct path is silent for more than 1.5 s (0.75 s with `path_fast_leave`) or 3 s, or
  - it is slower than the hub by more than **30 ms** for 5 s ("the direct path is slower: {:.1f} ms against {:.1f} ms through the hub"), or
  - there is "no answer on the direct path for 20 s", or
  - "the direct connection is gone".
- On every switch: "hybrid: path to peer {}: {} — …; resending {} unconfirmed reliable message(s) on it".
- If the hub is lost while the direct path is up, the session continues: "hybrid: peer {} stays on the direct path without the hub" and "The link to the hub is lost — staying on the direct path with your partner".

### 1.5 Framing, reliability, compression

All game packets start with `u32 kMagic 'NCOP' (0x4E434F50)` and `u8 MsgType` (`ProtocolCore.hpp`). The hybrid link adds its own frames, demuxed in `1800780b0`. The magics are written as little-endian u32 literals, so on the wire the bytes come out reversed (e.g. `TPCN`).

| Magic (u32) | Meaning | Evidence |
|---|---|---|
| `NCPT` 0x4E435054 | Path control: `u8 kind` + body. 1 = path hello, 2 = direct offer (to host), 3 = host's candidates, 4 = host refuses, 5 = ack `u32 epoch, u32 seq`, 6/7 = path ping/pong, 10 = resend request `u32,u32` | `18006c5d0`, `18007bb10` (kind 5), `18006a800` (kind 10), switch in `1800754c0` |
| `NCSQ` 0x4E435351 | Numbered reliable frame (stream epoch + sequence) | `18007b6f0`, `180076490` |
| `NCZQ` 0x4E435A51 | Zipped numbered frame: `u32 epoch, u32 seq, u8 mode (bit0 packed, bit1 no-history), varint len, u32 check, body` | `18007f970` |
| anything else | A legacy plain message, delivered as is | `1800780b0` tail |

- **Reliability.** A NightCoop-level sequence and ack layer runs on top of ENet so that one reliable stream can cross both paths.
  - Out-of-order data waits: "{} bytes wait for a gap to fill — dropping more (it will be resent)".
  - Restart: "peer {} restarted its reliable stream".
  - Dead-link cutoff: "{} MB of reliable messages wait for confirmation — the link is dead".
- **wire_zip.** A home-made LZ77/LZ4-style compressor (`1800632a0`): 256 KiB history window, 16K-entry hash (`*0x9E3779B1 >> 18`), 64 KiB maximum frame and offset, 4-byte minimum match. It compresses **against the whole stream history**, so one frame per network turn holds all of that turn's reliable messages.
  - On failure it falls back to frames without history: "zipped frame {} does not unpack against the stream history … this stream goes unzipped from now on".
  - A debug switch can corrupt the check on purpose: "test: … goes with a wrong check".
  - With `wire_zip` off: "one plain frame each, as before 10.10".
- **Crypto.** `CryptoHello` (147) goes first on each link, then everything is sealed with `0xC5 | u64 ctr | XChaCha20-Poly1305 | tag` (shared code, already known).
- **Throttle.** ENet's packet throttle is held open by default (`enet_no_throttle` = 1, `FUN_1805a90b0` → `DAT_180d81332`): "it drops no unreliable packets (npc snapshots, player states, path pings) when the round trip grows". The status shows `throttle=direct:{},hub:{}/32`.

### 1.6 NetSim / NetStats / RTT / status line

- **NetSim** (`1809d2960`, `NightCoopNetSim(Int32 delayMs, Int32 jitterMs, Float lossPct)`): clamps delay to 0–2000, jitter to 0–1000 and loss to 0–50 %. It affects **outgoing** messages only, and loss hits **unreliable** messages only. Log: "net sim: our outgoing messages go {} ms later (+0..{} ms), {:.1f}% of the unreliable ones lost — set the same on the other machine: the RTT grows by the sum".
- **NetStats** (`1809d2d90`, `NightCoopNetStats(Int32 seconds)`, 0–3600, 0 = off, stored at `DAT_180d8132c`): prints "netstats: {:.0f} s, peers {}; udp out … dgram/s KB/s with IP …; hub out {}, in {}; direct out {}, in {}; session out reliable {}, unreliable {} …; zipped reliable …; out by kind: {}; in by kind: {}". Sub-lines cover zip CPU and crypto cost per frame ("crypto: sealed {:.0f}/s ({:.2f} us each …)"). Hub sessions only.
- **Status** (`1800a4b80`): "role={} connected={} peerId={} peers={} rtt={:.1f}ms offset={}ms". Optional fields: `awaiting=`, `reconnects=`, `code=`, `sim=+{}ms(+0..{}) loss=`, `hub=… relay-only`, `path[{}]` with `rtt_direct`, `rtt_relay`, `zip=x{:.1f}`, `crypt=`, `throttle=`. Per-peer direct-path state is one of `trying`, `up({}) but not chosen`, `failed({}/5)`, `gave-up`, `,next-in-{}s`.
- **Network thread** (`1800b2640`): "network thread started", "network thread stalled for {} ms", and periodic "heartbeat: peers={} loops={} sent={} recv={} rtt={:.1f}ms clock {}ms (target {}ms)" with per-peer `lag[{}]=… (mean, dev)`.

### 1.7 NetCheck (diagnostic only)

- Started by `NightCoopNetCheck(String hub)` (`1809d22d0`; an empty string or `host[:port]`, default port 47800). It runs on a worker thread (`1800badd0` → `1800b7700` → `1800b7b80` → `1800b9df0`). Logs: "net: check started, about 10 seconds; result goes to the log and NetCheckStatus()" and "net: a check is already running".
- **STUN** (`1800baf60`): a Binding Request with magic cookie `0x2112A442` to a table at `0x180a9aec0`: `stun.l.google.com:19302`, `stun.cloudflare.com:3478`, `global.stun.twilio.com:3478`, `stun.nextcloud.com:3478`. NAT type comes from whether the mapping is the same for every server ("same address for every server" → moderate, "address differs per server" → strict). Other result: "no STUN replies of {} (UDP to the internet may be blocked)".
- **UPnP/SSDP** (`1800ba410`, `1800bb9a0`): M-SEARCH to 239.255.255.250:1900 for IGD v1/v2, fetch of the device XML, then SOAP **`GetExternalIPAddress` only**. There is **no `AddPortMapping`** anywhere. Results: "router WAN {} differs from the external {}", CGNAT detection.
- **IPv6** (`1800b9170`): a route probe toward `2001:4860:4860::8888`. Hub RTT: "hub {} RTT {:.0f} ms".
- Summary line (`1800b7e10`): "net: NAT {}; interface {}; {}; CGNAT {}{}; {}; IPv6 {}; {}".

---

## 2. Session layer

### 2.1 Message dispatcher `FUN_1800a85b0`

- **Header and parse failures.**
  - Bad header: "malformed packet from peer {} ({} bytes)".
  - Unknown type: "unhandled message {} from peer {}".
  - Refused message: "message {} from peer {} is not taken: {} ({} such so far)", where the reason comes from `1800a3270`.
- **Role.** `session+0x24`: 1 = host, 2 = guest.
- **Gating rules** (lines 245–300; host/guest checks first, then "said Hello first"):

| Rule | Applies to |
|---|---|
| A guest takes **anything** only from transport peer 0 (the host): "a guest takes messages from the host only" | all messages |
| `Welcome(2)`, `Reject(3)`, `TimeSyncPong(5)` are guest-only: "only a guest takes it, and only from the host" | guest |
| `Hello(1)`, `TimeSyncPing(4)` are host-only: "only the host takes it" | host |
| `TimeSyncPing(4)`, `PlayerState(6)`, `Bye(9)`, `Game(25)` need a prior Hello: "its sender has not said Hello in this session" | host |

- The switch covers types 1–110 directly. Later types are routed to the game modules.

### 2.2 Handshake

- **Hello** (guest → host, built in `1800a7b30` after "peer {} connected at transport level"). Log: "connected to host, sent Hello (protocol {}, game {})". Layout:
  ```
  'NCOP' | 01 | u32 protocol = 0x80 (128) | u64 clientId | string nickname ("guest" if empty) | u64 gameVersion
  ```
- **Client id.**
  - Generated once per process when it is zero: `rand()`-based value XOR clock, never 0. Stored at `session+0x2d8` and kept across reconnects, so a returning guest is recognised.
- **Host checks** (in this order):
  1. Protocol: `iVar9 == 0x80`. Otherwise "protocol mismatch: host {}, guest {}" and "rejected peer {}: protocol {} != {}".
  2. Game version, only when `same_game_version` is on (`DAT_180d81336`, default **on**): "game version mismatch … everyone in a session needs the same version of Cyberpunk 2077" and "rejected peer {} ('{}'): game {} != host's {} (same_game_version)".
  3. Ban list: "refused peer {} ('{}'): client {:016x} was kicked from this session", sent to the guest as "kicked: the host removed you from this session".
  4. Capacity: "refused peer {} ('{}'): the session is full — all {} guest(s) of {} are here". If a slot is held by an absent guest, the new guest gets it: "is still away and a new guest takes its place".
  5. Duplicate Hello: "a second Hello of another client on a connection that said Hello already".
  6. Accept: "peer {} accepted ('{}')", or for a known client id "peer {} is back ('{}')".
- **Welcome**:
  - Guest log: "welcomed as peer {}, initial clock offset {} ms".
  - After a hub restart: "session: back in the session as peer {} after {:.1f} s without the hub — the partners' bodies go on from where they stood (hub_resume)".
- **Reject**: "rejected by host: {}".
- **TimeSync**: the guest pings and the host pongs. Clock jumps are logged: "clock: the host's time moved by {} ms at once (rtt {:.1f} ms)". `SharedTimeMs()` exposes the shared clock.
- **PlayerState(6)** checks, on the host:
  - "a player state for another peer's number"
  - "a player state with a peer number or a place that cannot be"
  - Non-finite floats are reset: "a number that is not finite came — set to its default"
- **PeerJoined/PeerLeft/Bye**: "peer {} said goodbye", "a goodbye for another peer's number".
- **Kick(110)** (`1800a5730`):
  - The host sends type `0x6e` with a reason string capped at 256 bytes, bans the client id, and closes the connection after **1500 ms**: "peer {} ('{}') is kicked: {}; client {:016x} is banned from this session ({} banned), the connection closes in {} ms".
  - Guest side: "kicked by the host: {} — the session stops, this client is not let back in".

### 2.3 Game message routing (type 25 `Game`)

- Envelope: `u32 to (0xFFFFFFFF = everyone) | u32 from | u8 reliable | payload`.
- Host checks:
  - The sender must be honest: "game message with forged route: transport peer {}, claimed sender {}, role {} ({} dropped so far)".
  - Host-only kinds are not forwarded: "game message of peer {} that goes to the host only is addressed to {} — not relayed".
- The game thread queue is bounded: "a game message of {} B from peer {} is not queued: {} message(s), {} KB wait for the game thread already (limits {} and {} MB; loading or a flood)".

### 2.4 Peer numbering, presence, roster

- The host is peer 0. Guests are 1..N: on the hub the number comes from `HubJoinAccepted`; in direct mode the host assigns it. The kick handler checks "the peer number of a guest is 1 or more" (`1809cef20`). UI labels players without a nickname as "Player N".
- **Away grace.** A dropped guest's slot and body are kept ("awaiting="). It returns with the same client id under the same number ("peer {} is back"). A newcomer can take the slot only if the session is otherwise full ("a guest we still wait for gives its place to a new one").
- **Hub-loss grace for guests.**
  - "session: lost the hub in session {} — waiting up to {} s for the host to bring it back; the partners' bodies stay where they were (hub_resume)". The wait is 90 s per the switch text.
  - If the session does not come back: "{} partner(s) and their bodies are dropped, the session goes on as on a lost link".
  - Per peer: "peer {} did not come back after the hub's return — its body is removed".
- **PlayerPresence(111) / SessionRoster(112) / LobbyStart(113)** belong to the CoopMenu lobby:
  - Guest logs: "lobby (guest): our presence — where {}, {}, save …"
  - Roster logs: "lobby (host): roster rev {} — phase {}, world …, {} player(s)" and "lobby (guest): roster rev {} — the host is {} …"
  - The shared new-game start is synchronized at a shared time: "coop menu: the shared new game start #{} goes for everybody at the shared time {} (in {} ms, the slowest link rtt {} ms)".
- **BuildStats(141)** (TeamBuild.cpp): each V's attributes, level and street cred are "told the partners at every change and every 5 s". Dialogue and scene attribute checks then use the **team's best** (`build_checks_any`, `build_checks_native`).

### 2.5 Authority model (as seen from the session layer)

- **Star topology.** Guests talk only to the host, and the host validates and relays everything. Guests ignore non-host senders.
- **Host decides**:
  - admission, version checks, kicks and bans, capacity
  - session difficulty ("lobby (guest): the session difficulty is the host's")
  - new-game start, life path and difficulty screens ("the start, the difficulty and the life path are the host's")
  - PvP and "tougher enemies" ("Only the host switches PvP", "Only the host sets tougher enemies")
  - the world itself ("the host's world"); the guest's world comes by the host's save
  - the session clock (`clock_same_world`)
- Many gameplay subsystems (NPC owners, vehicles, story) have their own owner rules, outside this scope.

---

## 3. Hub client

### 3.1 Files (all next to the DLL in `red4ext/plugins/NightCoop/`)

| File | Purpose | Evidence |
|---|---|---|
| `servers.txt` | Server-picker state. Header "# NightCoop: servers of the mod menu «Server» (written by the game; edit only with the game closed)", then `nightcoop-servers 1`, `choice auto` / `choice main` / `choice letter X` / `choice own N`, own-server lines (address and label), and `hub-txt taken` | writer `18009a300`, parser `180095010` |
| `hub.txt` | A single own server. With `hub_picker` on it is imported **once** into servers.txt as the chosen own server ("hub.txt ({}) is taken into servers.txt as the own server — and chosen — once"). With `hub_picker` off it names the hub for every session (`hub_file`) | `180045360`, `1800b0330` |
| `locations.ncl` | Cached, signed locations list (`NCLOC1`) | `18008d180`, `180098590` |
| `hubs.ncl` | Cached, root-signed hub list ("NightCoop hub list 1") | `180050090`, `180050e90` |
| `name.txt` | Nickname. Rules: letters, digits, space, `- _ .`, at most 16 characters, at least one letter or digit | strings 40502–40512 |
| `switches.txt` | `name = on\|off` lines applied at start ("switches.txt: {} switch(es) applied") | strings 44905–44910 |

### 3.2 Server picker (`hub_picker`, default on)

- **Location list.** The client asks the main server for the signed locations list with UDP `0F FE 'NCloc?'` (answer `'NCloc!'`, `HubRules.hpp`). Log: "server picker: asking {} for the locations ({}; our list #{})". It keeps whichever list is newer: "older than ours #{} … ours stays", "kept from the last run (locations.ncl)", or the build's own list.
- **Pings.**
  - "server picker: ping round #{} ({}, {} ms): {} — auto now: {}". The UI says "The ping updates every 2 s while the menu is open".
  - Hub load is shown as `{} load {}%`. Old hubs: "answers only the pass … a hub before 22.10".
- **Choice.**
  - **Auto** = the nearest *open* location by RTT: "auto: the nearest open of {} answered".
  - **Main** = the project hub.
  - **Letter** = a fixed official location.
  - **Own** = a user-added server.
  - If no location answers, the fallback is the project hub ("no location answered — the project's hub").
  - When a hub refuses the host as full, `hub_full_next` sends it to the next nearest open server, up to two: "the hub is full: it counts as full for {} s".
- **Lettered hubs and codes.**
  - A plain code is 6 characters from `ABCDEFGHJKMNPQRSTUVWXYZ23456789` and goes to the main or chosen server.
  - A 7-character code starts with a hub letter: "the code's letter {} is a location of the list #{}". An unknown letter falls back to "its hub by name, as before".
  - "a code without a letter goes to the chosen own server".
  - Regions: eu-west, eu-east, na-east, na-west, na-central, South America, Oceania, Middle East, Africa.

### 3.3 Invite format and fingerprint UX

- **Invite string** (`1808a5e50` → `1808acad0`, separator `'@'` at `0x180c52054`): `CODE@address`. The address has the form "name or IP[:port][#fingerprint] — the default port is 47800".
  - An invite is built only when the host's session runs on an own (non-official) server ("Copy the invite — in the host's menu: the code and the server at once"). Otherwise only the code is copied.
  - Join accepts either form: "The code has 6 or 7 characters (or an invite code@address)".
- **Fingerprint.** 16 Crockford base32 characters, typed as `XXXX-XXXX-XXXX-XXXX` ("The fingerprint after # is 16 characters …").
  - The UI states: "Verified: the fingerprint …", "Encrypted, not verified: no fingerprint with the address", "The server's key does not match the fingerprint — no session through it".
  - The hub owner gets the fingerprint from the hub's log line: "the fingerprint of this hub's key is …".
- **Hub identity policy** (`180046af0`, `180047d00`, `18004a3b0`). A hub is "vouched", "NOT vouched" (links encrypted without authentication) or "refused". Evidence used, in order:
  1. the project root certificate,
  2. the build's pinned key for `hub.nightcoop.net`,
  3. the root-signed hub list for lettered hubs,
  4. the user-given fingerprint.

  Through the project hub the client accepts encrypted, hub-signed partners only ("through the project hub this build takes encrypted partners only").

### 3.4 Connection status UI

"The server does not answer", "No session with this code", "The host has another NightCoop version", "The session is full", "The server is full — pick another in Server:", "The server is closing", "Too many new sessions from your address — in a minute", "The server failed the key check (the log says why)".

Session flow messages:
- "session flow: the hub {} does not answer in 8 s — a wrong address, a closed UDP port or the hub is down"
- The code is re-shown "again every 30 s until a partner joins"

### 3.5 Resume after a hub restart (client side, `hub_resume`, default on)

**Host:**
1. It holds a `HubResumePass`: "the hub gave a resume pass for session {} (valid {} h) — if the hub restarts, the session comes back with the same code".
2. When the hub is lost (`18005bcd0`) it re-presents the pass: "bringing session {} back with its pass: up to **90** s, an attempt at least every **2** s".
3. Outcomes:
   - success: "session {} is back on the hub after {:.1f} s ({} attempt(s)) — guests come back by the code with their old peer numbers"
   - refusal: "the hub refused to give session {} back"
   - old hub: "a hub before 23.10 or --resume off"

**Guest:**
- Waits up to 90 s with partner bodies frozen, then rejoins by the same code and keeps its peer number.
- In hybrid mode an existing direct path keeps the game running meanwhile: "The hub is restarting — staying on the direct path with your partner".

---

## 4. Co-op menu (CoopMenu.cpp, SessionFlow.cpp)

- **Injection.** Adds a list item to the **main menu and the pause menu** (`gameuiMenuItemListGameController.AddMenuItem`) and opens a custom panel built from `inkVerticalPanel` / `inkHorizontalPanel`. The panel has many layout switches (`menu_fit`, `menu_scroll`, `menu_pairs`, `menu_steady`). The UI is bilingual (English and Russian strings side by side).
- **Top-level items**, labels as shown:
  - Host a session · Join by code · Connect by IP (Host by IP / Join by IP) · Change the nickname · Server: … (server window)
  - In a session: Copy the invite / Copy the code · Close the session (host) / Leave the session (guest) · Ready: yes/no · Start the new game · Start without the partners · Call the partners over · Move next to the host · Pull the story to the host's · Cancel the join · Create a character / Join the host's world · PvP on/off · Tougher enemies · Promo / V copies in photo mode · Phantom Liberty restart questions · the end-of-session choice "Keep my own world / Carry the session's world progress / Decide later"
- **Server window** (`hub_picker`):
  - Choices: "Auto: the nearest", official locations with ping and load, "Add an own server", per-server "Use this server / Change the address / Rename / Remove".
  - Each server shows "Verified" or "Encrypted, not verified". Own-server labels are limited to 24 characters.

### Flows

- **Host a session.** "coop menu: a session through the project hub {}:{} is asked from the {} — the code comes from the hub", shown as "Creating the session…". The code then appears ("Session code:"), and "Copy the invite/code" puts it on the clipboard.
- **Host by IP.** "coop menu: a direct session on port {} is asked from the {}" (port 1–65535, default 47800).
- **Join by code.**
  - A text entry takes over keys while open ("keys are ours until the entry closes; F and Enter do not press menu items").
  - Ctrl+V pastes a code or an invite: "coop menu: the clipboard holds a {} — {} is typed in".
  - Validation: 6–7 characters or `code@address`. Joining requires "Leave the session first" if one is running.
  - Then "coop menu: joining session {} through the hub from the {}", shown as "Joining session…".
  - SessionFlow may first take a **pre-session save** of the guest's campaign: "Saving before joining the session", "joining after a save", "saving is locked now (combat, a scene?) — the join waits for the save".
- **Join by IP.** "coop menu: joining {}:{} directly from the {}". Address rules: "Latin letters, digits, dot, hyphen".
- **Kick.** With `kick_in_panel` there is a `[ KICK ]` button next to each guest's nickname. The first click turns it into `[ SURE? ONCE MORE ]`, and a second click within **4 s** kicks ("coop menu: peer {} is kicked"). Otherwise a "Kick <nickname>" item is listed per guest. Only the host can kick ("coop menu: not the host").
- **Stop.** "Close the session" (host: "the host closed it from the menu", "The session is closed") or "Leave the session" (guest: "You left the session"). Both log "coop menu: the session is stopped".
- **Clipboard.** Win32 `OpenClipboard`/`SetClipboardData(CF_UNICODETEXT)` on copy (`1808a2e70`), and read on paste. This happens **only on explicit menu actions**; "The clipboard is busy — try again" on failure.
- **Nickname.** The menu asks for one on first open if `name.txt` is missing ("no nickname yet: it starts with the nickname entry"). It can be pasted from the clipboard and is saved to `name.txt`.

---

## 5. Script-callable functions

Registered in `PostRegisterTypes` (`1809ec910`) twice:
- as **global natives** `NightCoopX(...)` (callable from the CET console as `Game.NightCoopX(...)`),
- as static methods `X` on a native class **`NightCoop`** (`FUN_180013ae0`).

| Function (args → ret) | Handler | What it does |
|---|---|---|
| `NightCoopHost(Int32 port) → Bool` | `1809cd3c0` | Direct host on port, 7 guests. "Host requested on port {}" / "out of range" |
| `NightCoopJoin(String addr, Int32 port) → Bool` | `1809ce980` | Direct join. "Join requested: {}:{}" / "Join: empty address" |
| `NightCoopHostHub(String hub, Int32 port) → String` | `1809cd1c0` | Host through a given hub; returns status. "HostHub: session code {} — your partner types NightCoopJoinCode(\"…\")" |
| `NightCoopHostOnline() → String` | `1809cd560` | Host through the project hub / picker (port 47800) |
| `NightCoopJoinHub(String hub, Int32 port, String code) → String` | `1809ce6d0` | Join a code on a specific hub |
| `NightCoopJoinCode(String code) → String` | `1809ce200` | Join by code (letter → location; default `hub.nightcoop.net`) |
| `NightCoopCode() → String` | `1809ca0a0` | Current session code ("The hub has not answered yet — the code will be on the screen and in NightCoopCode()") |
| `NightCoopStop() → Bool` | `1809e56a0` | Stop the session |
| `NightCoopStatus() / NightCoopSessionStatus() → String` | `1809e5560` / `1809e4aa0` | Status lines (§1.6) |
| `NightCoopIsConnected() → Bool`, `NightCoopPeerCount() → Int32`, `NightCoopRtt() → Float`, `NightCoop.SharedTimeMs() → Float` | `1809cdfa0`, `1809d56b0`, `1809e3200`, `1809e5130` | Session queries |
| `NightCoopKick(Int32 peer) → String` | `1809cef20` | Kick a guest (peer ≥ 1) |
| `NightCoopName(String) → String` | `1809d1fd0` | Set the nickname (name.txt) |
| `NightCoopHubDirect(Bool) → Bool` | `1809cd950` | "HubDirect: direct path on / relay only for the next hub session" |
| `NightCoopMenu() / NightCoopMenuOn(Bool) → String` | `1809d0ba0` / `1809d0d90` | Co-op menu status / enable |
| `NightCoopNetCheck(String) / NightCoopNetCheckStatus()` | `1809d22d0` / `1809d2660` | §1.7 |
| `NightCoopNetSim(Int32, Int32, Float)` | `1809d2960` | §1.6 |
| `NightCoopNetStats(Int32 s)` | `1809d2d90` | §1.6 |
| `NightCoopLogSave(String)` | `1809cf4b0` | Save the last N minutes of the log ("NightCoop/logs") |
| `NightCoopQuestSet(String name, Bool)` | `1809da250` | Generic switch setter (the same names as switches.txt) |
| `NightCoopHostWorld`, `NightCoopToHost`, `NightCoopPreSessionSave(Bool)`, `NightCoopSubmit(5×Float)`, `NightCoopRemoteInfo(Int32)` | (various) | Session or world helpers. `Submit` pushes a local player state |

---

## 6. Network-related switches (`switches.txt` / `NightCoopQuestSet`)

Defaults are the initial `.data` values of the globals set in `1809da250`.

| Switch | Default | Effect (from its ON/OFF log text) |
|---|---|---|
| `net_crypto` | on (`DAT_180d81120`=1) | Encrypt links. Off = "unencrypted, as before 16.10 (a build that knows the project hub's key does not take such a partner through that hub)" |
| `wire_zip` | on (`DAT_180d81330`=1) | Zipped reliable frames, one per network turn |
| `net_guard` | on (`DAT_180d81320`=1) | Limit undelivered ENet data before ENet takes it |
| `enet_no_throttle` | on (`DAT_180d81332`=1) | Keep ENet's throttle open on the direct and hub peers |
| `path_fast_leave` | ? | Leave the direct path after 750 ms of silence instead of 1500 ms |
| `path_quiet` / `path_reason` | on | Hide hub trips under 5 s from the HUD / say why traffic goes through the hub |
| `hub_cookie` | on (`DAT_180d81328`) | Ask the hub for a connection pass (cookie) |
| `hub_chain` | on (`DAT_180d81121`) | Check hub identity (root cert / build key / fingerprint) |
| `hub_pick` | on (`DAT_180d81335`) | Nearest open hub of the root list |
| `hub_picker` | on (`DAT_180d81333`) | Menu server window, servers.txt |
| `hub_resume` | on (`DAT_180d81329`) | Sessions outlive a hub restart (host 90 s, guest waits 90 s) |
| `hub_file` | on (`DAT_180d81122`) | Read hub.txt |
| `hub_full_next` | ? | On "hub full", try the next nearest open server (up to two) |
| `same_game_version` | on (`DAT_180d81336`) | Host refuses guests with another game version. Off = "for checks only" |
| `log_hide_ips` | **off** (`DAT_180ea2b48`=0) | Write IPs as `<ip>` in the log |
| `kick_in_panel` | ? | Two-click KICK button next to nicknames |
| `clock_same_world` | ? | Take the host's clock only when in the host's world |

`?` means the default lives in a different global that I did not resolve. A few hub defaults (`hub_cookie`, `hub_chain`, `hub_pick`, `hub_picker`, `hub_resume`, `hub_file`) were mapped automatically to "the first global assigned after the name"; their ON state matches the help strings.

---

## 7. Surprising or security-relevant notes

1. **Kick bans are weak by design.** The ban key is a self-generated, unauthenticated 64-bit client id (rand ^ clock, made per game process, `1800a7b30`). A kicked player who restarts the game gets a new id and is let back in. The ban also lasts only for that session.
2. **Direct-IP sessions are encrypted but unauthenticated** ("no hub to vouch for the keys"), so they are open to man-in-the-middle on hostile networks. Hybrid direct paths do **not** have this problem: the direct hello must open with the hub-vouched link keys and carry the session tag.
3. **Hybrid hosts accept unsolicited ENet connections** on their single UDP socket. They are filtered by session tag, attempt id and sealed hello, and guests refuse all incoming direct connections. Datagrams go through EnetGuard before ENet.
4. **Third-party contacts:**
   - Only `NightCoopNetCheck` talks to Google, Cloudflare, Twilio and Nextcloud STUN servers and probes the router via SSDP/UPnP (read-only `GetExternalIPAddress`, no port mapping).
   - The `connect()` to 8.8.8.8:53 in the hybrid LAN discovery sends no packets; it only selects the local interface.
   - Normal play contacts only the hubs and the partner.
5. **Logs contain IP addresses by default** (`log_hide_ips` off). Users sharing `nightcoop.log` or crash logs leak their LAN and public IPs and the client id. There is also a "test" switch that deliberately corrupts zipped-frame checks and points a direct connection at 0.0.0.0, for fault injection.
6. **`same_game_version` can be turned off**, letting mismatched game versions in ("different enums and data: for checks only"). The protocol 128 check cannot be bypassed.
7. **Clipboard** use is limited to explicit menu copy and paste actions.
8. **Robustness is decent:**
   - Every message is gated by role and Hello state.
   - Spoofed senders are dropped ("forged route").
   - Player-state floats are checked for finiteness.
   - The game-thread queue has a size limit.
   - ENet's undelivered-data pool is guarded.
   - Reliable backlog over N MB counts as a dead link.
