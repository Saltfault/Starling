# Starling

**A federated, peer-to-peer communications platform — birds talking across the murmuration, with no company in the middle.**

Starling is Discord's shape (servers, channels, voice, video, DMs) without the company that owns every server. Direct messages and small calls go straight between friends, peer-to-peer. Communities live on a server that belongs to whoever runs it — not to a corporation. Every message is end-to-end encrypted.

> ⚠️ **Early access — under active development.** Starling is young and moving fast. Expect rough edges, breaking changes, and missing features. It's built in the open by [Saltfault](https://forgejo.hearthhome.lol/Saltfault), a two-person team; bug reports and feedback are welcome.

This is the **main repo** — you install it, and it installs the rest.

---

## Install

You install **Starling** once. That gives you the `starling` command, which then installs and manages the individual components.

**Prerequisites:** Rust and a C compiler. See [platform setup](https://forgejo.hearthhome.lol/Saltfault/Starling-TUI#platform-setup) for the per-OS steps (they're the same for every component).

```bash
# 1. Install the Starling launcher
cargo install --git https://forgejo.hearthhome.lol/Saltfault/Starling.git

# 2. Install the components you want
starling install tui        # the terminal client (chat, voice, video)
starling install server     # the roost server (host a community)
```

Then use them through the same `starling` command:

```bash
starling setup              # one-time profile + audio wizard
starling open               # launch the client
starling join BIRD-...      # join a flock by invite code
starling roost create my-community   # create a roost (needs `install server`)
```

| Component | Get it with | Status |
|-----------|-------------|--------|
| Terminal client | `starling install tui` | 🚧 Active |
| Roost server | `starling install server` | 🚧 Active |
| Desktop app | Download the installer | 📋 Planned |
| Android app | Android package (app store / APK) | 📋 Planned |
| Web app | Just a hosted page — nothing to install | 📋 Planned |

The `starling install` command only handles the command-line components (TUI and server). The Desktop, Android, and Web apps are graphical apps with no CLI — they're downloaded and installed the way those platforms expect.

---

## Where do I go?

| I want to… | Go here |
|------------|---------|
| **Use Starling right now** (chat, voice, video) | Install above, then see **[Starling-TUI](https://forgejo.hearthhome.lol/Saltfault/Starling-TUI)** for usage |
| **Run my own community server** | Install above, then see **[Starling-Server](https://forgejo.hearthhome.lol/Saltfault/Starling-Server)** for roost docs |
| **Build a client on the protocol** | [Starling-Server](https://forgejo.hearthhome.lol/Saltfault/Starling-Server) (it's also the shared library) |
| Follow the future GUI / mobile / web apps | [Desktop](https://forgejo.hearthhome.lol/Saltfault/Starling-Desktop) · [Android](https://forgejo.hearthhome.lol/Saltfault/Starling-Android) · [Web](https://forgejo.hearthhome.lol/Saltfault/Starling-Web) (all planned) |

---

## The repositories

Starling is split into six repos: this hub, one shared core, and four clients.

| Repo | What it is | Status |
|------|------------|--------|
| **[Starling](https://forgejo.hearthhome.lol/Saltfault/Starling)** (this) | Project hub — docs, protocol overview, roadmap | — |
| **[Starling-Server](https://forgejo.hearthhome.lol/Saltfault/Starling-Server)** | Shared protocol library **and** the headless roost server | 🚧 Active |
| **[Starling-TUI](https://forgejo.hearthhome.lol/Saltfault/Starling-TUI)** | Terminal client | 🚧 Active — text, voice, video |
| **[Starling-Desktop](https://forgejo.hearthhome.lol/Saltfault/Starling-Desktop)** | Native GUI client | 📋 Planned |
| **[Starling-Android](https://forgejo.hearthhome.lol/Saltfault/Starling-Android)** | Android client | 📋 Planned |
| **[Starling-Web](https://forgejo.hearthhome.lol/Saltfault/Starling-Web)** | Browser (WASM) client | 📋 Planned |

Only the **TUI** and **Server** are in active development. The three GUI clients are placeholders that will build on the Server library.

GitHub mirrors are available under [github.com/Saltfault](https://github.com/Saltfault).

---

## The vocabulary

Starling uses a handful of bird terms, and only where they carry weight. Everything else keeps its ordinary networking name.

| Word | Meaning |
|------|---------|
| **Starling** | The whole platform |
| **The murmuration** | The peer-to-peer network itself — thousands of leaderless birds, each reacting only to its neighbors, exactly like the gossip mesh underneath |
| **Bird** | A single node / user |
| **Flock** | A room — one gossip topic, one shared encryption key. **Hatched** by one bird, joined with its invite code |
| **Roost** | A bird that stays online to keep a community's history and channels |
| **Chirp** | A private message sealed to a single bird |

---

## How it works, briefly

- **Hatching a flock** — a bird runs the client; its persistent node ID becomes the room code (e.g. `BIRD-00CCFF-…`). The gossip topic and the E2E key both derive from that code, so sharing the code *is* sharing membership.
- **Joining** — another bird enters the same code, subscribes to the same topic, derives the same key. iroh's relay + hole-punching connects them across the internet with no addresses exchanged.
- **Text** rides gossip; **voice** rides QUIC datagrams (drop-if-late); **video** rides QUIC uni-streams (JPEG frames). **History** for latecomers rides QUIC bi-streams.
- **Encryption** — gossip text is end-to-end encrypted with ChaCha20-Poly1305; voice and video are E2E via QUIC TLS 1.3. Relays forward ciphertext they can't read.
- **Flocks vs roosts** — a flock is joinable by anyone holding its code; a roost is a persistent, self-hosted community whose access becomes identity-gated (invited birds only) as roles land.

---

## Protocol at a glance

| Layer | Protocol | Purpose |
|-------|----------|---------|
| Transport | QUIC (via iroh) | Peer connections, NAT traversal, relay fallback |
| Chat | Gossip (iroh-gossip) | Broadcast text to the flock |
| Voice | QUIC datagrams | Low-latency Opus audio |
| Video | QUIC uni-streams | JPEG frames from the webcam |
| Sync | QUIC bi-streams | History backfill for late joiners |
| Encryption | ChaCha20-Poly1305 | E2E for gossip text |
| Identity | Ed25519 (iroh) | Persistent node identity |
| Serialization | postcard | Compact binary encoding |

**Audio:** 48 kHz stereo Opus, 20 ms frames, with a 2-second jitter buffer.
**Video:** webcam via nokhwa (Media Foundation / AVFoundation / V4L2), JPEG frames rendered as terminal half-blocks.

---

## Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| 0 | Foundations — module layout, channels, logging | ✅ Shipped |
| 1 | Text chat in a flock | ✅ Shipped |
| 2 | Voice calls (Opus + QUIC datagrams) | ✅ Shipped |
| 3 | E2E encryption & profiles | ✅ Shipped |
| 4 | Video in the terminal | ✅ Shipped |
| 5 | Presence & history sync | 🚧 In progress |
| 6 | Many flocks at once | 🚧 In progress |
| 7 | Roosts: persistent servers & channels | 🚧 In progress |
| 8 | Roles & permissions (invite-only roosts) | 📋 Planned |
| 9 | Cryptographic identity — signing, chirps | 📋 Planned |
| 10 | Own the murmuration — self-hosted relays | 📋 Planned |

---

## License

Apache 2.0
