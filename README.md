# Starling

A federated peer-to-peer communications platform where peers — known as
**birds** — can communicate from anywhere in the world thanks to a
peer-to-peer network called **the murmuration**.

No central server. No company in the middle. Just birds, flocks, and the
murmuration.

---

## What is Starling?

Starling is a fully decentralized communication platform. Birds connect
directly to each other through iroh's global relay and discovery network.
Every flock (room) is end-to-end encrypted. Text, voice, and video all
travel peer-to-peer over QUIC — relays can't read your messages.

### The vocabulary

| Word | Meaning |
|------|---------|
| **Starling** | The whole platform |
| **The murmuration** | The peer-to-peer network itself |
| **Bird** | A single node / user |
| **Flock** | A room — one gossip topic, one shared encryption key |
| **Roost** | A bird that stays online to keep a flock's history (Phase 7) |
| **Chirp** | A private message sealed to a single bird (Phase 9) |

---

## Clients

Starling is designed to have multiple clients sharing the same protocol.
Currently available:

### Starling TUI
The terminal client. Text chat, voice calls, and video calls — all from
your terminal.

- **Repo:** [forgejo.hearthhome.lol/Saltfault/Starling-TUI](https://forgejo.hearthhome.lol/Saltfault/Starling-TUI)
- **Mirror:** [github.com/Saltfault/Starling-TUI](https://github.com/Saltfault/Starling-TUI)
- **Install:** `cargo install --git https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git`

### More clients coming
A GUI client, a mobile client, and a web client are on the roadmap.

---

## How it works

### Joining a flock

1. A bird opens a flock — their persistent node ID becomes the room code
   (e.g. `BIRD-00CCFF-00CCFF-...`). The gossip topic and E2E encryption
   key are both derived from this code.
2. Other birds join by entering the same room code — they subscribe to
   the same gossip topic and derive the same encryption key.
3. iroh's relay connects peers on the topic automatically. No node IDs
   or addresses need to be exchanged beyond the room code.
4. Text messages broadcast over gossip reach all birds in the mesh.
5. Voice calls use direct peer-to-peer QUIC datagram streams.
6. Video calls use QUIC unidirectional streams carrying JPEG frames.

### Encryption

All messages are end-to-end encrypted with ChaCha20-Poly1305 using a key
derived from the room code. Voice and video calls are E2E encrypted via
iroh's QUIC TLS 1.3. Relays and intermediaries cannot read message content.

### Identity

Each bird has a persistent cryptographic identity (Ed25519 keypair) saved
to disk. This means your room code stays the same every time you open a
flock — other birds can bookmark your code and rejoin later.

---

## Protocol

Starling uses:

| Layer | Protocol | Purpose |
|-------|----------|---------|
| Transport | QUIC (via iroh) | Peer connections, NAT traversal, relay fallback |
| Chat | Gossip (iroh-gossip) | Broadcast text messages to the flock |
| Voice | QUIC datagrams | Low-latency Opus audio frames |
| Video | QUIC uni streams | JPEG frames from webcam |
| Sync | QUIC bi streams | History backfill for late joiners |
| Encryption | ChaCha20-Poly1305 | E2E for gossip text |
| Identity | Ed25519 (iroh) | Node identity and authentication |
| Serialization | postcard | Compact binary encoding for all messages |

### Audio
48 kHz stereo Opus, 20 ms frames (960 samples per channel). Playback
uses a 2-second ring buffer to absorb network jitter.

### Video
Webcam capture via nokhwa (Media Foundation on Windows, AVFoundation on
macOS, V4L2 on Linux). Frames are JPEG-encoded and rendered in the
terminal using half-block Unicode characters.

---

## Roadmap

See the [Build Guide](docs/build-guide.html) for the full roadmap with
code-level detail.

| Phase | Feature | Status |
|-------|---------|--------|
| 0 | Foundations — module layout, channels, logging | ✅ Shipped |
| 1 | Text chat in a flock | ✅ Shipped |
| 2 | Voice calls (Opus + QUIC datagrams) | ✅ Shipped |
| 3 | E2E encryption & profiles | ✅ Shipped |
| 4 | Video in the terminal | ✅ Shipped |
| 5 | Presence & history sync | 🚧 In progress |
| 6 | Many flocks at once (tabs) | 📋 Planned |
| 7 | Roosts: persistent servers & channels | 📋 Planned |
| 8 | Roles & permissions | 📋 Planned |
| 9 | Real cryptographic identity (chirps, signing) | 📋 Planned |
| 10 | Own the murmuration (self-hosted relays) | 📋 Planned |

---

## Repositories

| Repo | Description |
|------|-------------|
| [Starling](https://forgejo.hearthhome.lol/Saltfault/Starling) | Primary project — docs, protocol spec, roadmap |
| [Starling-TUI](https://forgejo.hearthhome.lol/Saltfault/Starling-TUI) | Terminal client |
| [Starling-TUI (GitHub mirror)](https://github.com/Saltfault/Starling-TUI) | GitHub mirror of the TUI client |

---

## License

Apache 2.0
