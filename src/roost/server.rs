use super::history_proto::HistoryProto;
use super::history_store::HistoryStore;
use super::perms::Perm;
use super::store;
use super::store::Store;
use super::{ModRequest, RoostState, RoostWelcome};
use crate::config::Profile;
use crate::crypto::FlockCrypto;
use crate::event::GossipPayload;
use crate::history::HISTORY_V1_ALPN;
use crate::membership::{MembershipScopeId, MembershipState};
use crate::net::{encode_roost_code, receive_payload, topic_for};
use crate::protocol::{ChannelId, RoostId, SpaceId};
use iroh::{Endpoint, EndpointId, RelayMode, RelayUrl, endpoint::presets, protocol::Router};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use fs2::FileExt;

fn validate_roost_name(name: &str) -> anyhow::Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        anyhow::bail!("invalid roost name: use 1-64 ASCII letters, numbers, '-' or '_'");
    }
    Ok(())
}

fn roost_data_dir(name: &str) -> PathBuf {
    Profile::roosts_dir().join(name)
}

fn roost_db_path(name: &str) -> PathBuf {
    roost_data_dir(name).join("roost.db")
}

fn roost_key_path(name: &str) -> PathBuf {
    roost_data_dir(name).join("identity.key")
}

fn roost_lock_path(name: &str) -> PathBuf {
    roost_data_dir(name).join("lock.pid")
}

fn write_secret_key(path: &std::path::Path, bytes: &[u8; 32]) -> anyhow::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_invite_code(name: &str) -> anyhow::Result<String> {
    validate_roost_name(name)?;
    let key_path = roost_key_path(name);
    let bytes = std::fs::read(&key_path).map_err(|e| {
        anyhow::anyhow!(
            "roost '{name}' has no identity key at {}: {e}",
            key_path.display()
        )
    })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid identity key file (expected exactly 32 bytes)"))?;
    let secret = iroh::SecretKey::from_bytes(&arr);
    let node_id: iroh::EndpointId = secret.public();
    Ok(encode_roost_code(&node_id))
}

pub fn create(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if dir.exists() {
        anyhow::bail!("roost '{name}' already exists at {}", dir.display());
    }

    std::fs::create_dir_all(&dir)?;
    let result = create_contents(name, &dir);
    if let Err(err) = &result {
        if let Err(cleanup) = std::fs::remove_dir_all(&dir) {
            crate::logger::warn(&format!(
                "roost create: cleanup of {} failed: {cleanup}",
                dir.display()
            ));
        }
        crate::logger::warn(&format!("roost create '{name}' failed: {err}"));
    }
    result
}

fn create_contents(name: &str, dir: &std::path::Path) -> anyhow::Result<()> {
    let db = sled::open(roost_db_path(name))?;
    for tree in ["events", "space_index", "session_heads", "heads", "schema"] {
        db.open_tree(tree)?;
    }
    db.flush()?;
    crate::logger::info(&format!(
        "created roost database at {}",
        roost_db_path(name).display()
    ));
    drop(db);
    let key = iroh::SecretKey::generate();
    write_secret_key(&roost_key_path(name), &key.to_bytes())?;

    let node_id: iroh::EndpointId = key.public();
    let code = encode_roost_code(&node_id);
    println!("' roost '{name}' created");
    println!("  invite code: {code}");
    println!("  data: {}", dir.display());
    println!();
    println!("Start it with: starling roost open {name}");
    crate::logger::info(&format!(
        "roost '{name}' created, invite fingerprint {}",
        crate::logger::fingerprint(code.as_bytes())
    ));

    Ok(())
}

/// Derive a deterministic [`ChannelId`] from a channel name so the roost can
/// construct [`SpaceId::RoostChannel`] for history membership lookups without
/// storing a manifest.
fn channel_id_from_name(name: &str) -> ChannelId {
    let mut id = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(16);
    id[..len].copy_from_slice(&bytes[..len]);
    ChannelId(id)
}

/// Build a [`MembershipState`] from the current [`PermState`] and inject it
/// into the history store so that history requests can authorize callers
/// against the roost's live permission model.
fn update_history_membership(
    history_store: &HistoryStore,
    state: &RoostState,
    roost_id: RoostId,
) -> anyhow::Result<()> {
    let owner = state
        .perms
        .owner
        .ok_or_else(|| anyhow::anyhow!("roost owner not set"))?;
    let scope = MembershipScopeId::Roost(roost_id);
    let membership = MembershipState::from_flat(
        scope,
        owner,
        state.perms.members.keys().copied(),
        state.perms.key_epoch,
    );
    for channel in &state.channels {
        let channel_id = channel_id_from_name(channel);
        let space = SpaceId::RoostChannel {
            roost: roost_id,
            channel: channel_id,
        };
        history_store.set_membership(space, membership.clone())?;
    }
    Ok(())
}

pub async fn open(
    name: &str,
    silent: bool,
    mut console_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!(
            "roost '{name}' not found at {}. Create it first with: starling roost create {name}",
            dir.display()
        );
    }

    crate::logger::info(&format!("opening roost '{name}' from {}", dir.display()));

    // Acquire an exclusive lock file to prevent a second process from
    // opening the same sled database concurrently (platform-dependent
    // corruption risk with multiple writers).
    let lock_path = roost_lock_path(name);
    let lock = std::fs::File::create(&lock_path).map_err(|e| {
        anyhow::anyhow!(
            "roost '{name}': cannot create lock file at {}: {e}",
            lock_path.display()
        )
    })?;
    lock.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("roost '{name}' already running"))?;
    writeln!(&lock, "{}", std::process::id())?;
    // Lock is released on drop when this function returns (graceful shutdown
    // or error), so a subsequent start will succeed.

    let store = Arc::new(Store::open(roost_db_path(name))?);
    let history_store = Arc::new(HistoryStore::new(store.db())?);

    // The owner is the roost's own node id, known only after the endpoint binds.
    // `perms.owner` is filled in below once `my_id` is available. Any persisted
    // roles/members/invitations/bans are loaded so the door survives a restart.
    let persisted_perms = match store.load_perms() {
        Ok(perms) => perms, // Some(state) or None (fresh roost)
        Err(e) => anyhow::bail!(
            "roost '{name}': perms are corrupt ({e}); refusing to start with an empty \
             member/ban list — restore roost.db from backup"
        ),
    };
    let channels = store
        .load_channels()?
        .unwrap_or_else(|| vec!["general".to_string()]);
    let state = RoostState {
        name: name.to_string(),
        channels,
        perms: persisted_perms.unwrap_or_default(),
    };
    let state = Arc::new(Mutex::new(state));

    let key_path = roost_key_path(name);
    let bytes = std::fs::read(&key_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read roost identity at {}: {e}; run `roost doctor` and restore the key from backup",
            key_path.display()
        )
    })?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid roost identity at {} (expected exactly 32 bytes); refusing to change the roost identity",
            key_path.display()
        )
    })?;
    let secret = iroh::SecretKey::from_bytes(&key_bytes);

    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
    // Allow a community to point its roost's endpoint at a self-hosted
    // iroh-relay (run beside the roost) without rebuilding. Relays only
    // forward ciphertext the E2E crypto has already sealed, so this drops
    // the last centralized dependency in the roost flight path. Mirrors the
    // client override in Starling-TUI/src/net.rs for parity.
    if let Ok(url) = std::env::var("STARLING_RELAY") {
        match url.parse::<RelayUrl>() {
            Ok(relay) => builder = builder.relay_mode(RelayMode::Custom(relay.into())),
            Err(e) => crate::logger::warn(&format!(
                "ignoring invalid STARLING_RELAY ({e}); using default relay"
            )),
        }
    }
    let endpoint = builder.bind().await.map_err(|e| {
        crate::logger::error(&format!("endpoint bind failed for roost '{name}': {e}"));
        e
    })?;

    let my_id = endpoint.addr().id;
    // SAFETY: owner MUST be set before Router::spawn() below
    // registers RoostSync (and any other handler that checks
    // perms.owner).  If owner is None when a request arrives,
    // is_member(owner) returns false and the owner's own
    // requests are denied.  (SRV-41)
    {
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.perms.owner = Some(my_id);
    }

    // Spawn the Router as early as possible after the endpoint is bound so
    // that ALPNs are advertised immediately.  Any peer connecting between
    // bind and Router::spawn gets "peer doesn't support any known protocol"
    // (QUIC error 120) because the endpoint accepts the connection but has
    // no protocols registered yet.
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let history = HistoryProto::new(history_store.clone(), |remote, _request, membership| {
        membership.authorized_at(&remote, membership.revision(), membership.key_epoch())
    });
    let (state_tx, mut state_rx) = mpsc::channel::<RoostState>(32);
    let console_state_tx = state_tx.clone();
    let _router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(HISTORY_V1_ALPN, history)
        .accept(
            ROOST_SYNC_ALPN,
            RoostSync {
                store: store.clone(),
                state: state.clone(),
            },
        )
        .accept(
            MOD_ALPN,
            ModProto {
                state: state.clone(),
                store: store.clone(),
                state_tx,
            },
        )
        .accept(
            JOIN_ALPN,
            JoinProto {
                state: state.clone(),
                store: store.clone(),
            },
        )
        .spawn();

    // DIAGNOSTIC: confirm which ALPNs the endpoint is advertising. If a join
    // still fails with QUIC error 120, this lets us verify the server side
    // rather than guessing.
    println!(
        "roost '{name}' router active on {my_id}; registered ALPNs: {}",
        [
            GOSSIP_ALPN,
            HISTORY_V1_ALPN,
            ROOST_SYNC_ALPN,
            MOD_ALPN,
            JOIN_ALPN
        ]
        .iter()
        .map(|a| String::from_utf8_lossy(a).to_string())
        .collect::<Vec<_>>()
        .join(", ")
    );

    let roost_id = RoostId(*my_id.as_bytes());
    {
        let st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(e) = update_history_membership(&history_store, &st, roost_id) {
            crate::logger::warn(&format!(
                "roost '{name}': failed to inject initial history membership: {e}"
            ));
        }
    }
    let code = encode_roost_code(&my_id);
    println!("✓ roost '{name}' is online");
    println!("  code: {code}");
    println!("  join: starling join {code}");
    crate::logger::info(&format!(
        "roost '{name}' online, invite fingerprint {}",
        crate::logger::fingerprint(code.as_bytes())
    ));

    // Check relay reachability AFTER the Router is registered so local
    // connections (which don't need the relay) work immediately even when
    // the relay is slow or unreachable.
    if tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online())
        .await
        .is_err()
    {
        crate::logger::warn(&format!(
            "roost '{name}': not reachable yet (starting degraded)"
        ));
    }

    // The channel list is captured once at startup, but the subscription
    // tasks must also be spawned for channels added at runtime. We track
    // which channels are already subscribed so `state_rx` can detect new
    // additions and spawn their gossip task immediately.
    //
    // Each entry maps a channel name to the JoinHandle of its gossip task.
    // When a channel is removed at runtime (via ModRequest::RemoveChannel),
    // we abort the task, which drops the GossipReceiver and leaves the
    // gossip topic. The GossipSender is already dropped by `sub.split()`.
    let startup_channels = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .channels
        .clone();
    let subscribed_channels: Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let roost_secret = iroh::SecretKey::from_bytes(&key_bytes);
    for chan in &startup_channels {
        spawn_channel_task(
            &gossip,
            &store,
            &code,
            chan,
            &subscribed_channels,
            name,
            my_id,
            roost_secret.clone(),
        )
        .await;
    }

    let control_key = format!("{code}/_control");
    let control = topic_for(&format!("starling/roost/{control_key}"));
    // The control channel (where RoostState — including the ban list
    // and member roster — is broadcast) is now encrypted with a high-entropy
    // secret minted by the store, not derivable from the public roost code.
    // A non-member who merely knows the invite code can no longer read the
    // member list. The secret is handed to admitted birds through the join
    // handshake alongside the per-channel secrets.
    let control_secret = store.control_secret()?;
    let ctl_crypto = FlockCrypto::from_secret(&control_secret);
    let (ctl_tx, mut ctl_rx) = match gossip.subscribe(control, vec![]).await {
        Ok(sub) => sub.split(),
        Err(e) => anyhow::bail!(
            "roost '{name}': control channel unavailable (corrupt control secret?): {e}"
        ),
    };

    if !silent {
        println!(
            "Roost '{}' is running. Type 'help' for commands, 'quit' to stop.",
            name
        );
        println!("  invite code: {}", code);
    }

    // Periodic control-channel heartbeat so a subscriber that misses the
    // NeighborUp-triggered state broadcast (e.g. a saved-context rejoin where
    // gossip mesh formation over a relay outpaces the single NeighborUp
    // broadcast) still converges on the current RoostState within a few
    // seconds instead of timing out.
    let mut control_heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
    control_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    control_heartbeat.tick().await; // discard the immediate first tick

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if !silent {
                    println!("Shutting down...");
                }
                crate::logger::info(&format!("roost '{name}': shutting down on signal"));
                store.db().flush()?;
                history_store.flush()?;
                return Ok(());
            }
            _ = control_heartbeat.tick() => {
                // Heartbeat: re-broadcast the current state so a subscriber
                // that missed the NeighborUp broadcast still converges.
                let snapshot =
                    state.lock().unwrap_or_else(|p| p.into_inner()).clone();
                broadcast_state(&snapshot, &ctl_crypto, &ctl_tx).await;
            }
            cmd = console_rx.recv() => {
                if let Some(line) = cmd {
                    if line.is_empty() {
                        continue;
                    }
                    if handle_console_command(
                        &line,
                        name,
                        silent,
                        &state,
                        &store,
                        &code,
                        &dir,
                        &console_state_tx,
                    )
                    .await
                    {
                        store.db().flush()?;
                        history_store.flush()?;
                        return Ok(());
                    }
                }
            }
            event = ctl_rx.next() => {
                match event {
                    Some(Ok(Event::NeighborUp(_))) => {
                        let snapshot = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
                        broadcast_state(&snapshot, &ctl_crypto, &ctl_tx).await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        crate::logger::warn(&format!(
                            "roost: control subscription error: {e}"
                        ));
                    }
                    None => {
                        crate::logger::warn("roost: control subscription ended");
                        return Ok(());
                    }
                }
            }
            snapshot = state_rx.recv() => {
                if let Some(snapshot) = snapshot {
                    apply_state_update(
                        snapshot,
                        &history_store,
                        roost_id,
                        &gossip,
                        &store,
                        &code,
                        &subscribed_channels,
                        &ctl_crypto,
                        &ctl_tx,
                        name,
                        my_id,
                        roost_secret.clone(),
                    )
                    .await;
                }
            }
        }
    }
}

/// Spawn (or re-spawn) the gossip receive loop for a single roost channel.
///
/// The channel secret is loaded from the store, the gossip topic is
/// subscribed, and a task is spawned that authenticates and persists every
/// received frame. The task's [`tokio::task::JoinHandle`] is recorded in
/// `subscribed` so a later `RemoveChannel` can abort it and leave the topic.
///
/// Errors loading the secret or subscribing are logged and the helper returns
/// without inserting a handle — the channel is simply not subscribed, mirroring
/// the original `continue` behaviour in the inline loops.
#[allow(clippy::too_many_arguments)]
async fn spawn_channel_task(
    gossip: &Gossip,
    store: &Arc<Store>,
    code: &str,
    chan: &str,
    subscribed: &Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    name: &str,
    my_id: EndpointId,
    identity_secret: iroh::SecretKey,
) {
    let topic = topic_for(&format!("starling/roost/{code}/{chan}"));
    let secret = match store.channel_secret(chan) {
        Ok(secret) => secret,
        Err(e) => {
            crate::logger::error(&format!(
                "roost: failed to load channel secret for '{chan}': {e}"
            ));
            return;
        }
    };
    let crypto = FlockCrypto::from_secret(&secret);
    // Keep the sender alive so the roost remains a full mesh participant.
    // Dropping it would make the subscription receive-only, preventing the
    // roost from relaying NeighborUp events between clients.
    let (sender, mut rx) = match gossip.subscribe(topic, vec![]).await {
        Ok(sub) => sub.split(),
        Err(e) => {
            crate::logger::error(&format!("roost: subscribe failed for '{chan}': {e}"));
            return;
        }
    };
    let (st, ch) = (store.clone(), chan.to_string());
    let chan_for_map = chan.to_string();
    let roost_name = name.to_string();
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.next().await {
            match event {
                Ok(Event::Received(msg)) => match receive_payload(&crypto, &msg.content) {
                    Ok(Some(envelope)) => {
                        if let GossipPayload::Chat(m) = envelope.payload {
                            crate::logger::info(&format!(
                                "roost: #{} message from {}: {}",
                                ch,
                                m.author,
                                &m.body[..m.body.len().min(80)]
                            ));
                            if let Err(e) = st.append(&ch, &m) {
                                crate::logger::error(&format!(
                                    "roost: failed to persist message in '{ch}': {e}"
                                ));
                            }
                        }
                    }
                    Ok(None) => {
                        if let Some(plain) = crypto.decrypt(&msg.content)
                            && let Ok(GossipPayload::Chat(m)) =
                                postcard::from_bytes::<GossipPayload>(&plain)
                        {
                            crate::logger::warn(&format!(
                                "roost: persisting legacy unsigned chat from anonymous peer in '{ch}'"
                            ));
                            if let Err(e) = st.append(&ch, &m) {
                                crate::logger::error(&format!(
                                    "roost: failed to persist message in '{ch}': {e}"
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        crate::logger::warn(&format!(
                            "roost: gossip frame rejected on channel '{ch}': {e}"
                        ));
                    }
                },
                Ok(Event::NeighborUp(_)) => {
                    let payload = GossipPayload::Profile {
                        id: my_id,
                        name: roost_name.clone(),
                        dm_pk: Vec::new(),
                        pronouns: String::new(),
                    };
                    let _ =
                        crate::net::broadcast_payload(&sender, &crypto, &identity_secret, &payload)
                            .await;
                }
                Ok(_) => {}
                Err(e) => {
                    crate::logger::warn(&format!("roost: gossip error on channel '{ch}': {e}"));
                }
            }
        }
        crate::logger::warn(&format!(
            "roost: gossip subscription ended for channel '{ch}'"
        ));
    });
    subscribed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(chan_for_map, handle);
}

/// Serialise, encrypt, and broadcast the current [`RoostState`] on the control
/// channel. Used by the heartbeat tick, the `NeighborUp` event, and the
/// `state_rx` membership update. Failures are logged at the same severities as
/// the original inline blocks (warn for broadcast, error for encrypt/serialise);
/// the heartbeat variant previously prefixed messages with "heartbeat" —
/// they now share the control-channel wording for consistency.
async fn broadcast_state(snapshot: &RoostState, ctl_crypto: &FlockCrypto, ctl_tx: &GossipSender) {
    let blob = match postcard::to_stdvec(snapshot) {
        Ok(blob) => blob,
        Err(e) => {
            crate::logger::error(&format!("roost: failed to serialise roost state: {e}"));
            return;
        }
    };
    let encrypted = match ctl_crypto.try_encrypt(&blob) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::logger::error(&format!("roost: control encrypt failed: {e}"));
            return;
        }
    };
    if let Err(e) = ctl_tx.broadcast(encrypted.into()).await {
        crate::logger::warn(&format!(
            "roost: failed to broadcast state on control channel: {e}"
        ));
    }
}

/// Handle one console command line. Returns `true` for `quit`/`exit`/`q` so the
/// caller can flush the databases and shut down; any other input (including
/// empty lines, which the caller filters out before calling) returns `false`.
///
/// The `continue` statements in the original inline match arms become early
/// `return false`s here — control returns to the caller's `loop`, which keeps
/// running, preserving the original behaviour.
#[allow(clippy::too_many_arguments)]
async fn handle_console_command(
    line: &str,
    name: &str,
    silent: bool,
    state: &Arc<Mutex<RoostState>>,
    store: &Arc<Store>,
    code: &str,
    dir: &std::path::Path,
    console_state_tx: &tokio::sync::mpsc::Sender<RoostState>,
) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().copied() {
        Some("help") | Some("h") | Some("?") => {
            println!("Available commands:");
            println!("  status               — show roost info");
            println!("  members              — list members");
            println!("  invite               — show invite code");
            println!("  channel add <name>   — add a channel");
            println!("  channel remove <name> — remove a channel");
            println!("  logs                 — show log file path");
            println!("  quit | exit          — shut down the roost");
            println!("  help                 — show this help");
        }
        Some("status") | Some("s") => {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            println!("Roost: {name}");
            println!("  invite code: {code}");
            println!("  channels: {}", st.channels.join(", "));
            println!("  members: {}", st.perms.members.len());
            println!("  directory: {}", dir.display());
            drop(st);
            let db_size = store
                .db()
                .size_on_disk()
                .map(|s| format!("{} bytes", s))
                .unwrap_or_else(|_| "unknown".into());
            println!("  db size: {db_size}");
        }
        Some("members") | Some("m") => {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(owner) = &st.perms.owner {
                println!("  owner: {}", crate::logger::fingerprint(owner.as_bytes()));
            }
            for member in st.perms.members.keys() {
                println!(
                    "  member: {}",
                    crate::logger::fingerprint(member.as_bytes())
                );
            }
            if !st.perms.bans.is_empty() {
                println!("  bans ({}):", st.perms.bans.len());
                for ban in &st.perms.bans {
                    println!("    - {}", crate::logger::fingerprint(ban.as_bytes()));
                }
            }
            if !st.perms.invited.is_empty() {
                println!("  pending invites: {}", st.perms.invited.len());
            }
        }
        Some("invite") | Some("i") => {
            println!("{code}");
        }
        Some("logs") | Some("l") => {
            if let Some(log_path) = crate::logger::path() {
                println!("{}", log_path.display());
            } else {
                println!("Log file not available");
            }
        }
        Some("quit") | Some("exit") | Some("q") => {
            if !silent {
                println!("Shutting down...");
            }
            crate::logger::info(&format!("roost '{name}': shutting down on console command"));
            return true;
        }
        Some("channel") => {
            match parts.get(1).copied() {
                Some("add") => {
                    let Some(channel) = parts.get(2) else {
                        println!("Usage: channel add <name>");
                        return false;
                    };
                    let channel = channel.to_string();
                    if let Err(e) = store::validate_channel(&channel) {
                        println!("Invalid channel name: {e}");
                        return false;
                    }
                    let snapshot = {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        if st.channels.len() >= super::MAX_CHANNELS {
                            println!(
                                "Cannot add channel: maximum of {} channels reached",
                                super::MAX_CHANNELS
                            );
                            None
                        } else if st.channels.contains(&channel) {
                            println!("Channel '{channel}' already exists");
                            None
                        } else if let Err(e) = store.channel_secret(&channel) {
                            // Mint the channel secret so the gossip task can
                            // subscribe immediately.
                            println!("Failed to mint channel secret: {e}");
                            None
                        } else {
                            st.channels.push(channel.clone());
                            match store.save_channels(&st.channels) {
                                Ok(()) => Some(st.clone()),
                                Err(e) => {
                                    println!("Failed to save channels: {e}");
                                    None
                                }
                            }
                        }
                    };
                    let Some(snapshot) = snapshot else {
                        return false;
                    };
                    let _ = console_state_tx.send(snapshot).await;
                    println!("Channel '{channel}' added");
                    crate::logger::info(&format!("roost '{name}': channel '{channel}' added"));
                }
                Some("remove") => {
                    let Some(channel) = parts.get(2) else {
                        println!("Usage: channel remove <name>");
                        return false;
                    };
                    let channel = channel.to_string();
                    let snapshot = {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        if !st.channels.contains(&channel) {
                            println!("Channel '{channel}' does not exist");
                            None
                        } else if st.channels.len() == 1 {
                            println!("Cannot remove the only remaining channel");
                            None
                        } else {
                            st.channels.retain(|c| c != &channel);
                            match store.save_channels(&st.channels) {
                                Ok(()) => Some(st.clone()),
                                Err(e) => {
                                    println!("Failed to save channels: {e}");
                                    None
                                }
                            }
                        }
                    };
                    let Some(snapshot) = snapshot else {
                        return false;
                    };
                    let _ = console_state_tx.send(snapshot).await;
                    println!("Channel '{channel}' removed");
                    crate::logger::info(&format!("roost '{name}': channel '{channel}' removed"));
                }
                _ => {
                    println!("Unknown channel command. Try 'channel add' or 'channel remove'.");
                }
            }
        }
        _ => {
            println!("Unknown command: {line}");
            println!("Type 'help' for available commands.");
        }
    }
    false
}

/// Apply a [`RoostState`] update pushed by a moderation proto: refresh the
/// history membership, spawn gossip tasks for newly added channels, abort tasks
/// for removed channels, and rebroadcast the snapshot on the control channel.
/// Replaces the inline `state_rx` arm body verbatim, with the duplicated spawn
/// block delegated to [`spawn_channel_task`].
#[allow(clippy::too_many_arguments)]
async fn apply_state_update(
    snapshot: RoostState,
    history_store: &Arc<HistoryStore>,
    roost_id: RoostId,
    gossip: &Gossip,
    store: &Arc<Store>,
    code: &str,
    subscribed_channels: &Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    ctl_crypto: &FlockCrypto,
    ctl_tx: &GossipSender,
    name: &str,
    my_id: EndpointId,
    secret: iroh::SecretKey,
) {
    if let Err(e) = update_history_membership(history_store, &snapshot, roost_id) {
        crate::logger::warn(&format!(
            "roost: failed to update history membership after perm change: {e}"
        ));
    }
    // Spawn gossip subscriptions for channels added since
    // startup (e.g. via AddChannel moderation request), and
    // tear down subscriptions for channels that were removed
    // (e.g. via RemoveChannel moderation request).
    {
        let (new_channels, removed_channels): (Vec<String>, Vec<String>) = {
            let subscribed = subscribed_channels
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let added: Vec<String> = snapshot
                .channels
                .iter()
                .filter(|c| !subscribed.contains_key(*c))
                .cloned()
                .collect();
            let removed: Vec<String> = subscribed
                .keys()
                .filter(|c| !snapshot.channels.contains(c))
                .cloned()
                .collect();
            (added, removed)
        };
        // Tear down gossip tasks for removed channels.
        // Aborting the task drops the GossipReceiver, which —
        // together with the already-dropped GossipSender —
        // causes iroh-gossip to leave the topic.
        for chan in &removed_channels {
            if let Some(handle) = subscribed_channels
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(chan)
            {
                handle.abort();
            }
        }
        for chan in new_channels {
            spawn_channel_task(
                gossip,
                store,
                code,
                &chan,
                subscribed_channels,
                name,
                my_id,
                secret.clone(),
            )
            .await;
        }
    }
    broadcast_state(&snapshot, ctl_crypto, ctl_tx).await;
}

/// Request graceful shutdown of a running roost by reading its PID from the
/// lock file written by [`open`] and sending a termination signal.
pub fn request_shutdown(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }

    let lock_path = roost_lock_path(name);
    let pid_str = std::fs::read_to_string(&lock_path).map_err(|e| {
        anyhow::anyhow!(
            "roost '{name}' does not appear to be running (no lock file at {}: {e})",
            lock_path.display()
        )
    })?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid PID in lock file for roost '{name}': {e}"))?;

    send_shutdown_signal(pid)
        .map_err(|e| anyhow::anyhow!("could not signal roost '{name}' (PID {pid}): {e}"))?;

    println!("✓ requested shutdown of roost '{name}'");
    crate::logger::info(&format!("roost '{name}': shutdown requested (PID {pid})"));
    Ok(())
}

#[cfg(unix)]
fn send_shutdown_signal(pid: u32) -> anyhow::Result<()> {
    // SIGINT triggers the graceful shutdown path in open()'s
    // tokio::signal::ctrl_c() handler, flushing the database.
    let status = std::process::Command::new("kill")
        .arg("-INT")
        .arg(pid.to_string())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run kill: {e}"))?;
    if !status.success() {
        anyhow::bail!("kill returned exit code {}", status);
    }
    Ok(())
}

#[cfg(windows)]
fn send_shutdown_signal(pid: u32) -> anyhow::Result<()> {
    let status = std::process::Command::new("taskkill")
        .arg("/PID")
        .arg(pid.to_string())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run taskkill: {e}"))?;
    if !status.success() {
        anyhow::bail!("taskkill returned exit code {}", status);
    }
    Ok(())
}

pub fn destroy(name: &str, force: bool) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    if !force {
        anyhow::bail!("refusing to delete roost '{name}': re-run with --force");
    }
    if roost_lock_path(name).exists() {
        anyhow::bail!("roost '{name}' is running; stop it first");
    }
    std::fs::remove_dir_all(&dir)?;
    println!("✓ roost '{name}' destroyed");
    crate::logger::warn(&format!("roost '{name}' destroyed by user"));
    Ok(())
}

pub fn invite(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    let code = load_invite_code(name)?;
    println!("roost '{name}' invite code:");
    println!("  {code}");
    println!();
    println!("Join with: starling join {code}");
    Ok(())
}

pub fn status(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }

    let code = match load_invite_code(name) {
        Ok(c) => c,
        Err(e) => {
            println!("invite code unavailable: {e}");
            return Ok(());
        }
    };
    let db_size = roost_db_path(name).metadata().map(|m| m.len()).unwrap_or(0);

    println!("roost '{name}'");
    println!("  path:   {}", dir.display());
    println!("  code:   {code}");
    println!("  db:     {} bytes", db_size);
    Ok(())
}

/// List all members of a roost by reading the persisted permission state.
pub fn members(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    let db_path = roost_db_path(name);
    if !db_path.exists() {
        anyhow::bail!("roost '{name}' database not found");
    }
    let db = sled::open(&db_path)?;
    let store = Store::open(&db_path)?;
    let perms = store.load_perms()?.unwrap_or_default();
    drop(store);
    drop(db);

    println!("roost '{name}' members:");
    if let Some(owner) = perms.owner {
        let id = crate::net::encode_node_id(&owner);
        println!("  {id} (owner)");
    }
    let mut member_list: Vec<_> = perms.members.iter().collect();
    member_list.sort_by_key(|(id, _)| *id);
    for (member, role_indices) in &member_list {
        let id = crate::net::encode_node_id(member);
        if role_indices.is_empty() {
            println!("  {id}");
        } else {
            let roles: Vec<_> = role_indices
                .iter()
                .filter_map(|&i| perms.roles.get(i))
                .map(|r| r.name.as_str())
                .collect();
            println!("  {id} ({})", roles.join(", "));
        }
    }
    if perms.bans.is_empty()
        && perms.invited.is_empty()
        && member_list.is_empty()
        && perms.owner.is_none()
    {
        println!("  (no members yet)");
    }
    if !perms.bans.is_empty() {
        println!("\nbanned:");
        for ban in &perms.bans {
            println!("  {}", crate::net::encode_node_id(ban));
        }
    }
    if !perms.invited.is_empty() {
        println!("\ninvited:");
        for invite in &perms.invited {
            println!("  {}", crate::net::encode_node_id(invite));
        }
    }
    Ok(())
}

/// Add a channel to a roost's persisted state. The roost must not be running.
pub fn add_channel(name: &str, channel: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    if roost_lock_held(name) {
        anyhow::bail!("roost '{name}' is running; stop it first or use the moderation protocol");
    }
    store::validate_channel(channel)?;
    let db_path = roost_db_path(name);
    let store = Store::open(&db_path)?;
    let mut channels = store
        .load_channels()?
        .unwrap_or_else(|| vec!["general".into()]);
    if channels.iter().any(|c| c == channel) {
        anyhow::bail!("channel '{channel}' already exists in roost '{name}'");
    }
    if channels.len() >= super::MAX_CHANNELS {
        anyhow::bail!("roost '{name}' already has the maximum number of channels");
    }
    channels.push(channel.to_string());
    store.save_channels(&channels)?;
    // Mint a channel secret so the gossip key exists when the roost starts.
    store.channel_secret(channel)?;
    println!("✓ channel '{channel}' added to roost '{name}'");
    Ok(())
}

/// Remove a channel from a roost's persisted state. The roost must not be running.
pub fn remove_channel(name: &str, channel: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    if roost_lock_held(name) {
        anyhow::bail!("roost '{name}' is running; stop it first or use the moderation protocol");
    }
    let db_path = roost_db_path(name);
    let store = Store::open(&db_path)?;
    let mut channels = store
        .load_channels()?
        .unwrap_or_else(|| vec!["general".into()]);
    if channels.len() == 1 {
        anyhow::bail!("cannot remove the only remaining channel");
    }
    let pos = channels
        .iter()
        .position(|c| c == channel)
        .ok_or_else(|| anyhow::anyhow!("channel '{channel}' not found in roost '{name}'"))?;
    channels.remove(pos);
    store.save_channels(&channels)?;
    println!("✓ channel '{channel}' removed from roost '{name}'");
    Ok(())
}

/// Returns `true` if a roost process is currently running (the lock file exists
/// and is held exclusively by another process).
fn roost_lock_held(name: &str) -> bool {
    let lock_path = roost_lock_path(name);
    if !lock_path.exists() {
        return false;
    }
    // Try to acquire the exclusive lock ourselves. If we succeed, no other
    // process holds it — the roost is not running. Release immediately.
    match std::fs::OpenOptions::new().write(true).open(&lock_path) {
        Ok(file) => file.try_lock_exclusive().is_err(),
        Err(_) => {
            // Can't even open the lock file; assume running to be safe.
            true
        }
    }
}

/// Read-only health checks that are safe to run while the roost is live.
fn doctor_readonly(name: &str) -> anyhow::Result<()> {
    let mut issues = Vec::new();

    let key_path = roost_key_path(name);
    if key_path.exists() {
        let meta = key_path
            .metadata()
            .map_err(|e| anyhow::anyhow!("can't read identity key metadata: {e}"))?;
        if meta.len() != 32 {
            issues.push(format!(
                "identity key has wrong size ({} bytes, expected 32)",
                meta.len()
            ));
        }
    } else {
        issues.push("identity key missing".into());
    }

    let db_path = roost_db_path(name);
    if db_path.exists() {
        let db_size = db_path.metadata().map(|m| m.len()).unwrap_or(0);
        let min_size = 4096; // a valid sled DB is at least one page
        if db_size < min_size {
            issues.push(format!(
                "database file is suspiciously small ({} bytes)",
                db_size
            ));
        } else {
            println!(
                "  database: present ({} bytes; skipped entry scan while roost is live)",
                db_size
            );
        }
    } else {
        issues.push("database file missing".into());
    }

    if issues.is_empty() {
        println!("✓ roost '{name}' looks healthy (read-only check)");
    } else {
        println!("✗ roost '{name}' has issues:");
        for issue in &issues {
            println!("    - {issue}");
        }
    }
    Ok(())
}

fn check_identity_key(name: &str, issues: &mut Vec<String>) -> anyhow::Result<()> {
    let key_path = roost_key_path(name);
    if key_path.exists() {
        let meta = key_path
            .metadata()
            .map_err(|e| anyhow::anyhow!("can't read identity key metadata: {e}"))?;
        if meta.len() != 32 {
            issues.push(format!(
                "identity key has wrong size ({} bytes, expected 32)",
                meta.len()
            ));
        }
    } else {
        issues.push("identity key missing".into());
    }
    Ok(())
}

fn check_database(name: &str, issues: &mut Vec<String>) {
    let db_path = roost_db_path(name);
    if !db_path.exists() {
        issues.push("database file missing".into());
        return;
    }
    match sled::open(&db_path) {
        Ok(db) => {
            // Verify each expected tree instead of just counting top-level
            // entries. A corrupted tree may still open but will surface
            // errors during iteration or schema verification.
            for tree_name in ["events", "space_index", "session_heads", "heads", "schema"] {
                check_tree(&db, tree_name, issues);
            }
            drop(db);
        }
        Err(e) => issues.push(format!("database corrupt or unreadable: {e}")),
    }
}

// Verify a single sled tree: open it, full-scan every entry to surface
// page/b-tree corruption that `open_tree` alone misses, and (for the schema
// tree) confirm the recorded history schema version is one we support.
//
// Guard clauses flatten the original 5-deep nesting: each failure pushes a
// diagnostic string and returns early, leaving the happy path at depth 1.
fn check_tree(db: &sled::Db, tree_name: &str, issues: &mut Vec<String>) {
    let tree = match db.open_tree(tree_name) {
        Ok(t) => t,
        Err(e) => {
            issues.push(format!("tree '{tree_name}': {e}"));
            return;
        }
    };
    // Full scan surfaces corruption in page/b-tree structures that open_tree
    // alone would miss.
    let entries = match tree.iter().collect::<Result<Vec<_>, _>>() {
        Ok(v) => v,
        Err(e) => {
            issues.push(format!(
                "tree '{tree_name}': scan failed (corruption?): {e}"
            ));
            return;
        }
    };
    if tree_name != "schema" {
        println!("  tree '{tree_name}': ✓ ({} entries)", entries.len());
        return;
    }
    match tree.get(b"history") {
        Ok(Some(version)) => {
            if version.as_ref() != b"1" {
                issues.push(format!(
                    "tree '{tree_name}': unsupported history schema version"
                ));
            } else {
                println!(
                    "  tree '{tree_name}': ✓ ({} entries, schema v1)",
                    entries.len()
                );
            }
        }
        Ok(None) => {
            issues.push(format!(
                "tree '{tree_name}': missing history schema version"
            ));
        }
        Err(e) => {
            issues.push(format!("tree '{tree_name}': schema read error: {e}"));
        }
    }
}

fn report_issues(name: &str, issues: &[String]) {
    if issues.is_empty() {
        println!("✓ roost '{name}' looks healthy");
    } else {
        println!("✗ roost '{name}' has issues:");
        for issue in issues {
            println!("    - {issue}");
        }
    }
}

pub fn doctor(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }

    if roost_lock_held(name) {
        println!("⚠  roost '{name}' is currently running");
        println!("   performing read-only checks only (no sled open)");
        return doctor_readonly(name);
    }

    let mut issues = Vec::new();
    check_identity_key(name, &mut issues)?;
    check_database(name, &mut issues);
    report_issues(name, &issues);
    Ok(())
}

pub fn logs(name: &str) -> anyhow::Result<()> {
    validate_roost_name(name)?;
    let dir = roost_data_dir(name);
    if !dir.exists() {
        anyhow::bail!("roost '{name}' not found at {}", dir.display());
    }
    println!("roost '{name}' logs:");
    let log_path = roost_data_dir(name).join("logs/latest.log");
    println!("  {}", log_path.display());
    Ok(())
}

/// ALPN used by clients to request persisted channel history.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub const ROOST_SYNC_ALPN: &[u8] = b"starling/roost-sync/0";
const MAX_ROOST_SYNC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Wire request for roost history. Responses are postcard-encoded
/// `Vec<crate::event::ChatMessage>` values capped at 500 messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct RoostSyncRequest {
    pub channel: String,
    pub since: i64,
}

#[derive(Debug, Clone)]
struct RoostSync {
    store: Arc<Store>,
    state: Arc<Mutex<RoostState>>,
}

impl iroh::protocol::ProtocolHandler for RoostSync {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        // The door check: only members may pull history. The caller's identity is
        // authenticated by the transport, so it cannot be spoofed by a client.
        let who = conn.remote_id();
        if !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .perms
            .is_active_member(&who)
        {
            crate::logger::warn(&format!("roost-sync: refused non-member {who}"));
            return Ok(());
        }
        let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(IO_TIMEOUT, conn.accept_bi()).await
        else {
            crate::logger::warn("roost-sync: accept timed out");
            return Ok(());
        };

        let Ok(Ok(req)) = tokio::time::timeout(IO_TIMEOUT, recv.read_to_end(256)).await else {
            crate::logger::warn("roost-sync: read timed out");
            return Ok(());
        };
        let Ok(request): Result<RoostSyncRequest, _> = postcard::from_bytes(&req) else {
            crate::logger::warn("roost-sync: invalid request format");
            return Ok(());
        };

        let mut history = match self.store.since(&request.channel, request.since) {
            Ok(history) => history,
            Err(e) => {
                crate::logger::warn(&format!("roost-sync: invalid request: {e}"));
                return Ok(());
            }
        };
        let original_len = history.len();
        let mut bytes = match postcard::to_stdvec(&history) {
            Ok(bytes) => bytes,
            Err(e) => {
                crate::logger::error(&format!("roost-sync: failed to serialise history: {e}"));
                return Ok(());
            }
        };
        // Drop oldest messages until the serialised payload fits within the
        // response size limit, so the client always receives the newest history.
        while bytes.len() > MAX_ROOST_SYNC_RESPONSE_BYTES && !history.is_empty() {
            history.remove(0);
            match postcard::to_stdvec(&history) {
                Ok(b) => bytes = b,
                Err(e) => {
                    crate::logger::error(&format!("roost-sync: failed to serialise history: {e}"));
                    return Ok(());
                }
            }
        }
        if history.len() < original_len {
            crate::logger::warn(&format!(
                "roost-sync: response for #{} truncated ({}→{} msgs) to fit {} byte limit",
                request.channel,
                original_len,
                history.len(),
                MAX_ROOST_SYNC_RESPONSE_BYTES
            ));
        }
        match tokio::time::timeout(IO_TIMEOUT, send.write_all(&bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                crate::logger::warn(&format!("roost-sync: failed to send history: {e}"));
            }
            Err(_) => {
                crate::logger::warn("roost-sync: send timed out");
            }
        }
        let _ = send.finish();

        conn.closed().await;
        Ok(())
    }
}

/// ALPN for the moderation protocol: ban/kick/invite/delete, each re-checked
/// roost-side against the sender's authenticated identity.
pub const MOD_ALPN: &[u8] = b"starling/mod/0";

#[derive(Debug, Clone)]
struct ModProto {
    state: Arc<Mutex<RoostState>>,
    store: Arc<Store>,
    state_tx: mpsc::Sender<RoostState>,
}

impl iroh::protocol::ProtocolHandler for ModProto {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let from = conn.remote_id();
        if !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .perms
            .is_active_member(&from)
        {
            return Ok(());
        }
        let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(IO_TIMEOUT, conn.accept_bi()).await
        else {
            return Ok(());
        };
        let Ok(Ok(bytes)) = tokio::time::timeout(IO_TIMEOUT, recv.read_to_end(1024)).await else {
            return Ok(());
        };
        let Ok(req) = postcard::from_bytes::<ModRequest>(&bytes) else {
            return Ok(());
        };

        // Compute the verdict under the lock, then drop it before any await.
        // Compute the verdict under the lock, then drop it before any await. On a
        // successful mutation we snapshot perms and persist them so the roost's
        // member list, invitations, and bans survive a restart.
        let (verdict, dirty): (Result<(), String>, bool) = {
            let mut st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            compute_verdict(&mut st, req, &from, &self.store)
        };
        if dirty {
            let snapshot = self.state.lock().unwrap().clone();
            if let Err(e) = self.store.save_perms(&snapshot.perms) {
                crate::logger::warn(&format!("roost: failed to persist perms: {e}"));
            }
            if let Err(e) = self.store.save_channels(&snapshot.channels) {
                crate::logger::warn(&format!("roost: failed to persist channels: {e}"));
            }
            let _ = self.state_tx.send(snapshot).await;
        }

        let _ = tokio::time::timeout(
            IO_TIMEOUT,
            send.write_all(&postcard::to_stdvec(&verdict).unwrap_or_default()),
        )
        .await;
        let _ = send.finish();
        conn.closed().await;
        Ok(())
    }
}

/// Run a moderation request against the roost state and return `(verdict, dirty)`.
/// `verdict` is `Ok(())` on success or `Err(message)` for the client; `dirty` is
/// true only when a mutation should be persisted and rebroadcast on the control
/// channel.
///
/// Splitting the per-arm logic into helpers flattens the `else if` ladders that
/// pushed `accept` past the nesting limit; outcomes are identical to the
/// original inline match.
fn compute_verdict(
    st: &mut RoostState,
    req: ModRequest,
    from: &iroh::EndpointId,
    store: &Store,
) -> (Result<(), String>, bool) {
    match req {
        ModRequest::Ban(target) => once(st.perms.handle_ban(from, &target)),
        ModRequest::Kick(target) => once(st.perms.handle_kick(from, &target)),
        ModRequest::Invite(target) => once(st.perms.handle_invite(from, target)),
        ModRequest::DeleteMessage { channel, id } => delete_verdict(st, from, store, &channel, &id),
        ModRequest::AddChannel(name) => add_channel_verdict(st, from, &name),
        ModRequest::RemoveChannel(name) => remove_channel_verdict(st, from, &name),
        ModRequest::SetRole { target, role_index } => {
            once(st.perms.handle_set_role(from, &target, role_index))
        }
        ModRequest::TransferOwnership(target) => {
            once(st.perms.handle_transfer_ownership(from, &target))
        }
    }
}

/// Wrap a perms-handler result as the `(verdict, dirty)` pair the moderation
/// protocol reports back to the client. `dirty` is true iff the handler
/// succeeded (i.e. the membership actually changed). Shared by ban/kick/invite.
fn once(r: anyhow::Result<()>) -> (Result<(), String>, bool) {
    let ok = r.is_ok();
    (r.map_err(|e| e.to_string()), ok)
}

fn delete_verdict(
    st: &RoostState,
    from: &iroh::EndpointId,
    store: &Store,
    channel: &str,
    id: &str,
) -> (Result<(), String>, bool) {
    if !st.perms.effective(from).contains(Perm::MANAGE_MSGS) {
        return (Err("not allowed".into()), false);
    }
    match store.delete_message(channel, id) {
        Ok(true) => (Ok(()), false),
        Ok(false) => (Err("message not found".into()), false),
        Err(e) => (Err(e.to_string()), false),
    }
}

fn add_channel_verdict(
    st: &mut RoostState,
    from: &iroh::EndpointId,
    name: &str,
) -> (Result<(), String>, bool) {
    if !st.perms.effective(from).contains(Perm::MANAGE_CHANS) {
        return (Err("not allowed".into()), false);
    }
    if let Err(e) = store::validate_channel(name) {
        return (Err(e.to_string()), false);
    }
    if st.channels.iter().any(|c| c == name) {
        return (Err("channel already exists".into()), false);
    }
    if st.channels.len() >= super::MAX_CHANNELS {
        return (Err("too many channels".into()), false);
    }
    st.channels.push(name.to_string());
    (Ok(()), true)
}

fn remove_channel_verdict(
    st: &mut RoostState,
    from: &iroh::EndpointId,
    name: &str,
) -> (Result<(), String>, bool) {
    if !st.perms.effective(from).contains(Perm::MANAGE_CHANS) {
        return (Err("not allowed".into()), false);
    }
    if st.channels.len() == 1 {
        return (
            Err("cannot remove the only remaining channel".into()),
            false,
        );
    }
    if let Some(pos) = st.channels.iter().position(|c| c == name) {
        st.channels.remove(pos);
        (Ok(()), true)
    } else {
        (Err("channel not found".into()), false)
    }
}

/// ALPN for the join handshake: the only way to receive channel secrets. The
/// roost authenticates the caller's identity from the transport, runs the door
/// check, and on success returns the welcome (name + per-channel keys).
pub const JOIN_ALPN: &[u8] = b"starling/roost-join/0";
const MAX_JOIN_RESPONSE_BYTES: usize = 65_536;

#[derive(Debug, Clone)]
struct JoinProto {
    state: Arc<Mutex<RoostState>>,
    store: Arc<Store>,
}

impl iroh::protocol::ProtocolHandler for JoinProto {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let who = conn.remote_id();
        crate::logger::info(&format!("roost-join: incoming connection from {who}"));
        let Ok(Ok(mut send)) = tokio::time::timeout(IO_TIMEOUT, conn.open_uni()).await else {
            return Ok(());
        };

        // The door check: invited birds become members on first join; banned
        // birds and uninvited strangers are refused.
        //
        // On success, the welcome carries per-channel secrets AND the control
        // channel secret. All three are high-entropy random values minted by
        // the store; none are derivable from the public roost code.
        let verdict: Result<RoostWelcome, String> = {
            let mut st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match st.perms.handle_join(&who) {
                Ok(()) => {
                    // Persist the updated membership so it survives a restart.
                    let snapshot = st.perms.clone();
                    let channels = st
                        .channels
                        .iter()
                        .filter_map(|c| Some((c.clone(), self.store.channel_secret(c).ok()?)))
                        .collect();
                    let control_secret = self.store.control_secret().ok();
                    if control_secret.is_none() {
                        crate::logger::warn(&format!(
                            "roost-join: control secret unavailable for {who}"
                        ));
                    }
                    if let Err(e) = self.store.save_perms(&snapshot) {
                        crate::logger::warn(&format!(
                            "roost: failed to persist perms after join: {e}"
                        ));
                    }
                    Ok(RoostWelcome {
                        name: st.name.clone(),
                        channels,
                        control_secret,
                    })
                }
                Err(e) => Err(e.to_string()),
            }
        };

        let encoded = postcard::to_stdvec(&verdict).unwrap_or_default();
        if encoded.len() <= MAX_JOIN_RESPONSE_BYTES {
            let _ = tokio::time::timeout(IO_TIMEOUT, send.write_all(&encoded)).await;
        } else {
            crate::logger::warn(&format!(
                "roost-join: welcome for {who} is {} bytes, exceeds limit",
                encoded.len()
            ));
        }
        let _ = send.finish();
        conn.closed().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_roost_name;

    #[test]
    fn validates_roost_names_before_building_paths() {
        for valid in ["starling", "my-roost_2", "A"] {
            assert!(validate_roost_name(valid).is_ok());
        }
        for invalid in ["", ".", "..", "../outside", "a/b", "a\\b", "with space"] {
            assert!(
                validate_roost_name(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}
