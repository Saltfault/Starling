//! Durable, bounded message history backed by sled.

use super::perms::PermState;
use crate::event::ChatMessage;
use std::path::Path;

const MAX_BACKFILL_MESSAGES: usize = 500;
const MAX_SCAN_MESSAGES: usize = 5_000;
const KEY_VERSION: u8 = 1;
const CHANNEL_SECRET_PREFIX: u8 = 2;
const PERMS_KEY: u8 = 3;
const CONTROL_SECRET_KEY: u8 = 4;
const CHANNELS_KEY: u8 = 5;

/// A sled-backed message store.
#[derive(Debug)]
pub struct Store {
    db: sled::Db,
}

impl Store {
    /// Open (or create) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    pub(crate) fn db(&self) -> sled::Db {
        self.db.clone()
    }

    /// Load (or mint and persist) the 32-byte secret key for a roost channel.
    ///
    /// Unlike the legacy scheme where channel keys were derived from the
    /// public roost code, these secrets are random and stored in sled, so they
    /// cannot be derived by anyone who merely knows the code. The roost hands
    /// them out only to admitted birds via the join handshake.
    pub fn channel_secret(&self, channel: &str) -> anyhow::Result<[u8; 32]> {
        validate_channel(channel)?;
        let key = channel_secret_key(channel);
        if let Some(existing) = self.db.get(&key)? {
            let arr: [u8; 32] = existing
                .as_ref()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored channel secret is malformed"))?;
            return Ok(arr);
        }
        let secret = iroh::SecretKey::generate().to_bytes();
        self.db.insert(key, secret.to_vec())?;
        self.db.flush()?;
        Ok(secret)
    }

    /// Load (or mint and persist) the 32-byte secret key for the roost's
    /// control channel, where `RoostState` updates (member list, bans, roles)
    /// are broadcast. Like channel secrets, this is random and stored in sled,
    /// so a non-member who knows the public roost code cannot derive it. The
    /// roost hands it out only to admitted birds via the join handshake.
    pub fn control_secret(&self) -> anyhow::Result<[u8; 32]> {
        if let Some(existing) = self.db.get([CONTROL_SECRET_KEY])? {
            let arr: [u8; 32] = existing
                .as_ref()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored control secret is malformed"))?;
            return Ok(arr);
        }
        let secret = iroh::SecretKey::generate().to_bytes();
        self.db.insert([CONTROL_SECRET_KEY], secret.to_vec())?;
        self.db.flush()?;
        Ok(secret)
    }

    /// Load the persisted permission state, if any. Returns `None` for a fresh
    /// roost that has never persisted perms (e.g. before the first mutation).
    pub fn load_perms(&self) -> anyhow::Result<Option<PermState>> {
        let Some(bytes) = self.db.get([PERMS_KEY])? else {
            return Ok(None);
        };
        Ok(Some(postcard::from_bytes(bytes.as_ref())?))
    }

    /// Persist the permission state so members, invitations, and bans survive a
    /// roost restart. The owner is always re-derived from the roost identity on
    /// open, so a stale owner in the blob is harmless.
    pub fn save_perms(&self, perms: &PermState) -> anyhow::Result<()> {
        self.db.insert([PERMS_KEY], postcard::to_stdvec(perms)?)?;
        self.db.flush()?; // bans/kicks/invites must survive a crash
        Ok(())
    }

    /// Load the persisted channel list, if any. Returns `None` for a fresh roost
    /// that has never persisted channels.
    pub fn load_channels(&self) -> anyhow::Result<Option<Vec<String>>> {
        let Some(bytes) = self.db.get([CHANNELS_KEY])? else {
            return Ok(None);
        };
        Ok(Some(postcard::from_bytes(bytes.as_ref())?))
    }

    /// Persist the channel list so it survives a roost restart.
    pub fn save_channels(&self, channels: &[String]) -> anyhow::Result<()> {
        self.db
            .insert([CHANNELS_KEY], postcard::to_stdvec(channels)?)?;
        self.db.flush()?;
        Ok(())
    }

    /// Delete a single message by id from a channel's persisted history. Used by
    /// the moderation `DeleteMessage` action. This only removes the roost's copy;
    /// a gossip delete-tombstone to retract from clients' local history is a
    /// follow-on. Returns whether a message was found and removed.
    pub fn delete_message(&self, channel: &str, id: &str) -> anyhow::Result<bool> {
        validate_channel(channel)?;
        let prefix = channel_prefix(channel);
        for item in self.db.scan_prefix(prefix) {
            let (key, value) = item?;
            let message: ChatMessage = postcard::from_bytes(&value)?;
            if message.id == id {
                self.db.remove(key)?;
                self.db.flush()?; // deletion must survive a crash
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Persist a message without allowing equal timestamps to overwrite each other.
    pub fn append(&self, channel: &str, message: &ChatMessage) -> anyhow::Result<()> {
        validate_channel(channel)?;
        self.db
            .insert(message_key(channel, message), postcard::to_stdvec(message)?)?;
        self.db.flush()?;
        Ok(())
    }

    /// Return at most the newest 500 messages strictly newer than `since`.
    ///
    /// Legacy text keys are also scanned so existing databases remain readable.
    pub fn since(&self, channel: &str, since: i64) -> anyhow::Result<Vec<ChatMessage>> {
        validate_channel(channel)?;

        let mut messages = Vec::new();
        let prefix = channel_prefix(channel);
        for (i, item) in self.db.scan_prefix(prefix).enumerate() {
            if i >= MAX_SCAN_MESSAGES {
                break;
            }
            let (_, value) = item?;
            let message: ChatMessage = postcard::from_bytes(&value)?;
            if message.ts > since {
                messages.push(message);
            }
        }

        let legacy_prefix = format!("{channel}/");
        for (i, item) in self.db.scan_prefix(legacy_prefix.as_bytes()).enumerate() {
            if i >= MAX_SCAN_MESSAGES {
                break;
            }
            let (_, value) = item?;
            let message: ChatMessage = postcard::from_bytes(&value)?;
            if message.ts > since {
                messages.push(message);
            }
        }

        messages.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
        let mut seen = std::collections::HashSet::new();
        messages.retain(|m| seen.insert(m.id.clone()));
        if messages.len() > MAX_BACKFILL_MESSAGES {
            messages.drain(..messages.len() - MAX_BACKFILL_MESSAGES);
        }
        Ok(messages)
    }
}

pub(super) fn validate_channel(channel: &str) -> anyhow::Result<()> {
    let valid = !channel.is_empty()
        && channel.len() <= 64
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        anyhow::bail!("invalid channel name");
    }
    Ok(())
}

fn channel_prefix(channel: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(channel.len() + 2);
    key.push(KEY_VERSION);
    key.extend_from_slice(channel.as_bytes());
    key.push(0);
    key
}

/// sled key under which a channel's secret key is persisted.
fn channel_secret_key(channel: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(channel.len() + 1);
    key.push(CHANNEL_SECRET_PREFIX);
    key.extend_from_slice(channel.as_bytes());
    key
}

fn message_key(channel: &str, message: &ChatMessage) -> Vec<u8> {
    let mut key = channel_prefix(channel);
    let ordered_timestamp = (message.ts as u64) ^ (1_u64 << 63);
    key.extend_from_slice(&ordered_timestamp.to_be_bytes());
    key.extend_from_slice(message.id.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, ts: i64) -> ChatMessage {
        ChatMessage {
            id: id.into(),
            author: "bird".into(),
            body: id.into(),
            ts,
        }
    }

    fn temporary_store() -> Store {
        Store {
            db: sled::Config::new().temporary(true).open().unwrap(),
        }
    }

    #[test]
    fn equal_timestamps_do_not_overwrite_messages() {
        let store = temporary_store();
        store.append("general", &message("a", 10)).unwrap();
        store.append("general", &message("b", 10)).unwrap();

        let result = store.since("general", 0).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "a");
        assert_eq!(result[1].id, "b");
    }

    #[test]
    fn backfill_is_exclusive_and_bounded_to_newest_messages() {
        let store = temporary_store();
        for ts in 0..510 {
            store
                .append("general", &message(&format!("{ts:03}"), ts))
                .unwrap();
        }

        let result = store.since("general", 5).unwrap();
        assert_eq!(result.len(), MAX_BACKFILL_MESSAGES);
        assert_eq!(result.first().unwrap().ts, 10);
        assert_eq!(result.last().unwrap().ts, 509);
    }

    #[test]
    fn rejects_channels_that_can_escape_key_namespaces() {
        for channel in ["", "../general", "general/other", "contains space"] {
            assert!(validate_channel(channel).is_err());
        }
    }

    #[test]
    fn perms_round_trip_through_sled() {
        use starling::roost::perms::{Perm, PermState, Role};
        let store = temporary_store();
        let owner = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let member = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let role = Role {
            name: "mod".into(),
            color: (0, 200, 0),
            perms: Perm::KICK | Perm::BAN,
            position: 10,
        };
        let mut state = PermState {
            owner: Some(owner),
            ..Default::default()
        };
        state.members.insert(member, vec![0]);
        state.roles.push(role);
        state
            .bans
            .insert(iroh::SecretKey::from_bytes(&[3; 32]).public());
        store.save_perms(&state).unwrap();

        let loaded = store.load_perms().unwrap().expect("perms were saved");
        assert_eq!(loaded.owner, Some(owner));
        assert!(loaded.members.contains_key(&member));
        assert_eq!(loaded.roles.len(), 1);
        assert_eq!(loaded.roles[0].perms, Perm::KICK | Perm::BAN);
        assert_eq!(loaded.bans.len(), 1);
    }

    #[test]
    fn delete_message_removes_only_the_matching_id() {
        let store = temporary_store();
        store.append("general", &message("a", 10)).unwrap();
        store.append("general", &message("b", 20)).unwrap();

        assert!(store.delete_message("general", "a").unwrap());
        let remaining = store.since("general", 0).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "b");
        assert!(!store.delete_message("general", "missing").unwrap());
    }

    #[test]
    fn channel_secret_is_stable_across_loads_and_unique_per_channel() {
        let store = temporary_store();
        let first = store.channel_secret("general").unwrap();
        let second = store.channel_secret("general").unwrap();
        let other = store.channel_secret("random").unwrap();
        assert_eq!(first, second, "channel secret must be persisted and stable");
        assert_ne!(
            first, other,
            "different channels must get different secrets"
        );
    }

    #[test]
    fn control_secret_is_stable_and_distinct_from_channel_secrets() {
        let store = temporary_store();
        let first = store.control_secret().unwrap();
        let second = store.control_secret().unwrap();
        let channel = store.channel_secret("general").unwrap();
        assert_eq!(
            first, second,
            "control secret must be persisted and stable across loads"
        );
        assert_ne!(
            first, channel,
            "control secret must be distinct from channel secrets"
        );
    }
}
