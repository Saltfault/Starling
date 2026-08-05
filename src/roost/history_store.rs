//! Durable sled adapter for Starling's validated event history.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::history::{HistoryHead, TrustedEvent, TrustedStore};
use crate::membership::MembershipState;
use crate::protocol::{EventHash, SignedEventV1, SpaceId};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, Transactional};

const SCHEMA_VERSION: &[u8] = b"1";

#[derive(Debug, Serialize, Deserialize)]
struct StoredHead {
    frontier: Vec<EventHash>,
    event_count: u64,
}

/// Durable history storage. Membership is deliberately injected from the
/// runtime authority path and is never inferred from untrusted history data.
#[derive(Debug)]
pub struct HistoryStore {
    db: sled::Db,
    events: sled::Tree,
    space_index: sled::Tree,
    session_heads: sled::Tree,
    heads: sled::Tree,
    memberships: RwLock<HashMap<SpaceId, MembershipState>>,
}

impl HistoryStore {
    pub(crate) fn new(db: sled::Db) -> anyhow::Result<Self> {
        let events = db.open_tree("events")?;
        let space_index = db.open_tree("space_index")?;
        let session_heads = db.open_tree("session_heads")?;
        let heads = db.open_tree("heads")?;
        let schema = db.open_tree("schema")?;
        match schema.get(b"history")? {
            Some(version) => ensure!(
                version.as_ref() == SCHEMA_VERSION,
                "unsupported history schema"
            ),
            None => {
                schema.insert(b"history", SCHEMA_VERSION)?;
                db.flush().context("flush history schema")?;
            }
        }
        Ok(Self {
            db,
            events,
            space_index,
            session_heads,
            heads,
            memberships: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_membership(
        &self,
        space: SpaceId,
        membership: MembershipState,
    ) -> anyhow::Result<()> {
        ensure!(
            membership_scope(space) == membership.scope(),
            "membership scope does not match space"
        );
        self.memberships
            .write()
            .map_err(|_| anyhow::anyhow!("membership lock poisoned"))?
            .insert(space, membership);
        Ok(())
    }

    pub fn clear_membership(&self, space: &SpaceId) -> anyhow::Result<()> {
        self.memberships
            .write()
            .map_err(|_| anyhow::anyhow!("membership lock poisoned"))?
            .remove(space);
        Ok(())
    }

    /// Flush all buffered writes to disk so no data is lost on shutdown.
    pub fn flush(&self) -> anyhow::Result<()> {
        self.db.flush().context("flush history store")?;
        Ok(())
    }

    fn membership_if_present(&self, space: &SpaceId) -> anyhow::Result<Option<MembershipState>> {
        Ok(self
            .memberships
            .read()
            .map_err(|_| anyhow::anyhow!("membership lock poisoned"))?
            .get(space)
            .cloned())
    }
}

impl TrustedStore for HistoryStore {
    fn head(&self, space: &SpaceId) -> anyhow::Result<HistoryHead> {
        let Some(bytes) = self.heads.get(space_key(space)?)? else {
            return Ok(HistoryHead::empty());
        };
        let stored: StoredHead =
            postcard::from_bytes(&bytes).context("invalid stored history head")?;
        HistoryHead::new(stored.frontier, stored.event_count)
    }

    fn event(&self, space: &SpaceId, hash: &EventHash) -> anyhow::Result<Option<TrustedEvent>> {
        let Some(encoded) = self.events.get(event_key(space, hash)?)? else {
            return Ok(None);
        };
        let encoded = encoded.to_vec();
        let event: SignedEventV1 =
            postcard::from_bytes(&encoded).context("invalid stored signed event")?;
        ensure!(
            postcard::to_stdvec(&event)? == encoded,
            "stored event is not canonical"
        );
        ensure!(event.event.space == *space, "stored event space mismatch");
        ensure!(event.verify()? == *hash, "stored event hash mismatch");
        Ok(Some(TrustedEvent {
            hash: *hash,
            encoded,
            event,
        }))
    }

    fn sequence_hash(
        &self,
        space: &SpaceId,
        sender: &iroh::EndpointId,
        session: &[u8; 16],
        sequence: u64,
    ) -> anyhow::Result<Option<EventHash>> {
        self.space_index
            .get(sequence_key(space, sender, session, sequence)?)?
            .map(|v| hash_value(&v))
            .transpose()
    }

    fn sender_head(
        &self,
        space: &SpaceId,
        sender: &iroh::EndpointId,
    ) -> anyhow::Result<Option<EventHash>> {
        self.session_heads
            .get(sender_key(space, sender)?)?
            .map(|v| hash_value(&v))
            .transpose()
    }

    fn membership(&self, space: &SpaceId) -> anyhow::Result<MembershipState> {
        self.membership_if_present(space)?
            .context("membership state unavailable; history access denied")
    }

    fn commit(
        &self,
        space: &SpaceId,
        expected: &HistoryHead,
        events: &[TrustedEvent],
        new_head: &HistoryHead,
    ) -> anyhow::Result<()> {
        // Membership must still be available at commit time. This also makes
        // direct callers fail closed rather than bypassing validation policy.
        self.membership(space)?;
        let space_key = space_key(space)?;
        let expected_bytes = encode_head(expected)?;
        let new_bytes = encode_head(new_head)?;
        let staged: Vec<_> = events
            .iter()
            .map(|trusted| {
                ensure!(
                    trusted.event.event.space == *space,
                    "event space mismatch at commit"
                );
                ensure!(
                    trusted.event.verify()? == trusted.hash,
                    "event hash mismatch at commit"
                );
                ensure!(
                    postcard::to_stdvec(&trusted.event)? == trusted.encoded,
                    "event encoding is not canonical"
                );
                Ok((
                    event_key(space, &trusted.hash)?,
                    sequence_key(
                        space,
                        &trusted.event.event.sender,
                        &trusted.event.event.session_id,
                        trusted.event.event.sequence,
                    )?,
                    sender_key(space, &trusted.event.event.sender)?,
                    trusted.hash,
                    trusted.encoded.clone(),
                ))
            })
            .collect::<anyhow::Result<_>>()?;

        (
            &self.events,
            &self.space_index,
            &self.session_heads,
            &self.heads,
        )
            .transaction(|(event_tree, index_tree, sender_tree, head_tree)| {
                let actual = head_tree.get(&space_key)?;
                let expected_matches = match actual {
                    Some(ref value) => value.as_ref() == expected_bytes.as_slice(),
                    None => *expected == HistoryHead::empty(),
                };
                if !expected_matches {
                    return Err(ConflictableTransactionError::Abort(
                        "history head changed during validation",
                    ));
                }
                for (event_key, sequence_key, sender_key, hash, encoded) in &staged {
                    if event_tree.get(event_key)?.is_some()
                        || index_tree.get(sequence_key)?.is_some()
                    {
                        return Err(ConflictableTransactionError::Abort(
                            "event or sequence became present during commit",
                        ));
                    }
                    event_tree.insert(event_key.as_slice(), encoded.as_slice())?;
                    index_tree.insert(sequence_key.as_slice(), hash.as_slice())?;
                    sender_tree.insert(sender_key.as_slice(), hash.as_slice())?;
                }
                head_tree.insert(space_key.as_slice(), new_bytes.as_slice())?;
                Ok(())
            })
            .map_err(|e| anyhow::anyhow!("history transaction failed: {e}"))?;
        self.db.flush().context("flush committed history")?;
        Ok(())
    }
}

fn encode_head(head: &HistoryHead) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(&StoredHead {
        frontier: head.frontier.clone(),
        event_count: head.event_count,
    })?)
}
fn space_key(space: &SpaceId) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(space)?)
}
fn event_key(space: &SpaceId, hash: &EventHash) -> anyhow::Result<Vec<u8>> {
    let mut k = space_key(space)?;
    k.extend_from_slice(hash);
    Ok(k)
}
fn sequence_key(
    space: &SpaceId,
    sender: &iroh::EndpointId,
    session: &[u8; 16],
    sequence: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut k = space_key(space)?;
    k.extend_from_slice(sender.as_bytes());
    k.extend_from_slice(session);
    k.extend_from_slice(&sequence.to_be_bytes());
    Ok(k)
}
fn sender_key(space: &SpaceId, sender: &iroh::EndpointId) -> anyhow::Result<Vec<u8>> {
    let mut k = space_key(space)?;
    k.extend_from_slice(sender.as_bytes());
    Ok(k)
}
fn hash_value(value: &[u8]) -> anyhow::Result<EventHash> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid stored event hash"))
}
fn membership_scope(space: SpaceId) -> crate::membership::MembershipScopeId {
    match space {
        SpaceId::Flock(id) => crate::membership::MembershipScopeId::Flock(id),
        SpaceId::RoostChannel { roost, .. } => crate::membership::MembershipScopeId::Roost(roost),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EpochKey;
    use crate::history::validate_batch;
    use crate::membership::{MembershipScopeId, MembershipState};
    use crate::protocol::{EventMetadataV1, FlockId, KIND_EVENT_V1};

    fn fixture() -> (HistoryStore, SpaceId, iroh::SecretKey, SignedEventV1) {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let store = HistoryStore::new(db).unwrap();
        let space = SpaceId::Flock(FlockId([7; 32]));
        let key = iroh::SecretKey::from_bytes(&[9; 32]);
        store
            .set_membership(
                space,
                MembershipState::genesis(MembershipScopeId::Flock(FlockId([7; 32])), key.public()),
            )
            .unwrap();
        let epoch = EpochKey::derive(b"secret", b"space", 0).unwrap();
        let event =
            EventMetadataV1::new(KIND_EVENT_V1, space, key.public(), [3; 16], 0, 0, 0, vec![])
                .unwrap()
                .seal_and_sign(b"plaintext-marker", &epoch, &key)
                .unwrap();
        (store, space, key, event)
    }

    #[test]
    fn commits_all_indexes_atomically_and_rejects_stale_heads() {
        let (store, space, _, event) = fixture();
        let verified = validate_batch(
            &store,
            space,
            crate::history::RawBatch::from_events(space, &[event]).unwrap(),
        )
        .unwrap();
        assert!(
            store
                .commit(
                    &space,
                    &HistoryHead::empty(),
                    &verified.events,
                    &verified.head
                )
                .is_err()
        );
        assert_eq!(store.head(&space).unwrap(), verified.head);
        assert!(
            store
                .sequence_hash(&space, &verified.events[0].event.event.sender, &[3; 16], 0)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn flushes_durable_canonical_ciphertext_only() {
        let (store, space, _, event) = fixture();
        let hash = event.verify().unwrap();
        validate_batch(
            &store,
            space,
            crate::history::RawBatch::from_events(space, std::slice::from_ref(&event)).unwrap(),
        )
        .unwrap();
        let raw = store
            .events
            .get(event_key(&space, &hash).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(raw.as_ref(), postcard::to_stdvec(&event).unwrap());
        assert!(
            !raw.windows(b"plaintext-marker".len())
                .any(|w| w == b"plaintext-marker")
        );
        drop(store);
    }

    #[test]
    fn missing_membership_fails_closed_without_writes() {
        let (store, space, _, event) = fixture();
        store.clear_membership(&space).unwrap();
        assert!(
            validate_batch(
                &store,
                space,
                crate::history::RawBatch::from_events(space, &[event]).unwrap()
            )
            .is_err()
        );
        assert_eq!(store.events.len(), 0);
    }
}
