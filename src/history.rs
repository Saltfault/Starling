//! Bounded history exchange and atomic validation of signed event DAGs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::RwLock;

use anyhow::{Context, ensure};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2_10::{Digest, Sha256};

use crate::membership::{MembershipScopeId, MembershipState};
use crate::protocol::{
    EventHash, KIND_EVENT_V1, MAX_EVENT_CIPHERTEXT, MAX_EVENT_PARENTS, SignedEventV1, SpaceId,
};

pub const HISTORY_V1_ALPN: &[u8] = b"starling/history/1";
pub const FRAME_HISTORY_REQUEST_V1: u16 = 0x3101;
pub const FRAME_HISTORY_RESPONSE_V1: u16 = 0x3102;
pub const FRAME_HISTORY_ERROR_V1: u16 = 0x31ff;

pub const MAX_RAW_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BATCH_EVENTS: usize = 512;
pub const MAX_FRONTIER: usize = 64;
pub const MAX_HISTORY_HASHES: usize = 4096;
pub const MAX_HISTORY_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_EVENT_CIPHERTEXT;

const COMMIT_DOMAIN: &[u8] = b"starling/history/v1/head\0";
const REQUEST_DOMAIN: &[u8] = b"starling/history/v1/request\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub space: SpaceId,
    pub requester: EndpointId,
    pub challenge: [u8; 32],
    /// Trusted local heads. These are hints only and must not be treated as proof.
    pub have: Vec<EventHash>,
    /// Hashes the requester wants, normally discovered from summaries or parents.
    pub want: Vec<EventHash>,
    pub cursor: Option<EventHash>,
    pub max_events: u32,
    pub max_bytes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedHistoryRequest {
    pub request: HistoryRequest,
    pub signature: Signature,
}

impl HistoryRequest {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.have.len() <= MAX_HISTORY_HASHES,
            "too many have hashes"
        );
        ensure!(
            self.want.len() <= MAX_HISTORY_HASHES,
            "too many want hashes"
        );
        ensure!(
            self.max_events > 0 && self.max_events as usize <= MAX_BATCH_EVENTS,
            "invalid event page limit"
        );
        ensure!(
            self.max_bytes > 0 && self.max_bytes as usize <= MAX_HISTORY_PAGE_BYTES,
            "invalid byte page limit"
        );
        ensure!(
            is_sorted_unique(&self.have),
            "have hashes must be sorted and unique"
        );
        ensure!(
            is_sorted_unique(&self.want),
            "want hashes must be sorted and unique"
        );
        ensure!(
            self.challenge != [0; 32],
            "history challenge must not be zero"
        );
        Ok(())
    }

    pub fn sign(self, secret: &iroh::SecretKey) -> anyhow::Result<SignedHistoryRequest> {
        ensure!(
            self.requester == secret.public(),
            "history requester does not match signing key"
        );
        let signature = secret.sign(&self.signing_bytes()?);
        Ok(SignedHistoryRequest {
            request: self,
            signature,
        })
    }

    fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let encoded = postcard::to_stdvec(self)?;
        let mut bytes = Vec::with_capacity(REQUEST_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(REQUEST_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }
}

impl SignedHistoryRequest {
    pub fn verify(&self, remote: &EndpointId) -> anyhow::Result<()> {
        ensure!(
            &self.request.requester == remote,
            "history requester is not the connected peer"
        );
        self.request
            .requester
            .verify(&self.request.signing_bytes()?, &self.signature)
            .context("history request signature is invalid")
    }
}

/// An explicitly untrusted response description. Its fields are useful for
/// reconciliation, but become authoritative only after `validate_batch` commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryResponseSummary {
    pub space: SpaceId,
    pub advertised_frontier: Vec<EventHash>,
    pub event_count: u32,
    pub encoded_bytes: u32,
    pub next_cursor: Option<EventHash>,
}

impl HistoryResponseSummary {
    pub fn validate_untrusted(&self) -> anyhow::Result<()> {
        ensure!(
            self.advertised_frontier.len() <= MAX_FRONTIER,
            "advertised frontier is too large"
        );
        ensure!(
            is_sorted_unique(&self.advertised_frontier),
            "advertised frontier must be sorted and unique"
        );
        ensure!(
            self.event_count as usize <= MAX_BATCH_EVENTS,
            "advertised event count is too large"
        );
        ensure!(
            self.encoded_bytes as usize <= MAX_HISTORY_PAGE_BYTES,
            "advertised response is too large"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RawBatchWire {
    summary: HistoryResponseSummary,
    events: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RawBatch {
    pub summary: HistoryResponseSummary,
    /// Canonical postcard encodings of `SignedEventV1` values.
    pub events: Vec<Vec<u8>>,
}

impl RawBatch {
    pub fn new(summary: HistoryResponseSummary, events: Vec<Vec<u8>>) -> anyhow::Result<Self> {
        let batch = Self { summary, events };
        batch.validate_bounds()?;
        Ok(batch)
    }

    pub fn from_events(space: SpaceId, events: &[SignedEventV1]) -> anyhow::Result<Self> {
        let encoded: Vec<Vec<u8>> = events
            .iter()
            .map(postcard::to_stdvec)
            .collect::<Result<_, _>>()?;
        let encoded_bytes = encoded.iter().try_fold(0usize, |n, bytes| {
            n.checked_add(bytes.len())
                .context("batch byte count overflow")
        })?;
        Self::new(
            HistoryResponseSummary {
                space,
                advertised_frontier: Vec::new(),
                event_count: encoded.len().try_into()?,
                encoded_bytes: encoded_bytes.try_into()?,
                next_cursor: None,
            },
            encoded,
        )
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= MAX_RAW_FRAME_BYTES,
            "history frame is too large"
        );
        let wire: RawBatchWire =
            postcard::from_bytes(bytes).context("invalid history batch encoding")?;
        let batch = Self {
            summary: wire.summary,
            events: wire.events,
        };
        batch.validate_bounds()?;
        Ok(batch)
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_bounds()?;
        let bytes = postcard::to_stdvec(&RawBatchWire {
            summary: self.summary.clone(),
            events: self.events.clone(),
        })?;
        ensure!(
            bytes.len() <= MAX_RAW_FRAME_BYTES,
            "history frame is too large"
        );
        Ok(bytes)
    }

    fn validate_bounds(&self) -> anyhow::Result<()> {
        self.summary.validate_untrusted()?;
        ensure!(
            self.events.len() <= MAX_BATCH_EVENTS,
            "history batch has too many events"
        );
        ensure!(
            self.summary.event_count as usize == self.events.len(),
            "response event count mismatch"
        );
        let mut total = 0usize;
        for bytes in &self.events {
            ensure!(
                bytes.len() <= crate::protocol::MAX_BODY_BYTES,
                "encoded event is too large"
            );
            total = total
                .checked_add(bytes.len())
                .context("batch byte count overflow")?;
            ensure!(
                total <= MAX_HISTORY_PAGE_BYTES,
                "history batch payload is too large"
            );
        }
        ensure!(
            self.summary.encoded_bytes as usize == total,
            "response byte count mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TrustedEvent {
    pub hash: EventHash,
    pub encoded: Vec<u8>,
    pub event: SignedEventV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryHead {
    pub frontier: Vec<EventHash>,
    pub event_count: u64,
    pub commitment: [u8; 32],
}

impl HistoryHead {
    pub fn empty() -> Self {
        Self::new(Vec::new(), 0).expect("empty history head is valid")
    }

    pub fn new(mut frontier: Vec<EventHash>, event_count: u64) -> anyhow::Result<Self> {
        frontier.sort_unstable();
        frontier.dedup();
        ensure!(
            frontier.len() <= MAX_FRONTIER,
            "history frontier is too large"
        );
        let commitment = head_commitment(&frontier, event_count);
        Ok(Self {
            frontier,
            event_count,
            commitment,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedBatch {
    pub events: Vec<TrustedEvent>,
    pub head: HistoryHead,
}

pub trait TrustedStore {
    fn head(&self, space: &SpaceId) -> anyhow::Result<HistoryHead>;
    fn event(&self, space: &SpaceId, hash: &EventHash) -> anyhow::Result<Option<TrustedEvent>>;
    fn sequence_hash(
        &self,
        space: &SpaceId,
        sender: &EndpointId,
        session: &[u8; 16],
        sequence: u64,
    ) -> anyhow::Result<Option<EventHash>>;
    fn sender_head(
        &self,
        space: &SpaceId,
        sender: &EndpointId,
    ) -> anyhow::Result<Option<EventHash>>;
    fn membership(&self, space: &SpaceId) -> anyhow::Result<MembershipState>;

    /// Authenticate ciphertext when keys are available. Implementations may
    /// deliberately return `Ok(())` when operating in signature-only mode.
    fn authenticate(&self, _event: &SignedEventV1) -> anyhow::Result<()> {
        Ok(())
    }

    /// Atomically persist all events and replace `expected` with `new_head`.
    /// No event may become visible if this operation returns an error.
    fn commit(
        &self,
        space: &SpaceId,
        expected: &HistoryHead,
        events: &[TrustedEvent],
        new_head: &HistoryHead,
    ) -> anyhow::Result<()>;
}

pub fn validate_batch<S: TrustedStore>(
    store: &S,
    expected_space: SpaceId,
    raw: RawBatch,
) -> anyhow::Result<VerifiedBatch> {
    raw.validate_bounds()?;
    ensure!(
        raw.summary.space == expected_space,
        "history response space mismatch"
    );
    let old_head = store.head(&expected_space)?;
    ensure!(
        old_head.commitment == head_commitment(&old_head.frontier, old_head.event_count),
        "store returned an invalid history head"
    );
    ensure!(
        old_head.frontier.len() <= MAX_FRONTIER && is_sorted_unique(&old_head.frontier),
        "store returned an invalid frontier"
    );
    let membership = store.membership(&expected_space)?;
    ensure!(
        membership.scope() == membership_scope(expected_space),
        "membership scope does not match event space"
    );

    let mut incoming = BTreeMap::<EventHash, TrustedEvent>::new();
    let mut positions = HashMap::<(EndpointId, [u8; 16], u64), EventHash>::new();
    for encoded in raw.events {
        let event: SignedEventV1 =
            postcard::from_bytes(&encoded).context("invalid signed event encoding")?;
        ensure!(
            postcard::to_stdvec(&event)? == encoded,
            "event encoding is not canonical"
        );
        ensure!(event.event.kind == KIND_EVENT_V1, "unexpected event kind");
        ensure!(event.event.space == expected_space, "event space mismatch");
        ensure!(
            event.event.parents.len() <= MAX_EVENT_PARENTS,
            "event has too many parents"
        );
        ensure!(
            event.event.ciphertext.len() <= MAX_CIPHERTEXT_BYTES,
            "event ciphertext is too large"
        );
        let hash = event
            .verify()
            .context("invalid event signature or canonical hash")?;
        let snapshot = membership
            .snapshot(event.event.membership_revision)
            .context("unknown historical membership revision")?;
        ensure!(
            snapshot.key_epoch == event.event.key_epoch,
            "event key epoch does not exactly match membership revision"
        );
        ensure!(
            snapshot.is_member_at_epoch(&event.event.sender, event.event.key_epoch),
            "sender lacked historical membership authority"
        );
        store
            .authenticate(&event)
            .context("event ciphertext authentication failed")?;

        if let Some(stored) = store.event(&expected_space, &hash)? {
            ensure!(
                stored.encoded == encoded,
                "duplicate event hash has different bytes"
            );
            continue;
        }
        if let Some(previous) = incoming.get(&hash) {
            ensure!(
                previous.encoded == encoded,
                "duplicate event hash has different bytes"
            );
            continue;
        }
        let position = (
            event.event.sender,
            event.event.session_id,
            event.event.sequence,
        );
        if let Some(other) = positions.insert(position, hash) {
            ensure!(
                other == hash,
                "conflicting sender/session/sequence in batch"
            );
        }
        if let Some(other) =
            store.sequence_hash(&expected_space, &position.0, &position.1, position.2)?
        {
            ensure!(
                other == hash,
                "conflicting sender/session/sequence in store"
            );
        }
        incoming.insert(
            hash,
            TrustedEvent {
                hash,
                encoded,
                event,
            },
        );
    }

    validate_links(store, &expected_space, &incoming)?;
    let ordered_hashes = topological_order(store, &expected_space, &incoming)?;
    let events: Vec<TrustedEvent> = ordered_hashes
        .into_iter()
        .map(|hash| incoming[&hash].clone())
        .collect();

    let mut frontier: BTreeSet<EventHash> = old_head.frontier.iter().copied().collect();
    for trusted in &events {
        frontier.insert(trusted.hash);
        for parent in &trusted.event.event.parents {
            frontier.remove(parent);
        }
    }
    ensure!(
        frontier.len() <= MAX_FRONTIER,
        "resulting history frontier is too large"
    );
    let added: u64 = events.len().try_into()?;
    let new_head = HistoryHead::new(
        frontier.into_iter().collect(),
        old_head
            .event_count
            .checked_add(added)
            .context("history event count overflow")?,
    )?;
    store
        .commit(&expected_space, &old_head, &events, &new_head)
        .context("atomic history commit failed")?;
    Ok(VerifiedBatch {
        events,
        head: new_head,
    })
}

fn validate_links<S: TrustedStore>(
    store: &S,
    space: &SpaceId,
    incoming: &BTreeMap<EventHash, TrustedEvent>,
) -> anyhow::Result<()> {
    for trusted in incoming.values() {
        let e = &trusted.event.event;
        for parent in &e.parents {
            ensure!(
                incoming.contains_key(parent) || store.event(space, parent)?.is_some(),
                "event has an unresolved parent"
            );
        }
        if e.sequence == 0 {
            ensure!(
                store
                    .sequence_hash(space, &e.sender, &e.session_id, 0)?
                    .is_none(),
                "session genesis already exists"
            );
            let prior = store.sender_head(space, &e.sender)?;
            if let Some(prior) = prior {
                ensure!(
                    e.parents.binary_search(&prior).is_ok(),
                    "new session does not link the sender's prior accepted head"
                );
            }
        } else {
            let previous_sequence = e.sequence - 1;
            let previous = incoming
                .values()
                .find(|candidate| {
                    let p = &candidate.event.event;
                    p.sender == e.sender
                        && p.session_id == e.session_id
                        && p.sequence == previous_sequence
                })
                .map(|candidate| candidate.hash)
                .or(store.sequence_hash(space, &e.sender, &e.session_id, previous_sequence)?);
            let previous = previous.context("event sequence has a gap")?;
            ensure!(
                e.parents.binary_search(&previous).is_ok(),
                "event is missing its immediate sequence parent"
            );
        }
    }
    Ok(())
}

fn topological_order<S: TrustedStore>(
    store: &S,
    space: &SpaceId,
    incoming: &BTreeMap<EventHash, TrustedEvent>,
) -> anyhow::Result<Vec<EventHash>> {
    let mut indegree = BTreeMap::<EventHash, usize>::new();
    let mut children = BTreeMap::<EventHash, Vec<EventHash>>::new();
    for (&hash, trusted) in incoming {
        indegree.insert(hash, 0);
        for parent in &trusted.event.event.parents {
            if incoming.contains_key(parent) {
                *indegree.get_mut(&hash).expect("inserted") += 1;
                children.entry(*parent).or_default().push(hash);
            } else {
                ensure!(
                    store.event(space, parent)?.is_some(),
                    "event has an unresolved parent"
                );
            }
        }
    }
    let mut ready: BTreeSet<EventHash> = indegree
        .iter()
        .filter_map(|(&hash, &degree)| (degree == 0).then_some(hash))
        .collect();
    let mut ordered = Vec::with_capacity(incoming.len());
    while let Some(hash) = ready.pop_first() {
        ordered.push(hash);
        if let Some(next) = children.get(&hash) {
            for child in next {
                let degree = indegree.get_mut(child).expect("known child");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    ensure!(
        ordered.len() == incoming.len(),
        "history batch contains a cycle"
    );
    Ok(ordered)
}

/// Recursively discovers absent ancestors from untrusted advertised heads.
pub fn missing_parents<S: TrustedStore>(
    store: &S,
    space: &SpaceId,
    advertised: impl IntoIterator<Item = EventHash>,
    raw_events: &[TrustedEvent],
    max_hashes: usize,
) -> anyhow::Result<Vec<EventHash>> {
    ensure!(
        max_hashes <= MAX_HISTORY_HASHES,
        "missing-parent page limit is too large"
    );
    let supplied: HashMap<EventHash, &TrustedEvent> =
        raw_events.iter().map(|event| (event.hash, event)).collect();
    let mut queue: VecDeque<EventHash> = advertised.into_iter().collect();
    let mut seen = HashSet::new();
    let mut missing = BTreeSet::new();
    while let Some(hash) = queue.pop_front() {
        if !seen.insert(hash) {
            continue;
        }
        if store.event(space, &hash)?.is_some() {
            continue;
        }
        if let Some(event) = supplied.get(&hash) {
            queue.extend(event.event.event.parents.iter().copied());
        } else {
            missing.insert(hash);
            if missing.len() == max_hashes {
                break;
            }
        }
    }
    Ok(missing.into_iter().collect())
}

/// Produces a deterministic, count- and byte-capped response page. Input
/// events must already be trusted; request have/want data is never trusted.
pub fn reconciliation_page<S: TrustedStore>(
    store: &S,
    request: &HistoryRequest,
) -> anyhow::Result<RawBatch> {
    request.validate()?;
    let have: HashSet<EventHash> = request.have.iter().copied().collect();
    let count_cap = (request.max_events as usize).min(MAX_BATCH_EVENTS);
    let byte_cap = (request.max_bytes as usize).min(MAX_HISTORY_PAGE_BYTES);
    let mut queue: VecDeque<EventHash> = request.want.iter().copied().collect();
    if queue.is_empty() {
        queue.extend(store.head(&request.space)?.frontier);
    }
    let mut seen = HashSet::new();
    let mut selected = BTreeMap::<EventHash, Vec<u8>>::new();
    let mut bytes = 0usize;
    let mut next_cursor = None;
    while let Some(hash) = queue.pop_front() {
        if !seen.insert(hash) || have.contains(&hash) {
            continue;
        }
        let Some(event) = store.event(&request.space, &hash)? else {
            continue;
        };
        if selected.len() == count_cap || bytes.saturating_add(event.encoded.len()) > byte_cap {
            next_cursor = Some(hash);
            break;
        }
        bytes += event.encoded.len();
        queue.extend(event.event.event.parents.iter().copied());
        selected.insert(hash, event.encoded);
    }
    let events: Vec<Vec<u8>> = selected.into_values().collect();
    RawBatch::new(
        HistoryResponseSummary {
            space: request.space,
            advertised_frontier: store.head(&request.space)?.frontier,
            event_count: events.len().try_into()?,
            encoded_bytes: bytes.try_into()?,
            next_cursor,
        },
        events,
    )
}

fn membership_scope(space: SpaceId) -> MembershipScopeId {
    match space {
        SpaceId::Flock(flock) => MembershipScopeId::Flock(flock),
        SpaceId::RoostChannel { roost, .. } => MembershipScopeId::Roost(roost),
    }
}

fn head_commitment(frontier: &[EventHash], event_count: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(event_count.to_be_bytes());
    hasher.update((frontier.len() as u64).to_be_bytes());
    for hash in frontier {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Default)]
struct MemorySpace {
    head: Option<HistoryHead>,
    events: BTreeMap<EventHash, TrustedEvent>,
    sequences: HashMap<(EndpointId, [u8; 16], u64), EventHash>,
    sender_heads: HashMap<EndpointId, EventHash>,
}

type EventAuthenticator = dyn Fn(&SignedEventV1) -> anyhow::Result<()> + Send + Sync;

/// Test/reference store with a single-lock atomic commit. Production durable
/// adapters should implement the same compare-and-commit semantics.
pub struct InMemoryTrustedStore {
    membership: MembershipState,
    spaces: RwLock<HashMap<SpaceId, MemorySpace>>,
    authenticator: Option<Box<EventAuthenticator>>,
    fail_commits: RwLock<bool>,
}

impl InMemoryTrustedStore {
    pub fn new(membership: MembershipState) -> Self {
        Self {
            membership,
            spaces: RwLock::new(HashMap::new()),
            authenticator: None,
            fail_commits: RwLock::new(false),
        }
    }

    pub fn with_authenticator(
        mut self,
        authenticator: impl Fn(&SignedEventV1) -> anyhow::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.authenticator = Some(Box::new(authenticator));
        self
    }

    pub fn set_fail_commits(&self, fail: bool) {
        *self.fail_commits.write().expect("lock poisoned") = fail;
    }
}

impl TrustedStore for InMemoryTrustedStore {
    fn head(&self, space: &SpaceId) -> anyhow::Result<HistoryHead> {
        Ok(self
            .spaces
            .read()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
            .get(space)
            .and_then(|s| s.head.clone())
            .unwrap_or_else(HistoryHead::empty))
    }
    fn event(&self, space: &SpaceId, hash: &EventHash) -> anyhow::Result<Option<TrustedEvent>> {
        Ok(self
            .spaces
            .read()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
            .get(space)
            .and_then(|s| s.events.get(hash).cloned()))
    }
    fn sequence_hash(
        &self,
        space: &SpaceId,
        sender: &EndpointId,
        session: &[u8; 16],
        sequence: u64,
    ) -> anyhow::Result<Option<EventHash>> {
        Ok(self
            .spaces
            .read()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
            .get(space)
            .and_then(|s| s.sequences.get(&(*sender, *session, sequence)).copied()))
    }
    fn sender_head(
        &self,
        space: &SpaceId,
        sender: &EndpointId,
    ) -> anyhow::Result<Option<EventHash>> {
        Ok(self
            .spaces
            .read()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
            .get(space)
            .and_then(|s| s.sender_heads.get(sender).copied()))
    }
    fn membership(&self, _space: &SpaceId) -> anyhow::Result<MembershipState> {
        Ok(self.membership.clone())
    }
    fn authenticate(&self, event: &SignedEventV1) -> anyhow::Result<()> {
        self.authenticator
            .as_ref()
            .map_or(Ok(()), |authenticate| authenticate(event))
    }
    fn commit(
        &self,
        space: &SpaceId,
        expected: &HistoryHead,
        events: &[TrustedEvent],
        new_head: &HistoryHead,
    ) -> anyhow::Result<()> {
        ensure!(
            !*self
                .fail_commits
                .read()
                .map_err(|_| anyhow::anyhow!("store lock poisoned"))?,
            "injected commit failure"
        );
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        let state = spaces.entry(*space).or_default();
        let actual = state.head.clone().unwrap_or_else(HistoryHead::empty);
        ensure!(
            &actual == expected,
            "history head changed during validation"
        );
        let mut staged_events = state.events.clone();
        let mut staged_sequences = state.sequences.clone();
        let mut staged_sender_heads = state.sender_heads.clone();
        for trusted in events {
            ensure!(
                !staged_events.contains_key(&trusted.hash),
                "event became present during commit"
            );
            let e = &trusted.event.event;
            ensure!(
                staged_sequences
                    .insert((e.sender, e.session_id, e.sequence), trusted.hash)
                    .is_none(),
                "sequence became present during commit"
            );
            staged_sender_heads.insert(e.sender, trusted.hash);
            staged_events.insert(trusted.hash, trusted.clone());
        }
        state.events = staged_events;
        state.sequences = staged_sequences;
        state.sender_heads = staged_sender_heads;
        state.head = Some(new_head.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EpochKey;
    use crate::protocol::{EventMetadataV1, FlockId};

    fn fixture() -> (
        iroh::SecretKey,
        EpochKey,
        SpaceId,
        MembershipState,
        InMemoryTrustedStore,
    ) {
        let key = iroh::SecretKey::from_bytes(&[23; 32]);
        let epoch = EpochKey::derive(b"history secret", b"history space", 0).unwrap();
        let space = SpaceId::Flock(FlockId([4; 32]));
        let membership = MembershipState::genesis(membership_scope(space), key.public());
        let store = InMemoryTrustedStore::new(membership.clone());
        (key, epoch, space, membership, store)
    }

    fn event(
        key: &iroh::SecretKey,
        epoch: &EpochKey,
        space: SpaceId,
        session: u8,
        sequence: u64,
        parents: Vec<EventHash>,
    ) -> SignedEventV1 {
        EventMetadataV1::new(
            KIND_EVENT_V1,
            space,
            key.public(),
            [session; 16],
            sequence,
            0,
            0,
            parents,
        )
        .unwrap()
        .seal_and_sign(b"payload", epoch, key)
        .unwrap()
    }

    fn raw(space: SpaceId, events: &[SignedEventV1]) -> RawBatch {
        RawBatch::from_events(space, events).unwrap()
    }

    #[test]
    fn valid_contiguous_dag_is_deterministic_and_converges() {
        let (key, epoch, space, _, store_a) = fixture();
        let (_, _, _, _, store_b) = fixture();
        let first = event(&key, &epoch, space, 1, 0, vec![]);
        let first_hash = first.verify().unwrap();
        let second = event(&key, &epoch, space, 1, 1, vec![first_hash]);
        let a = validate_batch(
            &store_a,
            space,
            raw(space, &[second.clone(), first.clone()]),
        )
        .unwrap();
        let b = validate_batch(&store_b, space, raw(space, &[first, second])).unwrap();
        assert_eq!(
            a.events.iter().map(|e| e.hash).collect::<Vec<_>>(),
            b.events.iter().map(|e| e.hash).collect::<Vec<_>>()
        );
        assert_eq!(a.head, b.head);
        assert_eq!(a.head.event_count, 2);
    }

    #[test]
    fn rejects_gap_and_missing_immediate_parent() {
        let (key, epoch, space, _, store) = fixture();
        let gap = event(&key, &epoch, space, 1, 2, vec![]);
        assert!(validate_batch(&store, space, raw(space, &[gap])).is_err());
        let first = event(&key, &epoch, space, 1, 0, vec![]);
        let second = event(&key, &epoch, space, 1, 1, vec![]);
        assert!(validate_batch(&store, space, raw(space, &[first, second])).is_err());
    }

    #[test]
    fn rejects_signature_kind_membership_and_aead_tamper() {
        let (key, epoch, space, _, store) = fixture();
        let valid = event(&key, &epoch, space, 1, 0, vec![]);
        let mut signature = valid.clone();
        signature.event.nonce[0] ^= 1;
        assert!(validate_batch(&store, space, raw(space, &[signature])).is_err());
        let wrong_kind = EventMetadataV1::new(99, space, key.public(), [2; 16], 0, 0, 0, vec![])
            .unwrap()
            .seal_and_sign(b"x", &epoch, &key)
            .unwrap();
        assert!(validate_batch(&store, space, raw(space, &[wrong_kind])).is_err());
        let outsider = iroh::SecretKey::generate();
        let unauthorized = event(&outsider, &epoch, space, 3, 0, vec![]);
        assert!(validate_batch(&store, space, raw(space, &[unauthorized])).is_err());
        let (_, _, _, membership, _) = fixture();
        let aead_store =
            InMemoryTrustedStore::new(membership).with_authenticator(|_| anyhow::bail!("bad tag"));
        assert!(validate_batch(&aead_store, space, raw(space, &[valid])).is_err());
    }

    #[test]
    fn rejects_duplicate_sequence_conflicts_and_noncanonical_bytes() {
        let (key, epoch, space, _, store) = fixture();
        let a = event(&key, &epoch, space, 1, 0, vec![]);
        let b = event(&key, &epoch, space, 1, 0, vec![]);
        assert!(validate_batch(&store, space, raw(space, &[a, b])).is_err());
        let mut malformed = raw(space, &[]);
        malformed.events.push(vec![0xff]);
        malformed.summary.event_count = 1;
        malformed.summary.encoded_bytes = 1;
        assert!(validate_batch(&store, space, malformed).is_err());
    }

    #[test]
    fn raw_decode_rejects_oversize_before_decode() {
        assert!(RawBatch::decode(&vec![0; MAX_RAW_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn commit_failure_is_atomic_and_retry_is_durable() {
        let (key, epoch, space, _, store) = fixture();
        let first = event(&key, &epoch, space, 1, 0, vec![]);
        let hash = first.verify().unwrap();
        store.set_fail_commits(true);
        assert!(validate_batch(&store, space, raw(space, std::slice::from_ref(&first))).is_err());
        assert!(store.event(&space, &hash).unwrap().is_none());
        assert_eq!(store.head(&space).unwrap(), HistoryHead::empty());
        store.set_fail_commits(false);
        validate_batch(&store, space, raw(space, &[first])).unwrap();
        assert!(store.event(&space, &hash).unwrap().is_some());
        assert_eq!(store.head(&space).unwrap().event_count, 1);
    }

    #[test]
    fn session_genesis_links_prior_sender_head() {
        let (key, epoch, space, _, store) = fixture();
        let first = event(&key, &epoch, space, 1, 0, vec![]);
        let hash = first.verify().unwrap();
        validate_batch(&store, space, raw(space, &[first])).unwrap();
        let unlinked = event(&key, &epoch, space, 2, 0, vec![]);
        assert!(validate_batch(&store, space, raw(space, &[unlinked])).is_err());
        let linked = event(&key, &epoch, space, 2, 0, vec![hash]);
        validate_batch(&store, space, raw(space, &[linked])).unwrap();
    }

    #[test]
    fn reconciliation_is_paginated_and_missing_is_recursive() {
        let (key, epoch, space, _, store) = fixture();
        let first = event(&key, &epoch, space, 1, 0, vec![]);
        let first_hash = first.verify().unwrap();
        let second = event(&key, &epoch, space, 1, 1, vec![first_hash]);
        let second_hash = second.verify().unwrap();
        validate_batch(&store, space, raw(space, &[first, second])).unwrap();
        let request = HistoryRequest {
            space,
            requester: key.public(),
            challenge: [1; 32],
            have: vec![],
            want: vec![second_hash],
            cursor: None,
            max_events: 1,
            max_bytes: MAX_HISTORY_PAGE_BYTES as u32,
        };
        let page = reconciliation_page(&store, &request).unwrap();
        assert_eq!(page.events.len(), 1);
        assert!(page.summary.next_cursor.is_some());
        assert_eq!(
            missing_parents(&store, &space, [[9; 32]], &[], 10).unwrap(),
            vec![[9; 32]]
        );
    }
}
