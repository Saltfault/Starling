//! Short-lived, signed, space-scoped presence leases.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::ensure;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::membership::{MembershipScopeId, MembershipState};
use crate::protocol::SpaceId;

pub const MAX_LEASE_SECS: u64 = 60;

/// Number of membership revisions a presence lease may lag behind the current
/// view before it is rejected. A small window smooths over propagation delay
/// while still being stricter than accepting any past revision.
const REVISION_LAG: u64 = 2;

const LEASE_DOMAIN: &[u8] = b"starling/v1/presence-lease";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresenceLeaseBodyV1 {
    pub space: SpaceId,
    pub endpoint: EndpointId,
    pub sequence: u64,
    pub issued_unix_ms: i64,
    pub expiry_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPresenceLeaseV1 {
    pub body: PresenceLeaseBodyV1,
    pub signature: iroh::Signature,
}

impl PresenceLeaseBodyV1 {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::from(LEASE_DOMAIN);
        out.extend_from_slice(&postcard::to_stdvec(self)?);
        Ok(out)
    }

    pub fn sign(self, secret: &iroh::SecretKey) -> anyhow::Result<SignedPresenceLeaseV1> {
        ensure!(
            secret.public() == self.endpoint,
            "lease endpoint must be the signer"
        );
        let signature = secret.sign(&self.canonical_bytes()?);
        Ok(SignedPresenceLeaseV1 {
            body: self,
            signature,
        })
    }
}

impl SignedPresenceLeaseV1 {
    /// Verifies the signed wall-clock bounds and returns the remaining lease.
    /// Callers must immediately convert this duration to a monotonic deadline.
    pub fn verify(&self, now_ms: i64, max_skew_ms: i64) -> anyhow::Result<Duration> {
        ensure!(max_skew_ms >= 0, "maximum clock skew must not be negative");
        self.body
            .endpoint
            .verify(&self.body.canonical_bytes()?, &self.signature)
            .map_err(|_| anyhow::anyhow!("presence lease signature invalid"))?;
        ensure!(
            self.body.expiry_unix_ms > self.body.issued_unix_ms,
            "lease expiry precedes issue"
        );
        let duration_ms = self
            .body
            .expiry_unix_ms
            .checked_sub(self.body.issued_unix_ms)
            .ok_or_else(|| anyhow::anyhow!("lease duration overflow"))?;
        ensure!(
            duration_ms <= (MAX_LEASE_SECS as i64) * 1000,
            "lease exceeds the 60s maximum"
        );
        ensure!(
            self.body.issued_unix_ms <= now_ms.saturating_add(max_skew_ms),
            "lease issued too far in the future"
        );
        let remaining = self.body.expiry_unix_ms.saturating_sub(now_ms);
        ensure!(remaining > 0, "lease already expired");
        Ok(Duration::from_millis(remaining as u64))
    }
}

pub fn lease_deadline(remaining: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + remaining
}

#[derive(Clone, Debug)]
pub struct LivePresence {
    pub deadline: tokio::time::Instant,
    pub sequence: u64,
}

/// Replay and liveness state is independent for each space and endpoint.
#[derive(Clone, Debug, Default)]
pub struct PresenceTracker {
    accepted: HashMap<(SpaceId, EndpointId), LivePresence>,
}

impl PresenceTracker {
    /// Validate and record a signed presence lease.
    ///
    /// A lease is only accepted if the issuer is still a member at (or
    /// near) the **current** membership revision. If the issuer has fallen
    /// behind, the lease is rejected until they catch up — this is
    /// intentional: a stale membership view should not grant presence.
    ///
    /// To avoid rejecting leases during brief propagation lag, the check
    /// tolerates a small revision window ([`REVISION_LAG`]) behind the
    /// current revision.
    pub fn accept(
        &mut self,
        lease: &SignedPresenceLeaseV1,
        membership: &MembershipState,
        now_ms: i64,
        max_skew_ms: i64,
    ) -> anyhow::Result<&LivePresence> {
        let remaining = lease.verify(now_ms, max_skew_ms)?;
        let body = &lease.body;
        ensure!(
            membership.scope() == membership_scope(body.space),
            "presence membership scope mismatch"
        );
        // Accept leases whose membership view is no older than
        // REVISION_LAG revisions behind the current view.
        let floor = membership.revision().saturating_sub(REVISION_LAG);
        ensure!(
            membership.authorized_at(&body.endpoint, floor, membership.key_epoch()),
            "presence endpoint is not a current member"
        );
        let key = (body.space, body.endpoint);
        ensure!(
            self.accepted
                .get(&key)
                .is_none_or(|live| body.sequence > live.sequence),
            "presence sequence is not strictly increasing"
        );
        self.accepted.insert(
            key,
            LivePresence {
                deadline: lease_deadline(remaining),
                sequence: body.sequence,
            },
        );
        Ok(self.accepted.get(&key).expect("presence was inserted"))
    }

    pub fn live(
        &self,
        space: SpaceId,
        endpoint: &EndpointId,
        now: tokio::time::Instant,
    ) -> Option<&LivePresence> {
        self.accepted
            .get(&(space, *endpoint))
            .filter(|live| now < live.deadline)
    }

    /// Expire liveness while retaining the sequence to prevent replay.
    pub fn expire(&mut self, now: tokio::time::Instant) {
        for live in self.accepted.values_mut() {
            if live.deadline <= now {
                live.deadline = now;
            }
        }
    }
}

fn membership_scope(space: SpaceId) -> MembershipScopeId {
    match space {
        SpaceId::Flock(flock) => MembershipScopeId::Flock(flock),
        SpaceId::RoostChannel { roost, .. } => MembershipScopeId::Roost(roost),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FlockId;

    fn signed(
        key: &iroh::SecretKey,
        space: SpaceId,
        sequence: u64,
        issued: i64,
        expiry: i64,
    ) -> SignedPresenceLeaseV1 {
        PresenceLeaseBodyV1 {
            space,
            endpoint: key.public(),
            sequence,
            issued_unix_ms: issued,
            expiry_unix_ms: expiry,
        }
        .sign(key)
        .unwrap()
    }

    #[test]
    fn validates_signature_duration_skew_and_expiry() {
        let key = iroh::SecretKey::generate();
        let space = SpaceId::Flock(FlockId::random());
        assert_eq!(
            signed(&key, space, 1, 1_000, 2_000)
                .verify(1_000, 0)
                .unwrap(),
            Duration::from_secs(1)
        );
        assert!(
            signed(&key, space, 1, 1_000, 61_001)
                .verify(1_000, 0)
                .is_err()
        );
        assert!(
            signed(&key, space, 1, 2_000, 3_000)
                .verify(1_000, 10)
                .is_err()
        );
        assert!(signed(&key, space, 1, 0, 1_000).verify(1_000, 0).is_err());
        let mut tampered = signed(&key, space, 1, 1_000, 2_000);
        tampered.body.sequence = 2;
        assert!(tampered.verify(1_000, 0).is_err());
    }

    #[test]
    fn replay_membership_and_spaces_are_enforced() {
        let member = iroh::SecretKey::generate();
        let outsider = iroh::SecretKey::generate();
        let first = FlockId::random();
        let second = FlockId::random();
        let first_space = SpaceId::Flock(first);
        let second_space = SpaceId::Flock(second);
        let first_membership =
            MembershipState::genesis(MembershipScopeId::Flock(first), member.public());
        let second_membership =
            MembershipState::genesis(MembershipScopeId::Flock(second), member.public());
        let mut tracker = PresenceTracker::default();
        tracker
            .accept(
                &signed(&member, first_space, 2, 1_000, 2_000),
                &first_membership,
                1_000,
                0,
            )
            .unwrap();
        assert!(
            tracker
                .accept(
                    &signed(&member, first_space, 2, 1_000, 2_000),
                    &first_membership,
                    1_000,
                    0
                )
                .is_err()
        );
        tracker
            .accept(
                &signed(&member, second_space, 1, 1_000, 2_000),
                &second_membership,
                1_000,
                0,
            )
            .unwrap();
        assert!(
            tracker
                .accept(
                    &signed(&outsider, first_space, 3, 1_000, 2_000),
                    &first_membership,
                    1_000,
                    0
                )
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn monotonic_deadline_expires_without_losing_replay_state() {
        let member = iroh::SecretKey::generate();
        let flock = FlockId::random();
        let space = SpaceId::Flock(flock);
        let membership = MembershipState::genesis(MembershipScopeId::Flock(flock), member.public());
        let mut tracker = PresenceTracker::default();
        tracker
            .accept(
                &signed(&member, space, 1, 1_000, 2_000),
                &membership,
                1_000,
                0,
            )
            .unwrap();
        assert!(
            tracker
                .live(space, &member.public(), tokio::time::Instant::now())
                .is_some()
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tracker.expire(tokio::time::Instant::now());
        assert!(
            tracker
                .live(space, &member.public(), tokio::time::Instant::now())
                .is_none()
        );
        assert!(
            tracker
                .accept(
                    &signed(&member, space, 1, 1_000, 2_000),
                    &membership,
                    1_000,
                    0
                )
                .is_err()
        );
    }
}
