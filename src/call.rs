//! Signed, space-scoped call setup and teardown signals (Phase 7).
//!
//! [`CallSignalV1`] carries the authenticated intent to create, join, leave,
//! or end a voice/video call within a Starling space. Each signal binds the
//! sender's endpoint, the target [`CallId`]/[`SpaceId`], the negotiated
//! [`MediaCapabilities`], and the membership revision + wall-clock expiry
//! under a single Ed25519 signature so that any field-level tampering,
//! variant swapping, expiry exhaustion, or signer mismatch is detectable.

use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::membership::MembershipState;
use crate::protocol::{CallId, SpaceId};

/// ALPN protocol string for the voice (audio datagram) stream.
pub const VOICE_V1_ALPN: &[u8] = b"starling/voice/1";
/// ALPN protocol string for the video (unidirectional) stream.
pub const VIDEO_V1_ALPN: &[u8] = b"starling/video/1";

/// Maximum permitted lifetime of a call signal, matching the presence lease.
pub const MAX_CALL_SIGNAL_SECS: u64 = 60;

const SIGNING_DOMAIN: &[u8] = b"starling/v1/call-signal\0";
const HASH_DOMAIN: &[u8] = b"starling/v1/call-signal-hash\0";

/// SHA-256 hash of a canonical [`CallSignalV1`], domain-separated.
pub type CallSignalHash = [u8; 32];

/// What media a participant can send and/or receive on a call.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MediaCapabilities {
    pub send_voice: bool,
    pub recv_voice: bool,
    pub send_video: bool,
    pub recv_video: bool,
}

/// Fields common to every call signal variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallSignalBodyV1 {
    pub sender: EndpointId,
    pub call_id: CallId,
    pub space: SpaceId,
    pub media: MediaCapabilities,
    pub membership_revision: u64,
    pub issued_unix_ms: i64,
    pub expiry_unix_ms: i64,
}

/// Authenticated call setup/teardown intent.
///
/// The enum discriminant is part of the canonical bytes, so converting a
/// `Create` into a `Join` (or any other variant) without re-signing is
/// detectable by [`CallSignalV1::sign`]/[`SignedCallSignalV1::verify`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CallSignalV1 {
    Create(CallSignalBodyV1),
    Join(CallSignalBodyV1),
    Leave(CallSignalBodyV1),
    End(CallSignalBodyV1),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCallSignalV1 {
    pub signal: CallSignalV1,
    pub signature: Signature,
}

impl CallSignalV1 {
    pub fn body(&self) -> &CallSignalBodyV1 {
        match self {
            Self::Create(body) | Self::Join(body) | Self::Leave(body) | Self::End(body) => body,
        }
    }

    pub fn body_mut(&mut self) -> &mut CallSignalBodyV1 {
        match self {
            Self::Create(body) | Self::Join(body) | Self::Leave(body) | Self::End(body) => body,
        }
    }

    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.body().validate()?;
        Ok(postcard::to_stdvec(self)?)
    }

    fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let canonical = self.canonical_bytes()?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn hash(&self) -> anyhow::Result<CallSignalHash> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(HASH_DOMAIN);
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    pub fn sign(self, secret_key: &iroh::SecretKey) -> anyhow::Result<SignedCallSignalV1> {
        anyhow::ensure!(
            self.body().sender == secret_key.public(),
            "call signal sender does not match the signing key"
        );
        let signature = secret_key.sign(&self.signing_bytes()?);
        Ok(SignedCallSignalV1 {
            signal: self,
            signature,
        })
    }
}

impl CallSignalBodyV1 {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.expiry_unix_ms > self.issued_unix_ms,
            "call signal expiry must follow issue time"
        );
        let duration_ms = self
            .expiry_unix_ms
            .checked_sub(self.issued_unix_ms)
            .ok_or_else(|| anyhow::anyhow!("call signal duration overflow"))?;
        anyhow::ensure!(
            duration_ms <= (MAX_CALL_SIGNAL_SECS as i64) * 1000,
            "call signal exceeds the {MAX_CALL_SIGNAL_SECS}s maximum lifetime"
        );
        Ok(())
    }

    fn verify_time_bounds(&self, now_ms: i64, max_skew_ms: i64) -> anyhow::Result<()> {
        anyhow::ensure!(max_skew_ms >= 0, "maximum clock skew must not be negative");
        anyhow::ensure!(
            self.issued_unix_ms <= now_ms.saturating_add(max_skew_ms),
            "call signal was issued too far in the future"
        );
        let remaining = self.expiry_unix_ms.saturating_sub(now_ms);
        anyhow::ensure!(remaining > 0, "call signal already expired");
        Ok(())
    }
}

impl SignedCallSignalV1 {
    /// Verifies the signature, time bounds, shape, and that the sender is a
    /// member of the space at `membership_revision`, returning the
    /// domain-separated hash of the canonical signal.
    pub fn verify(
        &self,
        members: &MembershipState,
        now_ms: i64,
        max_skew_ms: i64,
    ) -> anyhow::Result<CallSignalHash> {
        let body = self.signal.body();
        body.validate()?;
        body.verify_time_bounds(now_ms, max_skew_ms)?;
        body.sender
            .verify(&self.signal.signing_bytes()?, &self.signature)
            .map_err(|_| anyhow::anyhow!("call signal signature invalid"))?;
        anyhow::ensure!(
            members.authorized_at(&body.sender, body.membership_revision, members.key_epoch()),
            "call signal sender is not a member of the space"
        );
        self.signal.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CallSignalBodyV1, CallSignalV1, MAX_CALL_SIGNAL_SECS, MediaCapabilities, SignedCallSignalV1,
    };
    use crate::membership::{MembershipScopeId, MembershipState};
    use crate::protocol::{CallId, FlockId, SpaceId};

    fn fixture_membership(key: &iroh::SecretKey) -> MembershipState {
        MembershipState::genesis(MembershipScopeId::Flock(FlockId::random()), key.public())
    }

    fn fixture_body(key: &iroh::SecretKey) -> CallSignalBodyV1 {
        CallSignalBodyV1 {
            sender: key.public(),
            call_id: CallId::random(),
            space: SpaceId::Flock(FlockId::random()),
            media: MediaCapabilities {
                send_voice: true,
                recv_voice: true,
                send_video: false,
                recv_video: false,
            },
            membership_revision: 0,
            issued_unix_ms: 1_000,
            expiry_unix_ms: 2_000,
        }
    }

    fn fixture_signal(key: &iroh::SecretKey) -> CallSignalV1 {
        CallSignalV1::Create(fixture_body(key))
    }

    #[test]
    fn all_variants_sign_and_verify() {
        let key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);
        let body = fixture_body(&key);
        for signal in [
            CallSignalV1::Create(body.clone()),
            CallSignalV1::Join(body.clone()),
            CallSignalV1::Leave(body.clone()),
            CallSignalV1::End(body.clone()),
        ] {
            let signed = signal.clone().sign(&key).unwrap();
            assert!(signed.verify(&members, 1_000, 0).is_ok());
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);
        let signal = fixture_signal(&key);
        let signed = signal.clone().sign(&key).unwrap();

        let expected_hash = signal.hash().unwrap();
        assert_eq!(signed.verify(&members, 1_000, 0).unwrap(), expected_hash);

        // postcard round-trip preserves the signature and hash.
        let encoded = postcard::to_stdvec(&signed).unwrap();
        let decoded: SignedCallSignalV1 = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.verify(&members, 1_000, 0).unwrap(), expected_hash);
    }

    #[test]
    fn tamper_detection_on_every_field() {
        let key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);
        let signed = fixture_signal(&key).sign(&key).unwrap();
        let baseline = signed.verify(&members, 1_000, 0).unwrap();

        // Variant discriminant: Create -> Join with the same body.
        let mut tampered = signed.clone();
        let body = tampered.signal.body().clone();
        tampered.signal = CallSignalV1::Join(body);
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // sender
        let mut tampered = signed.clone();
        tampered.signal.body_mut().sender = iroh::SecretKey::generate().public();
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // call_id
        let mut tampered = signed.clone();
        tampered.signal.body_mut().call_id.0[0] ^= 1;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // space
        let mut tampered = signed.clone();
        tampered.signal.body_mut().space = SpaceId::Flock(FlockId([0xff; 32]));
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // media.send_voice
        let mut tampered = signed.clone();
        tampered.signal.body_mut().media.send_voice = false;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // media.recv_voice
        let mut tampered = signed.clone();
        tampered.signal.body_mut().media.recv_voice = false;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // media.send_video
        let mut tampered = signed.clone();
        tampered.signal.body_mut().media.send_video = true;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // media.recv_video
        let mut tampered = signed.clone();
        tampered.signal.body_mut().media.recv_video = true;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // membership_revision
        let mut tampered = signed.clone();
        tampered.signal.body_mut().membership_revision += 1;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // issued_unix_ms
        let mut tampered = signed.clone();
        tampered.signal.body_mut().issued_unix_ms += 1;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // expiry_unix_ms
        let mut tampered = signed.clone();
        tampered.signal.body_mut().expiry_unix_ms += 1;
        assert!(tampered.verify(&members, 1_000, 0).is_err());

        // The unmodified signal still verifies and is stable.
        assert_eq!(signed.verify(&members, 1_000, 0).unwrap(), baseline);
    }

    #[test]
    fn rejects_wrong_signer() {
        let key = iroh::SecretKey::generate();
        let other = iroh::SecretKey::generate();
        let members = fixture_membership(&key);
        let other_members = fixture_membership(&other);

        // sign() refuses to sign when the body's sender is not the signing key.
        let mut body = fixture_body(&key);
        body.sender = other.public();
        assert!(CallSignalV1::Create(body).sign(&key).is_err());

        // A signal signed by `key` is not valid if the sender field is forged
        // to claim `other`'s identity: the signature no longer matches.
        let signed = fixture_signal(&key).sign(&key).unwrap();
        let mut forged = signed.clone();
        forged.signal.body_mut().sender = other.public();
        assert!(forged.verify(&members, 1_000, 0).is_err());

        // A signal genuinely signed by `other` verifies under `other`'s identity.
        let mut body = fixture_body(&key);
        body.sender = other.public();
        let signed_by_other = CallSignalV1::Create(body).sign(&other).unwrap();
        assert!(signed_by_other.verify(&other_members, 1_000, 0).is_ok());
    }

    #[test]
    fn rejects_expired_signals() {
        let key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);
        let signed = fixture_signal(&key).sign(&key).unwrap();

        // issued=1000, expiry=2000: valid up to 1999, expired at 2000.
        assert!(signed.verify(&members, 1_999, 0).is_ok());
        assert!(signed.verify(&members, 2_000, 0).is_err());
        assert!(signed.verify(&members, 10_000, 0).is_err());
    }

    #[test]
    fn rejects_oversized_duration_and_future_issued() {
        let key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);

        // A duration exceeding the maximum lifetime is rejected at sign time.
        let oversized = CallSignalBodyV1 {
            sender: key.public(),
            call_id: CallId::random(),
            space: SpaceId::Flock(FlockId::random()),
            media: MediaCapabilities::default(),
            membership_revision: 0,
            issued_unix_ms: 1_000,
            expiry_unix_ms: 1_000 + (MAX_CALL_SIGNAL_SECS as i64) * 1000 + 1,
        };
        assert!(CallSignalV1::Create(oversized).sign(&key).is_err());

        // A signal issued in the future is rejected unless skew covers it.
        let future = CallSignalBodyV1 {
            sender: key.public(),
            call_id: CallId::random(),
            space: SpaceId::Flock(FlockId::random()),
            media: MediaCapabilities::default(),
            membership_revision: 0,
            issued_unix_ms: 5_000,
            expiry_unix_ms: 6_000,
        };
        let signed = CallSignalV1::Create(future).sign(&key).unwrap();
        assert!(signed.verify(&members, 1_000, 0).is_err());
        assert!(signed.verify(&members, 1_000, 4_000).is_ok());
    }

    #[test]
    fn revision_and_expiry_are_bound() {
        let key = iroh::SecretKey::generate();
        let call_id = CallId::random();
        let space = SpaceId::Flock(FlockId([1; 32]));
        let media = MediaCapabilities {
            send_voice: true,
            recv_voice: true,
            send_video: false,
            recv_video: false,
        };

        // Build a membership state at revision 6 with the sender as a member.
        let scope = MembershipScopeId::Flock(FlockId([1; 32]));
        let mut members = MembershipState::genesis(scope, key.public());
        // Apply 6 no-op Add mutations to advance the revision to 6.
        for _ in 0..6 {
            use crate::membership::{MembershipMutationBodyV1, MembershipOperationV1};
            let mutation = MembershipMutationBodyV1 {
                scope,
                revision: members.revision() + 1,
                previous_hash: members.head_hash(),
                actor: key.public(),
                operation: MembershipOperationV1::Add {
                    member: iroh::SecretKey::generate().public(),
                    role: crate::membership::MemberRole::Member,
                },
                effective_key_epoch: members.key_epoch(),
            }
            .sign(&key)
            .unwrap();
            members.apply(&mutation).unwrap();
        }

        let base = CallSignalBodyV1 {
            sender: key.public(),
            call_id,
            space,
            media: media.clone(),
            membership_revision: 5,
            issued_unix_ms: 1_000,
            expiry_unix_ms: 2_000,
        };

        let signal_rev5 = CallSignalV1::Create(base.clone()).sign(&key).unwrap();

        // Different membership revisions produce distinct hashes.
        let mut rev6 = base.clone();
        rev6.membership_revision = 6;
        let signal_rev6 = CallSignalV1::Create(rev6).sign(&key).unwrap();
        assert_ne!(
            signal_rev5.verify(&members, 1_000, 0).unwrap(),
            signal_rev6.verify(&members, 1_000, 0).unwrap()
        );

        // Tampering the revision after signing is detected.
        let mut tampered_rev = signal_rev5.clone();
        tampered_rev.signal.body_mut().membership_revision = 6;
        assert!(tampered_rev.verify(&members, 1_000, 0).is_err());

        // Different expiries produce distinct hashes.
        let mut later_expiry = base.clone();
        later_expiry.expiry_unix_ms = 3_000;
        let signal_later = CallSignalV1::Create(later_expiry).sign(&key).unwrap();
        assert_ne!(
            signal_rev5.verify(&members, 1_000, 0).unwrap(),
            signal_later.verify(&members, 1_000, 0).unwrap()
        );

        // Tampering the expiry after signing is detected.
        let mut tampered_expiry = signal_rev5.clone();
        tampered_expiry.signal.body_mut().expiry_unix_ms = 3_000;
        assert!(tampered_expiry.verify(&members, 1_000, 0).is_err());

        // The expiry bound is enforced against wall-clock time: rev5 expires at
        // 2000 while the later-expiry signal is still live at 2500.
        assert!(signal_rev5.verify(&members, 2_500, 0).is_err());
        assert!(signal_later.verify(&members, 2_500, 0).is_ok());
    }

    #[test]
    fn rejects_non_member() {
        let key = iroh::SecretKey::generate();
        let non_member_key = iroh::SecretKey::generate();
        let members = fixture_membership(&key);

        // A signal from a non-member passes signature + time checks but fails
        // the membership authorization check.
        let mut body = fixture_body(&key);
        body.sender = non_member_key.public();
        let signed = CallSignalV1::Create(body).sign(&non_member_key).unwrap();
        assert!(signed.verify(&members, 1_000, 0).is_err());
    }
}
