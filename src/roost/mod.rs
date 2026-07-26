use std::collections::BTreeSet;

use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{ChannelId, RoostId};

pub mod perms;

pub const MANIFEST_VERSION: u16 = 1;
pub const MAX_CHANNELS: usize = 256;
pub const MAX_CHANNEL_NAME_BYTES: usize = 128;
pub const MAX_ROOST_NAME_BYTES: usize = 256;
const MANIFEST_SIGNING_DOMAIN: &[u8] = b"starling/roost-manifest/v1\0";
const MANIFEST_HASH_DOMAIN: &[u8] = b"starling/roost-manifest-hash/v1\0";

pub type ManifestHash = [u8; 32];

/// The original persisted state. Its wire representation must remain stable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoostState {
    pub name: String,
    pub channels: Vec<String>,
    /// Roles, memberships, bans, and invitations. A redacted copy of this travels
    /// over the roost control channel so clients can color names and gate menus;
    /// the enforcement verdicts are always recomputed roost-side.
    #[serde(default)]
    pub perms: perms::PermState,
}

/// A moderation request sent by a client to the roost's mod protocol. The
/// sender's identity is authenticated by the iroh transport, not claimed in the
/// request body, so a modified client cannot spoof `from`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModRequest {
    Ban(EndpointId),
    Kick(EndpointId),
    Invite(EndpointId),
    DeleteMessage { channel: String, id: String },
}

/// The roost's answer to a successful join handshake: its name and, per
/// channel, the secret key needed to decrypt gossip. Non-members never receive
/// one, so they can neither read channels nor derive their keys.
///
/// `control_secret` carries the key for the roost's control channel (where
/// `RoostState` updates are broadcast). Phase 9 added this so the control
/// channel is encrypted with a high-entropy secret rather than a
/// public-derivable room code — closing the last gap where a non-member
/// who merely knows the roost code could read the member/ban list.
/// `None` indicates an old server that still derives the control cipher from
/// the public code; clients fall back to `from_room_code` for back-compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoostWelcome {
    pub name: String,
    pub channels: Vec<(String, [u8; 32])>,
    #[serde(default)]
    pub control_secret: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelV1 {
    pub id: ChannelId,
    pub name: String,
    pub key_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestV1 {
    pub version: u16,
    pub roost_id: RoostId,
    pub name: String,
    pub revision: u64,
    pub previous: Option<ManifestHash>,
    pub authority: EndpointId,
    pub membership_epoch: u64,
    pub channels: Vec<ChannelV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedManifestV1 {
    pub manifest: ManifestV1,
    pub signature: Signature,
}

/// Supplies application policy without coupling the wire type to storage.
pub trait ManifestValidationHooks {
    fn authority_may_publish(
        &self,
        roost_id: &RoostId,
        membership_epoch: u64,
        authority: &EndpointId,
    ) -> anyhow::Result<()>;

    fn known_manifest(&self, hash: &ManifestHash) -> anyhow::Result<Option<ManifestV1>>;
}

impl ChannelV1 {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.id != ChannelId([0; 16]), "channel id must not be zero");
        anyhow::ensure!(!self.name.is_empty(), "channel name must not be empty");
        anyhow::ensure!(
            self.name.len() <= MAX_CHANNEL_NAME_BYTES,
            "channel name is too long"
        );
        Ok(())
    }
}

impl ManifestV1 {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == MANIFEST_VERSION,
            "unsupported manifest version"
        );
        anyhow::ensure!(
            self.roost_id != RoostId([0; 32]),
            "roost id must not be zero"
        );
        anyhow::ensure!(!self.name.is_empty(), "roost name must not be empty");
        anyhow::ensure!(
            self.name.len() <= MAX_ROOST_NAME_BYTES,
            "roost name is too long"
        );
        anyhow::ensure!(self.channels.len() <= MAX_CHANNELS, "too many channels");
        anyhow::ensure!(
            (self.revision == 0) == self.previous.is_none(),
            "genesis must have no predecessor and later revisions must have one"
        );

        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for channel in &self.channels {
            channel.validate()?;
            anyhow::ensure!(ids.insert(channel.id), "duplicate channel id");
            anyhow::ensure!(
                names.insert(channel.name.as_str()),
                "duplicate channel name"
            );
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(MANIFEST_SIGNING_DOMAIN, self)
    }

    pub fn hash(&self) -> anyhow::Result<ManifestHash> {
        self.validate_shape()?;
        let bytes = domain_encode(MANIFEST_HASH_DOMAIN, self)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedManifestV1> {
        anyhow::ensure!(
            self.authority == key.public(),
            "manifest authority does not match key"
        );
        let signature = key.sign(&self.signing_bytes()?);
        Ok(SignedManifestV1 {
            manifest: self,
            signature,
        })
    }
}

impl SignedManifestV1 {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.manifest.validate_shape()?;
        self.manifest
            .authority
            .verify(&self.manifest.signing_bytes()?, &self.signature)?;
        Ok(())
    }

    pub fn validate_with(&self, hooks: &impl ManifestValidationHooks) -> anyhow::Result<()> {
        self.verify()?;
        hooks.authority_may_publish(
            &self.manifest.roost_id,
            self.manifest.membership_epoch,
            &self.manifest.authority,
        )?;
        if let Some(previous_hash) = self.manifest.previous {
            let previous = hooks
                .known_manifest(&previous_hash)?
                .ok_or_else(|| anyhow::anyhow!("manifest predecessor is unknown"))?;
            anyhow::ensure!(
                previous.hash()? == previous_hash,
                "predecessor hash mismatch"
            );
            anyhow::ensure!(
                previous.roost_id == self.manifest.roost_id,
                "predecessor belongs to another roost"
            );
            anyhow::ensure!(
                previous.revision.checked_add(1) == Some(self.manifest.revision),
                "manifest revision is not contiguous"
            );
            anyhow::ensure!(
                previous.membership_epoch <= self.manifest.membership_epoch,
                "membership epoch regressed"
            );
        }
        Ok(())
    }
}

fn domain_encode<T: Serialize>(domain: &[u8], value: &T) -> anyhow::Result<Vec<u8>> {
    let encoded = postcard::to_stdvec(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn manifest(authority: EndpointId) -> ManifestV1 {
        ManifestV1 {
            version: MANIFEST_VERSION,
            roost_id: RoostId([1; 32]),
            name: "Nest".into(),
            revision: 0,
            previous: None,
            authority,
            membership_epoch: 3,
            channels: vec![ChannelV1 {
                id: ChannelId([2; 16]),
                name: "general".into(),
                key_epoch: 1,
            }],
        }
    }

    struct Hooks {
        allowed: EndpointId,
        manifests: HashMap<ManifestHash, ManifestV1>,
    }
    impl ManifestValidationHooks for Hooks {
        fn authority_may_publish(
            &self,
            _: &RoostId,
            _: u64,
            authority: &EndpointId,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(*authority == self.allowed, "not allowed");
            Ok(())
        }
        fn known_manifest(&self, hash: &ManifestHash) -> anyhow::Result<Option<ManifestV1>> {
            Ok(self.manifests.get(hash).cloned())
        }
    }

    #[test]
    fn signs_hashes_and_validates_revision_chain() {
        let key = iroh::SecretKey::generate();
        let first = manifest(key.public());
        let first_hash = first.hash().unwrap();
        let mut second = first.clone();
        second.revision = 1;
        second.previous = Some(first_hash);
        let signed = second.sign(&key).unwrap();
        let hooks = Hooks {
            allowed: key.public(),
            manifests: [(first_hash, first)].into(),
        };
        signed.validate_with(&hooks).unwrap();

        let encoded = postcard::to_stdvec(&signed).unwrap();
        postcard::from_bytes::<SignedManifestV1>(&encoded)
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn rejects_tampering_duplicates_limits_and_broken_chains() {
        let key = iroh::SecretKey::generate();
        let mut signed = manifest(key.public()).sign(&key).unwrap();
        signed.manifest.name.push('!');
        assert!(signed.verify().is_err());

        let mut duplicate = manifest(key.public());
        duplicate.channels.push(duplicate.channels[0].clone());
        assert!(duplicate.validate_shape().is_err());
        duplicate.channels.clear();
        duplicate.name = "x".repeat(MAX_ROOST_NAME_BYTES + 1);
        assert!(duplicate.validate_shape().is_err());

        let first = manifest(key.public());
        let hash = first.hash().unwrap();
        let mut later = first.clone();
        later.revision = 2;
        later.previous = Some(hash);
        let hooks = Hooks {
            allowed: key.public(),
            manifests: [(hash, first)].into(),
        };
        assert!(later.sign(&key).unwrap().validate_with(&hooks).is_err());
    }

    #[test]
    fn welcome_round_trips_control_secret_and_is_back_compatible() {
        // A Phase 9 welcome carries a control_secret.
        let welcome = RoostWelcome {
            name: "Nest".into(),
            channels: vec![("general".into(), [1; 32])],
            control_secret: Some([2; 32]),
        };
        let encoded = postcard::to_stdvec(&welcome).unwrap();
        let decoded: RoostWelcome = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.name, "Nest");
        assert_eq!(decoded.channels[0].1, [1; 32]);
        assert_eq!(decoded.control_secret, Some([2; 32]));

        // A legacy welcome (no control_secret) decodes with control_secret = None.
        let legacy = postcard::to_stdvec(&RoostWelcome {
            name: "Old".into(),
            channels: vec![("general".into(), [9; 32])],
            control_secret: None,
        })
        .unwrap();
        let decoded: RoostWelcome = postcard::from_bytes(&legacy).unwrap();
        assert_eq!(decoded.control_secret, None);
    }
}
