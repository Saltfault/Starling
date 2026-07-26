//! Canonical, signed membership authority chains.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, ensure};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{FlockId, RoostId};

const SIGNING_DOMAIN: &[u8] = b"starling/membership-mutation/v1/sign\0";
const HASH_DOMAIN: &[u8] = b"starling/membership-mutation/v1/hash\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MemberRole {
    Admin,
    Member,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum MembershipScopeId {
    Flock(FlockId),
    Roost(RoostId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MembershipOperationV1 {
    Add {
        member: EndpointId,
        role: MemberRole,
    },
    Remove {
        member: EndpointId,
    },
    TransferAdmin {
        to: EndpointId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipMutationBodyV1 {
    pub scope: MembershipScopeId,
    pub revision: u64,
    pub previous_hash: Option<[u8; 32]>,
    pub actor: EndpointId,
    pub operation: MembershipOperationV1,
    pub effective_key_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMembershipMutationV1 {
    pub body: MembershipMutationBodyV1,
    pub signer: EndpointId,
    pub signature: Signature,
}

impl MembershipMutationBodyV1 {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        domain_encode(SIGNING_DOMAIN, self)
    }

    pub fn hash(&self) -> anyhow::Result<[u8; 32]> {
        hash_encoded(HASH_DOMAIN, self)
    }

    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedMembershipMutationV1> {
        ensure!(
            self.actor == key.public(),
            "membership actor does not match signing key"
        );
        let signer = key.public();
        let signature = key.sign(&self.canonical_bytes()?);
        Ok(SignedMembershipMutationV1 {
            body: self,
            signer,
            signature,
        })
    }
}

impl SignedMembershipMutationV1 {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.body.canonical_bytes()
    }

    pub fn hash(&self) -> anyhow::Result<[u8; 32]> {
        self.body.hash()
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.signer == self.body.actor,
            "membership signer does not match actor"
        );
        self.signer
            .verify(&self.canonical_bytes()?, &self.signature)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberAuthorization {
    pub role: MemberRole,
    pub generation: u64,
    pub from_key_epoch: u64,
    pub until_key_epoch: Option<u64>,
}

impl MemberAuthorization {
    pub fn authorizes(&self, key_epoch: u64) -> bool {
        key_epoch >= self.from_key_epoch
            && self.until_key_epoch.is_none_or(|until| key_epoch < until)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipSnapshot {
    pub scope: MembershipScopeId,
    pub revision: u64,
    pub head_hash: Option<[u8; 32]>,
    pub key_epoch: u64,
    pub members: BTreeMap<EndpointId, MemberAuthorization>,
}

impl MembershipSnapshot {
    pub fn member(&self, member: &EndpointId) -> Option<&MemberAuthorization> {
        self.members.get(member)
    }

    pub fn is_member_at_epoch(&self, member: &EndpointId, key_epoch: u64) -> bool {
        self.member(member)
            .is_some_and(|entry| entry.authorizes(key_epoch))
    }

    pub fn is_admin(&self, member: &EndpointId) -> bool {
        self.member(member)
            .is_some_and(|entry| entry.role == MemberRole::Admin)
    }
}

#[derive(Clone, Debug)]
pub struct MembershipState {
    scope: MembershipScopeId,
    revision: u64,
    head_hash: Option<[u8; 32]>,
    key_epoch: u64,
    members: BTreeMap<EndpointId, MemberAuthorization>,
    generations: HashMap<EndpointId, u64>,
    authorizations: HashMap<EndpointId, Vec<MemberAuthorization>>,
    snapshots: BTreeMap<u64, MembershipSnapshot>,
}

impl MembershipState {
    pub fn genesis(scope: MembershipScopeId, creator: EndpointId) -> Self {
        let creator_authorization = MemberAuthorization {
            role: MemberRole::Admin,
            generation: 0,
            from_key_epoch: 0,
            until_key_epoch: None,
        };
        let members = BTreeMap::from([(creator, creator_authorization.clone())]);
        let snapshot = MembershipSnapshot {
            scope,
            revision: 0,
            head_hash: None,
            key_epoch: 0,
            members: members.clone(),
        };
        Self {
            scope,
            revision: 0,
            head_hash: None,
            key_epoch: 0,
            members,
            generations: HashMap::from([(creator, 0)]),
            authorizations: HashMap::from([(creator, vec![creator_authorization])]),
            snapshots: BTreeMap::from([(0, snapshot)]),
        }
    }

    /// Build a membership state directly from a flat list of members without a
    /// V1 mutation chain. Used by roost runtimes that manage membership through
    /// their own authority model (e.g. [`crate::roost::perms::PermState`]) rather
    /// than signed [`SignedMembershipMutationV1`] entries.
    pub fn from_flat(
        scope: MembershipScopeId,
        admin: EndpointId,
        members: impl IntoIterator<Item = EndpointId>,
        key_epoch: u64,
    ) -> Self {
        let admin_auth = MemberAuthorization {
            role: MemberRole::Admin,
            generation: 0,
            from_key_epoch: 0,
            until_key_epoch: None,
        };
        let mut members_map = BTreeMap::from([(admin, admin_auth.clone())]);
        let mut generations = HashMap::from([(admin, 0u64)]);
        let mut authorizations = HashMap::from([(admin, vec![admin_auth])]);

        for member in members {
            if member == admin {
                continue;
            }
            let auth = MemberAuthorization {
                role: MemberRole::Member,
                generation: 0,
                from_key_epoch: 0,
                until_key_epoch: None,
            };
            members_map.insert(member, auth.clone());
            generations.insert(member, 0u64);
            authorizations.insert(member, vec![auth]);
        }

        let snapshot = MembershipSnapshot {
            scope,
            revision: 0,
            head_hash: None,
            key_epoch,
            members: members_map.clone(),
        };
        Self {
            scope,
            revision: 0,
            head_hash: None,
            key_epoch,
            members: members_map,
            generations,
            authorizations,
            snapshots: BTreeMap::from([(0, snapshot)]),
        }
    }

    pub fn fold(
        scope: MembershipScopeId,
        creator: EndpointId,
        mutations: impl IntoIterator<Item = SignedMembershipMutationV1>,
    ) -> anyhow::Result<Self> {
        let mut state = Self::genesis(scope, creator);
        for mutation in mutations {
            state.apply(&mutation)?;
        }
        Ok(state)
    }

    pub fn apply(&mut self, mutation: &SignedMembershipMutationV1) -> anyhow::Result<()> {
        mutation
            .verify()
            .context("invalid membership mutation signature")?;
        let body = &mutation.body;
        ensure!(body.scope == self.scope, "membership scope mismatch");
        let next_revision = self
            .revision
            .checked_add(1)
            .context("membership revision overflow")?;
        ensure!(
            body.revision == next_revision,
            "membership revision must increment exactly once"
        );
        ensure!(
            body.previous_hash == self.head_hash,
            "membership fork or missing mutation"
        );
        ensure!(
            self.is_admin(&body.actor),
            "membership actor is not a current admin"
        );

        if matches!(body.operation, MembershipOperationV1::Remove { .. }) {
            let next_epoch = self
                .key_epoch
                .checked_add(1)
                .context("membership key epoch overflow")?;
            ensure!(
                body.effective_key_epoch == next_epoch,
                "removal must increment key epoch exactly once"
            );
        } else {
            ensure!(
                body.effective_key_epoch == self.key_epoch,
                "non-removal must not change the key epoch"
            );
        }

        match body.operation {
            MembershipOperationV1::Add { member, role } => {
                self.add(member, role, body.effective_key_epoch)?
            }
            MembershipOperationV1::Remove { member } => {
                self.remove(member, body.effective_key_epoch)?
            }
            MembershipOperationV1::TransferAdmin { to } => self.transfer(body.actor, to)?,
        }

        self.revision = body.revision;
        self.head_hash = Some(mutation.hash()?);
        self.key_epoch = body.effective_key_epoch;
        self.snapshots.insert(
            self.revision,
            MembershipSnapshot {
                scope: self.scope,
                revision: self.revision,
                head_hash: self.head_hash,
                key_epoch: self.key_epoch,
                members: self.members.clone(),
            },
        );
        Ok(())
    }

    pub fn scope(&self) -> MembershipScopeId {
        self.scope
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn head_hash(&self) -> Option<[u8; 32]> {
        self.head_hash
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn members(&self) -> &BTreeMap<EndpointId, MemberAuthorization> {
        &self.members
    }
    pub fn member(&self, member: &EndpointId) -> Option<&MemberAuthorization> {
        self.members.get(member)
    }
    pub fn snapshot(&self, revision: u64) -> Option<&MembershipSnapshot> {
        self.snapshots.get(&revision)
    }
    pub fn history(&self) -> &BTreeMap<u64, MembershipSnapshot> {
        &self.snapshots
    }
    pub fn authorization_history(&self, member: &EndpointId) -> &[MemberAuthorization] {
        self.authorizations
            .get(member)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
    pub fn is_admin(&self, member: &EndpointId) -> bool {
        self.member(member)
            .is_some_and(|entry| entry.role == MemberRole::Admin)
    }
    pub fn authorized_at(&self, member: &EndpointId, revision: u64, key_epoch: u64) -> bool {
        self.snapshot(revision)
            .is_some_and(|snapshot| snapshot.is_member_at_epoch(member, key_epoch))
    }
    pub fn admin_at(&self, member: &EndpointId, revision: u64, key_epoch: u64) -> bool {
        self.snapshot(revision).is_some_and(|snapshot| {
            snapshot.is_admin(member) && snapshot.is_member_at_epoch(member, key_epoch)
        })
    }

    fn add(&mut self, member: EndpointId, role: MemberRole, epoch: u64) -> anyhow::Result<()> {
        ensure!(
            !self.members.contains_key(&member),
            "member is already active"
        );
        let generation = match self.generations.get(&member) {
            Some(previous) => previous
                .checked_add(1)
                .context("membership generation overflow")?,
            None => 0,
        };
        let authorization = MemberAuthorization {
            role,
            generation,
            from_key_epoch: epoch,
            until_key_epoch: None,
        };
        self.generations.insert(member, generation);
        self.authorizations
            .entry(member)
            .or_default()
            .push(authorization.clone());
        self.members.insert(member, authorization);
        Ok(())
    }

    fn remove(&mut self, member: EndpointId, epoch: u64) -> anyhow::Result<()> {
        let current = self
            .members
            .get(&member)
            .context("cannot remove an inactive member")?;
        if current.role == MemberRole::Admin {
            ensure!(
                self.members
                    .values()
                    .filter(|entry| entry.role == MemberRole::Admin)
                    .count()
                    > 1,
                "cannot remove the final admin"
            );
        }
        let generation = current.generation;
        self.members.remove(&member);
        let interval = self
            .authorizations
            .get_mut(&member)
            .and_then(|entries| entries.last_mut())
            .context("missing membership authorization interval")?;
        ensure!(
            interval.generation == generation && interval.until_key_epoch.is_none(),
            "invalid membership authorization interval"
        );
        interval.until_key_epoch = Some(epoch);
        Ok(())
    }

    fn transfer(&mut self, from: EndpointId, to: EndpointId) -> anyhow::Result<()> {
        ensure!(from != to, "admin transfer endpoints must differ");
        ensure!(
            self.is_admin(&from),
            "admin transfer source is not an admin"
        );
        ensure!(
            self.members.contains_key(&to),
            "admin transfer target is not a member"
        );
        self.set_role(from, MemberRole::Member)?;
        self.set_role(to, MemberRole::Admin)
    }

    fn set_role(&mut self, member: EndpointId, role: MemberRole) -> anyhow::Result<()> {
        self.members
            .get_mut(&member)
            .context("member is not active")?
            .role = role;
        self.authorizations
            .get_mut(&member)
            .and_then(|entries| entries.last_mut())
            .context("missing membership authorization interval")?
            .role = role;
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

fn hash_encoded<T: Serialize>(domain: &[u8], value: &T) -> anyhow::Result<[u8; 32]> {
    Ok(Sha256::digest(domain_encode(domain, value)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(byte: u8) -> MembershipScopeId {
        MembershipScopeId::Flock(FlockId([byte; 32]))
    }
    fn mutation(
        state: &MembershipState,
        key: &iroh::SecretKey,
        operation: MembershipOperationV1,
        epoch: u64,
    ) -> SignedMembershipMutationV1 {
        MembershipMutationBodyV1 {
            scope: state.scope(),
            revision: state.revision() + 1,
            previous_hash: state.head_hash(),
            actor: key.public(),
            operation,
            effective_key_epoch: epoch,
        }
        .sign(key)
        .unwrap()
    }

    #[test]
    fn folds_history_and_tracks_readded_generations() {
        let admin = iroh::SecretKey::generate();
        let member = iroh::SecretKey::generate();
        let mut state = MembershipState::genesis(scope(1), admin.public());
        state
            .apply(&mutation(
                &state,
                &admin,
                MembershipOperationV1::Add {
                    member: member.public(),
                    role: MemberRole::Member,
                },
                0,
            ))
            .unwrap();
        state
            .apply(&mutation(
                &state,
                &admin,
                MembershipOperationV1::Remove {
                    member: member.public(),
                },
                1,
            ))
            .unwrap();
        assert!(state.authorized_at(&member.public(), 1, 0));
        assert!(!state.authorized_at(&member.public(), 2, 1));
        state
            .apply(&mutation(
                &state,
                &admin,
                MembershipOperationV1::Add {
                    member: member.public(),
                    role: MemberRole::Member,
                },
                1,
            ))
            .unwrap();
        assert_eq!(state.member(&member.public()).unwrap().generation, 1);
        assert_eq!(state.authorization_history(&member.public()).len(), 2);
    }

    #[test]
    fn rejects_tamper_fork_cross_scope_unauthorized_and_final_admin_removal() {
        let admin = iroh::SecretKey::generate();
        let outsider = iroh::SecretKey::generate();
        let member = iroh::SecretKey::generate();
        let state = MembershipState::genesis(scope(2), admin.public());
        let valid = mutation(
            &state,
            &admin,
            MembershipOperationV1::Add {
                member: member.public(),
                role: MemberRole::Member,
            },
            0,
        );
        let mut tampered = valid.clone();
        tampered.body.effective_key_epoch = 1;
        assert!(tampered.verify().is_err());
        let mut fork = valid.clone();
        fork.body.previous_hash = Some([9; 32]);
        assert!(state.clone().apply(&fork).is_err());
        let mut cross_scope = valid.clone();
        cross_scope.body.scope = scope(3);
        assert!(state.clone().apply(&cross_scope).is_err());
        let unauthorized = MembershipMutationBodyV1 {
            actor: outsider.public(),
            ..valid.body.clone()
        }
        .sign(&outsider)
        .unwrap();
        assert!(state.clone().apply(&unauthorized).is_err());
        assert!(
            state
                .clone()
                .apply(&mutation(
                    &state,
                    &admin,
                    MembershipOperationV1::Remove {
                        member: admin.public()
                    },
                    1
                ))
                .is_err()
        );
    }

    #[test]
    fn supports_roost_scope_and_admin_transfer() {
        let admin = iroh::SecretKey::generate();
        let successor = iroh::SecretKey::generate();
        let scope = MembershipScopeId::Roost(RoostId([4; 32]));
        let mut state = MembershipState::genesis(scope, admin.public());
        state
            .apply(&mutation(
                &state,
                &admin,
                MembershipOperationV1::Add {
                    member: successor.public(),
                    role: MemberRole::Member,
                },
                0,
            ))
            .unwrap();
        state
            .apply(&mutation(
                &state,
                &admin,
                MembershipOperationV1::TransferAdmin {
                    to: successor.public(),
                },
                0,
            ))
            .unwrap();
        assert!(!state.is_admin(&admin.public()));
        assert!(state.is_admin(&successor.public()));
    }
}
