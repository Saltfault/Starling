use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};

use crate::protocol::{FlockId, RoostId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MemberRole {
    Member,
    Admin,
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
        from: EndpointId,
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
