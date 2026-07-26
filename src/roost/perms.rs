//! Bitmask permissions, roles, and enforcement.
//!
//! The model mirrors Discord's proven shape: permissions are a bitmask, roles
//! bundle permissions, and a member's effective permissions are the OR of every
//! role they hold. The owner is always an admin.
//!
//! The iron rule of the roost: it enforces, the client only decorates. Hiding a
//! key in the TUI is courtesy; a modified client can send anything, so every
//! privileged action is re-checked by the roost before it is applied. The
//! sender's identity comes from the iroh transport itself (authenticated during
//! the TLS handshake), so it cannot be spoofed by a modified client.

use bitflags::bitflags;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

bitflags! {
    /// One bit per privileged action. Stored as a `u64` so the whole set travels
    /// cheaply inside [`crate::roost::RoostState`].
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Perm: u64 {
        const VIEW_CHANNEL = 1 << 0;
        const SEND_MESSAGE = 1 << 1;
        const MANAGE_MSGS  = 1 << 2;
        const KICK         = 1 << 3;
        const BAN          = 1 << 4;
        const MANAGE_CHANS = 1 << 5;
        const MANAGE_ROLES = 1 << 6;
        const ADMIN        = 1 << 7;
        const INVITE       = 1 << 8;
    }
}

/// A named bundle of permissions. `position` establishes a ranking so the roost
/// can decide who may act on whom: a bird can only moderate birds whose highest
/// role sits below its own.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub color: (u8, u8, u8),
    pub perms: Perm,
    /// Higher outranks lower.
    pub position: u16,
}

/// Membership + moderation state. Owned by the roost; a redacted copy travels
/// inside [`crate::roost::RoostState`] so clients can color names and gate
/// menus. The enforcement verdicts are always computed roost-side.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct PermState {
    pub roles: Vec<Role>,
    /// member → indices into `roles`.
    pub members: HashMap<EndpointId, Vec<usize>>,
    pub owner: Option<EndpointId>,
    pub bans: HashSet<EndpointId>,
    /// Birds approved by an invite but not yet admitted on first join.
    pub invited: HashSet<EndpointId>,
    /// Monotonically increasing epoch bumped on ban so that a banned bird's
    /// cached channel secrets stop working after the server mints new secrets
    /// and re-provisions remaining members.
    pub key_epoch: u64,
}

impl PermState {
    /// Effective permissions: OR of all held roles. The owner is always admin.
    /// Everyone gets a baseline of `VIEW_CHANNEL | SEND_MESSAGE` so a member
    /// with no roles can still read and talk.
    pub fn effective(&self, who: &EndpointId) -> Perm {
        if self.owner.as_ref() == Some(who) {
            return Perm::all();
        }
        self.members
            .get(who)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.roles.get(i))
            .fold(Perm::VIEW_CHANNEL | Perm::SEND_MESSAGE, |acc, r| {
                acc | r.perms
            })
    }

    /// Highest role position, for who-can-act-on-whom. The owner outranks all.
    pub fn rank(&self, who: &EndpointId) -> u16 {
        if self.owner.as_ref() == Some(who) {
            return u16::MAX;
        }
        self.members
            .get(who)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.roles.get(i))
            .map(|r| r.position)
            .max()
            .unwrap_or(0)
    }

    /// True when `a` outranks `b`. Used to gate moderation actions.
    pub fn outranks(&self, a: &EndpointId, b: &EndpointId) -> bool {
        self.rank(a) > self.rank(b)
    }

    /// Whether `who` is the owner or holds any role entry.
    pub fn is_member(&self, who: &EndpointId) -> bool {
        self.owner.as_ref() == Some(who) || self.members.contains_key(who)
    }

    /// Whether `who` is a member in good standing (not banned).
    /// Banned ex-members are still in `members`, so `is_member()` alone
    /// would let them pull history or send moderation requests.
    pub fn is_active_member(&self, who: &EndpointId) -> bool {
        self.is_member(who) && !self.bans.contains(who)
    }

    /// The enforcement pattern — every privileged action looks like this.
    /// Checks that `from` holds `BAN` and outranks `target`, then records the
    /// ban, removes the target from members, and bumps `key_epoch` so the
    /// caller can mint new channel secrets and re-provision remaining members.
    /// Until the caller wires that re-provisioning, a banned bird may still
    /// read traffic with cached keys.
    pub fn handle_ban(&mut self, from: &EndpointId, target: &EndpointId) -> anyhow::Result<()> {
        anyhow::ensure!(self.effective(from).contains(Perm::BAN), "not allowed");
        anyhow::ensure!(self.outranks(from, target), "can't ban equal/higher rank");
        self.bans.insert(*target);
        self.members.remove(target);
        self.key_epoch += 1;
        Ok(())
    }

    /// Delete a message from a channel. Requires the `MANAGE_MSGS` permission.
    /// Guards `ModRequest::DeleteMessage`.
    pub fn handle_delete_message(&self, from: &EndpointId) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.effective(from).contains(Perm::MANAGE_MSGS),
            "not allowed"
        );
        Ok(())
    }

    /// Remove a bird from the roost. Requires the `KICK` permission and that the
    /// actor outranks the target. The kicked bird is dropped from `members` and
    /// `invited`, so — the roost being invite-only — they cannot return without a
    /// fresh invitation. Unlike a ban, a kick does not block a future invite.
    pub fn handle_kick(&mut self, from: &EndpointId, target: &EndpointId) -> anyhow::Result<()> {
        anyhow::ensure!(self.effective(from).contains(Perm::KICK), "not allowed");
        anyhow::ensure!(self.outranks(from, target), "can't kick equal/higher rank");
        self.members.remove(target);
        self.invited.remove(target);
        Ok(())
    }

    /// Grant membership to a bird. Requires the `INVITE` permission and refuses
    /// to invite a bird that is already banned.
    pub fn handle_invite(&mut self, from: &EndpointId, target: EndpointId) -> anyhow::Result<()> {
        anyhow::ensure!(self.effective(from).contains(Perm::INVITE), "not allowed");
        anyhow::ensure!(!self.bans.contains(&target), "that bird is banned");
        self.invited.insert(target);
        Ok(())
    }

    /// The door check. Invited birds become members on first join; existing
    /// members are admitted unchanged; banned birds are refused.
    pub fn handle_join(&mut self, who: &EndpointId) -> anyhow::Result<()> {
        anyhow::ensure!(!self.bans.contains(who), "banned");
        if self.is_member(who) {
            return Ok(());
        }
        anyhow::ensure!(self.invited.remove(who), "not invited");
        self.members.insert(*who, vec![]); // member, no roles yet
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    fn mod_role() -> Role {
        Role {
            name: "mod".into(),
            color: (0, 200, 0),
            perms: Perm::KICK | Perm::BAN | Perm::MANAGE_MSGS,
            position: 10,
        }
    }

    #[test]
    fn owner_is_always_admin() {
        let owner = id(1);
        let state = PermState {
            owner: Some(owner),
            ..Default::default()
        };
        assert_eq!(state.effective(&owner), Perm::all());
        assert_eq!(state.rank(&owner), u16::MAX);
    }

    #[test]
    fn member_with_no_roles_gets_baseline() {
        let member = id(2);
        let state = PermState {
            members: [(member, vec![])].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            state.effective(&member),
            Perm::VIEW_CHANNEL | Perm::SEND_MESSAGE
        );
    }

    #[test]
    fn effective_perms_or_held_roles() {
        let role = mod_role();
        let member = id(3);
        let state = PermState {
            roles: vec![role],
            members: [(member, vec![0])].into_iter().collect(),
            ..Default::default()
        };
        let perms = state.effective(&member);
        assert!(perms.contains(Perm::BAN));
        assert!(perms.contains(Perm::KICK));
        assert!(perms.contains(Perm::VIEW_CHANNEL));
        assert!(perms.contains(Perm::SEND_MESSAGE));
        assert!(!perms.contains(Perm::ADMIN));
    }

    #[test]
    fn handle_ban_requires_perm_and_rank() {
        let role = mod_role();
        let mod_ = id(4);
        let peer = id(5);
        let equal_mod = id(6);
        let mut state = PermState {
            roles: vec![role],
            members: [(mod_, vec![0]), (peer, vec![]), (equal_mod, vec![0])]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        // mod can ban a lower-ranked peer.
        assert!(state.handle_ban(&mod_, &peer).is_ok());
        assert!(state.bans.contains(&peer));
        assert!(
            !state.members.contains_key(&peer),
            "banned member must be removed from members"
        );
        assert_eq!(state.key_epoch, 1, "key_epoch must be bumped on ban");

        // mod cannot ban an equal-ranked mod.
        assert!(state.handle_ban(&mod_, &equal_mod).is_err());

        // peer has no BAN perm and cannot ban anyone.
        assert!(state.handle_ban(&peer, &mod_).is_err());
    }

    #[test]
    fn handle_invite_requires_invite_perm_and_refuses_banned() {
        let inviter = id(7);
        let role = Role {
            name: "inviter".into(),
            color: (0, 0, 200),
            perms: Perm::INVITE,
            position: 5,
        };
        let target = id(8);
        let banned = id(9);
        let mut state = PermState {
            roles: vec![role],
            members: [(inviter, vec![0])].into_iter().collect(),
            bans: [banned].into_iter().collect(),
            ..Default::default()
        };

        assert!(state.handle_invite(&inviter, target).is_ok());
        assert!(state.invited.contains(&target));

        // banned birds cannot be invited.
        assert!(state.handle_invite(&inviter, banned).is_err());

        // a bird without INVITE cannot invite.
        let nobody = id(10);
        state.members.insert(nobody, vec![]);
        assert!(state.handle_invite(&nobody, target).is_err());
    }

    #[test]
    fn handle_join_admits_invited_and_refuses_others() {
        let owner = id(11);
        let invited_bird = id(12);
        let stranger = id(13);
        let banned = id(14);
        let mut state = PermState {
            owner: Some(owner),
            invited: [invited_bird].into_iter().collect(),
            bans: [banned].into_iter().collect(),
            ..Default::default()
        };

        // owner is already a member.
        assert!(state.handle_join(&owner).is_ok());

        // invited bird becomes a member on first join.
        assert!(state.handle_join(&invited_bird).is_ok());
        assert!(state.is_member(&invited_bird));
        assert!(!state.invited.contains(&invited_bird));

        // a stranger with no invitation is refused.
        assert!(state.handle_join(&stranger).is_err());
        assert!(!state.is_member(&stranger));

        // a banned bird is refused even if somehow invited.
        state.invited.insert(banned);
        assert!(state.handle_join(&banned).is_err());
    }

    #[test]
    fn handle_kick_requires_kick_perm_and_rank_and_unmembers_target() {
        let role = Role {
            name: "mod".into(),
            color: (0, 200, 0),
            perms: Perm::KICK | Perm::BAN,
            position: 10,
        };
        let mod_ = id(20);
        let peer = id(21);
        let invited_back = id(22);
        let mut state = PermState {
            roles: vec![role],
            members: [(mod_, vec![0]), (peer, vec![])].into_iter().collect(),
            invited: [invited_back].into_iter().collect(),
            ..Default::default()
        };

        assert!(state.handle_kick(&mod_, &peer).is_ok());
        assert!(!state.is_member(&peer));
        // kicking someone who was also invited clears the pending invite.
        state.invited.insert(peer);
        assert!(state.handle_kick(&mod_, &peer).is_ok());
        assert!(!state.invited.contains(&peer));
        // a banned bird is not a member and kick reports not-allowed-shaped failure
        // only via perm/rank; an equal-rank mod cannot be kicked.
        assert!(state.handle_kick(&mod_, &mod_).is_err());
    }

    #[test]
    fn is_member_covers_owner_and_role_holders() {
        let owner = id(15);
        let member = id(16);
        let stranger = id(17);
        let state = PermState {
            owner: Some(owner),
            members: [(member, vec![])].into_iter().collect(),
            ..Default::default()
        };
        assert!(state.is_member(&owner));
        assert!(state.is_member(&member));
        assert!(!state.is_member(&stranger));
    }
}
