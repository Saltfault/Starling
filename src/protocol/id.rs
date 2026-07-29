use rand::random;
use serde::{Deserialize, Serialize};

macro_rules! random_id {
    ($name:ident, $len:literal) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub fn random() -> Self {
                Self(random())
            }

            pub fn new() -> Self {
                Self::random()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::random()
            }
        }
    };
}

random_id!(FlockId, 32);
random_id!(RoostId, 32);
random_id!(ChannelId, 16);
random_id!(CallId, 16);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum SpaceId {
    Flock(FlockId),
    RoostChannel { roost: RoostId, channel: ChannelId },
}

#[cfg(test)]
mod tests {
    use super::{CallId, ChannelId, FlockId, RoostId};

    #[test]
    fn random_ids_are_independent() {
        assert_ne!(FlockId::random(), FlockId::random());
        assert_ne!(RoostId::random(), RoostId::random());
        assert_ne!(ChannelId::random(), ChannelId::random());
        assert_ne!(CallId::random(), CallId::random());

        let flock = FlockId::random();
        let roost = RoostId::random();
        assert_ne!(flock.0, roost.0);
        assert!(flock.0.iter().any(|byte| *byte != 0));
    }
}
