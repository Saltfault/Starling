use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct RoostState {
    pub name: String,
    pub channels: Vec<String>,
}
