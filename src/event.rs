use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub author: String,
    pub body: String,
    pub ts: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum GossipPayload {
    Chat(ChatMessage),
    Profile { id: EndpointId, name: String },
    Status { id: EndpointId, status: BirdStatus },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum BirdStatus {
    Online,
    Idle,
    InCall,
}
