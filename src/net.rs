use crate::crypto::FlockCrypto;
use crate::event::GossipPayload;
use iroh::EndpointId;
use iroh_gossip::proto::TopicId;
use sha2::{Digest, Sha256};

pub fn topic_for(name: &str) -> TopicId {
    let hash = Sha256::digest(name.as_bytes());
    TopicId::from_bytes(hash.into())
}

pub fn encode_node_id(node_id: &EndpointId) -> String {
    let bytes = node_id.as_bytes();
    let mut padded = bytes.to_vec();
    while !padded.len().is_multiple_of(3) {
        padded.push(0);
    }
    let colors: Vec<String> = padded
        .chunks(3)
        .map(|c| format!("{:02X}{:02X}{:02X}", c[0], c[1], c[2]))
        .collect();
    format!("BIRD-{}", colors.join("-"))
}

pub fn room_code_from_node_id(node_id: &EndpointId) -> String {
    encode_node_id(node_id)
}

pub fn decode_node_id(code: &str) -> Option<EndpointId> {
    let code = code.strip_prefix("BIRD-")?;
    let groups: Vec<_> = code.split('-').collect();
    if groups.len() != 11 {
        return None;
    }
    let mut bytes = Vec::with_capacity(33);
    for group in groups {
        if group.len() != 6 {
            return None;
        }
        let r = u8::from_str_radix(&group[0..2], 16).ok()?;
        let g = u8::from_str_radix(&group[2..4], 16).ok()?;
        let b = u8::from_str_radix(&group[4..6], 16).ok()?;
        bytes.push(r);
        bytes.push(g);
        bytes.push(b);
    }
    if bytes.len() != 33 || bytes[32] != 0 {
        return None;
    }
    let arr: [u8; 32] = bytes[..32].try_into().ok()?;
    EndpointId::from_bytes(&arr).ok()
}

pub async fn broadcast_payload(
    sender: &iroh_gossip::api::GossipSender,
    crypto: &FlockCrypto,
    payload: &GossipPayload,
) -> anyhow::Result<()> {
    let plaintext = postcard::to_stdvec(payload)?;
    let ciphertext = crypto.try_encrypt(&plaintext)?;
    sender.broadcast(ciphertext.into()).await?;
    Ok(())
}
