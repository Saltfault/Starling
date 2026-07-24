use crate::crypto::FlockCrypto;
use crate::event::GossipPayload;
use data_encoding::HEXUPPER;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeType {
    Flock,
    Roost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedCode {
    pub code_type: CodeType,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlockCode {
    pub secret: [u8; 32],
    pub opener: EndpointId,
}

pub fn encode_typed_code(code_type: CodeType, payload: &[u8]) -> String {
    let tag = match code_type {
        CodeType::Flock => 0,
        CodeType::Roost => 1,
    };
    let mut bytes = Vec::with_capacity(payload.len() + 1);
    bytes.push(tag);
    bytes.extend_from_slice(payload);
    HEXUPPER.encode(&bytes)
}

pub fn decode_typed_code(code: &str) -> Option<TypedCode> {
    let normalized = code.trim().to_ascii_uppercase();
    if normalized.is_empty() || normalized.contains('-') {
        return None;
    }
    let bytes = HEXUPPER.decode(normalized.as_bytes()).ok()?;
    let (&tag, payload) = bytes.split_first()?;
    if payload.is_empty() {
        return None;
    }
    let code_type = match tag {
        0 => CodeType::Flock,
        1 => CodeType::Roost,
        _ => return None,
    };
    Some(TypedCode {
        code_type,
        payload: payload.to_vec(),
    })
}

pub fn encode_flock_code(secret: &[u8; 32], opener: &EndpointId) -> String {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(secret);
    payload.extend_from_slice(opener.as_bytes());
    encode_typed_code(CodeType::Flock, &payload)
}

pub fn decode_flock_code(code: &TypedCode) -> Option<FlockCode> {
    if code.code_type != CodeType::Flock || code.payload.len() != 64 {
        return None;
    }
    let secret = code.payload[..32].try_into().ok()?;
    let opener_bytes: [u8; 32] = code.payload[32..].try_into().ok()?;
    let opener = EndpointId::from_bytes(&opener_bytes).ok()?;
    Some(FlockCode { secret, opener })
}

pub fn encode_roost_code(node_id: &EndpointId) -> String {
    encode_typed_code(CodeType::Roost, node_id.as_bytes())
}

pub fn typed_code_node_id(code: &TypedCode) -> Option<EndpointId> {
    if code.code_type != CodeType::Roost {
        return None;
    }
    let bytes: [u8; 32] = code.payload.as_slice().try_into().ok()?;
    EndpointId::from_bytes(&bytes).ok()
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

#[cfg(test)]
mod tests {
    use super::{
        CodeType, decode_flock_code, decode_typed_code, encode_flock_code, encode_typed_code,
    };

    #[test]
    fn typed_codes_round_trip_without_separators() {
        for code_type in [CodeType::Flock, CodeType::Roost] {
            let encoded = encode_typed_code(code_type, &[1, 2, 3, 4, 5]);
            assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let decoded = decode_typed_code(&encoded).expect("valid typed code");
            assert_eq!(decoded.code_type, code_type);
            assert_eq!(decoded.payload, [1, 2, 3, 4, 5]);
        }
    }

    #[test]
    fn typed_codes_reject_unknown_tags_and_empty_payloads() {
        assert!(decode_typed_code("00").is_none());
        assert!(decode_typed_code("FF00").is_none());
    }

    #[test]
    fn flock_codes_carry_a_secret_and_opener() {
        let opener = iroh::SecretKey::generate().public();
        let secret = [42; 32];
        let encoded = encode_flock_code(&secret, &opener);
        let typed = decode_typed_code(&encoded).expect("typed flock code");
        let decoded = decode_flock_code(&typed).expect("flock payload");

        assert_eq!(decoded.secret, secret);
        assert_eq!(decoded.opener, opener);
    }
}
