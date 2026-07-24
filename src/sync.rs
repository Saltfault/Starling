use crate::event::ChatMessage;
use iroh::endpoint::Connection;
use std::sync::{Arc, Mutex};

pub const SYNC_ALPN: &[u8] = b"starling/sync/0";
const MAX_MESSAGES: usize = 500;
const MAX_REQUEST_BYTES: usize = 16;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub type History = Arc<Mutex<Vec<ChatMessage>>>;

#[derive(Debug, Clone)]
pub struct SyncProto {
    pub history: History,
}

impl iroh::protocol::ProtocolHandler for SyncProto {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        self.serve(conn).await.map_err(|error| {
            iroh::protocol::AcceptError::from_err(std::io::Error::other(error.to_string()))
        })
    }
}

impl SyncProto {
    async fn serve(&self, conn: Connection) -> anyhow::Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let req = recv.read_to_end(MAX_REQUEST_BYTES).await?;
        let since: i64 = postcard::from_bytes(&req)?;

        let mut recent: Vec<ChatMessage> = {
            let h = self
                .history
                .lock()
                .map_err(|_| anyhow::anyhow!("history lock is poisoned"))?;
            let filtered: Vec<_> = h.iter().filter(|m| m.ts > since).cloned().collect();
            let start = filtered.len().saturating_sub(MAX_MESSAGES);
            filtered[start..].to_vec()
        };

        let response = loop {
            let encoded = postcard::to_stdvec(&recent)?;
            if encoded.len() <= MAX_RESPONSE_BYTES {
                break encoded;
            }
            if recent.is_empty() {
                anyhow::bail!("sync response exceeds the byte limit");
            }
            recent.remove(0);
        };

        send.write_all(&response).await?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}
