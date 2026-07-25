use crate::event::ChatMessage;
use iroh::endpoint::Connection;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

pub const SYNC_ALPN: &[u8] = b"starling/sync/0";
const MAX_MESSAGES: usize = 500;
const MAX_REQUEST_BYTES: usize = 16;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

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
        let (mut send, mut recv) = timeout(IO_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for a sync request"))??;
        let req = timeout(IO_TIMEOUT, recv.read_to_end(MAX_REQUEST_BYTES))
            .await
            .map_err(|_| anyhow::anyhow!("timed out reading the sync request"))??;
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

        timeout(IO_TIMEOUT, send.write_all(&response))
            .await
            .map_err(|_| anyhow::anyhow!("timed out writing the sync response"))??;
        send.finish()?;
        Ok(())
    }
}
