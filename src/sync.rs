use crate::event::ChatMessage;
use iroh::endpoint::Connection;
use std::sync::{Arc, Mutex};

pub const SYNC_ALPN: &[u8] = b"starling/sync/0";
const MAX_MESSAGES: usize = 500;

pub type History = Arc<Mutex<Vec<ChatMessage>>>;

#[derive(Debug, Clone)]
pub struct SyncProto {
    pub history: History,
}

impl iroh::protocol::ProtocolHandler for SyncProto {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let _ = self.serve(conn).await;
        Ok(())
    }
}

impl SyncProto {
    async fn serve(&self, conn: Connection) -> anyhow::Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let req = recv.read_to_end(64).await?;
        let since: i64 = postcard::from_bytes(&req)?;

        let recent: Vec<ChatMessage> = {
            let h = self.history.lock().unwrap();
            let mut filtered: Vec<_> = h.iter().filter(|m| m.ts > since).cloned().collect();
            if filtered.len() > MAX_MESSAGES {
                filtered = filtered.split_off(filtered.len() - MAX_MESSAGES);
            }
            filtered
        };

        send.write_all(&postcard::to_stdvec(&recent)?).await?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}
