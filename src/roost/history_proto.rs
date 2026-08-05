//! Bounded, authorized history protocol handler.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::history::{
    FRAME_HISTORY_REQUEST_V1, FRAME_HISTORY_RESPONSE_V1, HistoryRequest, MAX_HISTORY_HASHES,
    MAX_HISTORY_PAGE_BYTES, SignedHistoryRequest, TrustedStore, reconciliation_page,
};
use crate::membership::MembershipState;
use crate::protocol::{MAX_BODY_BYTES, read_frame, write_frame};
use anyhow::{Context, ensure};

use super::history_store::HistoryStore;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_PAYLOAD_LIMIT: usize = MAX_BODY_BYTES - 4096;

type AuthorizeRemote =
    dyn Fn(iroh::EndpointId, &HistoryRequest, &MembershipState) -> bool + Send + Sync;
type ChallengeCache = Arc<Mutex<lru::LruCache<(iroh::EndpointId, [u8; 32]), ()>>>;

#[derive(Clone)]
pub struct HistoryProto {
    store: Arc<HistoryStore>,
    authorize_remote: Arc<AuthorizeRemote>,
    seen_challenges: ChallengeCache,
}

impl std::fmt::Debug for HistoryProto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HistoryProto")
            .finish_non_exhaustive()
    }
}

impl HistoryProto {
    pub fn new(
        store: Arc<HistoryStore>,
        authorize_remote: impl Fn(iroh::EndpointId, &HistoryRequest, &MembershipState) -> bool
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            store,
            authorize_remote: Arc::new(authorize_remote),
            seen_challenges: Arc::new(Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(MAX_HISTORY_HASHES).unwrap(),
            ))),
        }
    }

    async fn handle(&self, conn: &iroh::endpoint::Connection) -> anyhow::Result<()> {
        let remote = conn.remote_id();
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, conn.accept_bi())
            .await
            .context("history stream accept timed out")??;
        let (header, body) = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut recv))
            .await
            .context("history request timed out")??;
        ensure!(
            header.kind == FRAME_HISTORY_REQUEST_V1,
            "unexpected history frame kind"
        );
        let signed: SignedHistoryRequest =
            postcard::from_bytes(&body).context("invalid history request")?;
        ensure!(
            postcard::to_stdvec(&signed)? == body,
            "history request is not canonical"
        );
        signed.verify(&remote)?;
        let mut request = signed.request;
        {
            let mut seen = self
                .seen_challenges
                .lock()
                .map_err(|_| anyhow::anyhow!("history challenge lock poisoned"))?;
            ensure!(
                seen.put((remote, request.challenge), ()).is_none(),
                "history challenge was replayed"
            );
        }

        // Clone membership before any await. Missing state and failed remote
        // authorization both deny access without revealing whether data exists.
        let membership = self.store.membership(&request.space)?;
        ensure!(
            (self.authorize_remote)(remote, &request, &membership),
            "history request denied"
        );

        request.max_bytes = request
            .max_bytes
            .min(RESPONSE_PAYLOAD_LIMIT as u32)
            .min(MAX_HISTORY_PAGE_BYTES as u32);
        let response = reconciliation_page(self.store.as_ref(), &request)?.encode()?;
        ensure!(
            response.len() <= MAX_BODY_BYTES,
            "encoded history response exceeds frame limit"
        );
        tokio::time::timeout(
            IO_TIMEOUT,
            write_frame(&mut send, FRAME_HISTORY_RESPONSE_V1, &response),
        )
        .await
        .context("history response timed out")??;
        send.finish()?;
        Ok(())
    }
}

impl iroh::protocol::ProtocolHandler for HistoryProto {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        if let Err(error) = self.handle(&conn).await {
            crate::logger::warn(&format!("history-v1: request rejected: {error}"));
        }
        Ok(())
    }
}
