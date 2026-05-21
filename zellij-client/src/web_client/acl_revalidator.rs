//! Background poller that re-validates every active ACL-backed session
//! against the Tachikoma API on a 10-second interval. Phase 4 of the
//! Zellij × Tachikoma ACL integration plan.
//!
//! Flow per tick :
//!   1. snapshot AclSessionStore (sha-256-hashed cookies → AclSessionInfo)
//!   2. for each entry that's not already revoked :
//!        - call TachikomaAclClient::verify_token(user_token, ctx, session, "still_attached")
//!        - on Ok(valid=true) → store.touch(hash)
//!        - on Ok(valid=false) → store.mark_revoked(hash, reason)
//!        - on Err(network) → check if grace expired ; if yes, mark_revoked
//!
//! mark_revoked() inside the store fires a DisconnectEvent that Phase 5's
//! WS handlers subscribe to.

use crate::web_client::acl_session_store::AclSessionStore;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use zellij_utils::tachikoma_acl::TachikomaAclClient;

pub struct AclRevalidator {
    client: Arc<TachikomaAclClient>,
    store: Arc<AclSessionStore>,
    poll_interval: Duration,
    grace: Duration,
}

impl AclRevalidator {
    pub fn new(
        client: Arc<TachikomaAclClient>,
        store: Arc<AclSessionStore>,
        poll_interval_secs: u64,
        grace_seconds: u64,
    ) -> Self {
        Self {
            client,
            store,
            poll_interval: Duration::from_secs(poll_interval_secs.max(1)),
            grace: Duration::from_secs(grace_seconds.max(1)),
        }
    }

    /// Spawn the revalidator on the current tokio runtime. Returns the
    /// JoinHandle so callers can abort on shutdown if needed.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(self) {
        // initial small delay so we don't probe immediately at startup
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut ticker = interval(self.poll_interval);
        // first tick fires immediately ; consume it so subsequent ticks
        // happen at the right cadence
        ticker.tick().await;
        loop {
            ticker.tick().await;
            self.poll_once().await;
        }
    }

    async fn poll_once(&self) {
        let snapshot = self.store.snapshot().await;
        for (hash, info) in snapshot {
            if info.revoked {
                continue;
            }
            match self
                .client
                .verify_token(
                    &info.user_token,
                    info.context_path.as_deref(),
                    info.session_name.as_deref(),
                    "still_attached",
                )
                .await
            {
                Ok(resp) if resp.valid => {
                    self.store.touch(&hash).await;
                },
                Ok(resp) => {
                    let reason = resp
                        .reason
                        .clone()
                        .unwrap_or_else(|| "acl_denied".to_string());
                    log::info!(
                        "[acl_revalidator] revoking session (hash={}…): {}",
                        &hash[..8.min(hash.len())],
                        reason,
                    );
                    self.store.mark_revoked(&hash, reason).await;
                },
                Err(e) => {
                    // Network / server error : check if we're past grace
                    if Instant::now().duration_since(info.last_verified_at) > self.grace {
                        log::warn!(
                            "[acl_revalidator] revoking session (hash={}…) — tachikoma unreachable for > {:?}: {}",
                            &hash[..8.min(hash.len())],
                            self.grace,
                            e,
                        );
                        self.store
                            .mark_revoked(&hash, format!("tachikoma_unreachable: {}", e))
                            .await;
                    } else {
                        log::debug!(
                            "[acl_revalidator] transient error for session (hash={}…), still in grace window: {}",
                            &hash[..8.min(hash.len())],
                            e,
                        );
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Unit tests would mock TachikomaAclClient ; deferred since the
    // module is structurally simple and live-tested in Phase 8.
    #[test]
    fn placeholder() {
        // ensures the module compiles in test mode
    }
}
