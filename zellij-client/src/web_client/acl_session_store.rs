//! Tracks active sessions that were authenticated with a Tachikoma user_token.
//!
//! Phase 4's `AclRevalidator` polls this store and revokes entries when the
//! Tachikoma API returns `valid=false` (or has been unreachable past the
//! configured grace window). Phase 5's WebSocket handlers subscribe to
//! [`DisconnectEvent`] broadcasts so that they can close in-flight WS
//! connections promptly when a token is revoked.
//!
//! Keys in this store are the SHA-256 hex of the zellij session cookie
//! (the value the client sends in the `session_token` cookie), so the raw
//! cookie value is never persisted in memory beyond the request scope.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, RwLock};

/// Per-session metadata captured at login time and refreshed by the
/// revalidator. Cloned on read; cheap because every field is small or
/// short-lived.
#[derive(Clone, Debug)]
pub struct AclSessionInfo {
    pub user_token: String,
    pub context_path: Option<String>,
    pub session_name: Option<String>,
    pub user_id: Option<String>,
    pub last_verified_at: Instant,
    pub revoked: bool,
    pub revoke_reason: Option<String>,
}

/// Broadcast payload emitted when [`AclSessionStore::mark_revoked`] is called.
/// WebSocket handlers (Phase 5) subscribe via
/// [`AclSessionStore::subscribe_disconnect`] and close the matching
/// connections.
#[derive(Clone, Debug)]
pub struct DisconnectEvent {
    /// SHA-256 hex of the zellij session cookie that should be disconnected.
    pub session_token_hash: String,
    /// Human-readable reason — propagated to the WS close frame for debugging.
    pub reason: String,
}

/// Thread-safe map of session-cookie-hash to ACL metadata, plus a
/// disconnect broadcast channel.
///
/// Cloneable via `Arc<Self>`; construct via [`AclSessionStore::new`] which
/// hands back an `Arc` directly to discourage accidental copies of the
/// underlying `RwLock`.
pub struct AclSessionStore {
    map: RwLock<HashMap<String, AclSessionInfo>>,
    disconnect_tx: broadcast::Sender<DisconnectEvent>,
}

impl AclSessionStore {
    /// Build an empty store wrapped in an [`Arc`]. The broadcast channel has
    /// capacity 256 — enough that several Phase 4 revalidator ticks can
    /// fan-out simultaneously without lagging subscribers.
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(256);
        Arc::new(Self {
            map: RwLock::new(HashMap::new()),
            disconnect_tx: tx,
        })
    }

    /// Insert (or replace) the metadata for `session_token_hash`.
    pub async fn register(&self, session_token_hash: String, info: AclSessionInfo) {
        let mut m = self.map.write().await;
        m.insert(session_token_hash, info);
    }

    /// Remove an entry — used on explicit logout / cookie clear.
    #[allow(dead_code)]
    pub async fn remove(&self, session_token_hash: &str) {
        let mut m = self.map.write().await;
        m.remove(session_token_hash);
    }

    /// Update `last_verified_at` to now, used by the Phase 4 revalidator on
    /// successful verification ticks.
    #[allow(dead_code)]
    pub async fn touch(&self, session_token_hash: &str) {
        let mut m = self.map.write().await;
        if let Some(info) = m.get_mut(session_token_hash) {
            info.last_verified_at = Instant::now();
        }
    }

    /// Mark a session as revoked and broadcast a [`DisconnectEvent`]. The
    /// session entry is intentionally NOT removed — auth_middleware uses the
    /// `revoked` bit to return 403 on subsequent HTTP requests until the
    /// cookie is cleared.
    #[allow(dead_code)]
    pub async fn mark_revoked(&self, session_token_hash: &str, reason: String) {
        let mut m = self.map.write().await;
        if let Some(info) = m.get_mut(session_token_hash) {
            info.revoked = true;
            info.revoke_reason = Some(reason.clone());
        }
        // Drop the lock before sending so subscribers can re-enter the store
        // if they choose to.
        drop(m);
        let _ = self.disconnect_tx.send(DisconnectEvent {
            session_token_hash: session_token_hash.to_string(),
            reason,
        });
    }

    /// True if the entry exists and has `revoked == true`. A missing entry
    /// returns `false` — that case is "not tracked by ACL", not "revoked".
    pub async fn is_revoked(&self, session_token_hash: &str) -> bool {
        let m = self.map.read().await;
        m.get(session_token_hash)
            .map(|i| i.revoked)
            .unwrap_or(false)
    }

    /// Cheap clone of every entry. Used by the Phase 4 revalidator to walk
    /// all active sessions without holding the write lock for the duration
    /// of HTTP I/O.
    #[allow(dead_code)]
    pub async fn snapshot(&self) -> Vec<(String, AclSessionInfo)> {
        let m = self.map.read().await;
        m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Subscribe to revoke broadcasts. Each WS handler obtains one receiver.
    #[allow(dead_code)]
    pub fn subscribe_disconnect(&self) -> broadcast::Receiver<DisconnectEvent> {
        self.disconnect_tx.subscribe()
    }
}
