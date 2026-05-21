//! Async HTTP client for the Tachikoma ACL verification endpoint.
//!
//! The client wraps `POST {base_url}/api/auth/verify-acl-token` with a small
//! TTL+LRU cache (3 s, 1024 entries) so that polling at ~0.1 Hz per active
//! session does not hammer Tachikoma.
//!
//! Wire integration into the zellij web client happens in **Phase 3** of the
//! ACL plan; this module exists in isolation so it can be tested in
//! isolation and shipped as a low-risk first step.

use std::sync::Arc;
use std::time::Duration;

use super::cache::TtlLru;
use super::types::{AclError, VerifyRequest, VerifyResponse};

/// HTTP timeout for a single verification call. Kept short — Tachikoma is on
/// the same box (or one hop away) and a slow ACL check stalls login.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Path of the verification endpoint, relative to `base_url`.
const VERIFY_PATH: &str = "/api/auth/verify-acl-token";

/// Header name used by the Tachikoma TSP bridge to authenticate non-local
/// callers. Kept in sync with `tachikoma/monorepo/api/routers/auth.py`.
const BRIDGE_AUTH_HEADER: &str = "X-Tsp-Bridge-Auth";

/// Async client wrapping `POST /api/auth/verify-acl-token`.
///
/// Cheap to clone — the underlying `reqwest::Client` and cache are wrapped
/// in `Arc`s internally so cloning shares state.
#[derive(Clone)]
pub struct TachikomaAclClient {
    base_url: String,
    bridge_auth: Option<String>,
    http: reqwest::Client,
    cache: Arc<TtlLru>,
}

impl TachikomaAclClient {
    /// Build a new client.
    ///
    /// `base_url` should not contain a trailing slash, e.g.
    /// `http://127.0.0.1:8000`. If it does, we strip it.
    pub fn new(base_url: String, bridge_auth: Option<String>) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url,
            bridge_auth,
            http,
            cache: Arc::new(TtlLru::new()),
        }
    }

    /// Verify a user token against Tachikoma.
    ///
    /// Returns `Ok(VerifyResponse)` on a successful 2xx HTTP exchange,
    /// regardless of whether `valid` is true or false. Returns `Err` only on
    /// transport failure or a non-2xx status.
    ///
    /// Results are cached for [`TTL`](super::cache::TTL) — repeated calls
    /// with identical arguments within the TTL window do not produce a new
    /// HTTP request.
    pub async fn verify_token(
        &self,
        token: &str,
        context_path: Option<&str>,
        session_name: Option<&str>,
        action: &str,
    ) -> Result<VerifyResponse, AclError> {
        self.verify_with_cache(token, context_path, session_name, action)
            .await
    }

    async fn verify_with_cache(
        &self,
        token: &str,
        context_path: Option<&str>,
        session_name: Option<&str>,
        action: &str,
    ) -> Result<VerifyResponse, AclError> {
        let key = TtlLru::key(token, context_path, session_name, action);
        if let Some(cached) = self.cache.get(key) {
            return Ok(cached);
        }
        let resp = self
            .verify_http(token, context_path, session_name, action)
            .await?;
        self.cache.insert(key, resp.clone());
        Ok(resp)
    }

    /// Force a network call without consulting (or populating) the cache.
    /// Exposed for callers that need an authoritative answer — e.g. the
    /// background revalidator added in Phase 4.
    #[allow(dead_code)]
    pub async fn verify_token_uncached(
        &self,
        token: &str,
        context_path: Option<&str>,
        session_name: Option<&str>,
        action: &str,
    ) -> Result<VerifyResponse, AclError> {
        self.verify_http(token, context_path, session_name, action)
            .await
    }

    async fn verify_http(
        &self,
        token: &str,
        context_path: Option<&str>,
        session_name: Option<&str>,
        action: &str,
    ) -> Result<VerifyResponse, AclError> {
        let url = format!("{}{}", self.base_url, VERIFY_PATH);
        let body = VerifyRequest {
            token,
            context_path,
            session_name,
            action,
        };
        let mut req = self.http.post(&url).json(&body);
        if let Some(secret) = self.bridge_auth.as_deref() {
            req = req.header(BRIDGE_AUTH_HEADER, secret);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(AclError::Server(status.as_u16()));
        }
        resp.json::<VerifyResponse>()
            .await
            .map_err(|e| AclError::Decode(e.to_string()))
    }

    /// Drop every cached entry. Useful when a revoke event is observed.
    #[allow(dead_code)]
    pub fn invalidate_cache(&self) {
        self.cache.clear();
    }
}
