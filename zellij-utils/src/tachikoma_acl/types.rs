//! Request, response, and error types for the Tachikoma ACL verification API.
//!
//! These types model the JSON contract of the
//! `POST /api/auth/verify-acl-token` endpoint exposed by Tachikoma.
//! See `docs/zellij-acl/PLAN.md` section 8 for the canonical schema.

use serde::{Deserialize, Serialize};

/// Body of a `verify-acl-token` request.
///
/// We borrow the inner strings so that the caller does not have to pay an
/// allocation on every verification call — the request is serialised once
/// per HTTP invocation and never stored.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyRequest<'a> {
    pub token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_name: Option<&'a str>,
    pub action: &'a str,
    /// When `true`, suppress the admin bypass on the Tachikoma side and
    /// treat an admin user as a regular user. Used by `--admin-as-user`
    /// to exercise the ACL flow from a privileged account.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub force_non_admin: bool,
}

/// Parsed response from the Tachikoma ACL endpoint.
///
/// Note: a `valid == false` reply is **not** an error — it is a perfectly
/// well-formed answer from the server saying "this user may not do that".
/// We only return `Err` for transport / decode failures.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<f64>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Errors raised by [`TachikomaAclClient`][crate::tachikoma_acl::TachikomaAclClient].
#[derive(thiserror::Error, Debug)]
pub enum AclError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("server returned status {0}")]
    Server(u16),
    #[error("response decode: {0}")]
    Decode(String),
}
