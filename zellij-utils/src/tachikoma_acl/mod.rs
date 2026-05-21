//! Tachikoma ACL verification client.
//!
//! This module provides [`TachikomaAclClient`], an async HTTP client for the
//! `POST /api/auth/verify-acl-token` endpoint exposed by Tachikoma. It is
//! used by the zellij web server to enforce Tachikoma-issued user tokens on
//! every login (and, in later phases, on a background revalidation timer).
//!
//! See `docs/zellij-acl/PLAN.md` (Phase 2) for the design rationale.
//!
//! ## Example
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use zellij_utils::tachikoma_acl::TachikomaAclClient;
//!
//! let client = TachikomaAclClient::new(
//!     "http://127.0.0.1:8000".to_string(),
//!     Some("dev-secret".to_string()),
//! );
//! let resp = client
//!     .verify_token("ut_abc...", Some("monorepo"), Some("dev"), "attach")
//!     .await?;
//! if resp.valid {
//!     // proceed with login
//! }
//! # Ok(()) }
//! ```

pub mod cache;
pub mod client;
pub mod types;

pub use client::TachikomaAclClient;
pub use types::{AclError, VerifyRequest, VerifyResponse};

#[cfg(test)]
mod tests;
