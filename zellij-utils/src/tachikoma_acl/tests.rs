//! Integration-style tests for [`TachikomaAclClient`] backed by a
//! `wiremock` server.
//!
//! These tests are `#[cfg(test)]`-only and pull `wiremock` as a dev
//! dependency. They exercise:
//!
//!   - successful 2xx → response is parsed
//!   - cache hit within TTL → no second HTTP call
//!   - cache miss after TTL expiry → new HTTP call issued
//!   - non-2xx → `AclError::Server`
//!   - transport failure (server returns malformed JSON) → `AclError::Decode`
//!   - cache `key()` is deterministic and discriminates on all four fields
//!
//! Each test stands up its own ephemeral `wiremock::MockServer` so they can
//! run in parallel without state bleed.

use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::cache::TtlLru;
use super::client::TachikomaAclClient;
use super::types::AclError;

const VERIFY_PATH: &str = "/api/auth/verify-acl-token";

fn ok_body() -> serde_json::Value {
    json!({
        "valid": true,
        "user_id": "ubuntu",
        "expires_at": 1_700_000_000.0,
        "permissions": ["read", "write"],
        "read_only": false,
        "reason": null,
    })
}

#[tokio::test]
async fn valid_response_is_parsed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(VERIFY_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(1)
        .mount(&server)
        .await;

    let client = TachikomaAclClient::new(server.uri(), None);
    let resp = client
        .verify_token("token-xyz", Some("monorepo"), Some("dev"), "attach")
        .await
        .expect("verify_token should succeed");

    assert!(resp.valid);
    assert_eq!(resp.user_id.as_deref(), Some("ubuntu"));
    assert_eq!(resp.permissions, vec!["read", "write"]);
    assert!(!resp.read_only);
    assert!(resp.reason.is_none());
}

#[tokio::test]
async fn cache_hit_avoids_second_http_call() {
    let server = MockServer::start().await;
    // `.expect(1)` is the assertion: if a second HTTP call leaks through,
    // wiremock fails the test on drop.
    Mock::given(method("POST"))
        .and(path(VERIFY_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(1)
        .mount(&server)
        .await;

    let client = TachikomaAclClient::new(server.uri(), None);

    let r1 = client
        .verify_token("tok", Some("ctx"), Some("sess"), "attach")
        .await
        .unwrap();
    let r2 = client
        .verify_token("tok", Some("ctx"), Some("sess"), "attach")
        .await
        .unwrap();

    assert!(r1.valid && r2.valid);
    assert_eq!(r1.user_id, r2.user_id);
}

#[tokio::test]
async fn cache_miss_after_ttl_issues_new_call() {
    // We can't easily fast-forward `Instant`, so we test the underlying cache
    // primitive directly with a tiny TTL. The HTTP layer is exercised by the
    // other tests; here we want to prove the eviction logic.
    let cache = TtlLru::with_params(8, Duration::from_millis(30));
    let key = TtlLru::key("t", Some("c"), Some("s"), "attach");
    let resp = super::types::VerifyResponse {
        valid: true,
        user_id: Some("u".into()),
        expires_at: None,
        permissions: vec![],
        read_only: false,
        reason: None,
    };
    cache.insert(key, resp.clone());
    assert!(cache.get(key).is_some(), "fresh entry must hit");

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        cache.get(key).is_none(),
        "entry must be evicted after TTL expiry"
    );
    assert_eq!(cache.len(), 0, "expired entry must be removed from map");
}

#[tokio::test]
async fn unauthorized_returns_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(VERIFY_PATH))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let client = TachikomaAclClient::new(server.uri(), None);
    let err = client
        .verify_token("bad-token", None, None, "attach")
        .await
        .expect_err("401 should be reported as AclError::Server");
    match err {
        AclError::Server(401) => {}
        other => panic!("expected Server(401), got {other:?}"),
    }
}

#[tokio::test]
async fn network_error_returns_network_variant() {
    // Bind to a port and immediately drop the listener so the client gets a
    // connection refused.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let client = TachikomaAclClient::new(format!("http://127.0.0.1:{port}"), None);
    let err = client
        .verify_token("tok", None, None, "attach")
        .await
        .expect_err("connection-refused must surface as Network error");
    assert!(
        matches!(err, AclError::Network(_)),
        "expected Network variant, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_json_returns_decode_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(VERIFY_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("not json", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = TachikomaAclClient::new(server.uri(), None);
    let err = client
        .verify_token("tok", None, None, "attach")
        .await
        .expect_err("garbage body must surface as Decode error");
    assert!(
        matches!(err, AclError::Decode(_)),
        "expected Decode variant, got {err:?}"
    );
}

#[tokio::test]
async fn bridge_auth_header_is_sent_when_configured() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(VERIFY_PATH))
        .and(header("X-Tsp-Bridge-Auth", "super-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(1)
        .mount(&server)
        .await;

    let client =
        TachikomaAclClient::new(server.uri(), Some("super-secret".to_string()));
    let resp = client
        .verify_token("tok", None, None, "attach")
        .await
        .expect("authorised call should succeed");
    assert!(resp.valid);
}

#[test]
fn cache_key_discriminates_on_each_field() {
    let base = TtlLru::key("t", Some("c"), Some("s"), "attach");
    assert_ne!(base, TtlLru::key("t2", Some("c"), Some("s"), "attach"));
    assert_ne!(base, TtlLru::key("t", Some("c2"), Some("s"), "attach"));
    assert_ne!(base, TtlLru::key("t", Some("c"), Some("s2"), "attach"));
    assert_ne!(base, TtlLru::key("t", Some("c"), Some("s"), "write"));
    // Same arguments must hash the same way (deterministic).
    assert_eq!(base, TtlLru::key("t", Some("c"), Some("s"), "attach"));
}
