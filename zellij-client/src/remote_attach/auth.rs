use super::config::{LOGIN_ENDPOINT, SESSION_ENDPOINT};
use super::http_client::HttpClientWithCookies;
use crate::RemoteClientError;
use isahc::{AsyncReadResponseExt, Request};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct LoginRequest {
    auth_token: String,
    remember_me: bool,
    // Tachikoma ACL fields (Phase 6). Omitted from JSON when absent so the
    // server falls back to legacy zweb-token-only behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    user_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_name: Option<String>,
    // `--admin-as-user` / `-aau` — suppress admin bypass server-side.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    admin_as_user: bool,
}

#[derive(Deserialize)]
pub struct SessionResponse {
    pub web_client_id: String,
}

pub async fn authenticate(
    server_base_url: &str,
    auth_token: &str,
    remember_me: bool,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    user_token: Option<String>,
    user_context: Option<String>,
    user_session: Option<String>,
    admin_as_user: bool,
) -> Result<(String, HttpClientWithCookies, Option<String>), RemoteClientError> {
    let http_client = HttpClientWithCookies::new(ca_cert, insecure)
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Step 1: Login with auth token
    let login_url = format!("{}{}", server_base_url, LOGIN_ENDPOINT);

    let login_request = LoginRequest {
        auth_token: auth_token.to_string(),
        remember_me,
        user_token,
        context_path: user_context,
        session_name: user_session,
        admin_as_user,
    };

    let response = http_client
        .send_with_cookies(
            Request::post(login_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body(
                    serde_json::to_vec(&login_request)
                        .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
                )
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    // Handle HTTP status codes
    match response.status().as_u16() {
        401 => return Err(RemoteClientError::InvalidAuthToken),
        status if !response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }

    // Step 2: Get session/client ID
    let session_url = format!("{}{}", server_base_url, SESSION_ENDPOINT);

    let mut session_response = http_client
        .send_with_cookies(
            Request::post(session_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body("{}".as_bytes().to_vec())
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    // Handle session response
    match session_response.status().as_u16() {
        401 => return Err(RemoteClientError::Unauthorized),
        status if !session_response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }

    let response_body = session_response
        .text()
        .await
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let session_data: SessionResponse =
        serde_json::from_str(&response_body).map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Extract session_token if remember_me was true
    let session_token = if remember_me {
        http_client.get_cookie("session_token")
    } else {
        None
    };

    Ok((session_data.web_client_id, http_client, session_token))
}

pub async fn validate_session_token(
    server_base_url: &str,
    session_token: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
) -> Result<(String, HttpClientWithCookies), RemoteClientError> {
    let http_client = HttpClientWithCookies::new(ca_cert, insecure)
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Pre-populate the session_token cookie
    http_client.set_cookie("session_token".to_string(), session_token.to_string());

    // Skip /login, go directly to /session endpoint
    let session_url = format!("{}{}", server_base_url, SESSION_ENDPOINT);

    let mut session_response = http_client
        .send_with_cookies(
            Request::post(session_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body("{}".as_bytes().to_vec())
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    match session_response.status().as_u16() {
        401 => Err(RemoteClientError::SessionTokenExpired),
        status if !session_response.status().is_success() => Err(
            RemoteClientError::ConnectionFailed(format!("Server returned status {}", status)),
        ),
        _ => {
            let response_body = session_response
                .text()
                .await
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
            let session_data: SessionResponse = serde_json::from_str(&response_body)
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
            Ok((session_data.web_client_id, http_client))
        },
    }
}
