mod auth;
mod config;
pub mod http_client;
pub mod websockets;

#[cfg(test)]
mod unit;

pub use websockets::WebSocketConnections;

use crate::os_input_output::ClientOsApi;
use crate::RemoteClientError;
use tokio::runtime::Handle;
use zellij_utils::remote_session_tokens;

// In tests, only attempt once (no retries) to avoid interactive prompts
// In production, allow up to 3 attempts (initial + 2 retries)
#[cfg(test)]
const MAX_AUTH_ATTEMPTS: u32 = 1;

#[cfg(not(test))]
const MAX_AUTH_ATTEMPTS: u32 = 3;

/// Attach to a remote Zellij session via HTTP(S)
///
/// This function handles the complete authentication flow including:
/// - URL validation
/// - Session token management (--forget, --token flags)
/// - Trying saved session tokens
/// - Interactive authentication with retry logic
/// - Saving session tokens when --remember is used
///
/// Returns WebSocketConnections on success
pub fn attach_to_remote_session(
    runtime: Handle,
    _os_input: Box<dyn ClientOsApi>,
    remote_session_url: &str,
    token: Option<String>,
    remember: bool,
    forget: bool,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    user_token: Option<String>,
    user_context: Option<String>,
    user_session: Option<String>,
    admin_as_user: bool,
) -> Result<WebSocketConnections, RemoteClientError> {
    // Phase 6/AAU UX — extract Tachikoma ACL fields from the URL query
    // string when the caller didn't pass them as CLI flags. Lets users do :
    //   zellij attach 'https://.../sess?user_token=…&context_path=…&session_name=…'
    // without remembering all 3 flags. Explicit --user-* still wins.
    let (url_user_token, url_user_context, url_user_session, url_admin_as_user) =
        extract_url_acl_params(remote_session_url);
    let user_token = user_token.or(url_user_token);
    let user_context = user_context.or(url_user_context);
    let user_session = user_session.or(url_user_session);
    let admin_as_user = admin_as_user || url_admin_as_user;

    // Extract server URL for token management
    let server_url = extract_server_url(remote_session_url)?;

    // Handle --forget flag
    if forget {
        let _ = remote_session_tokens::delete_session_token(&server_url);
    }

    // If --token provided, delete saved session token
    if token.is_some() {
        let _ = remote_session_tokens::delete_session_token(&server_url);
    }

    if token.is_none() {
        if let Some(connections) = try_to_connect_with_saved_session_token(
            runtime.clone(),
            remote_session_url,
            &server_url,
            ca_cert,
            insecure,
        )? {
            return Ok(connections);
        }
    }

    // Normal auth flow with retry logic
    authenticate_with_retry(
        runtime,
        remote_session_url,
        token,
        remember,
        ca_cert,
        insecure,
        user_token,
        user_context,
        user_session,
        admin_as_user,
    )
}

/// Try to connect using a saved session token
/// Returns Ok(Some(connections)) on success, Ok(None) if should retry with auth
fn try_to_connect_with_saved_session_token(
    runtime: Handle,
    remote_session_url: &str,
    server_url: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
) -> Result<Option<WebSocketConnections>, RemoteClientError> {
    if let Ok(Some(saved_session_token)) = remote_session_tokens::get_session_token(server_url) {
        // we have a saved session token, let's try to authenticate with it
        let ca_cert_owned = ca_cert.map(|p| p.to_path_buf());
        match runtime.block_on(async move {
            remote_attach_with_session_token(
                remote_session_url,
                &saved_session_token,
                ca_cert_owned.as_deref(),
                insecure,
            )
            .await
        }) {
            Ok(connections) => {
                return Ok(Some(connections));
            },
            Err(RemoteClientError::SessionTokenExpired) => {
                // Session expired - delete and return to retry
                let _ = remote_session_tokens::delete_session_token(server_url);
                eprintln!("Session expired, please re-authenticate");
                return Ok(None);
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
    Ok(None)
}

fn authenticate_with_retry(
    runtime: Handle,
    remote_session_url: &str,
    initial_token: Option<String>,
    remember: bool,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    user_token: Option<String>,
    user_context: Option<String>,
    user_session: Option<String>,
    admin_as_user: bool,
) -> Result<WebSocketConnections, RemoteClientError> {
    use dialoguer::{Confirm, Password};

    let mut attempt = 0;
    let mut current_token = initial_token;

    loop {
        attempt += 1;

        let auth_token = match &current_token {
            Some(t) => t.clone(),
            None if user_token.is_some() => {
                // Phase 6/AAU UX — when the caller has a valid Tachikoma
                // user_token, the zweb auth_token is redundant. The server
                // (login_handler) routes through create_session_token_acl
                // and skips the SQLite zweb-token check entirely when
                // auth_token is empty. No prompt, no second credential.
                String::new()
            },
            None => Password::new()
                .with_prompt("Enter authentication token")
                .interact()
                .map_err(|e| RemoteClientError::IoError(e))?,
        };

        let ca_cert_owned = ca_cert.map(|p| p.to_path_buf());
        let user_token_clone = user_token.clone();
        let user_context_clone = user_context.clone();
        let user_session_clone = user_session.clone();
        match runtime.block_on(async move {
            remote_attach(
                remote_session_url,
                &auth_token,
                remember,
                ca_cert_owned.as_deref(),
                insecure,
                user_token_clone,
                user_context_clone,
                user_session_clone,
                admin_as_user,
            )
            .await
        }) {
            Ok((connections, session_token_opt)) => {
                // Save session token if we got one
                if let Some(session_token) = session_token_opt {
                    let server_url = extract_server_url(remote_session_url)?;
                    let _ = remote_session_tokens::save_session_token(&server_url, &session_token);
                }
                return Ok(connections);
            },
            Err(RemoteClientError::InvalidAuthToken) => {
                eprintln!("Invalid authentication token");

                if attempt >= MAX_AUTH_ATTEMPTS {
                    eprintln!(
                        "Maximum authentication attempts ({}) exceeded.",
                        MAX_AUTH_ATTEMPTS
                    );
                    return Err(RemoteClientError::InvalidAuthToken);
                }

                match Confirm::new()
                    .with_prompt("Try again?")
                    .default(true)
                    .interact()
                {
                    Ok(true) => {
                        current_token = None;
                        continue;
                    },
                    Ok(false) => {
                        return Err(RemoteClientError::InvalidAuthToken);
                    },
                    Err(e) => {
                        return Err(RemoteClientError::IoError(e));
                    },
                }
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
}

async fn remote_attach(
    server_url: &str,
    auth_token: &str,
    remember_me: bool,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    user_token: Option<String>,
    user_context: Option<String>,
    user_session: Option<String>,
    admin_as_user: bool,
) -> Result<(websockets::WebSocketConnections, Option<String>), RemoteClientError> {
    let server_base_url = extract_server_url(server_url)?;
    let session_name = extract_session_name(server_url)?;
    let (web_client_id, http_client, session_token) = auth::authenticate(
        &server_base_url,
        auth_token,
        remember_me,
        ca_cert,
        insecure,
        user_token,
        user_context,
        user_session,
        admin_as_user,
    )
    .await?;
    let connections = websockets::establish_websocket_connections(
        &web_client_id,
        &http_client,
        &server_base_url,
        &session_name,
        ca_cert,
        insecure,
    )
    .await
    .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;
    Ok((connections, session_token))
}

async fn remote_attach_with_session_token(
    server_url: &str,
    session_token: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
) -> Result<websockets::WebSocketConnections, RemoteClientError> {
    let server_base_url = extract_server_url(server_url)?;
    let session_name = extract_session_name(server_url)?;
    let (web_client_id, http_client) =
        auth::validate_session_token(&server_base_url, session_token, ca_cert, insecure).await?;
    let connections = websockets::establish_websocket_connections(
        &web_client_id,
        &http_client,
        &server_base_url,
        &session_name,
        ca_cert,
        insecure,
    )
    .await
    .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;
    Ok(connections)
}

/// Extract Tachikoma ACL fields from the URL query string :
/// `?user_token=…&context_path=…&session_name=…&admin_as_user=true`
/// Returns (user_token, context_path, session_name, admin_as_user). Any
/// missing param comes back as None / false. Malformed URLs return all
/// defaults — never panics.
pub fn extract_url_acl_params(
    full_url: &str,
) -> (Option<String>, Option<String>, Option<String>, bool) {
    let parsed = match url::Url::parse(full_url) {
        Ok(u) => u,
        Err(_) => return (None, None, None, false),
    };
    let mut user_token = None;
    let mut context_path = None;
    let mut session_name = None;
    let mut admin_as_user = false;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "user_token" if !v.is_empty() => user_token = Some(v.into_owned()),
            "context_path" if !v.is_empty() => context_path = Some(v.into_owned()),
            "session_name" if !v.is_empty() => session_name = Some(v.into_owned()),
            "admin_as_user" => admin_as_user = matches!(v.as_ref(), "true" | "1" | "yes"),
            _ => {}
        }
    }
    (user_token, context_path, session_name, admin_as_user)
}

pub fn extract_server_url(full_url: &str) -> Result<String, RemoteClientError> {
    let parsed = url::Url::parse(full_url)?;
    let mut base_url = parsed.clone();
    base_url.set_path("");
    base_url.set_query(None);
    base_url.set_fragment(None);
    Ok(base_url.to_string().trim_end_matches('/').to_string())
}

fn extract_session_name(server_url: &str) -> Result<String, RemoteClientError> {
    let parsed_url = url::Url::parse(server_url)?;
    let path = parsed_url.path();
    // Extract session name from path (everything after the first /)
    if path.len() > 1 && path.starts_with('/') {
        Ok(path[1..].trim_end_matches('/').to_string())
    } else {
        Ok(String::new())
    }
}
