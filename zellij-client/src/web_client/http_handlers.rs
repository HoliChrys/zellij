use crate::web_client::acl_session_store::AclSessionInfo;
use crate::web_client::authentication::{IsReadOnly, SessionTokenHash};
use crate::web_client::types::{AppState, CreateClientIdResponse, LoginRequest, LoginResponse};
use crate::web_client::utils::{get_mime_type, parse_cookies};
use axum::{
    extract::{Path as AxumPath, Request, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use include_dir;
use std::time::Instant;
use uuid::Uuid;
use zellij_utils::{
    consts::VERSION,
    web_authentication_tokens::{create_session_token, hash_token},
};

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

const WEB_CLIENT_PAGE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/",
    "assets/index.html"
));

const ASSETS_DIR: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets");

pub async fn serve_html(State(state): State<AppState>, request: Request) -> Html<String> {
    let cookies = parse_cookies(&request);
    let is_authenticated = cookies.get("session_token").is_some();
    let auth_value = if is_authenticated { "true" } else { "false" };
    let base_url = html_escape(
        &state
            .config
            .lock()
            .unwrap()
            .web_client
            .base_url
            .clone()
            .unwrap_or("/".to_string()),
    );

    let html = Html(
        WEB_CLIENT_PAGE
            .replace("IS_AUTHENTICATED", &format!("{}", auth_value))
            .replace("BASE_URL", &base_url),
    );
    html
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    // Phase 3 (Tachikoma ACL) — short-circuit: when ACL is enforced but the
    // request omits the user_token, reject before touching any state.
    if state.acl_config.acl_required && login_request.user_token.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                success: false,
                message: "user_token required when ACL is enforced".to_string(),
            }),
        )
            .into_response();
    }

    // Phase 3 — verify the user_token against Tachikoma. Three outcomes:
    //  * client missing or user_token absent  -> ACL is dormant, behave as
    //    pre-Phase-3.
    //  * verify_token returns valid=false      -> 403 with the upstream reason.
    //  * verify_token returns a transport err  -> 503 if ACL is required,
    //    else fall back to legacy auth.
    let (acl_user_id, acl_user_token_for_store) = match (
        state.acl_client.as_ref(),
        login_request.user_token.as_deref(),
    ) {
        (Some(client), Some(user_token)) => {
            match client
                .verify_token_with(
                    user_token,
                    login_request.context_path.as_deref(),
                    login_request.session_name.as_deref(),
                    "attach",
                    login_request.admin_as_user,
                )
                .await
            {
                Ok(resp) if resp.valid => (resp.user_id.clone(), Some(user_token.to_string())),
                Ok(resp) => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(LoginResponse {
                            success: false,
                            message: format!(
                                "acl_denied: {}",
                                resp.reason.unwrap_or_else(|| "unknown".to_string())
                            ),
                        }),
                    )
                        .into_response();
                },
                Err(e) => {
                    log::warn!("ACL verify error during login: {e}");
                    if state.acl_config.acl_required {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(LoginResponse {
                                success: false,
                                message: "tachikoma_unreachable".to_string(),
                            }),
                        )
                            .into_response();
                    }
                    (None, None)
                },
            }
        },
        _ => (None, None),
    };

    match create_session_token(
        &login_request.auth_token,
        login_request.remember_me.unwrap_or(false),
    ) {
        Ok(session_token) => {
            // Phase 3 — register the new session in the ACL store so the
            // Phase 4 revalidator can poll it and the Phase 5 WS handlers
            // can close on revoke.
            if let (Some(store), Some(user_token)) = (
                state.acl_session_store.as_ref(),
                acl_user_token_for_store.as_ref(),
            ) {
                let hash = hash_token(&session_token);
                store
                    .register(
                        hash,
                        AclSessionInfo {
                            user_token: user_token.clone(),
                            context_path: login_request.context_path.clone(),
                            session_name: login_request.session_name.clone(),
                            user_id: acl_user_id.clone(),
                            last_verified_at: Instant::now(),
                            revoked: false,
                            revoke_reason: None,
                        },
                    )
                    .await;
            }

            let is_https = state.is_https;
            let cookie = if login_request.remember_me.unwrap_or(false) {
                // Persistent cookie for remember_me
                Cookie::build(("session_token", session_token))
                    .http_only(true)
                    .secure(is_https)
                    .same_site(SameSite::Strict)
                    .path("/")
                    .max_age(time::Duration::weeks(4))
                    .build()
            } else {
                // Session cookie - NO max_age means it expires when browser closes/refreshes
                Cookie::build(("session_token", session_token))
                    .http_only(true)
                    .secure(is_https)
                    .same_site(SameSite::Strict)
                    .path("/")
                    .build()
            };

            let mut response = Json(LoginResponse {
                success: true,
                message: "Login successful".to_string(),
            })
            .into_response();

            if let Ok(cookie_header) = axum::http::HeaderValue::from_str(&cookie.to_string()) {
                response.headers_mut().insert("set-cookie", cookie_header);
            }

            response
        },
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                success: false,
                message: "Invalid authentication token".to_string(),
            }),
        )
            .into_response(),
    }
}

pub async fn create_new_client(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Result<Json<CreateClientIdResponse>, (StatusCode, impl IntoResponse)> {
    // Extract is_read_only from request extensions (set by auth middleware)
    let is_read_only = request
        .extensions()
        .get::<IsReadOnly>()
        .copied()
        .unwrap_or(IsReadOnly(true))
        .0;
    let session_token_hash = request
        .extensions()
        .get::<SessionTokenHash>()
        .cloned()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json("Missing session info".to_string()),
        ))?;

    let web_client_id = String::from(Uuid::new_v4());
    let os_input = state
        .client_os_api_factory
        .create_client_os_api()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())))?;

    state.connection_table.lock().unwrap().add_new_client(
        web_client_id.to_owned(),
        os_input,
        is_read_only,
        session_token_hash.0,
    );

    Ok(Json(CreateClientIdResponse {
        web_client_id,
        is_read_only,
    }))
}

pub async fn get_static_asset(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');

    match ASSETS_DIR.get_file(path) {
        None => (
            [(header::CONTENT_TYPE, "text/html")],
            "Not Found".as_bytes(),
        ),
        Some(file) => {
            let ext = file.path().extension().and_then(|ext| ext.to_str());
            let mime_type = get_mime_type(ext);
            ([(header::CONTENT_TYPE, mime_type)], file.contents())
        },
    }
}

pub async fn version_handler() -> &'static str {
    VERSION
}
