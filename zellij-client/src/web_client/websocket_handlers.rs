use crate::web_client::authentication::SessionTokenHash;
use crate::web_client::control_message::{
    SetConfigPayload, TerminalMetricsPayload, WebClientToWebServerControlMessage,
    WebClientToWebServerControlMessagePayload, WebServerToWebClientControlMessage,
};
use crate::web_client::message_handlers::{
    parse_stdin, render_to_client, send_control_messages_to_client, StdinSession,
};
use crate::web_client::server_listener::zellij_server_listener;
use crate::web_client::types::{AppState, TerminalParams};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, Query, State,
    },
    response::IntoResponse,
};
use futures::StreamExt;
use std::sync::{atomic::AtomicBool, Arc};
use tokio_util::sync::CancellationToken;
use zellij_utils::{
    input::mouse::MouseEvent,
    ipc::{ClientToServerMsg, PixelDimensions},
    pane_size::SizeInPixels,
};

pub async fn ws_handler_control(
    ws: WebSocketUpgrade,
    _path: Option<AxumPath<String>>,
    State(state): State<AppState>,
    axum::Extension(session_token_hash): axum::Extension<SessionTokenHash>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_control(socket, state, session_token_hash))
}

pub async fn ws_handler_terminal(
    ws: WebSocketUpgrade,
    session_name: Option<AxumPath<String>>,
    Query(params): Query<TerminalParams>,
    State(state): State<AppState>,
    axum::Extension(session_token_hash): axum::Extension<SessionTokenHash>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        handle_ws_terminal(socket, session_name, params, state, session_token_hash)
    })
}

async fn handle_ws_control(
    socket: WebSocket,
    state: AppState,
    session_token_hash: SessionTokenHash,
) {
    let payload = SetConfigPayload::from(&*state.config.lock().unwrap());
    let set_config_msg = WebServerToWebClientControlMessage::SetConfig(payload);

    let (control_socket_tx, mut control_socket_rx) = socket.split();

    let (control_channel_tx, control_channel_rx) = tokio::sync::mpsc::unbounded_channel();
    send_control_messages_to_client(control_channel_rx, control_socket_tx);

    let _ = control_channel_tx.send(Message::Text(
        serde_json::to_string(&set_config_msg).unwrap().into(),
    ));

    let send_message_to_server = |deserialized_msg: WebClientToWebServerControlMessage| {
        let Some(client_connection) = state
            .connection_table
            .lock()
            .unwrap()
            .get_client_os_api(&deserialized_msg.web_client_id)
            .cloned()
        else {
            log::error!("Unknown web_client_id: {}", deserialized_msg.web_client_id);
            return;
        };
        let client_msg = match deserialized_msg.payload {
            WebClientToWebServerControlMessagePayload::TerminalResize(size) => {
                ClientToServerMsg::TerminalResize { new_size: size }
            },
            WebClientToWebServerControlMessagePayload::TerminalMetrics(metrics) => {
                terminal_metrics_to_ipc(metrics)
            },
        };

        let _ = client_connection.send_to_server(client_msg);
    };

    let mut set_client_control_channel = false;

    // Phase 5 — ACL revoke listener. The writer task (send_control_messages_to_client)
    // owns the WS sink, so we close the connection by sending a 4001 close frame
    // through the mpsc channel and breaking the read loop.
    let mut acl_revoke_rx = state
        .acl_session_store
        .as_ref()
        .map(|s| s.subscribe_disconnect());
    let my_session_hash = session_token_hash.0.clone();

    loop {
        tokio::select! {
            maybe_msg = control_socket_rx.next() => {
                let Some(Ok(msg)) = maybe_msg else {
                    return;
                };
                match msg {
                    Message::Text(msg) => {
                        let deserialized_msg: Result<WebClientToWebServerControlMessage, _> =
                            serde_json::from_str(&msg);
                        match deserialized_msg {
                            Ok(deserialized_msg) => {
                                if !state
                                    .connection_table
                                    .lock()
                                    .unwrap()
                                    .verify_client_ownership(
                                        &deserialized_msg.web_client_id,
                                        &session_token_hash.0,
                                    )
                                {
                                    log::error!(
                                        "Client attempted to use web_client_id {} that does not belong to their session",
                                        deserialized_msg.web_client_id
                                    );
                                    return;
                                }
                                if !set_client_control_channel {
                                    set_client_control_channel = true;
                                    state
                                        .connection_table
                                        .lock()
                                        .unwrap()
                                        .add_client_control_tx(
                                            &deserialized_msg.web_client_id,
                                            control_channel_tx.clone(),
                                        );
                                }
                                send_message_to_server(deserialized_msg);
                            },
                            Err(e) => {
                                log::error!("Failed to deserialize client msg: {:?}", e);
                            },
                        }
                    },
                    Message::Close(_) => {
                        return;
                    },
                    _ => {
                        log::error!("Unsupported messagetype : {:?}", msg);
                    },
                }
            }
            // Phase 5 — ACL revoke. Park forever when no ACL store is configured
            // so the arm is inert; otherwise, on a matching event, send a 4001
            // close frame through the writer channel and break the loop.
            event = async {
                if let Some(rx) = acl_revoke_rx.as_mut() {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(disconnect_event) = event {
                    if disconnect_event.session_token_hash == my_session_hash {
                        let close_frame = axum::extract::ws::CloseFrame {
                            code: 4001u16,
                            reason: format!(
                                "acl_revoked: {}",
                                disconnect_event.reason
                            )
                            .into(),
                        };
                        let _ = control_channel_tx
                            .send(Message::Close(Some(close_frame)));
                        log::info!(
                            "[ws_control] closed for acl_revoke (hash={}…, reason={})",
                            &my_session_hash[..8.min(my_session_hash.len())],
                            disconnect_event.reason,
                        );
                        break;
                    }
                    // Event was for another session — keep looping.
                }
                // Err(Lagged) / Err(Closed) — keep looping.
            }
        }
    }
}

async fn handle_ws_terminal(
    socket: WebSocket,
    session_name: Option<AxumPath<String>>,
    params: TerminalParams,
    state: AppState,
    session_token_hash: SessionTokenHash,
) {
    let web_client_id = params.web_client_id;

    // Verify the session token owns this web_client_id
    if !state
        .connection_table
        .lock()
        .unwrap()
        .verify_client_ownership(&web_client_id, &session_token_hash.0)
    {
        log::error!(
            "Terminal WebSocket: client does not own web_client_id {}",
            web_client_id
        );
        return;
    }

    let Some(os_input) = state
        .connection_table
        .lock()
        .unwrap()
        .get_client_os_api(&web_client_id)
        .cloned()
    else {
        log::error!("Unknown web_client_id: {}", web_client_id);
        return;
    };

    let (client_terminal_channel_tx, mut client_terminal_channel_rx) = socket.split();
    let (stdout_channel_tx, stdout_channel_rx) = tokio::sync::mpsc::unbounded_channel();
    state
        .connection_table
        .lock()
        .unwrap()
        .add_client_terminal_tx(&web_client_id, stdout_channel_tx);

    let (attachment_complete_tx, attachment_complete_rx) = tokio::sync::oneshot::channel();

    zellij_server_listener(
        os_input.clone(),
        state.connection_table.clone(),
        session_name.map(|p| p.0),
        state.config.lock().unwrap().clone(),
        state.config_options.clone(),
        Some(state.config_file_path.clone()),
        web_client_id.clone(),
        state.session_manager.clone(),
        Some(attachment_complete_tx),
    );

    let terminal_channel_cancellation_token = CancellationToken::new();
    let should_not_reconnect = state
        .connection_table
        .lock()
        .unwrap()
        .get_should_not_reconnect_flag(&web_client_id)
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

    // Phase 5 — ACL revoke listener. The writer task owns the WS sink, so
    // we hand it a subscriber + our session hash so it can write a 4001
    // close frame with the upstream reason. The recv loop below uses its
    // own subscriber to break out promptly.
    let (render_acl_rx, render_hash) = match state.acl_session_store.as_ref() {
        Some(store) => (
            Some(store.subscribe_disconnect()),
            Some(session_token_hash.0.clone()),
        ),
        None => (None, None),
    };
    let mut acl_revoke_rx = state
        .acl_session_store
        .as_ref()
        .map(|s| s.subscribe_disconnect());
    let my_session_hash = session_token_hash.0.clone();

    render_to_client(
        stdout_channel_rx,
        client_terminal_channel_tx,
        terminal_channel_cancellation_token.clone(),
        should_not_reconnect,
        render_acl_rx,
        render_hash,
    );
    state
        .connection_table
        .lock()
        .unwrap()
        .add_client_terminal_channel_cancellation_token(
            &web_client_id,
            terminal_channel_cancellation_token,
        );

    let explicitly_disable_kitty_keyboard_protocol = state
        .config
        .lock()
        .unwrap()
        .options
        .support_kitty_keyboard_protocol
        .map(|e| !e)
        .unwrap_or(false);

    let _ = attachment_complete_rx.await;

    let mut mouse_old_event = MouseEvent::new();
    // Per-connection parser state. Hoisted so a CSI / Kitty sequence
    // split across two WebSocket frames resolves on the second frame.
    let mut stdin_session = StdinSession::new(explicitly_disable_kitty_keyboard_protocol);
    let finalize_idle = std::time::Duration::from_millis(50);
    // Sentinel for the select arm below: distinguishes "frame arrived"
    // from "idle timeout fired" from "ACL revoke matched our session".
    enum TermRecv {
        Frame(Option<Result<Message, axum::Error>>),
        IdleFinalize,
        AclRevoked,
    }
    loop {
        // When termwiz is holding ambiguous-but-complete events from
        // the previous frame, race the next frame against an idle
        // timeout so the held events still drain if no further frame
        // arrives. The ACL revoke branch always races alongside so a
        // mark_revoked() tick breaks the loop promptly regardless of
        // pending_finalize state.
        let recv = if stdin_session.pending_finalize() {
            tokio::select! {
                msg = client_terminal_channel_rx.next() => TermRecv::Frame(msg),
                _ = tokio::time::sleep(finalize_idle) => TermRecv::IdleFinalize,
                event = async {
                    if let Some(rx) = acl_revoke_rx.as_mut() {
                        rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => match event {
                    Ok(ev) if ev.session_token_hash == my_session_hash => {
                        log::info!(
                            "[ws_terminal] closed for acl_revoke (hash={}…, reason={})",
                            &my_session_hash[..8.min(my_session_hash.len())],
                            ev.reason,
                        );
                        TermRecv::AclRevoked
                    }
                    _ => continue,
                },
            }
        } else {
            tokio::select! {
                msg = client_terminal_channel_rx.next() => TermRecv::Frame(msg),
                event = async {
                    if let Some(rx) = acl_revoke_rx.as_mut() {
                        rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => match event {
                    Ok(ev) if ev.session_token_hash == my_session_hash => {
                        log::info!(
                            "[ws_terminal] closed for acl_revoke (hash={}…, reason={})",
                            &my_session_hash[..8.min(my_session_hash.len())],
                            ev.reason,
                        );
                        TermRecv::AclRevoked
                    }
                    _ => continue,
                },
            }
        };
        let msg = match recv {
            TermRecv::Frame(Some(Ok(m))) => m,
            TermRecv::Frame(_) => break,
            TermRecv::AclRevoked => {
                // The writer task (render_to_client) handles the actual
                // 4001 close frame using its own broadcast subscriber;
                // we just break out of the read loop so the server-side
                // connection is torn down. ClientExited is sent below.
                break;
            }
            TermRecv::IdleFinalize => {
                // Idle timeout fired with `pending_finalize` set:
                // drain any ambiguous-but-complete events termwiz held
                // back on the previous frame.
                if let Some(client_connection) = state
                    .connection_table
                    .lock()
                    .unwrap()
                    .get_client_os_api(&web_client_id)
                    .cloned()
                {
                    stdin_session.finalize(&*client_connection, &mut mouse_old_event);
                } else {
                    // No client to send drained events to — clear the
                    // flag so we don't busy-loop the idle timer.
                    stdin_session.clear_pending_finalize();
                }
                continue;
            },
        };
        match msg {
            Message::Binary(buf) => {
                let Some(client_connection) = state
                    .connection_table
                    .lock()
                    .unwrap()
                    .get_client_os_api(&web_client_id)
                    .cloned()
                else {
                    log::error!("Unknown web_client_id: {}", web_client_id);
                    continue;
                };
                parse_stdin(
                    &buf,
                    client_connection.clone(),
                    &mut mouse_old_event,
                    &mut stdin_session,
                );
            },
            Message::Text(msg) => {
                let Some(client_connection) = state
                    .connection_table
                    .lock()
                    .unwrap()
                    .get_client_os_api(&web_client_id)
                    .cloned()
                else {
                    log::error!("Unknown web_client_id: {}", web_client_id);
                    continue;
                };
                parse_stdin(
                    msg.as_bytes(),
                    client_connection.clone(),
                    &mut mouse_old_event,
                    &mut stdin_session,
                );
            },
            Message::Close(_) => {
                state
                    .connection_table
                    .lock()
                    .unwrap()
                    .remove_client(&web_client_id);
                break;
            },
            // TODO: support Message::Binary
            _ => {
                log::error!("Unsupported websocket msg type");
            },
        }
    }
    os_input.send_to_server(ClientToServerMsg::ClientExited);
}

fn terminal_metrics_to_ipc(metrics: TerminalMetricsPayload) -> ClientToServerMsg {
    ClientToServerMsg::TerminalPixelDimensions {
        pixel_dimensions: PixelDimensions {
            text_area_size: Some(SizeInPixels {
                width: metrics.text_area_pixel_width,
                height: metrics.text_area_pixel_height,
            }),
            character_cell_size: Some(SizeInPixels {
                width: metrics.cell_pixel_width,
                height: metrics.cell_pixel_height,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_metrics_to_ipc_preserves_all_dimensions() {
        let metrics = TerminalMetricsPayload {
            cell_pixel_width: 9,
            cell_pixel_height: 18,
            text_area_pixel_width: 80 * 9,
            text_area_pixel_height: 24 * 18,
        };
        let msg = terminal_metrics_to_ipc(metrics);
        match msg {
            ClientToServerMsg::TerminalPixelDimensions { pixel_dimensions } => {
                let cell = pixel_dimensions
                    .character_cell_size
                    .expect("cell size missing");
                let area = pixel_dimensions
                    .text_area_size
                    .expect("text area size missing");
                assert_eq!(cell.width, 9);
                assert_eq!(cell.height, 18);
                assert_eq!(area.width, 720);
                assert_eq!(area.height, 432);
            },
            other => panic!("expected TerminalPixelDimensions, got {:?}", other),
        }
    }

    #[test]
    fn terminal_metrics_round_trips_through_json_payload() {
        // The browser sends this message as JSON over the control
        // socket. Verify that the on-wire shape deserializes into the
        // variant we route into terminal_metrics_to_ipc.
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "TerminalMetrics",
                "cell_pixel_width": 7,
                "cell_pixel_height": 14,
                "text_area_pixel_width": 560,
                "text_area_pixel_height": 336,
            }
        });
        let parsed: WebClientToWebServerControlMessage =
            serde_json::from_value(raw).expect("parse");
        let metrics = match parsed.payload {
            WebClientToWebServerControlMessagePayload::TerminalMetrics(m) => m,
            other => panic!("expected TerminalMetrics, got {:?}", other),
        };
        assert_eq!(metrics.cell_pixel_width, 7);
        assert_eq!(metrics.cell_pixel_height, 14);
        assert_eq!(metrics.text_area_pixel_width, 560);
        assert_eq!(metrics.text_area_pixel_height, 336);
    }

    #[test]
    fn terminal_resize_still_deserializes_after_adding_variant() {
        // Regression guard for the new enum variant: the existing
        // TerminalResize wire shape must continue to parse unchanged
        // (no `type` rename, no required-field changes).
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "TerminalResize",
                "rows": 24,
                "cols": 80,
            }
        });
        let parsed: WebClientToWebServerControlMessage =
            serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::TerminalResize(size) => {
                assert_eq!(size.rows, 24);
                assert_eq!(size.cols, 80);
            },
            other => panic!("expected TerminalResize, got {:?}", other),
        }
    }
}
