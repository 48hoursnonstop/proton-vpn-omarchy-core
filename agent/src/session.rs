use crate::{backend::BackendHandle, store::StoreHandle};
use futures_util::{stream::FuturesUnordered, SinkExt, StreamExt};
use proton_omarchy_protocol::{
    HelloParams, RequestEnvelope, ServerMessage, StateSnapshot, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    STORE_METHODS,
};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{net::UnixStream, sync::watch};
use tokio_util::codec::{Framed, LinesCodec};

const MAX_PENDING_REQUESTS_PER_CLIENT: usize = 32;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub async fn run(
    stream: UnixStream,
    mut state_rx: watch::Receiver<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
) -> io::Result<()> {
    let framed = Framed::new(stream, LinesCodec::new_with_max_length(MAX_FRAME_BYTES));
    let (mut sink, mut source) = framed.split();
    let mut hello_complete = false;
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let mut client_instance_id = format!("anonymous-session-{session_id}");
    let mut pending = FuturesUnordered::new();
    let mut pending_ids = HashSet::new();

    loop {
        tokio::select! {
            incoming = source.next() => {
                let Some(incoming) = incoming else { return Ok(()); };
                let line = incoming
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

                let request: RequestEnvelope = match serde_json::from_str(&line) {
                    Ok(request) => request,
                    Err(error) => {
                        send(
                            &mut sink,
                            &ServerMessage::error(None, "invalid_json", error.to_string()),
                        ).await?;
                        continue;
                    }
                };

                if request.message_type != "request" {
                    send(
                        &mut sink,
                        &ServerMessage::error(
                            Some(request.id),
                            "invalid_type",
                            "client frames must use type=request",
                        ),
                    ).await?;
                    continue;
                }
                if request.v != PROTOCOL_VERSION {
                    send(
                        &mut sink,
                        &ServerMessage::error(
                            Some(request.id),
                            "unsupported_version",
                            format!("protocol version {} is required", PROTOCOL_VERSION),
                        ),
                    ).await?;
                    continue;
                }
                if request.id.trim().is_empty() || request.id.len() > 128 {
                    send(
                        &mut sink,
                        &ServerMessage::error(
                            None,
                            "invalid_request_id",
                            "request id must contain between 1 and 128 characters",
                        ),
                    ).await?;
                    continue;
                }
                if !hello_complete && request.method != "hello" {
                    send(
                        &mut sink,
                        &ServerMessage::error(
                            Some(request.id),
                            "hello_required",
                            "send hello before other requests",
                        ),
                    ).await?;
                    continue;
                }

                match request.method.as_str() {
                    "hello" => {
                        if hello_complete {
                            send(
                                &mut sink,
                                &ServerMessage::error(
                                    Some(request.id),
                                    "hello_already_completed",
                                    "hello may only be sent once per socket session",
                                ),
                            ).await?;
                            continue;
                        }

                        let params: HelloParams = match serde_json::from_value(request.params.clone()) {
                            Ok(value) => value,
                            Err(error) => {
                                send(
                                    &mut sink,
                                    &ServerMessage::error(
                                        Some(request.id),
                                        "invalid_params",
                                        error.to_string(),
                                    ),
                                ).await?;
                                continue;
                            }
                        };

                        if params.client.trim().is_empty()
                            || params.client.len() > 64
                            || params.client_version.len() > 64
                            || params.client_instance_id.len() > 128
                            || (!params.client_instance_id.is_empty()
                                && !params.client_instance_id.chars().all(|character| {
                                    character.is_ascii_alphanumeric()
                                        || matches!(character, '.' | '_' | ':' | '-')
                                }))
                        {
                            send(
                                &mut sink,
                                &ServerMessage::error(
                                    Some(request.id),
                                    "invalid_params",
                                    "hello client fields have an invalid length",
                                ),
                            ).await?;
                            continue;
                        }

                        client_instance_id = if params.client_instance_id.trim().is_empty() {
                            format!("{}-session-{session_id}", params.client.trim())
                        } else {
                            params.client_instance_id.trim().to_owned()
                        };

                        hello_complete = true;
                        let flavor = backend.flavor();
                        let request_methods = flavor
                            .methods()
                            .iter()
                            .chain(STORE_METHODS.iter())
                            .copied()
                            .collect::<Vec<_>>();
                        send(
                            &mut sink,
                            &ServerMessage::ok(
                                request.id,
                                json!({
                                    "protocol_version": PROTOCOL_VERSION,
                                    "server": "proton-omarchy-agent",
                                    "mock_backend": false,
                                    "backend": flavor.name(),
                                    "client": params.client,
                                    "client_instance_id": client_instance_id.clone(),
                                    "request_methods": request_methods,
                                    "capabilities": flavor.capabilities(),
                                }),
                            ),
                        ).await?;

                        let snapshot = state_rx.borrow_and_update().clone();
                        send(
                            &mut sink,
                            &ServerMessage::event(
                                "state.snapshot",
                                serde_json::to_value(snapshot).unwrap_or(Value::Null),
                            ),
                        ).await?;
                    }
                    "state.get" => {
                        let snapshot = state_rx.borrow().clone();
                        send(
                            &mut sink,
                            &ServerMessage::ok(
                                request.id,
                                serde_json::to_value(snapshot).unwrap_or(Value::Null),
                            ),
                        ).await?;
                    }
                    method if backend.supports(method) => {
                        if pending.len() >= MAX_PENDING_REQUESTS_PER_CLIENT {
                            send(
                                &mut sink,
                                &ServerMessage::error_with_details(
                                    Some(request.id),
                                    "too_many_pending_requests",
                                    "too many requests are pending for this client",
                                    Some(json!({
                                        "limit": MAX_PENDING_REQUESTS_PER_CLIENT
                                    })),
                                    true,
                                ),
                            ).await?;
                            continue;
                        }

                        if !pending_ids.insert(request.id.clone()) {
                            send(
                                &mut sink,
                                &ServerMessage::error(
                                    Some(request.id),
                                    "duplicate_request_id",
                                    "request id is already pending",
                                ),
                            ).await?;
                            continue;
                        }

                        let request_id = request.id;
                        let request_method = request.method;
                        let request_params = request.params;
                        let request_backend = backend.clone();
                        let request_client_instance_id = client_instance_id.clone();
                        pending.push(tokio::spawn(async move {
                            let result = request_backend
                                .request(
                                    request_client_instance_id,
                                    request_method,
                                    request_params,
                                )
                                .await;
                            (request_id, result)
                        }));
                    }
                    method if STORE_METHODS.contains(&method) => {
                        if pending.len() >= MAX_PENDING_REQUESTS_PER_CLIENT {
                            send(
                                &mut sink,
                                &ServerMessage::error_with_details(
                                    Some(request.id),
                                    "too_many_pending_requests",
                                    "too many requests are pending for this client",
                                    Some(json!({
                                        "limit": MAX_PENDING_REQUESTS_PER_CLIENT
                                    })),
                                    true,
                                ),
                            ).await?;
                            continue;
                        }

                        if !pending_ids.insert(request.id.clone()) {
                            send(
                                &mut sink,
                                &ServerMessage::error(
                                    Some(request.id),
                                    "duplicate_request_id",
                                    "request id is already pending",
                                ),
                            ).await?;
                            continue;
                        }

                        let request_id = request.id;
                        let request_method = request.method;
                        let request_params = request.params;
                        let request_store = store.clone();
                        let request_client_instance_id = client_instance_id.clone();
                        pending.push(tokio::spawn(async move {
                            let result = request_store.request(
                                &request_client_instance_id,
                                &request_method,
                                request_params,
                            );
                            (request_id, result)
                        }));
                    }
                    _ => {
                        send(
                            &mut sink,
                            &ServerMessage::error(
                                Some(request.id),
                                "method_not_found",
                                "unknown request method",
                            ),
                        ).await?;
                    }
                }
            }
            completed = pending.next(), if !pending.is_empty() => {
                let Some(completed) = completed else {
                    continue;
                };
                let Ok((request_id, result)) = completed else {
                    continue;
                };
                pending_ids.remove(&request_id);
                match result {
                    Ok(result) => {
                        send(&mut sink, &ServerMessage::ok(request_id, result)).await?;
                    }
                    Err(error) => {
                        send(
                            &mut sink,
                            &ServerMessage::error_with_details(
                                Some(request_id),
                                error.code,
                                error.message,
                                error.details,
                                error.retryable,
                            ),
                        ).await?;
                    }
                }
            }
            changed = state_rx.changed(), if hello_complete => {
                if changed.is_err() {
                    return Ok(());
                }
                let snapshot = state_rx.borrow_and_update().clone();
                send(
                    &mut sink,
                    &ServerMessage::event(
                        "state.changed",
                        serde_json::to_value(snapshot).unwrap_or(Value::Null),
                    ),
                ).await?;
            }
        }
    }
}

async fn send<S>(sink: &mut S, message: &ServerMessage) -> io::Result<()>
where
    S: futures_util::Sink<String> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let line = serde_json::to_string(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if line.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server frame exceeds maximum size",
        ));
    }
    sink.send(line)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))
}
