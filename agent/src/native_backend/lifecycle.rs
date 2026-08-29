use super::network::{NetworkManagerBackend, WifiSecurityObservation};
use crate::{backend::BackendHandle, store::StoreHandle};
use nmdbus::dbus::{blocking::Connection, message::MatchRule};
use proton_omarchy_protocol::{AccountStatus, ConnectionStatus, StateSnapshot};
use serde_json::{json, Value};
use std::{thread, time::Duration};
use tokio::sync::{mpsc, watch};

const LIFECYCLE_CLIENT_ID: &str = "agent-lifecycle";
const WIFI_POLL_INTERVAL: Duration = Duration::from_secs(15);
const RESUME_RETRY_DELAYS: &[Duration] = &[
    Duration::ZERO,
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(15),
];

pub(super) fn spawn(
    state_tx: watch::Sender<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
    network: NetworkManagerBackend,
) {
    tokio::spawn(monitor_wifi(state_tx.clone(), network));

    let (sleep_tx, sleep_rx) = mpsc::unbounded_channel();
    spawn_sleep_signal_monitor(sleep_tx);
    tokio::spawn(handle_sleep_signals(
        sleep_rx,
        state_tx.subscribe(),
        backend,
        store,
    ));
}

async fn monitor_wifi(state_tx: watch::Sender<StateSnapshot>, network: NetworkManagerBackend) {
    let mut interval = tokio::time::interval(WIFI_POLL_INTERVAL);
    let mut previous: Option<WifiSecurityObservation> = None;
    loop {
        interval.tick().await;
        let result = tokio::task::spawn_blocking({
            let network = network.clone();
            move || network.wifi_security()
        })
        .await;
        match result {
            Ok(Ok(current)) => {
                let changed = current != previous;
                let connected = current.is_some();
                let insecure = current
                    .as_ref()
                    .map(|observation| !observation.secure)
                    .unwrap_or(false);
                let publish = {
                    let state = state_tx.borrow();
                    !state.network_security.known
                        || state.network_security.wifi_connected != connected
                        || state.network_security.insecure_wifi != insecure
                        || changed
                };
                if publish {
                    state_tx.send_modify(|state| {
                        state.network_security.known = true;
                        state.network_security.wifi_connected = connected;
                        state.network_security.insecure_wifi = insecure;
                        if changed {
                            state.network_security.generation =
                                state.network_security.generation.wrapping_add(1);
                        }
                        state.revision = state.revision.wrapping_add(1);
                    });
                }
                previous = current;
            }
            Ok(Err(_)) | Err(_) => {
                if state_tx.borrow().network_security.known {
                    state_tx.send_modify(|state| {
                        state.network_security.known = false;
                        state.revision = state.revision.wrapping_add(1);
                    });
                }
            }
        }
    }
}

fn spawn_sleep_signal_monitor(sender: mpsc::UnboundedSender<bool>) {
    tokio::task::spawn_blocking(move || {
        while !sender.is_closed() {
            if monitor_sleep_signals(&sender).is_err() && !sender.is_closed() {
                thread::sleep(Duration::from_secs(5));
            }
        }
    });
}

fn monitor_sleep_signals(sender: &mpsc::UnboundedSender<bool>) -> Result<(), nmdbus::dbus::Error> {
    let connection = Connection::new_system()?;
    let mut rule = MatchRule::new_signal("org.freedesktop.login1.Manager", "PrepareForSleep");
    rule.sender = Some("org.freedesktop.login1".into());
    rule.path = Some("/org/freedesktop/login1".into());
    let callback_sender = sender.clone();
    connection.add_match::<(bool,), _>(rule, move |(sleeping,), _, _| {
        callback_sender.send(sleeping).is_ok()
    })?;
    while !sender.is_closed() {
        connection.process(Duration::from_secs(30))?;
    }
    Ok(())
}

async fn handle_sleep_signals(
    mut sleep_rx: mpsc::UnboundedReceiver<bool>,
    state_rx: watch::Receiver<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
) {
    let mut active_before_sleep = None;
    while let Some(sleeping) = sleep_rx.recv().await {
        if sleeping {
            active_before_sleep = Some(vpn_is_active(&state_rx.borrow()));
            continue;
        }
        let Some(was_active) = active_before_sleep.take() else {
            continue;
        };
        reconnect_after_resume(&backend, &store, &state_rx, was_active).await;
    }
}

async fn reconnect_after_resume(
    backend: &BackendHandle,
    store: &StoreHandle,
    state_rx: &watch::Receiver<StateSnapshot>,
    was_active: bool,
) {
    if !should_reconnect(was_active, store.auto_connect_enabled()) {
        let _ = backend
            .request(LIFECYCLE_CLIENT_ID, "connection.observe", json!({}))
            .await;
        return;
    }

    for delay in RESUME_RETRY_DELAYS {
        if !delay.is_zero() {
            tokio::time::sleep(*delay).await;
        }
        if state_rx.borrow().account.status != AccountStatus::SignedIn {
            continue;
        }
        if !was_active && !store.auto_connect_enabled() {
            return;
        }
        if backend
            .request(LIFECYCLE_CLIENT_ID, "connection.observe", json!({}))
            .await
            .is_err()
        {
            continue;
        }
        if vpn_is_active(&state_rx.borrow()) {
            return;
        }

        let selection = if was_active {
            json!({ "selection": { "type": "last" } })
        } else {
            json!({})
        };
        let Ok(resolved) = store.request(LIFECYCLE_CLIENT_ID, "connection.resolve", selection)
        else {
            continue;
        };
        let params = resolved
            .get("connect_params")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if backend
            .request(LIFECYCLE_CLIENT_ID, "connection.connect", params)
            .await
            .is_ok()
        {
            record_recent(store, &resolved);
            return;
        }
    }
}

fn record_recent(store: &StoreHandle, resolved: &Value) {
    if let Some(recent) = resolved.get("recent") {
        let _ = store.request(
            LIFECYCLE_CLIENT_ID,
            "recents.record",
            json!({ "recent": recent }),
        );
    }
}

fn vpn_is_active(snapshot: &StateSnapshot) -> bool {
    matches!(
        snapshot.connection.status,
        ConnectionStatus::Connecting | ConnectionStatus::Connected
    )
}

fn should_reconnect(was_active: bool, auto_connect: bool) -> bool {
    was_active || auto_connect
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_restores_only_an_active_or_auto_connected_session() {
        assert!(should_reconnect(true, false));
        assert!(should_reconnect(true, true));
        assert!(should_reconnect(false, true));
        assert!(!should_reconnect(false, false));
    }
}
