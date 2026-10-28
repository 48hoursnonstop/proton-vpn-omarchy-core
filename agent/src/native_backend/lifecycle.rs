use super::network::{NetworkManagerBackend, WifiSecurityObservation};
use crate::{
    backend::BackendHandle,
    operations::{connection_sequence_interrupted, is_cancelled_error},
    store::StoreHandle,
};
use nmdbus::dbus::{blocking::Connection, message::MatchRule};
use proton_omarchy_protocol::{AccountStatus, ConnectionStatus, StateSnapshot};
use serde_json::{json, Value};
use std::{collections::HashSet, thread, time::Duration};
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
    tokio::spawn(monitor_connection(
        state_tx.subscribe(),
        backend.clone(),
        store.clone(),
    ));

    let (sleep_tx, sleep_rx) = mpsc::unbounded_channel();
    spawn_sleep_signal_monitor(sleep_tx);
    tokio::spawn(handle_sleep_signals(
        sleep_rx,
        state_tx.subscribe(),
        backend,
        store,
    ));
}

async fn monitor_connection(
    state_rx: watch::Receiver<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut owned_operations = None;
    loop {
        interval.tick().await;
        let before = state_rx.borrow().clone();
        if before.account.status != AccountStatus::SignedIn {
            owned_operations = None;
            continue;
        }
        if !before.operations.active.is_empty() {
            continue;
        }
        let Ok(observed) = backend
            .request(LIFECYCLE_CLIENT_ID, "connection.observe", json!({}))
            .await
        else {
            continue;
        };
        match observed.get("status").and_then(Value::as_str) {
            Some("connected") if observed.get("owned").and_then(Value::as_bool) == Some(true) => {
                owned_operations = Some(
                    before
                        .operations
                        .recent
                        .iter()
                        .map(|operation| operation.id.clone())
                        .collect::<HashSet<_>>(),
                );
            }
            Some("disconnected" | "error") => {
                if let Some(baseline) = owned_operations.take() {
                    if !connection_sequence_interrupted(
                        &state_rx.borrow(),
                        &baseline,
                        LIFECYCLE_CLIENT_ID,
                    ) {
                        reconnect_after_resume(&backend, &store, &state_rx, true).await;
                    }
                }
            }
            Some("connected") => owned_operations = None,
            _ => {}
        }
    }
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

    let initial_operations: HashSet<_> = state_rx
        .borrow()
        .operations
        .recent
        .iter()
        .map(|operation| operation.id.clone())
        .collect();
    let mut changes = state_rx.clone();
    for delay in RESUME_RETRY_DELAYS {
        if !delay.is_zero() {
            let sleep = tokio::time::sleep(*delay);
            tokio::pin!(sleep);
            loop {
                if connection_sequence_interrupted(
                    &changes.borrow(),
                    &initial_operations,
                    LIFECYCLE_CLIENT_ID,
                ) || (!was_active && !store.auto_connect_enabled())
                {
                    return;
                }
                tokio::select! {
                    biased;
                    changed = changes.changed() => if changed.is_err() { return; },
                    _ = &mut sleep => break,
                }
            }
        }
        if connection_sequence_interrupted(
            &changes.borrow(),
            &initial_operations,
            LIFECYCLE_CLIENT_ID,
        ) {
            return;
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
        if vpn_is_active(&state_rx.borrow())
            || connection_sequence_interrupted(
                &changes.borrow(),
                &initial_operations,
                LIFECYCLE_CLIENT_ID,
            )
            || (!was_active && !store.auto_connect_enabled())
        {
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
        match backend
            .request(LIFECYCLE_CLIENT_ID, "connection.connect", params)
            .await
        {
            Ok(_) => {
                record_recent(store, &resolved);
                return;
            }
            Err(error) if !error.retryable || is_cancelled_error(&error.code) => return,
            Err(_) => {}
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
    use crate::{
        backend::{BackendError, BackendFlavor},
        operations::OperationCoordinator,
    };

    async fn assert_resume_retry(
        error: BackendError,
        manual_action: Option<&str>,
        should_retry: bool,
    ) {
        let root = std::env::temp_dir().join(format!("proton-resume-{}", uuid::Uuid::new_v4()));
        let (state, receiver) = watch::channel(StateSnapshot::default());
        let operations = OperationCoordinator::new(state.clone());
        let store = StoreHandle::open(
            root.join("state.json"),
            &root.join("legacy.json"),
            root.join("config/proton-vpn-omarchy/lifecycle.json"),
            state.clone(),
            operations.clone(),
        )
        .unwrap();
        state.send_modify(|state| state.account.status = AccountStatus::SignedIn);
        let (tx, mut requests) = mpsc::channel(16);
        let backend = BackendHandle::new(tx, operations.clone(), BackendFlavor::Native);
        let task = tokio::spawn(async move {
            reconnect_after_resume(&backend, &store, &receiver, true).await;
        });
        let observe = requests.recv().await.unwrap();
        assert_eq!(observe.method, "connection.observe");
        observe.reply.send(Ok(json!({}))).unwrap();
        let connect = requests.recv().await.unwrap();
        assert_eq!(connect.method, "connection.connect");
        connect.reply.send(Err(error)).unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        if let Some(method) = manual_action {
            let lease = operations.begin("manual-client", method).unwrap();
            operations.finish(lease, Ok(()));
        }
        let next = tokio::time::timeout(Duration::from_secs(60), requests.recv()).await;
        let retried = matches!(next, Ok(Some(_)));
        if should_retry {
            if let Ok(Some(observe)) = next {
                assert_eq!(observe.method, "connection.observe");
                observe.reply.send(Ok(json!({}))).unwrap();
                let connect = requests.recv().await.unwrap();
                assert_eq!(connect.method, "connection.connect");
                connect.reply.send(Ok(json!({}))).unwrap();
            }
        }
        task.abort();
        let _ = task.await;
        std::fs::remove_dir_all(root).unwrap();
        assert!(retried == should_retry, "unexpected resume retry decision");
    }

    #[tokio::test(start_paused = true)]
    async fn resume_does_not_retry_cancelled_or_permanent_connection_errors() {
        for error in [
            BackendError::new("connection_cancelled", "cancelled").retryable(true),
            BackendError::new("not_authenticated", "sign in"),
        ] {
            assert_resume_retry(error, None, false).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn manual_action_during_resume_backoff_stops_reconnection() {
        for method in [
            "connection.cancel",
            "connection.disconnect",
            "connection.connect",
            "account.logout",
        ] {
            assert_resume_retry(
                BackendError::new("network_conflict_detected", "network is starting")
                    .retryable(true),
                Some(method),
                false,
            )
            .await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resume_still_retries_transient_connection_errors() {
        assert_resume_retry(
            BackendError::new("network_conflict_detected", "network is starting").retryable(true),
            None,
            true,
        )
        .await;
    }

    #[test]
    fn resume_restores_only_an_active_or_auto_connected_session() {
        assert!(should_reconnect(true, false));
        assert!(should_reconnect(true, true));
        assert!(should_reconnect(false, true));
        assert!(!should_reconnect(false, false));
    }
    async fn assert_unexpected_disconnect(manual: Option<&str>, owned: bool, recover: bool) {
        let root = std::env::temp_dir().join(format!("proton-monitor-{}", uuid::Uuid::new_v4()));
        let (state, receiver) = watch::channel(StateSnapshot::default());
        let operations = OperationCoordinator::new(state.clone());
        let store = StoreHandle::open(
            root.join("state.json"),
            &root.join("legacy.json"),
            root.join("config/proton-vpn-omarchy/lifecycle.json"),
            state.clone(),
            operations.clone(),
        )
        .unwrap();
        state.send_modify(|s| {
            s.account.status = AccountStatus::SignedIn;
            s.connection.status = ConnectionStatus::Connected;
        });
        let (tx, mut requests) = mpsc::channel(16);
        let backend = BackendHandle::new(tx, operations.clone(), BackendFlavor::Native);
        let task = tokio::spawn(monitor_connection(receiver, backend, store));
        let request = requests.recv().await.unwrap();
        assert_eq!(request.method, "connection.observe");
        request
            .reply
            .send(Ok(json!({"status":"connected", "owned": owned})))
            .unwrap();
        tokio::task::yield_now().await;
        if let Some(method) = manual {
            let lease = operations.begin("user", method).unwrap();
            operations.finish(lease, Ok(()));
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        let request = requests.recv().await.unwrap();
        assert_eq!(request.method, "connection.observe");
        state.send_modify(|s| s.connection.status = ConnectionStatus::Disconnected);
        request
            .reply
            .send(Ok(json!({"status":"disconnected", "owned":false})))
            .unwrap();
        if recover {
            let request = requests.recv().await.unwrap();
            assert_eq!(request.method, "connection.observe");
            request
                .reply
                .send(Ok(json!({"status":"disconnected"})))
                .unwrap();
            let request = requests.recv().await.unwrap();
            assert_eq!(request.method, "connection.connect");
            state.send_modify(|s| s.connection.status = ConnectionStatus::Connected);
            request.reply.send(Ok(json!({}))).unwrap();
        } else {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), requests.recv())
                    .await
                    .is_err()
            );
        }
        task.abort();
        let _ = task.await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unexpected_owned_tunnel_drop_reconnects_without_auto_connect() {
        assert_unexpected_disconnect(None, true, true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_does_not_reconnect_after_manual_actions_or_an_external_vpn() {
        for action in [
            "connection.disconnect",
            "connection.cancel",
            "account.logout",
        ] {
            assert_unexpected_disconnect(Some(action), true, false).await;
        }
        assert_unexpected_disconnect(None, false, false).await;
    }
}
