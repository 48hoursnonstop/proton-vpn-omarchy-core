use crate::{backend::BackendHandle, store::StoreHandle};
use proton_omarchy_protocol::{AccountStatus, ConnectionStatus, StateSnapshot};
use serde_json::{json, Value};
use tokio::sync::watch;

const AUTOCONNECT_CLIENT_ID: &str = "agent-autoconnect";

pub fn spawn(backend: BackendHandle, store: StoreHandle, state_rx: watch::Receiver<StateSnapshot>) {
    tokio::spawn(run(backend, store, state_rx));
}

async fn run(
    backend: BackendHandle,
    store: StoreHandle,
    mut state_rx: watch::Receiver<StateSnapshot>,
) {
    // Capture the observed state before the request: restoration can finish
    // while account.get is returning an earlier signed-out/pending snapshot.
    let mut previous_auto_connect = store.auto_connect_enabled();
    let mut previous_account = state_rx.borrow_and_update().account.status;
    if store.auto_connect_enabled() {
        attempt(&backend, &store, &state_rx).await;
    }
    while state_rx.changed().await.is_ok() {
        let snapshot = state_rx.borrow_and_update().clone();
        let auto_connect = snapshot.store.auto_connect;
        let signed_in_now = snapshot.account.status == AccountStatus::SignedIn;
        let signed_in_before = previous_account == AccountStatus::SignedIn;
        let enabled_now = auto_connect && !previous_auto_connect;
        let session_became_ready = auto_connect && signed_in_now && !signed_in_before;

        previous_auto_connect = auto_connect;
        previous_account = snapshot.account.status;
        if enabled_now || session_became_ready {
            attempt(&backend, &store, &state_rx).await;
            previous_auto_connect = store.auto_connect_enabled();
            previous_account = state_rx.borrow().account.status;
        }
    }
}

async fn attempt(
    backend: &BackendHandle,
    store: &StoreHandle,
    state_rx: &watch::Receiver<StateSnapshot>,
) {
    if !store.auto_connect_enabled() {
        return;
    }

    let account = match backend
        .request(AUTOCONNECT_CLIENT_ID, "account.get", json!({}))
        .await
    {
        Ok(account) => account,
        Err(_) => return,
    };
    if !account
        .get("logged_in")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return;
    }

    if backend
        .request(AUTOCONNECT_CLIENT_ID, "connection.observe", json!({}))
        .await
        .is_err()
    {
        return;
    }
    if matches!(
        state_rx.borrow().connection.status,
        ConnectionStatus::Connecting | ConnectionStatus::Connected
    ) {
        return;
    }
    if !store.auto_connect_enabled() {
        return;
    }

    let resolved = match store.request(AUTOCONNECT_CLIENT_ID, "connection.resolve", json!({})) {
        Ok(resolved) => resolved,
        Err(_) => return,
    };
    let params = resolved
        .get("connect_params")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if backend
        .request(AUTOCONNECT_CLIENT_ID, "connection.connect", params)
        .await
        .is_ok()
    {
        if let Some(recent) = resolved.get("recent") {
            let _ = store.request(
                AUTOCONNECT_CLIENT_ID,
                "recents.record",
                json!({ "recent": recent }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::{BackendFlavor, BackendRequest},
        operations::OperationCoordinator,
        state_reducer::apply_event,
    };
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn recovery_during_initial_account_request_still_auto_connects_once() {
        let root =
            std::env::temp_dir().join(format!("proton-autoconnect-{}", uuid::Uuid::new_v4()));
        let (state_tx, state_rx) = watch::channel(StateSnapshot::default());
        let operations = OperationCoordinator::new(state_tx.clone());
        let store = StoreHandle::open(
            root.join("data/state.json"),
            &root.join("legacy.json"),
            root.join("config/proton-vpn-omarchy/lifecycle.json"),
            state_tx.clone(),
            operations.clone(),
        )
        .unwrap();
        store
            .request("test", "preferences.set", json!({"auto_connect": true}))
            .unwrap();
        apply_event(
            &state_tx,
            &operations,
            &store,
            "account",
            json!({"status": "restoring"}),
        );
        let (tx, mut requests) = mpsc::channel::<BackendRequest>(16);
        let backend = BackendHandle::new(tx, operations.clone(), BackendFlavor::Native);
        let task = tokio::spawn(run(backend, store.clone(), state_rx));
        let test = async {
            let first = requests.recv().await.unwrap();
            assert_eq!(first.method, "account.get");
            // The account becomes available before the old reply is delivered.
            apply_event(
                &state_tx,
                &operations,
                &store,
                "account",
                json!({
                    "status": "signed_in", "name": "synthetic-account", "tier": 2,
                }),
            );
            first.reply.send(Ok(json!({"logged_in": false}))).unwrap();
            let account = requests.recv().await.unwrap();
            assert_eq!(account.method, "account.get");
            account.reply.send(Ok(json!({"logged_in": true}))).unwrap();
            let observe = requests.recv().await.unwrap();
            assert_eq!(observe.method, "connection.observe");
            state_tx.send_modify(|state| state.connection.status = ConnectionStatus::Disconnected);
            observe.reply.send(Ok(json!({}))).unwrap();
            let connect = requests.recv().await.unwrap();
            assert_eq!(connect.method, "connection.connect");
            state_tx.send_modify(|state| state.connection.status = ConnectionStatus::Connected);
            connect.reply.send(Ok(json!({}))).unwrap();
            // Ordinary snapshots after recovery must not repeat the request.
            state_tx.send_modify(|state| state.revision += 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), requests.recv())
                    .await
                    .is_err()
            );
        };
        let result = tokio::time::timeout(Duration::from_secs(2), test).await;
        task.abort();
        let _ = task.await;
        std::fs::remove_dir_all(root).unwrap();
        result.expect("auto-connect must observe restored credentials");
    }
}
