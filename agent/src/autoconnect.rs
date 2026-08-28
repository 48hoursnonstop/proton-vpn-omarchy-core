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
    if store.auto_connect_enabled() {
        attempt(&backend, &store, &state_rx).await;
    }

    let mut previous_auto_connect = store.auto_connect_enabled();
    let mut previous_account = state_rx.borrow().account.status;
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
