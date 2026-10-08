use crate::{
    backend::{BackendError, BackendHandle},
    store::StoreHandle,
};
use proton_omarchy_protocol::{AccountStatus, ConnectionStatus, OperationStatus, StateSnapshot};
use serde_json::{json, Value};
use std::{collections::HashSet, time::Duration};
use tokio::sync::watch;

const AUTOCONNECT_CLIENT_ID: &str = "agent-autoconnect";
const MAX_ATTEMPTS: usize = 8;

enum AttemptOutcome {
    WaitingForAccount,
    Finished,
    Interrupted,
}

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
    let mut user_stopped = false;
    if store.auto_connect_enabled() {
        match attempt(&backend, &store, &state_rx).await {
            // Do not treat restoration observed during an attempted connection
            // as a second sign-in event (especially after user cancellation).
            AttemptOutcome::Finished => previous_account = state_rx.borrow().account.status,
            AttemptOutcome::Interrupted => user_stopped = true,
            AttemptOutcome::WaitingForAccount => {}
        }
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
        if enabled_now {
            user_stopped = false;
        }
        if enabled_now || (session_became_ready && !user_stopped) {
            if matches!(
                attempt(&backend, &store, &state_rx).await,
                AttemptOutcome::Interrupted
            ) {
                user_stopped = true;
            }
            previous_auto_connect = store.auto_connect_enabled();
            previous_account = state_rx.borrow().account.status;
        }
    }
}

async fn attempt(
    backend: &BackendHandle,
    store: &StoreHandle,
    state_rx: &watch::Receiver<StateSnapshot>,
) -> AttemptOutcome {
    let initial_operations: HashSet<_> = {
        let state = state_rx.borrow();
        state
            .operations
            .recent
            .iter()
            .map(|operation| operation.id.clone())
            .collect()
    };
    let mut authenticated = false;
    let mut changes = state_rx.clone();
    for index in 0..MAX_ATTEMPTS {
        if user_interrupted(&changes.borrow(), &initial_operations) {
            return AttemptOutcome::Interrupted;
        }
        if !store.auto_connect_enabled() {
            break;
        }
        let result = attempt_once(
            backend,
            store,
            state_rx,
            &initial_operations,
            &mut authenticated,
        )
        .await;
        if user_interrupted(&changes.borrow(), &initial_operations) {
            return AttemptOutcome::Interrupted;
        }
        if matches!(result, Err(ref error) if matches!(error.code.as_str(), "connection_cancelled" | "operation_cancelled" | "cancelled"))
        {
            return AttemptOutcome::Interrupted;
        }
        if !matches!(result, Err(ref error) if error.retryable && !matches!(error.code.as_str(), "connection_cancelled" | "operation_cancelled" | "cancelled"))
            || index + 1 == MAX_ATTEMPTS
        {
            break;
        }
        // Retry transient boot/network failures without a frontend or a Wi-Fi
        // dependency. Bound the entire sequence and back off to avoid hammering
        // Proton while the network is coming up.
        let delay = Duration::from_secs((5_u64 << index).min(60));
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            if user_interrupted(&changes.borrow(), &initial_operations) {
                return AttemptOutcome::Interrupted;
            }
            if !store.auto_connect_enabled()
                || matches!(
                    changes.borrow().connection.status,
                    ConnectionStatus::Connected
                )
            {
                return AttemptOutcome::Finished;
            }
            tokio::select! {
                biased;
                changed = changes.changed() => if changed.is_err() { return AttemptOutcome::Finished; },
                _ = &mut sleep => break,
            }
        }
    }
    if authenticated {
        AttemptOutcome::Finished
    } else {
        AttemptOutcome::WaitingForAccount
    }
}

fn user_interrupted(state: &StateSnapshot, initial: &HashSet<String>) -> bool {
    state
        .operations
        .active
        .iter()
        .chain(&state.operations.recent)
        .any(|operation| {
            !initial.contains(&operation.id)
                && (operation.stage == "tunnel.cancelling"
                    || operation.state == OperationStatus::Cancelled
                    || (operation.initiator_client_instance_id != AUTOCONNECT_CLIENT_ID
                        && matches!(
                            operation.kind.as_str(),
                            "connection.connect"
                                | "connection.cancel"
                                | "connection.disconnect"
                                | "account.logout"
                        )))
        })
}

async fn attempt_once(
    backend: &BackendHandle,
    store: &StoreHandle,
    state_rx: &watch::Receiver<StateSnapshot>,
    initial_operations: &HashSet<String>,
    authenticated: &mut bool,
) -> Result<(), BackendError> {
    if !store.auto_connect_enabled() {
        return Ok(());
    }

    let account = match backend
        .request(AUTOCONNECT_CLIENT_ID, "account.get", json!({}))
        .await
    {
        Ok(account) => account,
        Err(error) => return Err(error),
    };
    if !account
        .get("logged_in")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    *authenticated = true;

    backend
        .request(AUTOCONNECT_CLIENT_ID, "connection.observe", json!({}))
        .await?;
    if matches!(
        state_rx.borrow().connection.status,
        ConnectionStatus::Connecting | ConnectionStatus::Connected
    ) {
        return Ok(());
    }
    if !store.auto_connect_enabled() || user_interrupted(&state_rx.borrow(), initial_operations) {
        return Ok(());
    }

    let resolved = match store.request(AUTOCONNECT_CLIENT_ID, "connection.resolve", json!({})) {
        Ok(resolved) => resolved,
        Err(error) => return Err(error),
    };
    let params = resolved
        .get("connect_params")
        .cloned()
        .unwrap_or_else(|| json!({}));
    backend
        .request(AUTOCONNECT_CLIENT_ID, "connection.connect", params)
        .await?;
    if let Some(recent) = resolved.get("recent") {
        let _ = store.request(
            AUTOCONNECT_CLIENT_ID,
            "recents.record",
            json!({ "recent": recent }),
        );
    }
    Ok(())
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

    struct Fixture {
        root: std::path::PathBuf,
        state: watch::Sender<StateSnapshot>,
        store: StoreHandle,
        operations: OperationCoordinator,
        requests: mpsc::Receiver<BackendRequest>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("proton-boot-retry-{}", uuid::Uuid::new_v4()));
            let (state, receiver) = watch::channel(StateSnapshot::default());
            let operations = OperationCoordinator::new(state.clone());
            let store = StoreHandle::open(
                root.join("state.json"),
                &root.join("legacy.json"),
                root.join("lifecycle.json"),
                state.clone(),
                operations.clone(),
            )
            .unwrap();
            store
                .request("test", "preferences.set", json!({"auto_connect": true}))
                .unwrap();
            state.send_modify(|snapshot| snapshot.account.status = AccountStatus::SignedIn);
            let (tx, requests) = mpsc::channel(16);
            let backend = BackendHandle::new(tx, operations.clone(), BackendFlavor::Native);
            let task = tokio::spawn(run(backend, store.clone(), receiver));
            Self {
                root,
                state,
                store,
                operations,
                requests,
                task,
            }
        }

        async fn respond(&mut self, error: Option<BackendError>) {
            let account = self.requests.recv().await.unwrap();
            assert_eq!(account.method, "account.get");
            self.state
                .send_modify(|state| state.account.status = AccountStatus::SignedIn);
            account.reply.send(Ok(json!({"logged_in": true}))).unwrap();
            let observe = self.requests.recv().await.unwrap();
            assert_eq!(observe.method, "connection.observe");
            self.state
                .send_modify(|state| state.connection.status = ConnectionStatus::Disconnected);
            observe.reply.send(Ok(json!({}))).unwrap();
            let connect = self.requests.recv().await.unwrap();
            assert_eq!(connect.method, "connection.connect");
            if let Some(error) = error {
                connect.reply.send(Err(error)).unwrap();
            } else {
                self.state
                    .send_modify(|state| state.connection.status = ConnectionStatus::Connected);
                connect.reply.send(Ok(json!({}))).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        async fn assert_idle(&mut self) {
            assert!(
                tokio::time::timeout(Duration::from_secs(600), self.requests.recv())
                    .await
                    .is_err()
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn transient() -> BackendError {
        BackendError::new("network_conflict_detected", "network is starting").retryable(true)
    }

    #[tokio::test(start_paused = true)]
    async fn transient_boot_failure_retries_without_panel_or_wifi() {
        let mut fixture = Fixture::new();
        let started = tokio::time::Instant::now();
        fixture.respond(Some(transient())).await;
        fixture.respond(None).await;
        assert!(started.elapsed() >= Duration::from_secs(5));
        fixture.assert_idle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn boot_retries_are_bounded_and_back_off() {
        let mut fixture = Fixture::new();
        let started = tokio::time::Instant::now();
        for _ in 0..MAX_ATTEMPTS {
            fixture.respond(Some(transient())).await;
        }
        assert!(started.elapsed() >= Duration::from_secs(255));
        fixture.assert_idle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn manual_disconnect_or_cancel_before_first_success_stops_boot_retries() {
        for method in [
            "connection.disconnect",
            "connection.cancel",
            "connection.connect",
        ] {
            let mut fixture = Fixture::new();
            fixture.respond(Some(transient())).await;
            let lease = fixture.operations.begin("manual-client", method).unwrap();
            fixture.operations.finish(lease, Ok(()));
            fixture.assert_idle().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabling_auto_connect_during_backoff_stops_retry() {
        let mut fixture = Fixture::new();
        fixture.respond(Some(transient())).await;
        fixture
            .store
            .request("test", "preferences.set", json!({"auto_connect": false}))
            .unwrap();
        fixture.assert_idle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_and_permanent_errors_do_not_retry() {
        for error in [
            BackendError::new("connection_cancelled", "cancelled").retryable(true),
            BackendError::new("not_authenticated", "sign in"),
        ] {
            let mut fixture = Fixture::new();
            fixture.respond(Some(error)).await;
            fixture.assert_idle().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_initial_restore_does_not_rearm_autoconnect() {
        let mut fixture = Fixture::new();
        fixture
            .state
            .send_modify(|state| state.account.status = AccountStatus::Restoring);
        fixture
            .respond(Some(BackendError::new(
                "connection_cancelled",
                "user cancelled",
            )))
            .await;
        fixture.assert_idle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_before_account_restore_survives_the_sign_in_event() {
        let mut fixture = Fixture::new();
        fixture
            .state
            .send_modify(|state| state.account.status = AccountStatus::Restoring);
        let account = fixture.requests.recv().await.unwrap();
        assert_eq!(account.method, "account.get");
        let lease = fixture
            .operations
            .begin("manual-client", "connection.cancel")
            .unwrap();
        fixture.operations.finish(lease, Ok(()));
        account.reply.send(Ok(json!({"logged_in": false}))).unwrap();
        fixture
            .state
            .send_modify(|state| state.account.status = AccountStatus::SignedIn);
        fixture.assert_idle().await;
        fixture
            .store
            .request("test", "preferences.set", json!({"auto_connect": false}))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        fixture
            .store
            .request("test", "preferences.set", json!({"auto_connect": true}))
            .unwrap();
        fixture.respond(None).await;
        fixture.assert_idle().await;
    }

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
