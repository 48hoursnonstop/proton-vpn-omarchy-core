use super::{
    api::{ApiSession, ProtonApi},
    network::{NetworkManagerBackend, ProtunProfile, TunnelState, VpnProfile},
    *,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::seq::SliceRandom;
use reqwest::Method;
use tokio::sync::{oneshot, OwnedMutexGuard};

mod dns;

// Public Proton Android bootstrap data, pinned in the source/package rather
// than accepted as unsigned input from the network or a writable cache.
const BUILTIN_SERVERS: &str = include_str!("guest_hole_servers.json");
const MAX_ATTEMPTS: usize = 5;

#[derive(Clone, Debug)]
pub(super) struct Endpoint {
    pub name: String,
    pub ip: String,
    pub public_key: String,
}

#[derive(Clone)]
pub(super) struct Operation {
    id: String,
    method: String,
    generation: u64,
}

#[derive(Clone, Default)]
pub(super) struct Recovery {
    lock: Arc<Mutex<()>>,
    generation: Arc<AtomicU64>,
}

pub(super) fn interface_name() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("pvgh{}", unsafe { libc::getuid() })
}

impl Recovery {
    pub async fn idle(&self) -> OwnedMutexGuard<()> {
        self.lock.clone().lock_owned().await
    }

    pub fn cancel(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub fn operation(&self, events: &EventSink) -> Option<Operation> {
        let state = events.state_tx.borrow();
        let active = state.operations.active.iter().find(|op| {
            matches!(
                op.kind.as_str(),
                "account.login"
                    | "account.submit_2fa"
                    | "account.authenticate_fido2"
                    | "account.refresh"
                    | "connection.connect"
            )
        })?;
        if active.stage.contains("cancelling") {
            return None;
        }
        Some(Operation {
            id: active.id.clone(),
            method: active.kind.clone(),
            generation: self.generation.load(Ordering::SeqCst),
        })
    }

    fn cancelled(&self, api: &ProtonApi, operation: &Operation) -> bool {
        self.generation.load(Ordering::SeqCst) != operation.generation
            || !api
                .events
                .state_tx
                .borrow()
                .operations
                .active
                .iter()
                .any(|op| op.id == operation.id && !op.stage.contains("cancelling"))
    }

    pub async fn request(
        &self,
        api: ProtonApi,
        operation: Operation,
        method: Method,
        endpoint: String,
        body: Option<Value>,
        session: Option<ApiSession>,
    ) -> NativeResult<Value> {
        let recovery = self.clone();
        let (mut reply, result) = oneshot::channel();
        // This worker retains the mutex until NetworkManager activation has
        // finished and cleanup has run, even if the requesting future is dropped.
        tokio::spawn(async move {
            let _guard = tokio::select! {
                guard = recovery.idle() => guard,
                _ = reply.closed() => return,
            };
            let result = recovery
                .run(
                    &api,
                    &operation,
                    &method,
                    &endpoint,
                    body,
                    session.as_ref(),
                    &reply,
                )
                .await;
            let _ = reply.send(result);
        });
        result
            .await
            .map_err(|_| NativeError::new("guest_hole_failed", "The recovery request stopped"))?
    }

    async fn run(
        &self,
        api: &ProtonApi,
        op: &Operation,
        method: &Method,
        endpoint: &str,
        body: Option<Value>,
        session: Option<&ApiSession>,
        reply: &oneshot::Sender<NativeResult<Value>>,
    ) -> NativeResult<Value> {
        let cancelled = || reply.is_closed() || self.cancelled(api, op);
        if cancelled() {
            return Err(cancelled_error());
        }
        let network = NetworkManagerBackend;
        tokio::task::spawn_blocking(move || {
            if network.observe()?.state != TunnelState::Disconnected
                || !network.conflicting_interfaces()?.is_empty()
            {
                return Err(NativeError::new(
                    "guest_hole_vpn_active",
                    "Disconnect the existing VPN before API recovery",
                ));
            }
            if network.network_blocked()? {
                return Err(NativeError::new(
                    "guest_hole_network_blocked",
                    "The active kill switch blocks temporary API recovery",
                ));
            }
            Ok::<_, NativeError>(())
        })
        .await
        .map_err(join_error)??;
        let endpoints = recovery_endpoints()?;
        let mut last_error =
            NativeError::new("guest_hole_unavailable", "No recovery server is available")
                .retryable(true);
        for target in endpoints.into_iter().take(MAX_ATTEMPTS) {
            if cancelled() {
                return Err(cancelled_error());
            }
            api.events.stage(&op.method, "guest_hole.connecting", true);
            let profile = VpnProfile::Protun(ProtunProfile::guest(&target)?);
            let uuid = profile.uuid().to_owned();
            let started =
                tokio::task::spawn_blocking(move || NetworkManagerBackend.connect(&profile))
                    .await
                    .map_err(join_error)
                    .and_then(|result| result);
            let attempted = match started {
                Ok(_) => {
                    let action = async {
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                        loop {
                            if cancelled() {
                                return Err(cancelled_error());
                            }
                            let uuid = uuid.clone();
                            let observation = tokio::task::spawn_blocking(move || {
                                NetworkManagerBackend.observe_uuid(&uuid)
                            })
                            .await
                            .map_err(join_error)??;
                            match observation.state {
                                TunnelState::Connected => break,
                                TunnelState::Error => {
                                    return Err(NativeError::new(
                                        "guest_hole_failed",
                                        "The recovery tunnel did not start",
                                    )
                                    .retryable(true))
                                }
                                _ => {}
                            }
                            if tokio::time::Instant::now() >= deadline {
                                return Err(NativeError::new(
                                    "guest_hole_timeout",
                                    "The recovery tunnel timed out",
                                )
                                .retryable(true));
                            }
                            tokio::time::sleep(Duration::from_millis(125)).await;
                        }
                        let addresses = dns::resolve_api(&interface_name()).await?;
                        if cancelled() {
                            return Err(cancelled_error());
                        }
                        api.events.stage(&op.method, "guest_hole.requesting", true);
                        let bound = api.for_guest_hole(&interface_name(), &addresses)?;
                        let request =
                            bound.request_direct(method.clone(), endpoint, body.clone(), session);
                        tokio::pin!(request);
                        let timeout = tokio::time::sleep(Duration::from_secs(30));
                        tokio::pin!(timeout);
                        loop {
                            tokio::select! {
                                result = &mut request => return result,
                                _ = &mut timeout => return Err(NativeError::new("guest_hole_timeout", "The recovery API request timed out").retryable(true)),
                                _ = tokio::time::sleep(Duration::from_millis(125)) => if cancelled() { return Err(cancelled_error()); },
                            }
                        }
                    };
                    action.await
                }
                Err(error) => Err(error),
            };
            api.events
                .stage(&op.method, "guest_hole.cleaning_up", false);
            // Cleanup precedes every return and every subsequent candidate.
            tokio::task::spawn_blocking(move || NetworkManagerBackend.disconnect_uuid(&uuid))
                .await
                .map_err(join_error)?
                .map_err(|error| {
                    NativeError::new(
                        "guest_hole_cleanup_failed",
                        "The temporary recovery tunnel could not be removed",
                    )
                    .with_source(error)
                })?;
            match attempted {
                Ok(value) => return Ok(value),
                Err(error) if error.code == "guest_hole_cancelled" => return Err(error),
                Err(error)
                    if !transport_failure(&error.code)
                        && !error.code.starts_with("guest_hole_") =>
                {
                    return Err(error)
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

pub(super) fn transport_failure(code: &str) -> bool {
    matches!(
        code,
        "api_unreachable" | "tls_pin_mismatch" | "api_response_invalid" | "api_response_too_large"
    )
}

fn cancelled_error() -> NativeError {
    NativeError::new(
        "guest_hole_cancelled",
        "Temporary API recovery was cancelled",
    )
}

fn builtin_endpoints() -> NativeResult<Vec<Endpoint>> {
    let servers: Vec<Value> = serde_json::from_str(BUILTIN_SERVERS).map_err(|error| {
        NativeError::new(
            "guest_hole_invalid_bootstrap",
            "The bundled recovery catalog is invalid",
        )
        .with_source(error)
    })?;
    let mut endpoints = Vec::new();
    for logical in servers {
        for server in logical
            .get("Servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // Linux ProTun v1 cannot express Windows relay/bouncing labels.
            // Retain direct entries and skip relay-only bootstrap entries.
            let ip = server.get("EntryIP").and_then(Value::as_str);
            let key = server.get("X25519PublicKey").and_then(Value::as_str);
            if let (Some(ip), Some(key)) = (ip, key) {
                if ip.parse::<std::net::Ipv4Addr>().is_ok()
                    && BASE64.decode(key).is_ok_and(|bytes| bytes.len() == 32)
                {
                    endpoints.push(Endpoint {
                        name: logical
                            .get("Name")
                            .and_then(Value::as_str)
                            .unwrap_or("Recovery")
                            .to_owned(),
                        ip: ip.into(),
                        public_key: key.into(),
                    });
                }
            }
        }
    }
    if endpoints.is_empty() {
        return Err(NativeError::new(
            "guest_hole_unavailable",
            "The bundled recovery catalog has no Stealth endpoints",
        ));
    }
    Ok(endpoints)
}

fn recovery_endpoints() -> NativeResult<Vec<Endpoint>> {
    let mut builtin = builtin_endpoints()?;
    builtin.shuffle(&mut rand::rng());
    let mut endpoints = Vec::new();
    if let Ok(paths) = Paths::discover() {
        if let Ok(mut catalog) = ServerCatalog::load(&paths.catalog) {
            catalog.logical_servers.shuffle(&mut rand::rng());
            for server in catalog.logical_servers.iter().filter(|server| {
                server.enabled() && server.features & models::FEATURE_NON_STANDARD == 0
            }) {
                if let Some(physical) = server.servers.iter().find(|physical| {
                    physical.status == 1 && server_validation::validate(physical).is_ok()
                }) {
                    endpoints.push(Endpoint {
                        name: server.name.clone(),
                        ip: physical.entry_ip.clone(),
                        public_key: physical.x25519_public_key.clone(),
                    });
                    if endpoints.len() == 3 {
                        break;
                    }
                }
            }
        }
    }
    endpoints.extend(builtin.into_iter().take(MAX_ATTEMPTS - endpoints.len()));
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn bundled_recovery_endpoints_are_pinned_and_have_valid_keys() {
        assert_eq!(
            format!("{:x}", Sha256::digest(BUILTIN_SERVERS.as_bytes())),
            "5cd4a67c0413b6afd54a285a48c8668700a277e06482eee76f5525c67ca22ac2"
        );
        assert!(!builtin_endpoints().unwrap().is_empty());
        assert!(!transport_failure("invalid_credentials"));
        assert!(!transport_failure("authentication_expired"));
        assert!(transport_failure("api_unreachable"));
    }
    fn fixture() -> (PathBuf, EventSink) {
        let root = env::temp_dir().join(format!("proton-guest-test-{}", uuid::Uuid::new_v4()));
        let (state_tx, _) = watch::channel(proton_omarchy_protocol::StateSnapshot::default());
        let operations = crate::operations::OperationCoordinator::new(state_tx.clone());
        let store = StoreHandle::open(
            root.join("state.json"),
            &root.join("legacy.json"),
            root.join("config/proton-vpn-omarchy/lifecycle.json"),
            state_tx.clone(),
            operations.clone(),
        )
        .unwrap();
        (
            root,
            EventSink {
                state_tx,
                operations,
                store,
            },
        )
    }

    #[tokio::test]
    async fn background_reads_and_signout_never_authorize_a_recovery_tunnel() {
        let (root, events) = fixture();
        let recovery = Recovery::default();
        assert!(recovery.operation(&events).is_none());
        let lease = events
            .operations
            .begin("fixture", "account.logout")
            .unwrap();
        assert!(recovery.operation(&events).is_none());
        events.operations.finish(lease, Ok(()));
        let lease = events.operations.begin("fixture", "account.login").unwrap();
        assert!(recovery.operation(&events).is_some());
        events.operations.finish(lease, Ok(()));
        assert!(recovery.operation(&events).is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancellation_and_completed_operations_stop_before_network_access() {
        for cancel in [false, true] {
            let (root, events) = fixture();
            let api = ProtonApi::new(events.clone()).unwrap();
            let recovery = Recovery::default();
            let lease = events
                .operations
                .begin("fixture", "connection.connect")
                .unwrap();
            let operation = recovery.operation(&events).unwrap();
            if cancel {
                recovery.cancel();
            } else {
                events.operations.finish(lease, Ok(()));
            }
            let result = recovery
                .request(api, operation, Method::GET, "/vpn/v2".into(), None, None)
                .await;
            assert_eq!(result.unwrap_err().code, "guest_hole_cancelled");
            fs::remove_dir_all(root).unwrap();
        }
    }
}
