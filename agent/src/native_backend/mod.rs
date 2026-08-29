mod alternative_routing;
mod api;
mod apps;
mod catalog;
mod fido2;
mod lifecycle;
mod local_agent;
mod models;
mod network;
mod secret_store;
mod session_bootstrap;
mod settings_store;
mod split_tunnel;
mod support;
mod system_launch;
mod telemetry;
mod web_auth;

use crate::{
    backend::{BackendError, BackendFlavor, BackendHandle, BackendRequest},
    operations::OperationCoordinator,
    state_reducer::apply_event,
    store::StoreHandle,
};
use api::{ApiSession, ProtonApi};
use catalog::ConnectionTarget;
use ipnet::IpNet;
use local_agent::{AgentSnapshot, AgentUpdate, RunningAgent};
use models::{ClientConfig, NativeSettings, ServerCatalog, SessionData, SplitTunnelingConfig};
use network::{NetworkManagerBackend, TunnelObservation, TunnelState, VpnProfile};
use proton_omarchy_protocol::{OperationDomain, StateSnapshot};
use secret_store::SecretStore;
use serde_json::{json, Value};
use split_tunnel::SplitTunnelBackend;
use std::{
    collections::HashSet,
    env, fmt, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use zeroize::Zeroizing;

const NATIVE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/rust-v2");
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(45);
const LOCAL_AGENT_READY_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(125);
const PROTUN_DESCRIPTOR: &str = "/usr/lib/NetworkManager/VPN/nm-protun.name";
const OPENVPN_DESCRIPTOR: &str = "/usr/lib/NetworkManager/VPN/nm-openvpn-service.name";
const ACCOUNT_URL: &str = "https://account.protonvpn.com/account";
const SIGNUP_URL: &str = "https://account.protonvpn.com/signup";
const AUTO_LOGIN_BASE_URL: &str = "https://account.proton.me/lite";
const UPGRADE_CHILD_CLIENT_ID: &str = "web-account-lite";
const LAN_BYPASS_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];
const LOCAL_NAME_BYPASS_RANGES: &[&str] = &[
    "224.0.0.251/32", // mDNS
    "224.0.0.252/32", // LLMNR
    "ff02::fb/128",   // mDNS
    "ff02::1:3/128",  // LLMNR
];

pub type NativeResult<T> = Result<T, NativeError>;

#[derive(Debug)]
pub struct NativeError {
    code: String,
    message: String,
    details: Option<Value>,
    retryable: bool,
    source: Option<String>,
}

impl NativeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
            retryable: false,
            source: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_source(mut self, source: impl fmt::Display) -> Self {
        self.source = Some(source.to_string());
        self
    }

    fn backend_error(self) -> BackendError {
        let mut error = BackendError::new(self.code, self.message).retryable(self.retryable);
        let mut details = self
            .details
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        if let Some(source) = self.source {
            details.insert("source".into(), Value::String(source));
        }
        if !details.is_empty() {
            error = error.with_details(Value::Object(details));
        }
        error
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(formatter, "{}: {} ({source})", self.code, self.message),
            None => write!(formatter, "{}: {}", self.code, self.message),
        }
    }
}

#[derive(Clone)]
struct EventSink {
    state_tx: watch::Sender<StateSnapshot>,
    operations: OperationCoordinator,
    store: StoreHandle,
}

impl EventSink {
    fn emit(&self, event: &str, data: Value) {
        apply_event(&self.state_tx, &self.operations, &self.store, event, data);
    }

    fn stage(&self, method: &str, stage: &str, cancelable: bool) {
        self.emit(
            "operation.stage",
            json!({
                "method": method,
                "stage": stage,
                "cancelable": cancelable,
            }),
        );
    }

    fn stage_auth(&self, stage: &str) {
        self.operations
            .update_domain_stage(OperationDomain::AuthSession, stage, Some(false));
    }
}

#[derive(Clone, Debug)]
struct Paths {
    catalog: PathBuf,
    client_config: PathBuf,
    settings: PathBuf,
    statistics: PathBuf,
}

impl Paths {
    fn discover() -> NativeResult<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| NativeError::new("environment_invalid", "HOME is required"))?;
        let cache_home = env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"));
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        Ok(Self {
            catalog: cache_home.join("Proton/VPN/serverlist.json"),
            client_config: cache_home.join("Proton/VPN/clientconfig.json"),
            settings: config_home.join("Proton/VPN/settings.json"),
            statistics: config_home.join("Proton/VPN/statistical-events.json"),
        })
    }
}

#[derive(Debug)]
struct TrafficSample {
    rx: u64,
    tx: u64,
    observed_at: Instant,
}

#[derive(Default)]
struct RuntimeState {
    session: Option<SessionData>,
    catalog: Option<ServerCatalog>,
    client_config: Option<ClientConfig>,
    settings: NativeSettings,
    selected: Option<ConnectionTarget>,
    traffic: Option<TrafficSample>,
    connection_feedback_feature_enabled: bool,
    feedback_session: Option<telemetry::ConnectionFeedbackSession>,
    pending_connection_trigger: String,
}

struct NativeRuntime {
    events: EventSink,
    api: ProtonApi,
    secret_store: SecretStore,
    network: NetworkManagerBackend,
    split_tunnel: SplitTunnelBackend,
    paths: Paths,
    state: RwLock<RuntimeState>,
    network_write: Mutex<()>,
    settings_write: Mutex<()>,
    telemetry_write: Arc<Mutex<()>>,
    auth_write: Mutex<()>,
    pending_auth: Mutex<Option<ApiSession>>,
    fido_operation: Mutex<Option<Arc<fido2::FidoOperation>>>,
    local_agent: Mutex<Option<RunningAgent>>,
    local_agent_snapshot: RwLock<AgentSnapshot>,
    owned_connection_uuid: Mutex<Option<String>>,
    split_available: AtomicBool,
    destination_policy_available: AtomicBool,
    destination_policy_override: RwLock<Option<(bool, bool)>>,
    split_kill_switch_bypass_active: AtomicBool,
    split_route_write: Mutex<()>,
    connection_attempt: AtomicU64,
}

pub fn spawn(
    state_tx: watch::Sender<StateSnapshot>,
    operations: OperationCoordinator,
    store: StoreHandle,
) -> BackendHandle {
    let (tx, rx) = mpsc::channel(64);
    let events = EventSink {
        state_tx,
        operations: operations.clone(),
        store,
    };
    tokio::spawn(run(rx, events));
    BackendHandle::new(tx, operations, BackendFlavor::Native)
}

pub fn spawn_lifecycle(
    state_tx: watch::Sender<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
) {
    lifecycle::spawn(state_tx, backend, store, NetworkManagerBackend);
}

async fn run(mut rx: mpsc::Receiver<BackendRequest>, events: EventSink) {
    let paths = match Paths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            while let Some(request) = rx.recv().await {
                let _ = request.reply.send(Err(error_message(&error)));
            }
            return;
        }
    };
    let api = match ProtonApi::new(events.clone()) {
        Ok(api) => api,
        Err(error) => {
            while let Some(request) = rx.recv().await {
                let _ = request.reply.send(Err(error_message(&error)));
            }
            return;
        }
    };
    let runtime = Arc::new(NativeRuntime {
        events,
        api,
        secret_store: SecretStore,
        network: NetworkManagerBackend,
        split_tunnel: SplitTunnelBackend,
        paths,
        state: RwLock::new(RuntimeState::default()),
        network_write: Mutex::new(()),
        settings_write: Mutex::new(()),
        telemetry_write: Arc::new(Mutex::new(())),
        auth_write: Mutex::new(()),
        pending_auth: Mutex::new(None),
        fido_operation: Mutex::new(None),
        local_agent: Mutex::new(None),
        local_agent_snapshot: RwLock::new(AgentSnapshot::default()),
        owned_connection_uuid: Mutex::new(None),
        split_available: AtomicBool::new(false),
        destination_policy_available: AtomicBool::new(false),
        destination_policy_override: RwLock::new(None),
        split_kill_switch_bypass_active: AtomicBool::new(false),
        split_route_write: Mutex::new(()),
        connection_attempt: AtomicU64::new(0),
    });

    runtime.initialize().await;
    NativeRuntime::spawn_maintenance(&runtime);
    while let Some(request) = rx.recv().await {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            let result = runtime
                .dispatch(&request.method, request.params)
                .await
                .map_err(NativeError::backend_error);
            let _ = request.reply.send(result);
        });
    }
}

impl NativeRuntime {
    fn spawn_maintenance(runtime: &Arc<Self>) {
        let token_runtime = Arc::downgrade(runtime);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(12 * 60 * 60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(runtime) = token_runtime.upgrade() else {
                    return;
                };
                let _ = runtime.refresh_tokens().await;
            }
        });

        let certificate_runtime = Arc::downgrade(runtime);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(runtime) = certificate_runtime.upgrade() else {
                    return;
                };
                let _ = runtime.refresh_certificate_if_needed().await;
            }
        });

        let policy_runtime = Arc::downgrade(runtime);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(runtime) = policy_runtime.upgrade() else {
                    return;
                };
                if !runtime.destination_policy_available.load(Ordering::Acquire) {
                    continue;
                }
                let mut settings = runtime.state.read().await.settings.clone();
                if let Some((allow_lan, allow_local_dns)) =
                    *runtime.destination_policy_override.read().await
                {
                    settings.allow_lan_connections = allow_lan;
                    settings.allow_local_dns = allow_local_dns;
                }
                if settings.allow_lan_connections || settings.allow_local_dns {
                    if let Err(error) = runtime.apply_destination_policy(&settings).await {
                        eprintln!(
                            "proton-omarchy-agent: destination policy reconciliation failed: {error}"
                        );
                    }
                }
            }
        });

        let split_route_runtime = Arc::downgrade(runtime);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(runtime) = split_route_runtime.upgrade() else {
                    return;
                };
                if !runtime
                    .split_kill_switch_bypass_active
                    .load(Ordering::Acquire)
                {
                    continue;
                }
                let observation = match runtime.observe_blocking().await {
                    Ok(observation) => observation,
                    Err(_) => continue,
                };
                let settings = runtime.state.read().await.settings.clone();
                let active = observation.owned && observation.state == TunnelState::Connected;
                if let Err(error) = runtime
                    .reconcile_split_kill_switch_bypass(&settings, active)
                    .await
                {
                    eprintln!(
                        "proton-omarchy-agent: split/kill-switch route reconciliation failed: {error}"
                    );
                }
            }
        });
    }

    async fn initialize(self: &Arc<Self>) {
        let paths = self.paths.clone();
        let loaded = tokio::task::spawn_blocking(move || load_state(&paths)).await;
        let mut initialization_error = None;
        match loaded {
            Ok(Ok(state)) => *self.state.write().await = state,
            Ok(Err(error)) => initialization_error = Some(error.to_string()),
            Err(error) => {
                initialization_error = Some(format!("Rust backend initialization failed: {error}"))
            }
        }
        let state_loaded = initialization_error.is_none();

        self.api
            .set_alternative_routing(self.state.read().await.settings.alternative_routing)
            .await;

        self.emit_backend_state(initialization_error).await;
        self.emit_account().await;
        let split_tunnel = self.split_tunnel.clone();
        let split_available = tokio::task::spawn_blocking(move || split_tunnel.available())
            .await
            .unwrap_or(false);
        self.split_available
            .store(split_available, Ordering::Release);
        if split_available && state_loaded {
            let split_settings = self
                .state
                .read()
                .await
                .settings
                .features
                .split_tunneling
                .clone();
            let active = split_settings.config(&split_settings.mode);
            let split_tunnel = self.split_tunnel.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || {
                split_tunnel.apply(split_settings.enabled, &active)
            })
            .await
            .map_err(join_error)
            .and_then(|result| result)
            {
                eprintln!("proton-omarchy-agent: split policy recovery failed: {error}");
            }
        }
        let split_tunnel = self.split_tunnel.clone();
        let destination_policy_available =
            tokio::task::spawn_blocking(move || split_tunnel.destination_policy_available())
                .await
                .unwrap_or(false);
        self.destination_policy_available
            .store(destination_policy_available, Ordering::Release);
        if destination_policy_available {
            let settings = self.state.read().await.settings.clone();
            if let Err(error) = self.apply_destination_policy(&settings).await {
                eprintln!("proton-omarchy-agent: destination policy recovery failed: {error}");
            }
        }
        self.emit_features().await;

        match self.observe_blocking().await {
            Ok(observation) => {
                self.emit_connection(&observation, None).await;
                let manages_connection =
                    observation.owned || observation.state == TunnelState::Disconnected;
                if manages_connection {
                    let (mode, server_ip, ipv6_leak_protection) = {
                        let state = self.state.read().await;
                        (
                            state.settings.killswitch,
                            state
                                .selected
                                .as_ref()
                                .map(|target| target.physical.entry_ip.clone()),
                            state.settings.ipv6_leak_protection,
                        )
                    };
                    let kill_switch_result = self
                        .reconcile_kill_switch(
                            mode,
                            observation.state == TunnelState::Connected,
                            server_ip,
                            ipv6_leak_protection,
                        )
                        .await;
                    let combined_result = match kill_switch_result {
                        Ok(()) => {
                            let settings = self.state.read().await.settings.clone();
                            self.reconcile_split_kill_switch_bypass(
                                &settings,
                                observation.owned && observation.state == TunnelState::Connected,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    };
                    if let Err(error) = combined_result {
                        self.emit_connection(&observation, Some(&error.message))
                            .await;
                        if observation.owned {
                            *self.owned_connection_uuid.lock().await = observation.uuid.clone();
                            self.disconnect_after_local_agent_rejection().await;
                        }
                    } else if observation.owned && observation.state == TunnelState::Connected {
                        self.restore_owned_local_agent(&observation).await;
                    }
                }
            }
            Err(error) => self.events.emit(
                "connection",
                json!({
                    "observation_known": false,
                    "status": "unknown",
                    "server": null,
                    "protocol": self.state.read().await.settings.protocol,
                    "secure_core": false,
                    "error": error.message,
                }),
            ),
        }

        self.emit_device_location().await;
        if self.state.read().await.session.is_some() {
            let runtime = Arc::clone(self);
            tokio::spawn(async move {
                runtime.refresh_connection_feedback_flag().await;
                runtime.flush_statistics_queue().await;
            });
        }
    }

    async fn dispatch(self: &Arc<Self>, method: &str, params: Value) -> NativeResult<Value> {
        if !params.is_object() && !params.is_null() {
            return Err(NativeError::new(
                "invalid_params",
                "params must be a JSON object",
            ));
        }
        match method {
            "account.get" => {
                self.emit_account().await;
                self.emit_features().await;
                Ok(json!({ "logged_in": self.state.read().await.session.is_some() }))
            }
            "account.upgrade_url" => self.account_upgrade_url(params).await,
            "report_issue.categories.get" => self.report_issue_categories().await,
            "report_issue.submit" => self.report_issue_submit(params).await,
            "account.login" => self.account_login(params).await,
            "account.login_guest" => self.account_login_guest().await,
            "account.submit_2fa" => self.account_submit_2fa(params).await,
            "account.authenticate_fido2" => self.account_authenticate_fido2().await,
            "account.submit_fido2_pin" => self.account_submit_fido2_pin(params).await,
            "account.cancel_fido2" => self.account_cancel_fido2().await,
            "account.logout" => self.account_logout().await,
            "locations.get" => self.locations().await,
            "servers.get" => self.servers(&params).await,
            "protocol.set" => self.protocol_set(params).await,
            "feature.set" => self.feature_set(params).await,
            "dns.set" => self.dns_set(params).await,
            "apps.get" => self.apps_get(params).await,
            "system.launch" => system_launch::launch(&params).await,
            "split_tunneling.set" => self.split_tunneling_set(params).await,
            "connection.observe" => self.connection_observe().await,
            "connection.connect" => self.connection_connect(params).await,
            "connection.cancel" => self.connection_cancel().await,
            "connection.disconnect" => self.connection_disconnect().await,
            "connection.feedback" => self.connection_feedback(params).await,
            "netshield.stats.get" => self.netshield_stats().await,
            "traffic.get" => self.traffic().await,
            "diagnostics.get" => self.diagnostics().await,
            _ => Err(NativeError::new(
                "native_method_pending",
                format!("{method} has not migrated to the Rust backend yet"),
            )),
        }
    }

    async fn require_session(&self) -> NativeResult<(SessionData, u8)> {
        let state = self.state.read().await;
        let session = state.session.clone().ok_or_else(|| {
            NativeError::new(
                "not_authenticated",
                "Sign in to Proton before using VPN controls",
            )
        })?;
        let tier = session.tier();
        Ok((session, tier))
    }

    async fn account_upgrade_url(&self, params: Value) -> NativeResult<Value> {
        let modal_source = params
            .get("modal_source")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !modal_source
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        {
            return Err(NativeError::new(
                "invalid_params",
                "modal_source must be an enum-style token",
            ));
        }

        let stored = self.state.read().await.session.clone();
        if stored
            .as_ref()
            .is_some_and(|session| session.credentialless)
        {
            return Ok(json!({ "url": SIGNUP_URL, "authenticated": false }));
        }
        let selector = match stored {
            Some(stored) => {
                let session = session_bootstrap::stored_api_session(&stored);
                self.api
                    .post(
                        "/auth/v4/sessions/forks",
                        json!({
                            "ChildClientID": UPGRADE_CHILD_CLIENT_ID,
                            "Independent": 0,
                        }),
                        &session,
                    )
                    .await
                    .ok()
                    .and_then(|response| {
                        response
                            .get("Selector")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|selector| !selector.is_empty())
                            .map(str::to_owned)
                    })
            }
            None => None,
        };

        let Some(selector) = selector else {
            return Ok(json!({ "url": ACCOUNT_URL, "authenticated": false }));
        };
        Ok(json!({
            "url": upgrade_url(&selector, modal_source),
            "authenticated": true,
        }))
    }

    async fn emit_account(&self) {
        let pending = self.pending_auth.lock().await;
        if let Some(pending) = pending.as_ref() {
            let security_key_supported = fido2::FidoRequest::from_session(pending).is_ok();
            self.events.emit(
                "account",
                json!({
                    "status": "two_factor_required",
                    "name": null,
                    "tier": null,
                    "credentialless": false,
                    "two_factor_code_supported": true,
                    "two_factor_security_key_supported": security_key_supported,
                    "sso_supported": true,
                }),
            );
            return;
        }
        drop(pending);
        let state = self.state.read().await;
        let data = match &state.session {
            Some(session) => json!({
                "status": "signed_in",
                "name": session.account_name,
                "tier": session.tier(),
                "credentialless": session.credentialless,
                "two_factor_code_supported": true,
                "two_factor_security_key_supported": false,
                "sso_supported": true,
            }),
            None => json!({
                "status": "signed_out",
                "name": null,
                "tier": null,
                "credentialless": false,
                "two_factor_code_supported": true,
                "two_factor_security_key_supported": false,
                "sso_supported": true,
            }),
        };
        drop(state);
        self.events.emit("account", data);
    }

    async fn account_login(&self, params: Value) -> NativeResult<Value> {
        let _auth = self.auth_write.lock().await;
        let username = required_param(&params, "username", 320, true)?;
        let password = required_param(&params, "password", 4096, false)?;
        if self.state.read().await.session.is_some() {
            return Ok(json!({
                "success": true,
                "authenticated": true,
                "two_factor_required": false,
            }));
        }

        self.events.emit(
            "account",
            json!({
                "status": "signing_in",
                "name": null,
                "tier": null,
                "credentialless": false,
                "two_factor_code_supported": false,
                "two_factor_security_key_supported": false,
                "sso_supported": true,
            }),
        );
        self.events
            .stage("account.login", "auth.verifying_credentials", false);
        let auth = match self
            .api
            .authenticate(username.clone(), Zeroizing::new(password))
            .await
        {
            Ok(auth) => auth,
            Err(error) if error.code == "sso_required" => {
                self.events
                    .stage("account.login", "auth.waiting_for_sso", false);
                match self.api.authenticate_sso(username).await {
                    Ok(auth) => auth,
                    Err(error) => {
                        self.pending_auth.lock().await.take();
                        self.emit_account().await;
                        return Err(login_error(error, "sso"));
                    }
                }
            }
            Err(error) => {
                self.pending_auth.lock().await.take();
                self.emit_account().await;
                return Err(login_error(error, "credentials"));
            }
        };
        if auth.needs_two_factor() {
            *self.pending_auth.lock().await = Some(auth);
            self.events
                .stage("account.login", "auth.waiting_for_two_factor", false);
            self.emit_account().await;
            self.emit_features().await;
            return Ok(json!({
                "success": false,
                "authenticated": true,
                "two_factor_required": true,
            }));
        }

        self.events.stage("account.login", "auth.finalizing", false);
        if let Err(error) = self.finalize_auth(auth, "account.login").await {
            self.emit_account().await;
            return Err(error);
        }
        Ok(json!({
            "success": true,
            "authenticated": true,
            "two_factor_required": false,
        }))
    }

    async fn account_login_guest(&self) -> NativeResult<Value> {
        let _auth = self.auth_write.lock().await;
        if let Some(session) = self.state.read().await.session.as_ref() {
            return Ok(json!({
                "success": true,
                "authenticated": true,
                "credentialless": session.credentialless,
                "two_factor_required": false,
            }));
        }

        self.events.emit(
            "account",
            json!({
                "status": "signing_in",
                "name": null,
                "tier": null,
                "credentialless": true,
                "two_factor_code_supported": false,
                "two_factor_security_key_supported": false,
                "sso_supported": false,
            }),
        );
        self.events
            .stage("account.login_guest", "auth.creating_guest_session", false);
        let auth = match self.api.authenticate_guest().await {
            Ok(auth) => auth,
            Err(error) => {
                self.emit_account().await;
                return Err(error);
            }
        };
        self.events
            .stage("account.login_guest", "auth.finalizing", false);
        if let Err(error) = self.finalize_auth(auth, "account.login_guest").await {
            self.emit_account().await;
            return Err(error);
        }
        Ok(json!({
            "success": true,
            "authenticated": true,
            "credentialless": true,
            "two_factor_required": false,
        }))
    }

    async fn account_submit_2fa(&self, params: Value) -> NativeResult<Value> {
        let _auth = self.auth_write.lock().await;
        let code = required_param(&params, "code", 32, true)?;
        let mut auth = self.pending_auth.lock().await.take().ok_or_else(|| {
            NativeError::new(
                "two_factor_not_required",
                "The current Proton session is not waiting for two-factor authentication",
            )
        })?;
        self.events
            .stage("account.submit_2fa", "auth.verifying_two_factor", false);
        if let Err(error) = self.api.submit_2fa(&mut auth, &code).await {
            if error.code != "authentication_expired" {
                *self.pending_auth.lock().await = Some(auth);
            }
            self.emit_account().await;
            return Err(login_error(error, "two_factor"));
        }
        if auth.needs_two_factor() {
            *self.pending_auth.lock().await = Some(auth);
            self.emit_account().await;
            return Err(NativeError::new(
                "two_factor_failed",
                "The two-factor code was not accepted",
            )
            .retryable(true));
        }

        self.events
            .stage("account.submit_2fa", "auth.finalizing", false);
        if let Err(error) = self.finalize_auth(auth, "account.submit_2fa").await {
            self.emit_account().await;
            return Err(error);
        }
        Ok(json!({
            "success": true,
            "authenticated": true,
            "two_factor_required": false,
        }))
    }

    async fn account_authenticate_fido2(&self) -> NativeResult<Value> {
        let _auth = self.auth_write.lock().await;
        if self.fido_operation.lock().await.is_some() {
            return Err(NativeError::new(
                "fido2_operation_active",
                "Security-key authentication is already running",
            ));
        }

        let request = {
            let pending = self.pending_auth.lock().await;
            let session = pending.as_ref().ok_or_else(|| {
                NativeError::new(
                    "two_factor_not_required",
                    "The current Proton session is not waiting for two-factor authentication",
                )
            })?;
            fido2::FidoRequest::from_session(session)?
        };

        let operation = Arc::new(fido2::FidoOperation::new());
        *self.fido_operation.lock().await = Some(Arc::clone(&operation));
        self.events.stage(
            "account.authenticate_fido2",
            "auth.scanning_security_keys",
            true,
        );
        let events = self.events.clone();
        let operation_for_worker = Arc::clone(&operation);
        let assertion = tokio::task::spawn_blocking(move || {
            fido2::authenticate(request, operation_for_worker, events)
        })
        .await
        .map_err(|error| {
            NativeError::new(
                "fido2_worker_failed",
                "The security-key worker stopped unexpectedly",
            )
            .with_source(error)
        })?;
        self.fido_operation.lock().await.take();
        let assertion = assertion?;

        self.events.stage(
            "account.authenticate_fido2",
            "auth.verifying_security_key",
            false,
        );
        let mut auth = self.pending_auth.lock().await.take().ok_or_else(|| {
            NativeError::new(
                "authentication_expired",
                "The pending Proton authentication session expired",
            )
        })?;
        if let Err(error) = self.api.submit_fido2(&mut auth, &assertion).await {
            if error.code != "authentication_expired" {
                *self.pending_auth.lock().await = Some(auth);
            }
            self.emit_account().await;
            return Err(login_error(error, "security_key"));
        }
        if auth.needs_two_factor() {
            *self.pending_auth.lock().await = Some(auth);
            self.emit_account().await;
            return Err(
                NativeError::new("fido2_rejected", "The security key was not accepted")
                    .retryable(true),
            );
        }

        self.events
            .stage("account.authenticate_fido2", "auth.finalizing", false);
        if let Err(error) = self.finalize_auth(auth, "account.authenticate_fido2").await {
            self.emit_account().await;
            return Err(error);
        }
        Ok(json!({
            "success": true,
            "authenticated": true,
            "two_factor_required": false,
        }))
    }

    async fn account_submit_fido2_pin(&self, params: Value) -> NativeResult<Value> {
        let pin = Zeroizing::new(required_param(&params, "pin", 256, false)?);
        if pin.is_empty() {
            return Err(NativeError::new(
                "invalid_params",
                "The security-key PIN cannot be empty",
            ));
        }
        let operation = self
            .fido_operation
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                NativeError::new(
                    "fido2_operation_not_active",
                    "Security-key authentication is not running",
                )
            })?;
        let result = operation.submit_pin(pin.as_str()).await;
        result?;
        Ok(json!({ "submitted": true }))
    }

    async fn account_cancel_fido2(&self) -> NativeResult<Value> {
        let operation = self
            .fido_operation
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                NativeError::new(
                    "fido2_operation_not_active",
                    "Security-key authentication is not running",
                )
            })?;
        tokio::task::spawn_blocking(move || operation.cancel())
            .await
            .map_err(join_error)??;
        Ok(json!({ "cancelled": true }))
    }

    async fn finalize_auth(&self, auth: ApiSession, method: &str) -> NativeResult<()> {
        self.events.stage(method, "auth.loading_account", false);
        let settings = self.state.read().await.settings.clone();
        let bootstrap = session_bootstrap::fetch(&self.api, auth, &settings)
            .await
            .map_err(|error| login_error(error, "account"))?;

        let catalog_path = self.paths.catalog.clone();
        let client_config_path = self.paths.client_config.clone();
        let catalog_json = bootstrap.catalog_json.clone();
        let client_config_json = bootstrap.client_config_json.clone();
        tokio::task::spawn_blocking(move || {
            settings_store::save_value(&catalog_path, &catalog_json)?;
            settings_store::save_value(&client_config_path, &client_config_json)
        })
        .await
        .map_err(join_error)??;

        let secret_store = self.secret_store.clone();
        let session_for_store = bootstrap.session.clone();
        tokio::task::spawn_blocking(move || secret_store.save(&session_for_store))
            .await
            .map_err(join_error)??;
        {
            let mut state = self.state.write().await;
            state.session = Some(bootstrap.session);
            state.catalog = Some(bootstrap.catalog);
            state.client_config = Some(bootstrap.client_config);
        }
        self.pending_auth.lock().await.take();
        self.refresh_connection_feedback_flag().await;
        self.emit_account().await;
        self.emit_features().await;
        self.emit_device_location().await;
        self.flush_statistics_queue().await;
        Ok(())
    }

    async fn refresh_connection_feedback_flag(&self) {
        let api_session = self
            .state
            .read()
            .await
            .session
            .as_ref()
            .map(session_bootstrap::stored_api_session);
        let enabled = match api_session {
            Some(api_session) => self
                .api
                .get("/feature/v2/frontend", &api_session)
                .await
                .ok()
                .map(|value| feature_flag_enabled(&value, "IsConnectionFeedbackEnabled"))
                .unwrap_or(false),
            None => false,
        };
        self.state.write().await.connection_feedback_feature_enabled = enabled;
        self.emit_features().await;
    }

    async fn flush_statistics_queue(&self) {
        let (session, enabled) = {
            let state = self.state.read().await;
            (state.session.clone(), state.settings.share_statistics)
        };
        let Some(session) = session.filter(|_| enabled) else {
            return;
        };
        let api = self.api.clone();
        let path = self.paths.statistics.clone();
        let write = Arc::clone(&self.telemetry_write);
        tokio::spawn(telemetry::flush_existing(api, session, path, write));
    }

    async fn account_logout(&self) -> NativeResult<Value> {
        let _auth = self.auth_write.lock().await;
        self.events
            .stage("account.logout", "auth.disconnecting", false);
        let observation = self.observe_blocking().await?;
        if observation.state != TunnelState::Disconnected && observation.owned {
            let _network = self.network_write.lock().await;
            self.disconnect_inner().await?;
        }
        self.events
            .stage("account.logout", "auth.clearing_session", false);

        let pending = self.pending_auth.lock().await.take();
        let stored = self.state.read().await.session.clone();
        let api_session =
            pending.or_else(|| stored.as_ref().map(session_bootstrap::stored_api_session));
        if let Some(api_session) = api_session.as_ref() {
            if let Err(error) = self.api.logout(api_session).await {
                if error.code != "authentication_expired" {
                    return Err(error);
                }
            }
        }
        if let Some(session) = stored.as_ref() {
            let secret_store = self.secret_store.clone();
            let account_name = session.account_name.clone();
            tokio::task::spawn_blocking(move || secret_store.delete(&account_name))
                .await
                .map_err(join_error)??;
        }
        {
            let mut state = self.state.write().await;
            state.session = None;
            state.catalog = None;
            state.client_config = None;
            state.selected = None;
            state.traffic = None;
            state.connection_feedback_feature_enabled = false;
            state.feedback_session = None;
        }
        remove_cache_file(&self.paths.catalog)?;
        remove_cache_file(&self.paths.client_config)?;
        self.emit_account().await;
        self.emit_features().await;
        self.events.emit(
            "device_location",
            json!({
                "known": false,
                "ip_address": null,
                "country_code": null,
                "isp": null,
                "latitude": null,
                "longitude": null,
            }),
        );
        Ok(json!({ "logged_out": true }))
    }

    async fn refresh_tokens(&self) -> NativeResult<()> {
        let _auth = self.auth_write.lock().await;
        let stored = self.state.read().await.session.clone();
        let Some(mut stored) = stored else {
            return Ok(());
        };
        let mut api_session = session_bootstrap::stored_api_session(&stored);
        self.api.refresh(&mut api_session).await?;
        stored.access_token = api_session.access_token;
        stored.refresh_token = api_session.refresh_token;
        stored.scopes = api_session.scopes;
        let secret_store = self.secret_store.clone();
        let for_store = stored.clone();
        tokio::task::spawn_blocking(move || secret_store.save(&for_store))
            .await
            .map_err(join_error)??;
        self.state.write().await.session = Some(stored);
        Ok(())
    }

    async fn refresh_certificate_if_needed(&self) -> NativeResult<bool> {
        let _auth = self.auth_write.lock().await;
        let mut stored = match self.state.read().await.session.clone() {
            Some(stored) => stored,
            None => return Ok(false),
        };
        let now = unix_seconds()?;
        let required = stored.vpn.certificate.expiration_time <= now.saturating_add(60);
        if !required && stored.vpn.certificate.refresh_time > now {
            return Ok(false);
        }

        let mut api_session = session_bootstrap::stored_api_session(&stored);
        if let Err(error) = self.api.refresh(&mut api_session).await {
            return if required { Err(error) } else { Ok(false) };
        }
        stored.access_token = api_session.access_token;
        stored.refresh_token = api_session.refresh_token;
        stored.scopes = api_session.scopes;
        self.persist_session_data(stored.clone()).await?;

        let settings = self.state.read().await.settings.clone();
        let certificate =
            match session_bootstrap::refresh_certificate(&self.api, &stored, &settings).await {
                Ok(certificate) => certificate,
                Err(_error) if !required => return Ok(false),
                Err(error) => return Err(error),
            };
        stored.vpn.certificate = certificate;
        self.persist_session_data(stored).await?;
        Ok(true)
    }

    async fn persist_session_data(&self, session: SessionData) -> NativeResult<()> {
        let secret_store = self.secret_store.clone();
        let for_store = session.clone();
        tokio::task::spawn_blocking(move || secret_store.save(&for_store))
            .await
            .map_err(join_error)??;
        self.state.write().await.session = Some(session);
        Ok(())
    }

    async fn emit_device_location(&self) {
        let location = self.state.read().await.session.as_ref().map(|session| {
            json!({
                "known": true,
                "ip_address": session.vpn.location.ip,
                "country_code": session.vpn.location.country,
                "isp": session.vpn.location.isp,
                "latitude": session.vpn.location.lat,
                "longitude": session.vpn.location.long,
            })
        });
        if let Some(location) = location {
            self.events.emit("device_location", location);
        }
    }

    async fn emit_features(&self) {
        let local_agent = self.local_agent_snapshot.read().await.clone();
        let state = self.state.read().await;
        let signed_in = state.session.is_some();
        let paid = state
            .session
            .as_ref()
            .map(|session| session.tier() > 0)
            .unwrap_or(false);
        let settings = &state.settings;
        let split_available = self.split_available.load(Ordering::Acquire);
        let destination_policy_available =
            self.destination_policy_available.load(Ordering::Acquire);
        let split = split_state(
            &settings.features.split_tunneling,
            split_available,
            destination_policy_available,
        );
        let dns_servers = if settings.custom_dns.enabled {
            settings
                .custom_dns
                .ip_list
                .iter()
                .filter_map(dns_value)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let secure_core = state
            .selected
            .as_ref()
            .map(|selected| selected.logical.features & models::FEATURE_SECURE_CORE != 0)
            .unwrap_or(false);
        let protocols = available_protocols();
        let feedback_viewed = state
            .feedback_session
            .as_ref()
            .map(telemetry::ConnectionFeedbackSession::viewed)
            .unwrap_or(false);
        let feedback_sent = state
            .feedback_session
            .as_ref()
            .map(telemetry::ConnectionFeedbackSession::sent)
            .unwrap_or(false);
        let feedback_available = signed_in
            && settings.share_statistics
            && state.connection_feedback_feature_enabled
            && state.feedback_session.is_some()
            && !feedback_sent;
        let data = json!({
            "protocol": {
                "selected": normalized_protocol(&settings.protocol),
                "available": protocols,
                "profile_available": protocols,
            },
            "kill_switch": { "mode": kill_switch_name(settings.killswitch) },
            "netshield": {
                "level": settings.features.netshield,
                "statistics_known": local_agent.netshield_malware.is_some()
                    || local_agent.netshield_ads.is_some()
                    || local_agent.netshield_trackers.is_some(),
                "malware_blocked": local_agent.netshield_malware.unwrap_or(0),
                "ads_blocked": local_agent.netshield_ads.unwrap_or(0),
                "trackers_blocked": local_agent.netshield_trackers.unwrap_or(0),
            },
            "vpn_accelerator": { "enabled": settings.features.vpn_accelerator },
            "anonymous_crash_reports": { "enabled": settings.anonymous_crash_reports },
            "anonymous_usage_statistics": { "enabled": settings.share_statistics },
            "connection_feedback": {
                "available": feedback_available,
                "viewed": feedback_viewed,
                "sent": feedback_sent,
            },
            "moderate_nat": { "enabled": settings.features.moderate_nat },
            "ipv6": { "enabled": settings.ipv6 },
            "ipv6_leak_protection": { "enabled": settings.ipv6_leak_protection },
            "alternative_routing": { "enabled": settings.alternative_routing },
            "allow_lan_connections": { "enabled": settings.allow_lan_connections },
            "allow_local_dns": { "enabled": settings.allow_local_dns },
            "secure_core": secure_core,
            "split_tunneling": split,
            "port_forwarding": {
                "enabled": settings.features.port_forwarding,
                "active_port": local_agent.forwarded_port,
            },
            "custom_dns": {
                "enabled": settings.custom_dns.enabled,
                "servers": dns_servers,
            },
            "writes": {
                "protocol": signed_in,
                // Advanced Kill Switch can intentionally block the network at
                // sign-in, so it must remain switchable while signed out.
                "kill_switch": true,
                "netshield": paid,
                "vpn_accelerator": paid,
                "anonymous_crash_reports": signed_in,
                "anonymous_usage_statistics": signed_in,
                "moderate_nat": paid,
                "ipv6": signed_in,
                "ipv6_leak_protection": signed_in,
                "alternative_routing": true,
                "allow_lan_connections": signed_in && destination_policy_available,
                "allow_local_dns": signed_in && destination_policy_available,
                "custom_dns": signed_in,
                "secure_core": signed_in,
                "split_tunneling": signed_in && split_available,
                "port_forwarding": paid,
            },
            "known": true,
            "writable": signed_in,
        });
        drop(state);
        self.events.emit("features", data);
    }

    async fn protocol_set(&self, params: Value) -> NativeResult<Value> {
        self.require_session().await?;
        let value = params
            .get("value")
            .and_then(Value::as_str)
            .map(normalized_protocol)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| NativeError::new("invalid_params", "protocol value is required"))?;
        if !available_protocol(&value) {
            return Err(NativeError::new(
                "protocol_unavailable",
                format!("VPN protocol is unavailable: {value}"),
            ));
        }
        let observation = self.observe_blocking().await?;
        if observation.state != TunnelState::Disconnected {
            return Err(NativeError::new(
                "connection_active",
                "VPN protocol can only be changed while disconnected",
            ));
        }

        let _write = self.settings_write.lock().await;
        let mut settings = self.state.read().await.settings.clone();
        settings.protocol = value.clone();
        self.persist_settings(settings).await?;
        self.events.stage("protocol.set", "settings.applied", false);
        self.emit_features().await;
        Ok(json!({ "applied": true, "protocol": value }))
    }

    async fn apply_destination_policy(&self, settings: &NativeSettings) -> NativeResult<()> {
        if !self.destination_policy_available.load(Ordering::Acquire) {
            return Err(NativeError::new(
                "destination_policy_unavailable",
                "LAN and local DNS policy require the Proton Omarchy Rust split service",
            ));
        }
        let allow_lan = settings.allow_lan_connections;
        let allow_local_dns = settings.allow_local_dns;
        let split_tunnel = self.split_tunnel.clone();
        tokio::task::spawn_blocking(move || {
            let mut ranges = HashSet::new();
            if allow_lan {
                ranges.extend(LAN_BYPASS_RANGES.iter().map(|range| (*range).to_owned()));
            }
            if allow_local_dns {
                ranges.extend(
                    LOCAL_NAME_BYPASS_RANGES
                        .iter()
                        .map(|range| (*range).to_owned()),
                );
                for address in NetworkManagerBackend.physical_dns_servers()? {
                    let address = address.parse::<IpAddr>().map_err(|error| {
                        NativeError::new(
                            "local_dns_invalid",
                            "NetworkManager returned an invalid physical DNS server",
                        )
                        .with_source(error)
                    })?;
                    ranges.insert(format!(
                        "{address}/{}",
                        if address.is_ipv4() { 32 } else { 128 }
                    ));
                }
            }
            let mut ranges = ranges.into_iter().collect::<Vec<_>>();
            ranges.sort();
            split_tunnel.apply_destination_policy(ranges)
        })
        .await
        .map_err(join_error)?
    }

    async fn apply_connection_destination_policy(
        &self,
        global: &NativeSettings,
        effective: &NativeSettings,
    ) -> NativeResult<()> {
        let differs = global.allow_lan_connections != effective.allow_lan_connections
            || global.allow_local_dns != effective.allow_local_dns;
        if !differs {
            *self.destination_policy_override.write().await = None;
            return Ok(());
        }
        self.apply_destination_policy(effective).await?;
        *self.destination_policy_override.write().await =
            Some((effective.allow_lan_connections, effective.allow_local_dns));
        Ok(())
    }

    async fn restore_global_destination_policy(&self) -> NativeResult<()> {
        if self.destination_policy_override.read().await.is_none() {
            return Ok(());
        }
        let global = self.state.read().await.settings.clone();
        self.apply_destination_policy(&global).await?;
        *self.destination_policy_override.write().await = None;
        Ok(())
    }

    async fn feature_set(&self, params: Value) -> NativeResult<Value> {
        let feature = params
            .get("feature")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let tier = self
            .state
            .read()
            .await
            .session
            .as_ref()
            .map(SessionData::tier);
        if tier.is_none() && !matches!(feature.as_str(), "kill_switch" | "alternative_routing") {
            return Err(NativeError::new(
                "not_authenticated",
                "Sign in to Proton VPN first",
            ));
        }
        let tier = tier.unwrap_or(0);
        if feature == "split_tunneling" {
            return Err(NativeError::new(
                "invalid_method",
                "Use split_tunneling.set so app lists and mode stay atomic",
            ));
        }
        if feature == "secure_core" {
            return Err(NativeError::new(
                "invalid_method",
                "Secure Core is connection-derived; use connection.connect",
            ));
        }
        let _write = self.settings_write.lock().await;
        let previous = self.state.read().await.settings.clone();
        let mut settings = previous.clone();
        match feature.as_str() {
            "anonymous_crash_reports" => {
                settings.anonymous_crash_reports = bool_feature_value(&params, &feature)?;
            }
            "anonymous_usage_statistics" => {
                settings.share_statistics = bool_feature_value(&params, &feature)?;
            }
            "kill_switch" => {
                let mode = params
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(kill_switch_value)
                    .ok_or_else(|| {
                        NativeError::new(
                            "invalid_params",
                            "kill_switch value must be off, standard or advanced",
                        )
                    })?;
                settings.killswitch = mode;
            }
            "netshield" => {
                require_paid_feature(tier, "NetShield")?;
                let level = params.get("value").and_then(Value::as_u64).ok_or_else(|| {
                    NativeError::new(
                        "invalid_params",
                        "netshield value must be an integer from 0 through 2",
                    )
                })?;
                if level > 2 {
                    return Err(NativeError::new(
                        "invalid_params",
                        "netshield value must be an integer from 0 through 2",
                    ));
                }
                if level > 0 && settings.custom_dns.enabled {
                    return Err(NativeError::new(
                        "setting_conflict",
                        "Disable Custom DNS before enabling NetShield",
                    ));
                }
                settings.features.netshield = level as u8;
            }
            "vpn_accelerator" => {
                require_paid_feature(tier, "VPN Accelerator")?;
                settings.features.vpn_accelerator = bool_feature_value(&params, &feature)?;
            }
            "moderate_nat" => {
                require_paid_feature(tier, "Moderate NAT")?;
                let enabled = bool_feature_value(&params, &feature)?;
                if enabled && settings.features.port_forwarding {
                    return Err(NativeError::new(
                        "setting_conflict",
                        "Disable port forwarding before enabling Moderate NAT",
                    ));
                }
                settings.features.moderate_nat = enabled;
            }
            "ipv6" => {
                settings.ipv6 = bool_feature_value(&params, &feature)?;
            }
            "ipv6_leak_protection" => {
                settings.ipv6_leak_protection = bool_feature_value(&params, &feature)?;
            }
            "alternative_routing" => {
                settings.alternative_routing = bool_feature_value(&params, &feature)?;
            }
            "allow_lan_connections" => {
                settings.allow_lan_connections = bool_feature_value(&params, &feature)?;
            }
            "allow_local_dns" => {
                settings.allow_local_dns = bool_feature_value(&params, &feature)?;
            }
            "port_forwarding" => {
                require_paid_feature(tier, "Port forwarding")?;
                let enabled = bool_feature_value(&params, &feature)?;
                if enabled && settings.features.moderate_nat {
                    return Err(NativeError::new(
                        "setting_conflict",
                        "Moderate NAT and port forwarding cannot be enabled together",
                    ));
                }
                settings.features.port_forwarding = enabled;
            }
            _ => {
                return Err(NativeError::new("invalid_params", "Unknown feature"));
            }
        }

        let observation = self.observe_blocking().await?;
        let active = observation.state == TunnelState::Connected;
        let mut applied_live = false;
        let local_only = matches!(
            feature.as_str(),
            "anonymous_crash_reports"
                | "anonymous_usage_statistics"
                | "alternative_routing"
                | "allow_lan_connections"
                | "allow_local_dns"
        );
        if active && !observation.owned && !local_only {
            return Err(NativeError::new(
                "connection_not_owned",
                "Reconnect with the native backend before changing live connection features",
            ));
        }
        let selected = self.state.read().await.selected.clone();
        let is_local_agent_feature = matches!(
            feature.as_str(),
            "netshield" | "vpn_accelerator" | "port_forwarding" | "moderate_nat"
        );
        if feature == "kill_switch" {
            let server_ip = active
                .then(|| {
                    selected
                        .as_ref()
                        .map(|target| target.physical.entry_ip.clone())
                })
                .flatten();
            if settings.killswitch == 0 && previous.killswitch != 0 {
                self.reconcile_split_kill_switch_bypass(&previous, false)
                    .await?;
                self.reconcile_kill_switch(
                    previous.killswitch,
                    false,
                    server_ip.clone(),
                    previous.ipv6_leak_protection,
                )
                .await?;
            }
            let applied = match self
                .reconcile_kill_switch(
                    settings.killswitch,
                    active,
                    server_ip.clone(),
                    settings.ipv6_leak_protection,
                )
                .await
            {
                Ok(()) => {
                    self.reconcile_split_kill_switch_bypass(&settings, active)
                        .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = applied {
                let _ = self
                    .reconcile_kill_switch(
                        previous.killswitch,
                        active,
                        server_ip,
                        previous.ipv6_leak_protection,
                    )
                    .await;
                let _ = self
                    .reconcile_split_kill_switch_bypass(&previous, active)
                    .await;
                return Err(error);
            }
            applied_live = active || settings.killswitch == 2;
        }
        if feature == "ipv6_leak_protection" {
            let server_ip = active
                .then(|| {
                    selected
                        .as_ref()
                        .map(|target| target.physical.entry_ip.clone())
                })
                .flatten();
            if let Err(error) = self
                .reconcile_kill_switch(
                    settings.killswitch,
                    active,
                    server_ip.clone(),
                    settings.ipv6_leak_protection,
                )
                .await
            {
                let _ = self
                    .reconcile_kill_switch(
                        previous.killswitch,
                        active,
                        server_ip,
                        previous.ipv6_leak_protection,
                    )
                    .await;
                let _ = self
                    .reconcile_split_kill_switch_bypass(&previous, active)
                    .await;
                return Err(error);
            }
            applied_live = active || settings.killswitch == 2;
        }
        if active && is_local_agent_feature {
            let target = self.state.read().await.selected.clone().ok_or_else(|| {
                NativeError::new(
                    "connection_state_unknown",
                    "The active Proton server could not be identified",
                )
            })?;
            let requested = connection_agent_features(&settings, &target, tier);
            let agent = self.local_agent.lock().await;
            let agent = agent.as_ref().ok_or_else(|| {
                NativeError::new(
                    "connection_not_owned",
                    "Reconnect with the native backend before changing live connection features",
                )
            })?;
            agent.request_features(requested).await?;
            applied_live = true;
        }
        if matches!(
            feature.as_str(),
            "allow_lan_connections" | "allow_local_dns"
        ) && self.destination_policy_override.read().await.is_none()
        {
            self.apply_destination_policy(&settings).await?;
            applied_live = true;
        }

        if let Err(error) = self.persist_settings(settings).await {
            if matches!(feature.as_str(), "kill_switch" | "ipv6_leak_protection") {
                let server_ip = active
                    .then(|| {
                        selected
                            .as_ref()
                            .map(|target| target.physical.entry_ip.clone())
                    })
                    .flatten();
                let _ = self
                    .reconcile_kill_switch(
                        previous.killswitch,
                        active,
                        server_ip,
                        previous.ipv6_leak_protection,
                    )
                    .await;
                let _ = self
                    .reconcile_split_kill_switch_bypass(&previous, active)
                    .await;
            } else if matches!(
                feature.as_str(),
                "allow_lan_connections" | "allow_local_dns"
            ) && applied_live
            {
                let _ = self.apply_destination_policy(&previous).await;
            } else if applied_live {
                if let (Some(target), Some(agent)) = (
                    self.state.read().await.selected.clone(),
                    self.local_agent.lock().await.as_ref(),
                ) {
                    let _ = agent
                        .request_features(connection_agent_features(&previous, &target, tier))
                        .await;
                }
            }
            return Err(error);
        }
        if feature == "anonymous_usage_statistics" {
            let enabled = self.state.read().await.settings.share_statistics;
            if !enabled {
                let path = self.paths.statistics.clone();
                tokio::task::spawn_blocking(move || telemetry::clear(&path))
                    .await
                    .map_err(join_error)??;
            } else {
                self.flush_statistics_queue().await;
            }
        }
        if feature == "alternative_routing" {
            self.api
                .set_alternative_routing(self.state.read().await.settings.alternative_routing)
                .await;
        }
        let reconnect_required = feature == "ipv6" && active;
        self.events.stage("feature.set", "settings.applied", false);
        self.emit_features().await;
        Ok(json!({
            "applied": true,
            "applied_live": applied_live,
            "reconnect_required": reconnect_required,
        }))
    }

    async fn reconcile_kill_switch(
        &self,
        mode: u8,
        tunnel_active: bool,
        server_ip: Option<String>,
        ipv6_leak_protection: bool,
    ) -> NativeResult<()> {
        let network = self.network.clone();
        let result = tokio::task::spawn_blocking(move || {
            network.reconcile_kill_switch(
                mode,
                tunnel_active,
                server_ip.as_deref(),
                ipv6_leak_protection,
            )
        })
        .await
        .map_err(join_error)?;
        if result.is_ok() {
            self.emit_backend_state(None).await;
        }
        result
    }

    async fn reconcile_split_kill_switch_bypass(
        &self,
        settings: &NativeSettings,
        tunnel_active: bool,
    ) -> NativeResult<()> {
        let _write = self.split_route_write.lock().await;
        let enabled =
            tunnel_active && settings.killswitch != 0 && settings.features.split_tunneling.enabled;
        let combination_configured =
            settings.killswitch != 0 && settings.features.split_tunneling.enabled;
        if !enabled
            && !combination_configured
            && !self.split_kill_switch_bypass_active.load(Ordering::Acquire)
        {
            return Ok(());
        }
        let routes = if enabled {
            let network = self.network.clone();
            tokio::task::spawn_blocking(move || network.physical_default_routes())
                .await
                .map_err(join_error)??
        } else {
            Vec::new()
        };
        let split_tunnel = self.split_tunnel.clone();
        tokio::task::spawn_blocking(move || split_tunnel.set_kill_switch_bypass(enabled, routes))
            .await
            .map_err(join_error)??;
        self.split_kill_switch_bypass_active
            .store(enabled, Ordering::Release);
        Ok(())
    }

    async fn emit_backend_state(&self, initialization_error: Option<String>) {
        let connection_available =
            Path::new(PROTUN_DESCRIPTOR).exists() || Path::new(OPENVPN_DESCRIPTOR).exists();
        let network = self.network.clone();
        let blocked = tokio::task::spawn_blocking(move || network.network_blocked()).await;
        let (network_blocked_known, network_blocked) = match blocked {
            Ok(Ok(value)) => (true, value),
            _ => (false, false),
        };
        self.events.emit(
            "backend",
            json!({
                "kind": "proton_rust",
                "core_available": initialization_error.is_none(),
                "connection_available": connection_available,
                "connection_availability_known": true,
                "settings_known": initialization_error.is_none(),
                "connector_initialized": true,
                "network_blocked_known": network_blocked_known,
                "network_blocked": network_blocked,
                "core_version": NATIVE_VERSION,
                "error": initialization_error,
            }),
        );
    }

    async fn dns_set(&self, params: Value) -> NativeResult<Value> {
        self.require_session().await?;
        let enabled = params
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| NativeError::new("invalid_params", "enabled must be a boolean"))?;
        let raw_servers = params
            .get("servers")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                NativeError::new(
                    "invalid_params",
                    "servers must be an array with at most 16 IP addresses",
                )
            })?;
        if raw_servers.len() > 16 {
            return Err(NativeError::new(
                "invalid_params",
                "servers must be an array with at most 16 IP addresses",
            ));
        }
        let mut normalized = Vec::new();
        let mut seen = HashSet::new();
        for raw in raw_servers {
            let value = raw
                .as_str()
                .ok_or_else(|| NativeError::new("invalid_params", "DNS servers must be strings"))?;
            if value.trim().is_empty() {
                continue;
            }
            let ip = value
                .trim()
                .parse::<IpAddr>()
                .map_err(|error| {
                    NativeError::new("invalid_dns", "Invalid custom DNS IP").with_source(error)
                })?
                .to_string();
            if seen.insert(ip.clone()) {
                normalized.push(ip);
            }
        }
        if enabled && normalized.is_empty() {
            return Err(NativeError::new(
                "invalid_dns",
                "At least one valid DNS IP is required when custom DNS is enabled",
            ));
        }

        let _write = self.settings_write.lock().await;
        let mut settings = self.state.read().await.settings.clone();
        settings.custom_dns.enabled = enabled;
        settings.custom_dns.ip_list = normalized
            .iter()
            .map(|ip| json!({ "ip": ip, "enabled": true }))
            .collect();
        self.persist_settings(settings).await?;
        self.events.stage("dns.set", "settings.applied", false);
        self.emit_features().await;
        Ok(json!({ "applied": true, "enabled": enabled, "servers": normalized }))
    }

    async fn apps_get(&self, params: Value) -> NativeResult<Value> {
        tokio::task::spawn_blocking(move || apps::list(&params))
            .await
            .map_err(join_error)?
    }

    async fn split_tunneling_set(&self, params: Value) -> NativeResult<Value> {
        self.require_session().await?;
        if !self.split_available.load(Ordering::Acquire) {
            return Err(NativeError::new(
                "split_tunneling_unavailable",
                "Proton split tunneling service is unavailable on this system",
            ));
        }
        let enabled = params
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| NativeError::new("invalid_params", "enabled must be a boolean"))?;
        let mut mode_name = params
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("standard")
            .trim()
            .to_ascii_lowercase();
        if mode_name == "off" && !enabled {
            mode_name = "standard".into();
        }
        let mode = match mode_name.as_str() {
            "standard" => "exclude",
            "inverse" => "include",
            _ => {
                return Err(NativeError::new(
                    "invalid_params",
                    "mode must be standard or inverse",
                ));
            }
        };

        let _write = self.settings_write.lock().await;
        let previous = self.state.read().await.settings.clone();
        let previous_standard = previous.features.split_tunneling.config("exclude");
        let previous_inverse = previous.features.split_tunneling.config("include");
        let standard = split_request_config(&params, "standard", "exclude", &previous_standard)?;
        let inverse = split_request_config(&params, "inverse", "include", &previous_inverse)?;
        let active = if mode == "include" {
            &inverse
        } else {
            &standard
        };
        if enabled && active.app_paths.is_empty() && active.ip_ranges.is_empty() {
            return Err(NativeError::new(
                "split_tunneling_empty_selection",
                "The active Split Tunneling mode requires at least one application or IP range",
            ));
        }

        let mut settings = previous.clone();
        settings.features.split_tunneling.enabled = enabled;
        settings.features.split_tunneling.mode = mode.into();
        settings
            .features
            .split_tunneling
            .config_by_mode
            .insert("exclude".into(), standard);
        settings
            .features
            .split_tunneling
            .config_by_mode
            .insert("include".into(), inverse);
        let active = settings.features.split_tunneling.config(mode);
        let observation = self.observe_blocking().await?;
        let tunnel_active = observation.state == TunnelState::Connected;
        if tunnel_active && !observation.owned {
            return Err(NativeError::new(
                "connection_not_owned",
                "Reconnect with the native backend before changing Split Tunneling",
            ));
        }

        self.events.stage(
            "split_tunneling.set",
            "settings.applying_split_tunneling",
            false,
        );
        if tunnel_active && previous.killswitch != 0 && previous.features.split_tunneling.enabled {
            self.reconcile_split_kill_switch_bypass(&previous, false)
                .await?;
        }
        let split_tunnel = self.split_tunnel.clone();
        let active_for_apply = active.clone();
        let apply_result =
            tokio::task::spawn_blocking(move || split_tunnel.apply(enabled, &active_for_apply))
                .await
                .map_err(join_error)
                .and_then(|result| result);
        if let Err(error) = apply_result {
            let _ = self
                .reconcile_split_kill_switch_bypass(&previous, tunnel_active)
                .await;
            return Err(error);
        }
        if let Err(error) = self
            .reconcile_split_kill_switch_bypass(&settings, tunnel_active)
            .await
        {
            let rollback = previous.features.split_tunneling.clone();
            let rollback_config = rollback.config(&rollback.mode);
            let split_tunnel = self.split_tunnel.clone();
            let _ = tokio::task::spawn_blocking(move || {
                split_tunnel.apply(rollback.enabled, &rollback_config)
            })
            .await;
            let _ = self
                .reconcile_split_kill_switch_bypass(&previous, tunnel_active)
                .await;
            return Err(error);
        }
        if let Err(error) = self.persist_settings(settings.clone()).await {
            let _ = self
                .reconcile_split_kill_switch_bypass(&settings, false)
                .await;
            let rollback = previous.features.split_tunneling.clone();
            let rollback_config = rollback.config(&rollback.mode);
            let split_tunnel = self.split_tunnel.clone();
            let _ = tokio::task::spawn_blocking(move || {
                split_tunnel.apply(rollback.enabled, &rollback_config)
            })
            .await;
            let _ = self
                .reconcile_split_kill_switch_bypass(&previous, tunnel_active)
                .await;
            return Err(error);
        }
        self.emit_features().await;
        Ok(json!({
            "applied": true,
            "enabled": enabled,
            "mode": mode_name,
            "app_paths_supported": true,
            "ip_ranges_supported": self.destination_policy_available.load(Ordering::Acquire),
        }))
    }

    async fn persist_settings(&self, settings: NativeSettings) -> NativeResult<()> {
        let path = self.paths.settings.clone();
        let for_write = settings.clone();
        tokio::task::spawn_blocking(move || settings_store::save(&path, &for_write))
            .await
            .map_err(join_error)??;
        self.state.write().await.settings = settings;
        Ok(())
    }

    async fn locations(&self) -> NativeResult<Value> {
        let (_, tier) = self.require_session().await?;
        let state = self.state.read().await;
        let catalog = state.catalog.as_ref().ok_or_else(catalog_unavailable)?;
        Ok(catalog.locations(tier))
    }

    async fn servers(&self, params: &Value) -> NativeResult<Value> {
        let (_, tier) = self.require_session().await?;
        let state = self.state.read().await;
        let catalog = state.catalog.as_ref().ok_or_else(catalog_unavailable)?;
        catalog.servers_page(params, tier)
    }

    async fn connection_observe(&self) -> NativeResult<Value> {
        self.require_session().await?;
        let observation = self.observe_blocking().await?;
        self.emit_connection(&observation, None).await;
        self.emit_features().await;
        Ok(json!({
            "observation_known": true,
            "status": tunnel_state_name(observation.state),
            "connector_initialized": true,
        }))
    }

    async fn connection_connect(self: &Arc<Self>, params: Value) -> NativeResult<Value> {
        self.refresh_certificate_if_needed().await?;
        let _network_guard = self.network_write.lock().await;
        let (session, tier) = self.require_session().await?;
        let current = self.observe_blocking().await?;
        if current.state != TunnelState::Disconnected {
            return Err(NativeError::new(
                "connection_active",
                "Disconnect the active VPN connection before starting another one",
            ));
        }
        self.state.write().await.pending_connection_trigger = connection_trigger(&params).into();
        self.events
            .stage("connection.connect", "tunnel.selecting_server", true);

        let (target, client_config, global_settings, settings, protocol, profile_settings_applied) = {
            let state = self.state.read().await;
            let catalog = state.catalog.as_ref().ok_or_else(catalog_unavailable)?;
            let client_config = state
                .client_config
                .clone()
                .ok_or_else(client_config_unavailable)?;
            let global_settings = state.settings.clone();
            let (settings, protocol, profile_settings_applied) =
                effective_connection_settings(&params, &global_settings, tier)?;
            let excluded_locations = self.events.store.excluded_locations();
            let target = catalog.select(&params, tier, &excluded_locations)?;
            (
                target,
                client_config,
                global_settings,
                settings,
                protocol,
                profile_settings_applied,
            )
        };

        let profile = VpnProfile::new(&target, &protocol, &session, &client_config, &settings)?;
        let conflict_network = self.network.clone();
        let network_conflicts = tokio::task::spawn_blocking(move || {
            conflict_network
                .conflicting_interfaces()
                .unwrap_or_default()
        })
        .await
        .map_err(join_error)?;
        self.apply_connection_destination_policy(&global_settings, &settings)
            .await?;
        let attempt = self.connection_attempt.fetch_add(1, Ordering::SeqCst) + 1;
        self.events
            .stage("connection.connect", "tunnel.connecting", true);
        self.events.emit(
            "connection",
            json!({
                "observation_known": true,
                "status": "connecting",
                "server": target.logical.serialized(),
                "protocol": protocol,
                "secure_core": target.logical.features & models::FEATURE_SECURE_CORE != 0,
                "error": null,
                "error_code": null,
                "network_conflicts": network_conflicts.clone(),
            }),
        );

        let network = self.network.clone();
        let profile_for_connect = profile.clone();
        let kill_switch_mode = settings.killswitch;
        let ipv6_leak_protection = settings.ipv6_leak_protection;
        let server_ip = target.physical.entry_ip.clone();
        let activation = tokio::task::spawn_blocking(move || {
            network.reconcile_kill_switch(
                kill_switch_mode,
                true,
                Some(&server_ip),
                ipv6_leak_protection,
            )?;
            match network.connect(&profile_for_connect) {
                Ok(activation) => Ok(activation),
                Err(error) => {
                    let _ = network.reconcile_kill_switch(
                        kill_switch_mode,
                        false,
                        Some(&server_ip),
                        ipv6_leak_protection,
                    );
                    Err(error)
                }
            }
        })
        .await;
        let activation = match activation {
            Ok(activation) => activation,
            Err(error) => {
                self.restore_global_destination_policy().await?;
                return Err(join_error(error));
            }
        };
        let activation = match activation {
            Ok(activation) => activation,
            Err(error) => {
                self.restore_global_destination_policy().await?;
                let error = with_network_conflicts(error, &network_conflicts);
                self.events.emit(
                    "connection",
                    json!({
                        "observation_known": true,
                        "status": "error",
                        "server": target.logical.serialized(),
                        "protocol": protocol,
                        "secure_core": target.logical.features & models::FEATURE_SECURE_CORE != 0,
                        "error": error.message.clone(),
                        "error_code": error.code.clone(),
                        "network_conflicts": network_conflicts.clone(),
                    }),
                );
                return Err(error);
            }
        };
        *self.owned_connection_uuid.lock().await = activation.uuid.clone();

        {
            let mut state = self.state.write().await;
            state.selected = Some(target.clone());
            state.traffic = None;
        }

        let started_at = Instant::now();
        let deadline = started_at + CONNECTION_TIMEOUT;
        loop {
            if self.connection_attempt.load(Ordering::SeqCst) != attempt {
                self.cleanup_owned_connection(profile.uuid()).await;
                return Err(NativeError::new(
                    "connection_cancelled",
                    "VPN connection attempt was cancelled",
                ));
            }
            let observation = self.observe_blocking().await?;
            match observation.state {
                TunnelState::Connected => {
                    if let Err(error) = self
                        .reconcile_split_kill_switch_bypass(&settings, true)
                        .await
                    {
                        self.cleanup_owned_connection(profile.uuid()).await;
                        return Err(error);
                    }
                    self.events
                        .stage("connection.connect", "tunnel.securing_session", true);
                    let requested =
                        (tier > 0).then(|| connection_agent_features(&settings, &target, tier));
                    let (agent, mut updates) =
                        match local_agent::start(&target.logical.domain, &session, requested).await
                        {
                            Ok(agent) => agent,
                            Err(error) => {
                                self.cleanup_owned_connection(profile.uuid()).await;
                                return Err(error);
                            }
                        };
                    *self.local_agent.lock().await = Some(agent);
                    let ready = match tokio::time::timeout(
                        LOCAL_AGENT_READY_TIMEOUT,
                        wait_for_local_agent_ready(&mut updates),
                    )
                    .await
                    {
                        Ok(Ok(snapshot)) => snapshot,
                        Ok(Err(error)) => {
                            self.cleanup_owned_connection(profile.uuid()).await;
                            return Err(error);
                        }
                        Err(_) => {
                            self.cleanup_owned_connection(profile.uuid()).await;
                            return Err(NativeError::new(
                                "local_agent_timeout",
                                "The Proton Local Agent did not confirm the VPN session in time",
                            )
                            .retryable(true));
                        }
                    };
                    *self.local_agent_snapshot.write().await = ready;
                    tokio::spawn(Arc::clone(self).watch_local_agent(updates, attempt));
                    self.emit_connection(&observation, None).await;
                    self.emit_features().await;
                    return Ok(json!({
                        "accepted": true,
                        "server": target.logical.serialized(),
                        "protocol": protocol,
                        "profile_settings_applied": profile_settings_applied,
                        "secure_core": target.logical.features & models::FEATURE_SECURE_CORE != 0,
                    }));
                }
                TunnelState::Error => {
                    let error = with_network_conflicts(
                        NativeError::new(
                            "connection_failed",
                            "NetworkManager reported that the VPN tunnel failed",
                        )
                        .with_details(json!({ "protocol": protocol }))
                        .retryable(true),
                        &network_conflicts,
                    );
                    self.emit_connection(&observation, Some(&error.message))
                        .await;
                    self.cleanup_owned_connection(profile.uuid()).await;
                    return Err(error);
                }
                TunnelState::Disconnected
                    if Instant::now().duration_since(started_at) >= Duration::from_secs(2) =>
                {
                    self.cleanup_owned_connection(profile.uuid()).await;
                    return Err(with_network_conflicts(
                        NativeError::new(
                            "connection_failed",
                            "The VPN service stopped before the tunnel became ready",
                        )
                        .with_details(json!({ "protocol": protocol }))
                        .retryable(true),
                        &network_conflicts,
                    ));
                }
                _ if Instant::now() >= deadline => {
                    self.cleanup_owned_connection(profile.uuid()).await;
                    return Err(with_network_conflicts(
                        NativeError::new(
                            "connection_timeout",
                            "VPN connection timed out before the tunnel became ready",
                        )
                        .with_details(json!({ "protocol": protocol }))
                        .retryable(true),
                        &network_conflicts,
                    ));
                }
                _ => tokio::time::sleep(CONNECTION_POLL_INTERVAL).await,
            }
        }
    }

    async fn connection_cancel(&self) -> NativeResult<Value> {
        self.connection_attempt.fetch_add(1, Ordering::SeqCst);
        self.events
            .stage("connection.connect", "tunnel.cancelling", false);
        let owned_uuid = self.owned_connection_uuid.lock().await.clone();
        let Some(owned_uuid) = owned_uuid else {
            return Ok(json!({ "accepted": false, "reason": "no_native_attempt" }));
        };
        self.disconnect_owned_inner(&owned_uuid).await?;
        Ok(json!({ "accepted": true }))
    }

    async fn connection_disconnect(&self) -> NativeResult<Value> {
        self.connection_attempt.fetch_add(1, Ordering::SeqCst);
        self.events
            .stage("connection.disconnect", "tunnel.disconnecting", false);
        let _network_guard = self.network_write.lock().await;
        let owned_uuid = self
            .owned_connection_uuid
            .lock()
            .await
            .clone()
            .ok_or_else(|| {
                NativeError::new(
                    "connection_not_owned",
                    "The active VPN connection belongs to another Proton client",
                )
            })?;
        self.disconnect_owned_inner(&owned_uuid).await?;
        Ok(json!({ "accepted": true }))
    }

    async fn disconnect_inner(&self) -> NativeResult<()> {
        let owned_uuid = self.owned_connection_uuid.lock().await.clone();
        match owned_uuid {
            Some(uuid) => self.disconnect_owned_inner(&uuid).await,
            None => Ok(()),
        }
    }

    async fn disconnect_owned_inner(&self, uuid: &str) -> NativeResult<()> {
        let (settings, server_ip) = {
            let state = self.state.read().await;
            (
                state.settings.clone(),
                state
                    .selected
                    .as_ref()
                    .map(|target| target.physical.entry_ip.clone()),
            )
        };
        // Remove the only physical bypass before taking the tunnel down. If
        // this fails, keep the tunnel up so protected traffic cannot leak.
        self.reconcile_split_kill_switch_bypass(&settings, false)
            .await?;
        // Restore global LAN/DNS routing while the tunnel is still protecting
        // traffic. If this fails, keep the tunnel up instead of leaking a
        // profile-specific bypass into the disconnected state.
        self.restore_global_destination_policy().await?;
        self.stop_local_agent().await;
        let kill_switch_mode = settings.killswitch;
        let ipv6_leak_protection = settings.ipv6_leak_protection;
        let network = self.network.clone();
        let uuid_for_disconnect = uuid.to_owned();
        tokio::task::spawn_blocking(move || {
            network.disconnect_uuid(&uuid_for_disconnect)?;
            network.reconcile_kill_switch(
                kill_switch_mode,
                false,
                server_ip.as_deref(),
                ipv6_leak_protection,
            )?;
            Ok::<_, NativeError>(())
        })
        .await
        .map_err(join_error)??;
        self.owned_connection_uuid.lock().await.take();
        {
            let mut state = self.state.write().await;
            state.selected = None;
            state.traffic = None;
        }
        let observation = self.observe_blocking().await?;
        self.emit_connection(&observation, None).await;
        self.emit_features().await;
        Ok(())
    }

    async fn cleanup_owned_connection(&self, uuid: &str) {
        let _ = self.disconnect_owned_inner(uuid).await;
    }

    async fn stop_local_agent(&self) {
        self.local_agent.lock().await.take();
        *self.local_agent_snapshot.write().await = AgentSnapshot::default();
    }

    async fn restore_owned_local_agent(self: &Arc<Self>, observation: &TunnelObservation) {
        *self.owned_connection_uuid.lock().await = observation.uuid.clone();
        let restore = {
            let state = self.state.read().await;
            match (&state.session, &state.selected) {
                (Some(session), Some(target)) => {
                    let tier = session.tier();
                    let requested = (tier > 0)
                        .then(|| connection_agent_features(&state.settings, target, tier));
                    Some((session.clone(), target.logical.domain.clone(), requested))
                }
                _ => None,
            }
        };
        let Some((session, domain, requested)) = restore else {
            self.emit_connection(
                observation,
                Some("The owned VPN session could not be restored"),
            )
            .await;
            self.disconnect_after_local_agent_rejection().await;
            return;
        };

        let (agent, mut updates) = match local_agent::start(&domain, &session, requested).await {
            Ok(value) => value,
            Err(error) => {
                self.emit_connection(observation, Some(&error.message))
                    .await;
                self.disconnect_after_local_agent_rejection().await;
                return;
            }
        };
        *self.local_agent.lock().await = Some(agent);
        match tokio::time::timeout(
            LOCAL_AGENT_READY_TIMEOUT,
            wait_for_local_agent_ready(&mut updates),
        )
        .await
        {
            Ok(Ok(snapshot)) => {
                *self.local_agent_snapshot.write().await = snapshot;
                self.emit_connection(observation, None).await;
                self.emit_features().await;
                let attempt = self.connection_attempt.load(Ordering::SeqCst);
                tokio::spawn(Arc::clone(self).watch_local_agent(updates, attempt));
            }
            Ok(Err(error)) => {
                self.emit_connection(observation, Some(&error.message))
                    .await;
                self.disconnect_after_local_agent_rejection().await;
            }
            Err(_) => {
                self.emit_connection(
                    observation,
                    Some("The Proton Local Agent restore timed out"),
                )
                .await;
                self.disconnect_after_local_agent_rejection().await;
            }
        }
    }

    async fn watch_local_agent(
        self: Arc<Self>,
        mut updates: mpsc::UnboundedReceiver<AgentUpdate>,
        attempt: u64,
    ) {
        let mut retry_delay = Duration::from_secs(1);
        loop {
            while let Some(update) = updates.recv().await {
                match update {
                    AgentUpdate::Status(status) => {
                        let snapshot = AgentSnapshot::from_status(&status);
                        let hard_jailed = snapshot.hard_jailed;
                        let reason = snapshot
                            .reason
                            .clone()
                            .unwrap_or_else(|| "The Proton VPN session was restricted".into());
                        *self.local_agent_snapshot.write().await = snapshot;
                        if let Ok(observation) = self.observe_blocking().await {
                            self.emit_connection(
                                &observation,
                                hard_jailed.then_some(reason.as_str()),
                            )
                            .await;
                        }
                        self.emit_features().await;
                        if hard_jailed {
                            self.disconnect_after_local_agent_rejection().await;
                            return;
                        }
                    }
                    AgentUpdate::Error(error) => {
                        if let Ok(observation) = self.observe_blocking().await {
                            if observation.state == TunnelState::Connected {
                                self.emit_connection(&observation, Some(&error)).await;
                            }
                        }
                    }
                    AgentUpdate::Stopped => {
                        break;
                    }
                }
            }

            if self.connection_attempt.load(Ordering::SeqCst) != attempt {
                return;
            }
            let observation = match self.observe_blocking().await {
                Ok(observation) if observation.state == TunnelState::Connected => observation,
                _ => return,
            };
            *self.local_agent_snapshot.write().await = AgentSnapshot::default();
            self.emit_connection(&observation, Some("The Proton Local Agent is reconnecting"))
                .await;
            self.emit_features().await;
            self.local_agent.lock().await.take();

            tokio::time::sleep(retry_delay).await;
            if self.connection_attempt.load(Ordering::SeqCst) != attempt {
                return;
            }
            let observation = match self.observe_blocking().await {
                Ok(observation) if observation.state == TunnelState::Connected => observation,
                _ => return,
            };
            let reconnect = {
                let state = self.state.read().await;
                match (&state.session, &state.selected) {
                    (Some(session), Some(target)) => {
                        let tier = session.tier();
                        let requested = (tier > 0)
                            .then(|| connection_agent_features(&state.settings, target, tier));
                        Some((session.clone(), target.logical.domain.clone(), requested))
                    }
                    _ => None,
                }
            };
            let Some((session, domain, requested)) = reconnect else {
                self.emit_connection(
                    &observation,
                    Some("The Proton Local Agent session could not be restored"),
                )
                .await;
                return;
            };

            match local_agent::start(&domain, &session, requested).await {
                Ok((agent, mut next_updates)) => {
                    *self.local_agent.lock().await = Some(agent);
                    match tokio::time::timeout(
                        LOCAL_AGENT_READY_TIMEOUT,
                        wait_for_local_agent_ready(&mut next_updates),
                    )
                    .await
                    {
                        Ok(Ok(snapshot)) => {
                            *self.local_agent_snapshot.write().await = snapshot;
                            self.emit_connection(&observation, None).await;
                            self.emit_features().await;
                            updates = next_updates;
                            retry_delay = Duration::from_secs(1);
                            continue;
                        }
                        Ok(Err(error)) if !error.retryable => {
                            self.emit_connection(&observation, Some(&error.message))
                                .await;
                            self.disconnect_after_local_agent_rejection().await;
                            return;
                        }
                        Ok(Err(error)) => {
                            self.emit_connection(&observation, Some(&error.message))
                                .await;
                        }
                        Err(_) => {
                            self.emit_connection(
                                &observation,
                                Some("The Proton Local Agent reconnect timed out"),
                            )
                            .await;
                        }
                    }
                    self.local_agent.lock().await.take();
                }
                Err(error) => {
                    self.emit_connection(&observation, Some(&error.message))
                        .await;
                }
            }
            retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
        }
    }

    async fn disconnect_after_local_agent_rejection(&self) {
        self.connection_attempt.fetch_add(1, Ordering::SeqCst);
        let owned_uuid = self.owned_connection_uuid.lock().await.clone();
        if let Some(uuid) = owned_uuid {
            let _network_guard = self.network_write.lock().await;
            let _ = self.disconnect_owned_inner(&uuid).await;
        }
    }

    async fn observe_blocking(&self) -> NativeResult<TunnelObservation> {
        let network = self.network.clone();
        tokio::task::spawn_blocking(move || network.observe())
            .await
            .map_err(join_error)?
    }

    async fn emit_connection(&self, observation: &TunnelObservation, error: Option<&str>) {
        let local_agent = self.local_agent_snapshot.read().await.clone();
        let mut state = self.state.write().await;
        if state.selected.is_none() {
            if let (Some(catalog), Some(id)) = (&state.catalog, observation.id.as_deref()) {
                let server_name = id.strip_prefix("ProtonVPN ").unwrap_or(id);
                if let Some(logical) = catalog
                    .logical_servers
                    .iter()
                    .find(|logical| logical.name.eq_ignore_ascii_case(server_name))
                {
                    if let Some(physical) = observation
                        .endpoint
                        .as_deref()
                        .and_then(|endpoint| {
                            logical
                                .servers
                                .iter()
                                .find(|server| server.entry_ip == endpoint && server.status == 1)
                        })
                        .or_else(|| logical.servers.iter().find(|server| server.status == 1))
                    {
                        state.selected = Some(ConnectionTarget {
                            logical: logical.clone(),
                            physical: physical.clone(),
                        });
                    }
                }
            }
        }
        let protocol = observation
            .protocol
            .clone()
            .unwrap_or_else(|| normalized_protocol(&state.settings.protocol));
        if observation.state == TunnelState::Connected && state.feedback_session.is_none() {
            if let Some(target) = state.selected.clone() {
                state.feedback_session = Some(telemetry::ConnectionFeedbackSession::new(
                    target,
                    protocol.clone(),
                    state.pending_connection_trigger.clone(),
                ));
            }
        }
        let selected = state.selected.as_ref();
        let mut server = selected.map(|target| target.logical.serialized());
        if observation.state == TunnelState::Connected {
            if let (Some(payload), Some(target)) = (&mut server, selected) {
                if let Some(object) = payload.as_object_mut() {
                    object.insert(
                        "server_ip".into(),
                        Value::String(
                            local_agent
                                .server_ipv4
                                .clone()
                                .unwrap_or_else(|| target.physical.exit_ip.clone()),
                        ),
                    );
                    object.insert(
                        "server_ipv6".into(),
                        local_agent
                            .server_ipv6
                            .clone()
                            .map_or(Value::Null, Value::String),
                    );
                    object.insert(
                        "device_ip".into(),
                        local_agent
                            .device_ip
                            .clone()
                            .map_or(Value::Null, Value::String),
                    );
                    object.insert(
                        "device_country".into(),
                        local_agent
                            .device_country
                            .clone()
                            .map_or(Value::Null, Value::String),
                    );
                }
            }
        }
        let secure_core = selected
            .map(|target| target.logical.features & models::FEATURE_SECURE_CORE != 0)
            .unwrap_or(false);
        let completed_feedback =
            if observation.state == TunnelState::Disconnected && state.settings.share_statistics {
                state
                    .feedback_session
                    .take()
                    .zip(state.session.clone())
                    .map(|(feedback, session)| (feedback, session, state.settings.clone()))
            } else {
                if observation.state == TunnelState::Disconnected {
                    state.feedback_session = None;
                }
                None
            };
        if observation.state == TunnelState::Disconnected {
            state.selected = None;
            state.traffic = None;
            server = None;
        }
        drop(state);
        let restriction_reason_code = local_agent
            .hard_jailed
            .then_some(local_agent.reason_code)
            .flatten();
        let error_code =
            restriction_reason_code.map(|reason| local_agent_reason_code(Some(reason)));
        self.events.emit(
            "connection",
            json!({
                "observation_known": true,
                "status": tunnel_state_name(observation.state),
                "server": server,
                "protocol": protocol,
                "secure_core": secure_core,
                "error": error,
                "error_code": error_code,
                "restriction_reason_code": restriction_reason_code,
            }),
        );
        if let Some((feedback, session, settings)) = completed_feedback {
            let event = feedback.event(
                &session,
                &settings,
                !self.events.store.excluded_locations().is_empty(),
            );
            tokio::spawn(telemetry::enqueue_and_flush(
                self.api.clone(),
                session,
                self.paths.statistics.clone(),
                event,
                Arc::clone(&self.telemetry_write),
            ));
        }
    }

    async fn connection_feedback(&self, params: Value) -> NativeResult<Value> {
        let value = params
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !matches!(value.as_str(), "viewed" | "positive" | "negative") {
            return Err(NativeError::new(
                "invalid_params",
                "Connection feedback must be viewed, positive or negative",
            ));
        }
        let mut state = self.state.write().await;
        if !state.settings.share_statistics || !state.connection_feedback_feature_enabled {
            return Err(NativeError::new(
                "connection_feedback_unavailable",
                "Connection feedback is unavailable for this session",
            ));
        }
        let feedback = state.feedback_session.as_mut().ok_or_else(|| {
            NativeError::new(
                "connection_feedback_unavailable",
                "Connect Proton VPN before submitting connection feedback",
            )
        })?;
        if feedback.sent() && value != "viewed" {
            return Err(NativeError::new(
                "connection_feedback_already_sent",
                "Connection feedback was already submitted for this session",
            ));
        }
        feedback.update_feedback(&value);
        let sent = feedback.sent();
        drop(state);
        self.events
            .stage("connection.feedback", "support.feedback_recorded", false);
        self.emit_features().await;
        Ok(json!({ "recorded": true, "sent": sent }))
    }

    async fn netshield_stats(&self) -> NativeResult<Value> {
        let observation = self.observe_blocking().await?;
        if observation.state != TunnelState::Connected {
            return Ok(json!({ "requested": false, "reason": "not_connected" }));
        }
        let agent = self.local_agent.lock().await;
        let agent = agent.as_ref().ok_or_else(|| {
            NativeError::new(
                "connection_not_owned",
                "Reconnect with the native backend before requesting NetShield statistics",
            )
        })?;
        agent.request_statistics().await?;
        Ok(json!({ "requested": true }))
    }

    async fn traffic(&self) -> NativeResult<Value> {
        let observation = self.observe_blocking().await?;
        if observation.state != TunnelState::Connected {
            self.state.write().await.traffic = None;
            return Ok(json!({ "known": false }));
        }
        let stats = Path::new("/sys/class/net/proton0/statistics");
        let rx = read_counter(&stats.join("rx_bytes"))?;
        let tx = read_counter(&stats.join("tx_bytes"))?;
        let now = Instant::now();
        let mut state = self.state.write().await;
        let (download_speed, upload_speed) = state
            .traffic
            .as_ref()
            .and_then(|sample| {
                let elapsed = now.duration_since(sample.observed_at).as_secs_f64();
                (elapsed >= 0.5 && rx >= sample.rx && tx >= sample.tx).then(|| {
                    (
                        ((rx - sample.rx) as f64 / elapsed) as u64,
                        ((tx - sample.tx) as f64 / elapsed) as u64,
                    )
                })
            })
            .unwrap_or((0, 0));
        state.traffic = Some(TrafficSample {
            rx,
            tx,
            observed_at: now,
        });
        Ok(json!({
            "known": true,
            "download_bytes": rx,
            "upload_bytes": tx,
            "download_bytes_per_second": download_speed,
            "upload_bytes_per_second": upload_speed,
        }))
    }

    async fn report_issue_categories(&self) -> NativeResult<Value> {
        let session = self.state.read().await.session.clone();
        if let Some(session) = session {
            let api_session = session_bootstrap::stored_api_session(&session);
            if let Ok(response) = self.api.get(support::CATEGORY_ENDPOINT, &api_session).await {
                if let Some(categories) = response.get("Categories") {
                    if let Ok(categories) = support::normalize_categories(categories) {
                        return Ok(json!({ "categories": categories, "source": "api" }));
                    }
                }
            }
        }
        Ok(json!({
            "categories": support::fallback_categories()?,
            "source": "fallback",
        }))
    }

    async fn report_issue_submit(&self, params: Value) -> NativeResult<Value> {
        let request = support::report_request(&params)?;
        let stored = self.state.read().await.session.clone();
        let api_session = stored.as_ref().map(session_bootstrap::stored_api_session);
        let username = stored
            .as_ref()
            .map(|session| session.account_name.trim())
            .filter(|name| !name.is_empty())
            .unwrap_or("Not provided")
            .to_owned();
        let (os, os_version) = support::os_release();
        let mut fields = vec![
            ("OS".to_owned(), os),
            ("OSVersion".to_owned(), os_version),
            ("Client".to_owned(), support::REPORT_CLIENT.to_owned()),
            (
                "ClientVersion".to_owned(),
                support::REPORT_CLIENT_VERSION.to_owned(),
            ),
            ("ClientType".to_owned(), "2".to_owned()),
            ("Title".to_owned(), support::REPORT_TITLE.to_owned()),
            (
                "Description".to_owned(),
                support::report_description(&request),
            ),
            ("Username".to_owned(), username),
            ("Email".to_owned(), request.email.clone()),
        ];
        if let Some(session) = &stored {
            if !session.vpn.location.isp.trim().is_empty() {
                fields.push(("ISP".to_owned(), session.vpn.location.isp.clone()));
            }
            if !session.vpn.location.country.trim().is_empty() {
                fields.push(("Country".to_owned(), session.vpn.location.country.clone()));
            }
        }

        let logs = if request.include_logs {
            tokio::task::spawn_blocking(support::collect_logs)
                .await
                .map_err(join_error)?
        } else {
            support::LogCollection::default()
        };
        let attachments = logs
            .attachments
            .iter()
            .enumerate()
            .map(|(index, attachment)| {
                (
                    format!("Attachment-{index}"),
                    attachment.filename.clone(),
                    attachment.data.clone(),
                )
            })
            .collect::<Vec<_>>();
        let dry_run =
            env::var_os("PROTON_OMARCHY_REPORT_ISSUE_DRY_RUN").is_some_and(|value| value == "1");
        if !dry_run {
            self.api
                .post_multipart(
                    support::REPORT_ENDPOINT,
                    &fields,
                    &attachments,
                    api_session.as_ref(),
                )
                .await
                .map_err(|error| {
                    NativeError::new(
                        "report_issue_submit_failed",
                        "Proton could not submit the support report",
                    )
                    .with_source(error)
                    .retryable(true)
                })?;
        }
        Ok(json!({
            "sent": !dry_run,
            "dry_run": dry_run,
            "include_logs": request.include_logs,
            "attachment_count": attachments.len(),
            "attachment_names": logs.attachments.iter().map(|item| item.filename.clone()).collect::<Vec<_>>(),
            "log_source_count": if request.include_logs { 3 } else { 0 },
            "log_failures": logs.failures,
            "category": request.category,
            "field_count": request.fields.len(),
            "client": support::REPORT_CLIENT,
            "title": support::REPORT_TITLE,
            "destination": "proton_ag",
        }))
    }

    async fn diagnostics(&self) -> NativeResult<Value> {
        let (signed_in, catalog_loaded, client_config_loaded) = {
            let state = self.state.read().await;
            (
                state.session.is_some(),
                state.catalog.is_some(),
                state.client_config.is_some(),
            )
        };
        let observation = self.observe_blocking().await?;
        let api_probe = tokio::time::timeout(
            Duration::from_secs(5),
            self.api.public_get("/vpn/v2/clientconfig"),
        )
        .await;
        let (api_reachable, tls_pin_verified) = match api_probe {
            Ok(Ok(_)) => (true, true),
            Ok(Err(_)) => (false, false),
            Err(_) => (false, false),
        };
        let logs = tokio::task::spawn_blocking(support::collect_log_metadata)
            .await
            .map_err(join_error)?;
        let sources = logs
            .attachments
            .iter()
            .map(|attachment| {
                json!({
                    "source": attachment.source,
                    "available": true,
                    "bytes": attachment.data.len(),
                })
            })
            .collect::<Vec<_>>();
        let (os, os_version) = support::os_release();
        let protocols = available_protocols();
        let tunnel_state = tunnel_state_name(observation.state);
        let summary = support::diagnostic_summary(&support::DiagnosticSummary {
            os: &os,
            os_version: &os_version,
            backend_version: NATIVE_VERSION,
            signed_in,
            catalog_loaded,
            client_config_loaded,
            tunnel_state,
            protocol: observation.protocol.as_deref(),
            protocols: &protocols,
            api_reachable,
            tls_pin_verified,
            log_sources_available: sources.len(),
            log_source_failures: logs.failures.len(),
        });
        Ok(json!({
            "backend": "proton_rust",
            "backend_version": NATIVE_VERSION,
            "signed_in": signed_in,
            "catalog_loaded": catalog_loaded,
            "client_config_loaded": client_config_loaded,
            "settings_loaded": true,
            "connection_observation": tunnel_state,
            "protocol": observation.protocol,
            "protocols": protocols,
            "api_reachable": api_reachable,
            "tls_pin_verified": tls_pin_verified,
            "sources": sources,
            "failure_count": logs.failures.len(),
            "failures": logs.failures,
            "raw_contents_exposed": false,
            "summary": summary,
        }))
    }
}

async fn wait_for_local_agent_ready(
    updates: &mut mpsc::UnboundedReceiver<AgentUpdate>,
) -> NativeResult<AgentSnapshot> {
    while let Some(update) = updates.recv().await {
        match update {
            AgentUpdate::Status(status) => {
                let snapshot = AgentSnapshot::from_status(&status);
                if snapshot.connected {
                    return Ok(snapshot);
                }
                if snapshot.hard_jailed {
                    return Err(NativeError::new(
                        local_agent_reason_code(snapshot.reason_code),
                        snapshot
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Proton restricted this VPN session".into()),
                    )
                    .with_details(json!({ "reason_code": snapshot.reason_code }))
                    .retryable(false));
                }
            }
            AgentUpdate::Error(error) => {
                return Err(NativeError::new(
                    "local_agent_failed",
                    "Proton rejected the requested VPN session features",
                )
                .with_source(error)
                .retryable(true));
            }
            AgentUpdate::Stopped => {
                return Err(NativeError::new(
                    "local_agent_disconnected",
                    "The Proton Local Agent connection stopped before confirming the VPN session",
                )
                .retryable(true));
            }
        }
    }
    Err(NativeError::new(
        "local_agent_disconnected",
        "The Proton Local Agent connection closed unexpectedly",
    )
    .retryable(true))
}

fn local_agent_reason_code(reason: Option<i32>) -> &'static str {
    match reason {
        Some(local_agent_rs::REASON_CODE_CERTIFICATE_EXPIRED) => "vpn_certificate_expired",
        Some(local_agent_rs::REASON_CODE_2FA_UNSPECIFIED)
        | Some(local_agent_rs::REASON_CODE_2FA_EXPIRED)
        | Some(local_agent_rs::REASON_CODE_2FA_SITUATION_CHANGED) => "two_factor_required",
        Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_UNKNOWN)
        | Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_FREE)
        | Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_BASIC)
        | Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_PLUS)
        | Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_VISIONARY)
        | Some(local_agent_rs::REASON_CODE_MAX_SESSIONS_PRO) => "maximum_sessions_reached",
        Some(local_agent_rs::REASON_CODE_USER_TORRENT_NOT_ALLOWED) => "p2p_not_allowed",
        _ => "local_agent_jailed",
    }
}

fn connection_agent_features(
    settings: &NativeSettings,
    target: &ConnectionTarget,
    tier: u8,
) -> local_agent_rs::AgentFeatures {
    debug_assert!(tier > 0);
    local_agent::requested_features(
        settings.features.netshield,
        settings.features.moderate_nat,
        settings.features.vpn_accelerator,
        settings.features.port_forwarding,
        &target.physical.label,
    )
}

fn effective_connection_settings(
    params: &Value,
    global: &NativeSettings,
    tier: u8,
) -> NativeResult<(NativeSettings, String, bool)> {
    let Some(raw) = params.get("profile_settings") else {
        let protocol = normalized_protocol(&global.protocol);
        if !available_protocol(&protocol) {
            return Err(NativeError::new(
                "protocol_unavailable",
                format!("VPN protocol is unavailable: {protocol}"),
            ));
        }
        return Ok((global.clone(), protocol, false));
    };
    let raw = raw.as_object().ok_or_else(|| {
        NativeError::new("invalid_params", "profile_settings must be a JSON object")
    })?;
    let protocol = raw
        .get("protocol")
        .and_then(Value::as_str)
        .map(normalized_protocol)
        .unwrap_or_else(|| "protun-smart".into());
    if !available_protocol(&protocol) {
        return Err(NativeError::new(
            "protocol_unavailable",
            format!("VPN protocol is unavailable: {protocol}"),
        ));
    }

    let netshield_enabled = optional_profile_bool(raw, "netshield_enabled", true)?;
    let netshield_level = raw
        .get("netshield_level")
        .map(|value| {
            value.as_u64().filter(|level| *level <= 2).ok_or_else(|| {
                NativeError::new(
                    "invalid_params",
                    "profile netshield_level must be an integer from 0 through 2",
                )
            })
        })
        .transpose()?
        .unwrap_or(2) as u8;
    let moderate_nat = optional_profile_bool(raw, "moderate_nat", false)?;
    let port_forwarding = optional_profile_bool(raw, "port_forwarding", false)?;
    let custom_dns = profile_custom_dns(raw.get("custom_dns"))?;
    let allow_lan_connections = optional_profile_policy(raw, "allow_lan_connections")?;
    let allow_local_dns = optional_profile_policy(raw, "allow_local_dns")?;
    if tier == 0 && (netshield_enabled || moderate_nat || port_forwarding) {
        return Err(NativeError::new(
            "feature_unavailable",
            "Profile NetShield, Moderate NAT and port forwarding require a paid plan",
        ));
    }
    if moderate_nat && port_forwarding {
        return Err(NativeError::new(
            "profile_settings_conflict",
            "Moderate NAT and port forwarding cannot be enabled together",
        ));
    }
    if netshield_enabled && custom_dns.as_ref().is_some_and(|dns| dns.enabled) {
        return Err(NativeError::new(
            "profile_settings_conflict",
            "Custom DNS and NetShield cannot be enabled in the same profile",
        ));
    }

    let mut settings = global.clone();
    settings.protocol = protocol.clone();
    settings.features.netshield = if netshield_enabled {
        netshield_level
    } else {
        0
    };
    settings.features.moderate_nat = moderate_nat;
    settings.features.port_forwarding = port_forwarding;
    if let Some(custom_dns) = custom_dns {
        settings.custom_dns = custom_dns;
    } else if netshield_enabled {
        // Preserve the existing profile precedence: an explicit profile
        // NetShield choice wins over inherited global DNS. Explicit custom
        // DNS is rejected above instead of being silently discarded.
        settings.custom_dns.enabled = false;
    }
    if let Some(allow) = allow_lan_connections {
        settings.allow_lan_connections = allow;
    }
    if let Some(allow) = allow_local_dns {
        settings.allow_local_dns = allow;
    }
    Ok((settings, protocol, true))
}

fn profile_custom_dns(value: Option<&Value>) -> NativeResult<Option<models::CustomDns>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(|| {
        NativeError::new("invalid_params", "profile custom_dns must be an object")
    })?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("inherit")
        .trim()
        .to_ascii_lowercase();
    if mode == "inherit" {
        return Ok(None);
    }
    if mode == "off" {
        return Ok(Some(models::CustomDns::default()));
    }
    if mode != "custom" {
        return Err(NativeError::new(
            "invalid_params",
            "profile custom DNS mode must be inherit, off or custom",
        ));
    }
    let servers = object
        .get("servers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            NativeError::new(
                "invalid_dns",
                "A custom DNS profile requires an array of DNS server IPs",
            )
        })?;
    if servers.len() > 16 {
        return Err(NativeError::new(
            "invalid_dns",
            "A profile can contain at most 16 custom DNS servers",
        ));
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in servers {
        let value = value.as_str().ok_or_else(|| {
            NativeError::new("invalid_dns", "Profile DNS servers must be strings")
        })?;
        if value.trim().is_empty() {
            continue;
        }
        let address = value.trim().parse::<IpAddr>().map_err(|error| {
            NativeError::new("invalid_dns", "Invalid profile DNS IP").with_source(error)
        })?;
        let address = address.to_string();
        if seen.insert(address.clone()) {
            normalized.push(json!({ "ip": address, "enabled": true }));
        }
    }
    if normalized.is_empty() {
        return Err(NativeError::new(
            "invalid_dns",
            "A custom DNS profile requires at least one DNS server",
        ));
    }
    Ok(Some(models::CustomDns {
        enabled: true,
        ip_list: normalized,
        extra: serde_json::Map::new(),
    }))
}

fn optional_profile_policy(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> NativeResult<Option<bool>> {
    object
        .get(key)
        .map(|value| {
            if value.is_null() {
                Ok(None)
            } else {
                value.as_bool().map(Some).ok_or_else(|| {
                    NativeError::new(
                        "invalid_params",
                        format!("profile {key} must be boolean or null"),
                    )
                })
            }
        })
        .transpose()
        .map(Option::flatten)
}

fn optional_profile_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default: bool,
) -> NativeResult<bool> {
    object
        .get(key)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                NativeError::new("invalid_params", format!("profile {key} must be boolean"))
            })
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn bool_feature_value(params: &Value, feature: &str) -> NativeResult<bool> {
    params.get("value").and_then(Value::as_bool).ok_or_else(|| {
        NativeError::new("invalid_params", format!("{feature} value must be boolean"))
    })
}

fn require_paid_feature(tier: u8, feature: &str) -> NativeResult<()> {
    if tier == 0 {
        return Err(NativeError::new(
            "feature_restricted",
            format!("{feature} requires a paid Proton VPN plan"),
        ));
    }
    Ok(())
}

fn unix_seconds() -> NativeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            NativeError::new("clock_invalid", "System clock is before the Unix epoch")
                .with_source(error)
        })
}

fn load_state(paths: &Paths) -> NativeResult<RuntimeState> {
    let session = SecretStore.load_default()?;
    let catalog = Some(ServerCatalog::load(&paths.catalog)?);
    let client_config = load_json::<ClientConfig>(&paths.client_config).ok();
    let settings = load_json::<NativeSettings>(&paths.settings).unwrap_or_default();
    Ok(RuntimeState {
        session,
        catalog,
        client_config,
        settings,
        selected: None,
        traffic: None,
        connection_feedback_feature_enabled: false,
        feedback_session: None,
        pending_connection_trigger: "connection_card".into(),
    })
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> NativeResult<T> {
    let raw = fs::read(path).map_err(|error| {
        NativeError::new(
            "cache_unavailable",
            format!("Unable to read Proton cache file {}", path.display()),
        )
        .with_source(error)
        .retryable(true)
    })?;
    serde_json::from_slice(&raw).map_err(|error| {
        NativeError::new(
            "cache_invalid",
            format!("Proton cache file is invalid: {}", path.display()),
        )
        .with_source(error)
        .retryable(true)
    })
}

fn normalized_protocol(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "smart" | "protun-smart" => "protun-smart",
        "wireguard" | "wireguard-udp" | "protun-udp" => "protun-udp",
        "wireguard-tcp" | "protun-tcp" => "protun-tcp",
        "wireguard-tls" | "stealth" | "protun-tls" => "protun-tls",
        value => value,
    }
    .to_owned()
}

fn connection_trigger(params: &Value) -> &'static str {
    if params.get("profile_settings").is_some() {
        return "profile";
    }
    let target = params.get("target").and_then(Value::as_object);
    match target {
        Some(target)
            if target
                .get("gateway_name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                && target
                    .get("server_name")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty()) =>
        {
            "gateways_server"
        }
        Some(target)
            if target
                .get("gateway_name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()) =>
        {
            "gateways_gateway"
        }
        Some(target)
            if target
                .get("server_name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()) =>
        {
            "countries_server"
        }
        Some(target)
            if target
                .get("country_code")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()) =>
        {
            "countries_country"
        }
        _ => "connection_card",
    }
}

fn feature_flag_enabled(payload: &Value, name: &str) -> bool {
    payload
        .get("toggles")
        .or_else(|| payload.get("Toggles"))
        .and_then(Value::as_array)
        .and_then(|toggles| {
            toggles.iter().find(|toggle| {
                toggle
                    .get("Name")
                    .or_else(|| toggle.get("name"))
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
            })
        })
        .and_then(|toggle| toggle.get("enabled").or_else(|| toggle.get("Enabled")))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn tunnel_state_name(state: TunnelState) -> &'static str {
    match state {
        TunnelState::Disconnected => "disconnected",
        TunnelState::Connecting => "connecting",
        TunnelState::Connected => "connected",
        TunnelState::Error => "error",
    }
}

fn kill_switch_name(value: u8) -> &'static str {
    match value {
        2 => "advanced",
        1 => "standard",
        _ => "off",
    }
}

fn kill_switch_value(value: &str) -> Option<u8> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(0),
        "standard" | "on" => Some(1),
        "advanced" | "permanent" => Some(2),
        _ => None,
    }
}

fn split_state(
    value: &models::SplitTunnelingSettings,
    available: bool,
    ip_ranges_supported: bool,
) -> Value {
    let standard = value.config("exclude");
    let inverse = value.config("include");
    json!({
        "mode": if !value.enabled { "off" } else if value.mode == "include" { "inverse" } else { "standard" },
        "availability_known": true,
        "available": available,
        "app_paths_supported": available,
        "ip_ranges_supported": ip_ranges_supported,
        "standard": {
            "app_paths": standard.app_paths,
            "ip_ranges": standard.ip_ranges,
        },
        "inverse": {
            "app_paths": inverse.app_paths,
            "ip_ranges": inverse.ip_ranges,
        },
    })
}

fn available_protocol(protocol: &str) -> bool {
    match protocol {
        "protun-smart" | "protun-udp" | "protun-tcp" | "protun-tls" => {
            Path::new(PROTUN_DESCRIPTOR).exists()
        }
        "openvpn-udp" | "openvpn-tcp" => Path::new(OPENVPN_DESCRIPTOR).exists(),
        _ => false,
    }
}

fn available_protocols() -> Vec<&'static str> {
    let mut protocols = Vec::with_capacity(6);
    if Path::new(PROTUN_DESCRIPTOR).exists() {
        protocols.extend(["protun-smart", "protun-udp", "protun-tcp", "protun-tls"]);
    }
    if Path::new(OPENVPN_DESCRIPTOR).exists() {
        protocols.extend(["openvpn-udp", "openvpn-tcp"]);
    }
    protocols
}

fn split_request_config(
    params: &Value,
    request_name: &str,
    mode: &str,
    previous: &SplitTunnelingConfig,
) -> NativeResult<SplitTunnelingConfig> {
    const MAX_SPLIT_APPS: usize = 128;
    const MAX_SPLIT_APP_PATH_BYTES: usize = 4096;

    let raw = params
        .get(request_name)
        .cloned()
        .unwrap_or_else(|| json!({}));
    let object = raw.as_object().ok_or_else(|| {
        NativeError::new("invalid_params", "standard/inverse configs must be objects")
    })?;
    let raw_apps = object
        .get("app_paths")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let apps = raw_apps
        .as_array()
        .ok_or_else(|| NativeError::new("invalid_split_apps", "app_paths must be an array"))?;
    if apps.len() > MAX_SPLIT_APPS {
        return Err(NativeError::new(
            "invalid_split_apps",
            format!("app_paths must contain at most {MAX_SPLIT_APPS} entries"),
        ));
    }
    let mut app_paths = Vec::new();
    let mut seen = HashSet::new();
    for raw in apps {
        let value = raw
            .as_str()
            .ok_or_else(|| NativeError::new("invalid_split_apps", "App entries must be strings"))?;
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
            || value.len() > MAX_SPLIT_APP_PATH_BYTES
        {
            return Err(NativeError::new(
                "invalid_split_apps",
                "App entry contains invalid characters or is too long",
            ));
        }
        if seen.insert(value.to_owned()) {
            app_paths.push(value.to_owned());
        }
    }
    const MAX_SPLIT_IP_RANGES: usize = 256;
    let raw_ranges = object
        .get("ip_ranges")
        .cloned()
        .unwrap_or_else(|| json!(previous.ip_ranges));
    let ranges = raw_ranges
        .as_array()
        .ok_or_else(|| NativeError::new("invalid_split_ip_ranges", "ip_ranges must be an array"))?;
    if ranges.len() > MAX_SPLIT_IP_RANGES {
        return Err(NativeError::new(
            "invalid_split_ip_ranges",
            format!("ip_ranges must contain at most {MAX_SPLIT_IP_RANGES} entries"),
        ));
    }
    let mut ip_ranges = Vec::new();
    let mut seen_ranges = HashSet::new();
    for raw in ranges {
        let value = raw.as_str().ok_or_else(|| {
            NativeError::new(
                "invalid_split_ip_ranges",
                "IP range entries must be strings",
            )
        })?;
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let network = value
            .parse::<IpNet>()
            .or_else(|_| {
                value.parse::<IpAddr>().map(|address| match address {
                    IpAddr::V4(address) => IpNet::new(address.into(), 32).expect("valid prefix"),
                    IpAddr::V6(address) => IpNet::new(address.into(), 128).expect("valid prefix"),
                })
            })
            .map_err(|error| {
                NativeError::new(
                    "invalid_split_ip_ranges",
                    format!("Invalid IP address or CIDR range: {value}"),
                )
                .with_source(error)
            })?
            .trunc()
            .to_string();
        if seen_ranges.insert(network.clone()) {
            ip_ranges.push(network);
        }
    }

    let mut config = previous.clone();
    config.mode = mode.into();
    config.app_paths = app_paths;
    config.ip_ranges = ip_ranges;
    Ok(config)
}

fn dns_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Object(value)
            if value
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true) =>
        {
            value
                .get("ip")
                .or_else(|| value.get("address"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        }
        _ => None,
    }
}

fn read_counter(path: &Path) -> NativeResult<u64> {
    fs::read_to_string(path)
        .map_err(|error| {
            NativeError::new(
                "traffic_unavailable",
                "VPN traffic counters are unavailable",
            )
            .with_source(error)
            .retryable(true)
        })?
        .trim()
        .parse::<u64>()
        .map_err(|error| {
            NativeError::new("traffic_invalid", "VPN traffic counters are invalid")
                .with_source(error)
        })
}

fn upgrade_url(selector: &str, modal_source: &str) -> String {
    let mut redirect = "proton-vpn://refresh-account".to_owned();
    if !modal_source.is_empty() {
        redirect.push_str("?modal-source=");
        redirect.push_str(modal_source);
    }
    format!(
        "{AUTO_LOGIN_BASE_URL}?action=subscribe-account&fullscreen=off&redirect={redirect}&start=compare&type=upgrade&app=vpn#selector={selector}"
    )
}

fn catalog_unavailable() -> NativeError {
    NativeError::new(
        "catalog_unavailable",
        "The Proton server catalog is not available in the local cache",
    )
    .retryable(true)
}

fn client_config_unavailable() -> NativeError {
    NativeError::new(
        "client_config_unavailable",
        "The Proton client configuration is not available in the local cache",
    )
    .retryable(true)
}

fn join_error(error: tokio::task::JoinError) -> NativeError {
    NativeError::new(
        "native_task_failed",
        "A Rust backend worker stopped unexpectedly",
    )
    .with_source(error)
    .retryable(true)
}

fn with_network_conflicts(error: NativeError, conflicts: &[String]) -> NativeError {
    if conflicts.is_empty() {
        return error;
    }
    NativeError::new(
        "network_conflict_detected",
        "Another active VPN or tunnel interface might be preventing Proton VPN from connecting",
    )
    .with_details(json!({
        "interfaces": conflicts,
        "underlying_code": error.code,
        "underlying_error": error.message,
    }))
    .retryable(true)
}

fn required_param(
    params: &Value,
    name: &str,
    max_bytes: usize,
    trim: bool,
) -> NativeResult<String> {
    let value = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| NativeError::new("invalid_params", format!("{name} is required")))?;
    let value = if trim { value.trim() } else { value };
    if value.is_empty() || value.len() > max_bytes {
        return Err(NativeError::new(
            "invalid_params",
            format!("{name} must contain between 1 and {max_bytes} bytes"),
        ));
    }
    Ok(value.to_owned())
}

fn login_error(mut error: NativeError, stage: &str) -> NativeError {
    error.code = match (stage, error.code.as_str()) {
        (_, "human_verification_required" | "sso_required") => error.code,
        ("two_factor", "authentication_expired") => "two_factor_session_expired".into(),
        ("two_factor", "authentication_failed") => "two_factor_failed".into(),
        ("credentials", "authentication_failed") => "login_failed".into(),
        _ => error.code,
    };
    let mut details = error
        .details
        .take()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    details.insert("auth_stage".into(), Value::String(stage.to_owned()));
    error.details = Some(Value::Object(details));
    if error.code == "login_failed" || error.code == "two_factor_failed" {
        error.retryable = true;
    }
    error
}

fn remove_cache_file(path: &Path) -> NativeResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(NativeError::new(
            "cache_delete_failed",
            format!("Unable to remove Proton cache file {}", path.display()),
        )
        .with_source(error)),
    }
}

fn error_message(error: &NativeError) -> BackendError {
    BackendError::new(&error.code, &error.message).retryable(error.retryable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_aliases_are_canonical() {
        assert_eq!(normalized_protocol("smart"), "protun-smart");
        assert_eq!(normalized_protocol("wireguard"), "protun-udp");
        assert_eq!(normalized_protocol("wireguard-tcp"), "protun-tcp");
        assert_eq!(normalized_protocol("stealth"), "protun-tls");
    }

    #[test]
    fn windows_connection_feedback_feature_flag_is_case_tolerant() {
        assert!(feature_flag_enabled(
            &json!({ "toggles": [{ "Name": "IsConnectionFeedbackEnabled", "enabled": true }] }),
            "isconnectionfeedbackenabled"
        ));
        assert!(!feature_flag_enabled(&json!({ "toggles": [] }), "missing"));
    }

    #[test]
    fn kill_switch_names_round_trip() {
        for (name, value) in [("off", 0), ("standard", 1), ("advanced", 2)] {
            assert_eq!(kill_switch_value(name), Some(value));
            assert_eq!(kill_switch_name(value), name);
        }
        assert_eq!(kill_switch_value("permanent"), Some(2));
        assert_eq!(kill_switch_value("invalid"), None);
    }

    #[test]
    fn split_settings_preserve_both_modes() {
        let settings: models::SplitTunnelingSettings = serde_json::from_value(json!({
            "enabled": true,
            "mode": "include",
            "config_by_mode": {
                "exclude": { "app_paths": ["/a"], "ip_ranges": [] },
                "include": { "app_paths": ["/b"], "ip_ranges": ["10.0.0.0/8"] },
            },
        }))
        .expect("settings");
        let split = split_state(&settings, true, true);
        assert_eq!(split["mode"], "inverse");
        assert_eq!(split["available"], true);
        assert_eq!(split["standard"]["app_paths"][0], "/a");
        assert_eq!(split["inverse"]["app_paths"][0], "/b");
    }

    #[test]
    fn split_request_accepts_apps_or_canonical_ip_ranges() {
        let previous = SplitTunnelingConfig::new("exclude");
        let config = split_request_config(
            &json!({
                "standard": {
                    "app_paths": [],
                    "ip_ranges": ["192.0.2.42/24", "192.0.2.0/24", "2001:db8::1"]
                }
            }),
            "standard",
            "exclude",
            &previous,
        )
        .expect("valid IP-only split configuration");
        assert!(config.app_paths.is_empty());
        assert_eq!(config.ip_ranges, ["192.0.2.0/24", "2001:db8::1/128"]);

        let error = split_request_config(
            &json!({ "standard": { "ip_ranges": ["not-a-network"] } }),
            "standard",
            "exclude",
            &previous,
        )
        .expect_err("invalid range must fail");
        assert_eq!(error.code, "invalid_split_ip_ranges");
    }

    #[test]
    fn upgrade_handoff_matches_frozen_web_contract() {
        assert_eq!(
            upgrade_url("selector-token", "Countries"),
            "https://account.proton.me/lite?action=subscribe-account&fullscreen=off&redirect=proton-vpn://refresh-account?modal-source=Countries&start=compare&type=upgrade&app=vpn#selector=selector-token"
        );
    }

    #[test]
    fn login_error_only_blames_credentials_for_proton_auth_rejection() {
        let rejected = login_error(
            NativeError::new("authentication_failed", "rejected"),
            "credentials",
        );
        assert_eq!(rejected.code, "login_failed");

        let transport = login_error(
            NativeError::new("api_response_invalid", "bad response").retryable(true),
            "credentials",
        );
        assert_eq!(transport.code, "api_response_invalid");
        assert!(transport.retryable);
        assert_eq!(transport.details.unwrap()["auth_stage"], "credentials");
    }

    #[test]
    fn profile_custom_dns_and_destination_policies_are_strictly_parsed() {
        let dns = profile_custom_dns(Some(&json!({
            "mode": "custom",
            "servers": ["1.1.1.1", "1.1.1.1", "2001:0db8::1"]
        })))
        .expect("valid profile DNS")
        .expect("explicit profile DNS");
        assert!(dns.enabled);
        assert_eq!(dns.ip_list.len(), 2);
        assert_eq!(dns.ip_list[1]["ip"], "2001:db8::1");

        assert!(profile_custom_dns(Some(&json!({ "mode": "inherit" })))
            .unwrap()
            .is_none());
        assert!(
            !profile_custom_dns(Some(&json!({ "mode": "off" })))
                .unwrap()
                .unwrap()
                .enabled
        );

        let policies = json!({
            "allow_lan_connections": true,
            "allow_local_dns": null
        });
        let policies = policies.as_object().unwrap();
        assert_eq!(
            optional_profile_policy(policies, "allow_lan_connections").unwrap(),
            Some(true)
        );
        assert_eq!(
            optional_profile_policy(policies, "allow_local_dns").unwrap(),
            None
        );
    }
}
