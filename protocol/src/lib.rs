use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const SOCKET_FILE_NAME: &str = "proton-omarchy.sock";

fn default_true() -> bool {
    true
}

/// Stable public request methods retained for JSON Lines v1 compatibility.
/// The Rust backend may expose a compatible superset; its exact catalog lives
/// beside its dispatcher in `agent/src/backend.rs`.
pub const BACKEND_METHODS: &[&str] = &[
    "account.get",
    "account.upgrade_url",
    "report_issue.categories.get",
    "report_issue.submit",
    "diagnostics.get",
    "account.login",
    "account.login_guest",
    "account.submit_2fa",
    "account.authenticate_fido2",
    "account.submit_fido2_pin",
    "account.cancel_fido2",
    "account.logout",
    "locations.get",
    "servers.get",
    "feature.set",
    "protocol.set",
    "dns.set",
    "apps.get",
    "split_tunneling.set",
    "connection.observe",
    "connection.connect",
    "connection.cancel",
    "connection.disconnect",
    "traffic.get",
];

/// Requests owned directly by the Rust store authority.
pub const STORE_METHODS: &[&str] = &[
    "store.get",
    "onboarding.complete",
    "preferences.set",
    "profiles.list",
    "profiles.save",
    "profiles.duplicate",
    "profiles.delete",
    "excluded_locations.get",
    "excluded_locations.set",
    "recents.list",
    "recents.record",
    "recents.pin",
    "recents.delete",
    "default_connection.set",
    "connection.resolve",
];

#[derive(Debug, Clone, Deserialize)]
pub struct RequestEnvelope {
    pub v: u16,
    pub id: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Response {
        v: u16,
        id: Option<String>,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProtocolError>,
    },
    Event {
        v: u16,
        event: String,
        data: Value,
    },
}

impl ServerMessage {
    pub fn ok(id: impl Into<String>, result: Value) -> Self {
        Self::Response {
            v: PROTOCOL_VERSION,
            id: Some(id.into()),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::error_with_details(id, code, message, None, false)
    }

    pub fn error_with_details(
        id: Option<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        details: Option<Value>,
        retryable: bool,
    ) -> Self {
        Self::Response {
            v: PROTOCOL_VERSION,
            id,
            ok: false,
            result: None,
            error: Some(ProtocolError {
                code: code.into(),
                message: message.into(),
                details,
                retryable,
            }),
        }
    }

    pub fn event(name: impl Into<String>, data: Value) -> Self {
        Self::Event {
            v: PROTOCOL_VERSION,
            event: name.into(),
            data,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloParams {
    pub client: String,
    pub client_version: String,
    #[serde(default)]
    pub client_instance_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectParams {
    #[serde(default)]
    pub target: Option<ConnectTarget>,
    #[serde(default)]
    pub profile_settings: Option<ProfileConnectionSettings>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConnectionSettings {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub netshield_enabled: bool,
    #[serde(default)]
    pub netshield_level: u8,
    #[serde(default)]
    pub moderate_nat: bool,
    #[serde(default)]
    pub port_forwarding: bool,
    #[serde(default)]
    pub custom_dns: ProfileCustomDns,
    #[serde(default)]
    pub allow_lan_connections: Option<bool>,
    #[serde(default)]
    pub allow_local_dns: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileCustomDns {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectTarget {
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub country_name: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub gateway_name: Option<String>,
    #[serde(default)]
    pub server_load: Option<u8>,
    #[serde(default)]
    pub secure_core: bool,
    #[serde(default)]
    pub p2p: bool,
    #[serde(default)]
    pub tor: bool,
    #[serde(default)]
    pub random: bool,
    #[serde(default)]
    pub free_random: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLoginParams {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountTwoFactorParams {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServersGetParams {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_server_page_size")]
    pub limit: usize,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub gateway_name: String,
    #[serde(default)]
    pub feature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTunnelingSetParams {
    pub enabled: bool,
    pub mode: SplitTunnelingMode,
    #[serde(default)]
    pub standard: SplitTunnelingConfigState,
    #[serde(default)]
    pub inverse: SplitTunnelingConfigState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppsGetParams {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_server_page_size")]
    pub limit: usize,
    #[serde(default)]
    pub query: String,
}

fn default_server_page_size() -> usize {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSetParams {
    pub feature: FeatureName,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureName {
    KillSwitch,
    Netshield,
    VpnAccelerator,
    AnonymousCrashReports,
    SecureCore,
    SplitTunneling,
    PortForwarding,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub revision: u64,
    pub account: AccountState,
    pub backend: BackendState,
    pub connection: ConnectionState,
    #[serde(default)]
    pub device_location: DeviceLocationState,
    #[serde(default)]
    pub network_security: NetworkSecurityState,
    pub features: FeatureState,
    #[serde(default)]
    pub operations: OperationState,
    #[serde(default)]
    pub store: CanonicalStoreState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSecurityState {
    /// Whether NetworkManager has supplied a current observation.
    pub known: bool,
    pub wifi_connected: bool,
    pub insecure_wifi: bool,
    /// Changes whenever the active Wi-Fi network or its security changes.
    /// The SSID deliberately remains private to the agent.
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalStoreState {
    pub revision: u64,
    pub ready: bool,
    pub onboarding_complete: bool,
    pub locale: String,
    pub start_with_omarchy: bool,
    pub auto_connect: bool,
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
    #[serde(default = "default_true")]
    pub port_forwarding_notifications_enabled: bool,
    pub account_scope_known: bool,
    pub profile_count: usize,
    pub recent_count: usize,
    pub default_connection: Value,
    pub migration_available: bool,
}

impl Default for CanonicalStoreState {
    fn default() -> Self {
        Self {
            revision: 0,
            ready: false,
            onboarding_complete: false,
            locale: "es-MX".into(),
            start_with_omarchy: true,
            auto_connect: false,
            notifications_enabled: true,
            port_forwarding_notifications_enabled: true,
            account_scope_known: false,
            profile_count: 0,
            recent_count: 0,
            default_connection: serde_json::json!({ "type": "fastest" }),
            migration_available: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationState {
    #[serde(default)]
    pub active: Vec<OperationRecord>,
    #[serde(default)]
    pub recent: Vec<OperationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: String,
    pub initiator_client_instance_id: String,
    pub domain: OperationDomain,
    pub kind: String,
    pub state: OperationStatus,
    pub stage: String,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub cancelable: bool,
    pub error: Option<OperationError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationDomain {
    AuthSession,
    TunnelConfiguration,
    Support,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationError {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub status: AccountStatus,
    pub name: Option<String>,
    pub tier: Option<u8>,
    #[serde(default)]
    pub credentialless: bool,
    #[serde(default)]
    pub two_factor_code_supported: bool,
    #[serde(default)]
    pub two_factor_security_key_supported: bool,
    // The pinned Linux core does not expose the Windows SSO challenge flow.
    // Keep this explicit so the UI never invents a browser authentication path.
    pub sso_supported: bool,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            status: AccountStatus::Unknown,
            name: None,
            tier: None,
            credentialless: false,
            two_factor_code_supported: false,
            two_factor_security_key_supported: false,
            sso_supported: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Unknown,
    SignedOut,
    SigningIn,
    TwoFactorRequired,
    SignedIn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendState {
    pub kind: String,
    pub core_available: bool,
    pub connection_available: bool,
    pub connection_availability_known: bool,
    pub settings_known: bool,
    pub connector_initialized: bool,
    // Advanced Kill Switch login banner requires a real "network blocked" observation.
    // The pinned Linux core has no passive observation contract for it yet.
    pub network_blocked_known: bool,
    pub network_blocked: bool,
    pub core_version: Option<String>,
    pub error: Option<String>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            kind: "proton_linux".into(),
            core_available: false,
            connection_available: false,
            connection_availability_known: false,
            settings_known: false,
            connector_initialized: false,
            network_blocked_known: false,
            network_blocked: false,
            core_version: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub observation_known: bool,
    pub status: ConnectionStatus,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub entry_country_code: Option<String>,
    pub entry_country_name: Option<String>,
    pub state: Option<String>,
    pub city: Option<String>,
    pub server_name: Option<String>,
    pub server_ip: Option<String>,
    pub server_load: Option<u8>,
    #[serde(default)]
    pub p2p: bool,
    #[serde(default)]
    pub tor: bool,
    pub latency_ms: Option<u32>,
    /// Exact connector-advertised protocol identifier; never coarsen it in transport.
    pub protocol: Option<String>,
    pub connected_at_unix_ms: Option<u64>,
    pub error: Option<String>,
    /// Stable machine-readable reason for a connection restriction or failure.
    #[serde(default)]
    pub error_code: Option<String>,
    /// Raw Proton Local Agent reason code, when the server supplied one.
    #[serde(default)]
    pub restriction_reason_code: Option<i32>,
    /// Active non-Proton tunnel interfaces that can interfere with route setup.
    #[serde(default)]
    pub network_conflicts: Vec<String>,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            observation_known: false,
            status: ConnectionStatus::Unknown,
            country_code: None,
            country_name: None,
            entry_country_code: None,
            entry_country_name: None,
            state: None,
            city: None,
            server_name: None,
            server_ip: None,
            server_load: None,
            p2p: false,
            tor: false,
            latency_ms: None,
            protocol: None,
            connected_at_unix_ms: None,
            error: None,
            error_code: None,
            restriction_reason_code: None,
            network_conflicts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Unknown,
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceLocationState {
    pub known: bool,
    pub ip_address: Option<String>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureState {
    pub protocol: ProtocolSettingsState,
    pub kill_switch: KillSwitchState,
    pub netshield: NetShieldState,
    pub vpn_accelerator: VpnAcceleratorState,
    pub anonymous_crash_reports: AnonymousCrashReportsState,
    pub anonymous_usage_statistics: AnonymousUsageStatisticsState,
    pub connection_feedback: ConnectionFeedbackState,
    pub moderate_nat: ToggleFeatureState,
    pub ipv6: ToggleFeatureState,
    pub ipv6_leak_protection: ToggleFeatureState,
    pub alternative_routing: ToggleFeatureState,
    pub allow_lan_connections: ToggleFeatureState,
    pub allow_local_dns: ToggleFeatureState,
    pub secure_core: bool,
    pub split_tunneling: SplitTunnelingState,
    pub port_forwarding: PortForwardingState,
    pub custom_dns: CustomDnsState,
    pub writes: FeatureWriteCapabilities,
    pub known: bool,
    pub writable: bool,
}

impl Default for FeatureState {
    fn default() -> Self {
        Self {
            protocol: ProtocolSettingsState::default(),
            kill_switch: KillSwitchState {
                mode: KillSwitchMode::Off,
            },
            netshield: NetShieldState::default(),
            vpn_accelerator: VpnAcceleratorState { enabled: false },
            anonymous_crash_reports: AnonymousCrashReportsState { enabled: false },
            anonymous_usage_statistics: AnonymousUsageStatisticsState { enabled: false },
            connection_feedback: ConnectionFeedbackState::default(),
            moderate_nat: ToggleFeatureState::default(),
            ipv6: ToggleFeatureState { enabled: true },
            ipv6_leak_protection: ToggleFeatureState { enabled: true },
            alternative_routing: ToggleFeatureState { enabled: true },
            allow_lan_connections: ToggleFeatureState { enabled: false },
            allow_local_dns: ToggleFeatureState { enabled: false },
            secure_core: false,
            split_tunneling: SplitTunnelingState {
                mode: SplitTunnelingMode::Off,
                availability_known: false,
                available: false,
                app_paths_supported: false,
                ip_ranges_supported: false,
                standard: SplitTunnelingConfigState::default(),
                inverse: SplitTunnelingConfigState::default(),
            },
            port_forwarding: PortForwardingState {
                enabled: false,
                active_port: None,
            },
            custom_dns: CustomDnsState {
                enabled: false,
                servers: Vec::new(),
            },
            writes: FeatureWriteCapabilities::default(),
            known: false,
            writable: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolSettingsState {
    pub selected: String,
    pub available: Vec<String>,
    #[serde(default)]
    pub profile_available: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchState {
    pub mode: KillSwitchMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchMode {
    Off,
    Standard,
    Advanced,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetShieldState {
    pub level: u8,
    #[serde(default)]
    pub statistics_known: bool,
    #[serde(default)]
    pub malware_blocked: u32,
    #[serde(default)]
    pub ads_blocked: u32,
    #[serde(default)]
    pub trackers_blocked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnAcceleratorState {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousCrashReportsState {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTunnelingState {
    pub mode: SplitTunnelingMode,
    pub availability_known: bool,
    pub available: bool,
    pub app_paths_supported: bool,
    pub ip_ranges_supported: bool,
    pub standard: SplitTunnelingConfigState,
    pub inverse: SplitTunnelingConfigState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SplitTunnelingConfigState {
    pub app_paths: Vec<String>,
    pub ip_ranges: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelingMode {
    Off,
    Standard,
    Inverse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardingState {
    pub enabled: bool,
    pub active_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDnsState {
    pub enabled: bool,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousUsageStatisticsState {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionFeedbackState {
    pub available: bool,
    pub viewed: bool,
    pub sent: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToggleFeatureState {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureWriteCapabilities {
    pub protocol: bool,
    pub kill_switch: bool,
    pub netshield: bool,
    pub vpn_accelerator: bool,
    pub anonymous_crash_reports: bool,
    pub anonymous_usage_statistics: bool,
    pub moderate_nat: bool,
    pub ipv6: bool,
    pub ipv6_leak_protection: bool,
    pub alternative_routing: bool,
    pub allow_lan_connections: bool,
    pub allow_local_dns: bool,
    pub custom_dns: bool,
    pub secure_core: bool,
    pub split_tunneling: bool,
    pub port_forwarding: bool,
}
