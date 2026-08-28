use isocountry::CountryCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const FEATURE_SECURE_CORE: u32 = 1 << 0;
pub const FEATURE_TOR: u32 = 1 << 1;
pub const FEATURE_P2P: u32 = 1 << 2;
pub const FEATURE_STREAMING: u32 = 1 << 3;
pub const FEATURE_IPV6: u32 = 1 << 4;
pub const FEATURE_RESTRICTED: u32 = 1 << 5;
pub const FEATURE_PARTNER: u32 = 1 << 6;
pub const FEATURE_DOUBLE_RESTRICTED: u32 = 1 << 7;
pub const FEATURE_B2B: u32 = FEATURE_RESTRICTED | FEATURE_DOUBLE_RESTRICTED;
pub const FEATURE_NON_STANDARD: u32 = FEATURE_SECURE_CORE
    | FEATURE_TOR
    | FEATURE_RESTRICTED
    | FEATURE_PARTNER
    | FEATURE_DOUBLE_RESTRICTED;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionData {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub account_name: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(rename = "vpn")]
    pub vpn: VpnSessionData,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

fn default_environment() -> String {
    "prod".into()
}

impl SessionData {
    pub fn is_authenticated(&self) -> bool {
        !self.uid.is_empty()
            && !self.access_token.is_empty()
            && !self.refresh_token.is_empty()
            && !self.account_name.is_empty()
    }

    pub fn tier(&self) -> u8 {
        self.vpn
            .vpninfo
            .get("VPN")
            .and_then(Value::as_object)
            .and_then(|vpn| vpn.get("MaxTier"))
            .and_then(Value::as_u64)
            .and_then(|tier| u8::try_from(tier).ok())
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnSessionData {
    pub vpninfo: Value,
    pub certificate: VpnCertificate,
    pub secrets: VpnSecrets,
    pub location: VpnLocation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpnCertificate {
    pub certificate: String,
    pub client_key: String,
    #[serde(default)]
    pub client_key_fingerprint: String,
    pub expiration_time: u64,
    pub refresh_time: u64,
    #[serde(default)]
    pub server_public_key: String,
    #[serde(default)]
    pub server_public_key_mode: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnSecrets {
    pub ed25519_privatekey: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpnLocation {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(default)]
    pub country: String,
    #[serde(rename = "ISP", default)]
    pub isp: String,
    pub lat: Option<f64>,
    pub long: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServerCatalog {
    #[serde(default)]
    pub expiration_time: f64,
    #[serde(default)]
    pub loads_expiration_time: f64,
    #[serde(default)]
    pub max_tier: u8,
    #[serde(default)]
    pub logical_servers: Vec<LogicalServer>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogicalServer {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub entry_country: String,
    #[serde(default)]
    pub exit_country: String,
    #[serde(default)]
    pub host_country: Option<String>,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub tier: u8,
    #[serde(default)]
    pub features: u32,
    #[serde(default)]
    pub load: u8,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub status: u8,
    #[serde(default)]
    pub location: ServerLocation,
    #[serde(default)]
    pub servers: Vec<PhysicalServer>,
    #[serde(rename = "VPNGatewayID", default)]
    pub vpn_gateway_id: Option<String>,
    #[serde(rename = "GatewayName", default)]
    pub gateway_name: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServerLocation {
    pub lat: Option<f64>,
    pub long: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PhysicalServer {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "EntryIP", default)]
    pub entry_ip: String,
    #[serde(rename = "ExitIP", default)]
    pub exit_ip: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub status: u8,
    #[serde(rename = "X25519PublicKey", default)]
    pub x25519_public_key: String,
    #[serde(default)]
    pub label: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl LogicalServer {
    pub fn enabled(&self) -> bool {
        self.status == 1 && self.servers.iter().any(|server| server.status == 1)
    }

    pub fn maintenance(&self) -> bool {
        !self.enabled()
    }

    pub fn standard(&self) -> bool {
        self.features & FEATURE_NON_STANDARD == 0
    }

    pub fn gateway_name(&self) -> &str {
        if !self.gateway_name.is_empty() {
            &self.gateway_name
        } else {
            self.extra
                .get("GatewayName")
                .and_then(Value::as_str)
                .unwrap_or("")
        }
    }

    pub fn serialized(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "country_code": self.exit_country,
            "country_name": country_name(&self.exit_country),
            "entry_country_code": self.entry_country,
            "entry_country_name": country_name(&self.entry_country),
            "state": self.state,
            "city": if self.city.is_empty() { &self.state } else { &self.city },
            "latitude": self.location.lat,
            "longitude": self.location.long,
            "load": self.load,
            "tier": self.tier,
            "enabled": self.enabled(),
            "maintenance": self.maintenance(),
            "secure_core": self.features & FEATURE_SECURE_CORE != 0,
            "tor": self.features & FEATURE_TOR != 0,
            "p2p": self.features & FEATURE_P2P != 0,
            "streaming": self.features & FEATURE_STREAMING != 0,
            "ipv6": self.features & FEATURE_IPV6 != 0,
            "restricted": self.features & FEATURE_B2B != 0,
            "partner": self.features & FEATURE_PARTNER != 0,
            "smart_routing": self.host_country.is_some(),
            "gateway_name": self.gateway_name(),
        })
    }
}

pub fn country_name(code: &str) -> String {
    CountryCode::for_alpha2_caseless(code)
        .map(|country| country.name().to_owned())
        .unwrap_or_else(|_| code.to_ascii_uppercase())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ClientConfig {
    pub default_ports: DefaultPorts,
    #[serde(default)]
    pub smart_protocol: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DefaultPorts {
    #[serde(rename = "WireGuard")]
    pub wire_guard: ProtocolPorts,
    #[serde(rename = "OpenVPN", default)]
    pub open_vpn: ProtocolPorts,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct ProtocolPorts {
    #[serde(default)]
    pub udp: Vec<u16>,
    #[serde(default)]
    pub tcp: Vec<u16>,
    #[serde(default)]
    pub tls: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NativeSettings {
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub killswitch: u8,
    #[serde(default)]
    pub custom_dns: CustomDns,
    #[serde(default = "default_true")]
    pub ipv6: bool,
    #[serde(default = "default_true")]
    pub ipv6_leak_protection: bool,
    #[serde(default = "default_true")]
    pub alternative_routing: bool,
    #[serde(default)]
    pub allow_lan_connections: bool,
    #[serde(default)]
    pub allow_local_dns: bool,
    #[serde(default = "default_true")]
    pub anonymous_crash_reports: bool,
    #[serde(default = "default_true")]
    pub share_statistics: bool,
    #[serde(default)]
    pub features: SettingsFeatures,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

fn default_protocol() -> String {
    "wireguard".into()
}

fn default_true() -> bool {
    true
}

impl Default for NativeSettings {
    fn default() -> Self {
        Self {
            protocol: default_protocol(),
            killswitch: 0,
            custom_dns: CustomDns::default(),
            ipv6: true,
            ipv6_leak_protection: true,
            alternative_routing: true,
            allow_lan_connections: false,
            allow_local_dns: false,
            anonymous_crash_reports: true,
            share_statistics: true,
            features: SettingsFeatures::default(),
            extra: serde_json::Map::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CustomDns {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ip_list: Vec<Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettingsFeatures {
    #[serde(default)]
    pub netshield: u8,
    #[serde(default)]
    pub moderate_nat: bool,
    #[serde(default = "default_true")]
    pub vpn_accelerator: bool,
    #[serde(default)]
    pub port_forwarding: bool,
    #[serde(default)]
    pub split_tunneling: SplitTunnelingSettings,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl Default for SettingsFeatures {
    fn default() -> Self {
        Self {
            netshield: 0,
            moderate_nat: false,
            vpn_accelerator: true,
            port_forwarding: false,
            split_tunneling: SplitTunnelingSettings::default(),
            extra: serde_json::Map::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SplitTunnelingSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_split_mode")]
    pub mode: String,
    #[serde(default = "default_split_configs")]
    pub config_by_mode: HashMap<String, SplitTunnelingConfig>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl Default for SplitTunnelingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_split_mode(),
            config_by_mode: default_split_configs(),
            extra: serde_json::Map::new(),
        }
    }
}

impl SplitTunnelingSettings {
    pub fn config(&self, mode: &str) -> SplitTunnelingConfig {
        self.config_by_mode
            .get(mode)
            .cloned()
            .unwrap_or_else(|| SplitTunnelingConfig::new(mode))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SplitTunnelingConfig {
    #[serde(default = "default_split_mode")]
    pub mode: String,
    #[serde(default)]
    pub app_paths: Vec<String>,
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl SplitTunnelingConfig {
    pub fn new(mode: &str) -> Self {
        Self {
            mode: mode.to_owned(),
            app_paths: Vec::new(),
            ip_ranges: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

fn default_split_mode() -> String {
    "exclude".into()
}

fn default_split_configs() -> HashMap<String, SplitTunnelingConfig> {
    HashMap::from([
        ("exclude".into(), SplitTunnelingConfig::new("exclude")),
        ("include".into(), SplitTunnelingConfig::new("include")),
    ])
}
