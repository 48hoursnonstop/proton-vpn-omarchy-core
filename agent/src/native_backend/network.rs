use super::{
    catalog::ConnectionTarget,
    models::{ClientConfig, NativeSettings, SessionData, FEATURE_IPV6},
    NativeError, NativeResult,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use nmdbus::{
    accesspoint::AccessPoint,
    connection_active::ConnectionActive,
    dbus::{
        self,
        arg::{cast, PropMap, RefArg, Variant},
        blocking::Connection,
    },
    device::Device,
    device_wireless::DeviceWireless,
    ip4config::IP4Config,
    ip6config::IP6Config,
    settings::Settings,
    settings_connection::SettingsConnection,
    vpn_connection::VPNConnection,
    NetworkManager,
};
use pkcs8::{EncodePrivateKey, LineEnding, PrivateKeyInfo};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const NM_BUS: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const PROTUN_SERVICE: &str = "org.freedesktop.NetworkManager.protun";
const OPENVPN_SERVICE: &str = "org.freedesktop.NetworkManager.openvpn";
const PROTUN_INTERFACE: &str = "proton0";
const PROTON_OMARCHY_OWNER_KEY: &str = "proton-omarchy-owner";
const PROTON_OMARCHY_OWNER_VALUE: &str = "rust-v2";
const PROTON_OMARCHY_PROFILE_ID_KEY: &str = "proton-omarchy-profile-id";
const PROTON_OMARCHY_STABLE_ID: &str = "proton-omarchy-rust-v2";
const IPV6_LEAK_CONNECTION_ID: &str = "pvpn-killswitch-ipv6";
const IPV6_LEAK_INTERFACE: &str = "ipv6leakintrf0";
const KILL_SWITCH_CONNECTION_ID: &str = "pvpn-killswitch";
const KILL_SWITCH_PERMANENT_CONNECTION_ID: &str = "pvpn-killswitch-perm";
const KILL_SWITCH_INTERFACE: &str = "pvpnksintrf0";
const KILL_SWITCH_PERMANENT_INTERFACE: &str = "pvpnksintrf1";
const DBUS_ROOT: &str = "/";
const OPENVPN_CA: &str = include_str!("openvpn_ca.pem");
const OPENVPN_TLS_CRYPT: &str = include_str!("openvpn_tls_crypt.pem");

const VPN_STATE_PREPARE: u32 = 1;
const VPN_STATE_NEED_AUTH: u32 = 2;
const VPN_STATE_CONNECT: u32 = 3;
const VPN_STATE_IP_CONFIG_GET: u32 = 4;
const VPN_STATE_ACTIVATED: u32 = 5;
const VPN_STATE_FAILED: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Clone, Debug)]
pub struct TunnelObservation {
    pub state: TunnelState,
    pub active_path: Option<String>,
    pub connection_path: Option<String>,
    pub id: Option<String>,
    pub uuid: Option<String>,
    pub protocol: Option<String>,
    pub endpoint: Option<String>,
    pub profile_id: Option<String>,
    pub owned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WifiSecurityObservation {
    /// Stable only for the lifetime of the active association. Never leaves the agent.
    pub identity: Vec<u8>,
    pub secure: bool,
}

#[derive(Clone)]
pub(super) struct ProtunProfile {
    pub id: String,
    pub uuid: String,
    pub protocol: String,
    pub profile_id: Option<String>,
    pub settings_json: String,
    pub private_key: Zeroizing<String>,
    pub enable_ipv6: bool,
    pub custom_dns_v4: Vec<String>,
    pub custom_dns_v6: Vec<String>,
}

#[derive(Clone)]
pub(super) struct OpenVpnProfile {
    id: String,
    uuid: String,
    protocol: String,
    profile_id: Option<String>,
    remote: String,
    domain: String,
    passphrase: Zeroizing<String>,
    credential_dir: PathBuf,
    ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
    tls_crypt: PathBuf,
    enable_ipv6: bool,
    custom_dns_v4: Vec<String>,
    custom_dns_v6: Vec<String>,
}

#[derive(Clone)]
pub enum VpnProfile {
    Protun(ProtunProfile),
    OpenVpn(OpenVpnProfile),
}

impl VpnProfile {
    pub fn new(
        target: &ConnectionTarget,
        protocol: &str,
        session: &SessionData,
        client_config: &ClientConfig,
        settings: &NativeSettings,
        profile_id: Option<String>,
    ) -> NativeResult<Self> {
        match normalize_protocol(protocol).as_str() {
            "openvpn-udp" | "openvpn-tcp" => OpenVpnProfile::new(
                target,
                protocol,
                session,
                client_config,
                settings,
                profile_id,
            )
            .map(Self::OpenVpn),
            _ => ProtunProfile::new(
                target,
                protocol,
                session,
                client_config,
                settings,
                profile_id,
            )
            .map(Self::Protun),
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Protun(profile) => &profile.id,
            Self::OpenVpn(profile) => &profile.id,
        }
    }

    pub fn uuid(&self) -> &str {
        match self {
            Self::Protun(profile) => &profile.uuid,
            Self::OpenVpn(profile) => &profile.uuid,
        }
    }

    pub fn protocol(&self) -> &str {
        match self {
            Self::Protun(profile) => &profile.protocol,
            Self::OpenVpn(profile) => &profile.protocol,
        }
    }

    pub fn profile_id(&self) -> Option<&str> {
        match self {
            Self::Protun(profile) => profile.profile_id.as_deref(),
            Self::OpenVpn(profile) => profile.profile_id.as_deref(),
        }
    }

    fn dbus_settings(&self) -> HashMap<&str, PropMap> {
        match self {
            Self::Protun(profile) => profile.dbus_settings(),
            Self::OpenVpn(profile) => profile.dbus_settings(),
        }
    }

    fn cleanup_credentials(&self) {
        if let Self::OpenVpn(profile) = self {
            let _ = fs::remove_dir_all(&profile.credential_dir);
        }
    }
}

impl ProtunProfile {
    pub fn new(
        target: &ConnectionTarget,
        protocol: &str,
        session: &SessionData,
        client_config: &ClientConfig,
        settings: &NativeSettings,
        profile_id: Option<String>,
    ) -> NativeResult<Self> {
        let (udp_ports, tcp_ports, tls_ports) = match protocol {
            "protun-smart" | "smart" => (
                client_config.default_ports.wire_guard.udp.clone(),
                client_config.default_ports.wire_guard.tcp.clone(),
                client_config.default_ports.wire_guard.tls.clone(),
            ),
            "wireguard" | "wireguard-udp" | "protun-udp" => (
                client_config.default_ports.wire_guard.udp.clone(),
                Vec::new(),
                Vec::new(),
            ),
            "protun-tcp" | "wireguard-tcp" => (
                Vec::new(),
                client_config.default_ports.wire_guard.tcp.clone(),
                Vec::new(),
            ),
            "protun-tls" | "wireguard-tls" | "stealth" => (
                Vec::new(),
                Vec::new(),
                client_config.default_ports.wire_guard.tls.clone(),
            ),
            value => {
                return Err(NativeError::new(
                    "protocol_unavailable",
                    format!("The Rust backend cannot create a ProTun profile for {value}"),
                ));
            }
        };

        if udp_ports.is_empty() && tcp_ports.is_empty() && tls_ports.is_empty() {
            return Err(NativeError::new(
                "protocol_unavailable",
                "The Proton client configuration provides no ports for this protocol",
            ));
        }

        let settings_json = json!({
            "version": 1,
            "peers": [{
                "id": target.logical.name,
                "endpoint": target.physical.entry_ip,
                "public-key": target.physical.x25519_public_key,
                "udp-ports": udp_ports,
                "tcp-ports": tcp_ports,
                "tls-ports": tls_ports,
                "priority": 0,
            }],
            "pcap-file": Value::Null,
        })
        .to_string()
        .replace(',', r"\,");

        let private_key = wireguard_private_key(&session.vpn.secrets.ed25519_privatekey)?;
        let (custom_dns_v4, custom_dns_v6) = if settings.custom_dns.enabled {
            enabled_dns(&settings.custom_dns.ip_list)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Self {
            id: format!("ProtonVPN {}", target.logical.name),
            uuid: Uuid::new_v4().to_string(),
            protocol: normalize_protocol(protocol),
            profile_id,
            settings_json,
            private_key: Zeroizing::new(private_key),
            enable_ipv6: settings.ipv6 && target.logical.features & FEATURE_IPV6 != 0,
            custom_dns_v4,
            custom_dns_v6,
        })
    }

    fn dbus_settings(&self) -> HashMap<&str, PropMap> {
        let mut connection = PropMap::new();
        prop(&mut connection, "id", self.id.clone());
        prop(&mut connection, "uuid", self.uuid.clone());
        prop(&mut connection, "type", "vpn".to_owned());
        prop(
            &mut connection,
            "stable-id",
            PROTON_OMARCHY_STABLE_ID.to_owned(),
        );
        prop(
            &mut connection,
            "interface-name",
            PROTUN_INTERFACE.to_owned(),
        );
        let username = env::var("USER").unwrap_or_else(|_| "user".into());
        prop(
            &mut connection,
            "permissions",
            vec![format!("user:{username}:")],
        );
        let mut ipv4 = PropMap::new();
        prop(&mut ipv4, "method", "manual".to_owned());
        prop(&mut ipv4, "address-data", vec![address("10.2.0.2", 32)]);
        prop(&mut ipv4, "auto-route-ext-gw", 0_i32);
        prop(&mut ipv4, "dns-priority", -1500_i32);
        prop(&mut ipv4, "ignore-auto-dns", true);
        if self.custom_dns_v4.is_empty() {
            prop(&mut ipv4, "dns-data", vec!["10.2.0.1".to_owned()]);
            prop(&mut ipv4, "dns-search", vec!["~".to_owned()]);
        } else {
            prop(&mut ipv4, "dns-data", self.custom_dns_v4.clone());
        }

        let mut ipv6 = PropMap::new();
        if self.enable_ipv6 {
            prop(&mut ipv6, "method", "manual".to_owned());
            prop(
                &mut ipv6,
                "address-data",
                vec![address("2a07:b944::2:2", 128)],
            );
            prop(&mut ipv6, "auto-route-ext-gw", 0_i32);
            prop(&mut ipv6, "dns-priority", -1500_i32);
            prop(&mut ipv6, "ignore-auto-dns", true);
            if self.custom_dns_v6.is_empty() {
                prop(&mut ipv6, "dns-data", vec!["2a07:b944::2:1".to_owned()]);
                prop(&mut ipv6, "dns-search", vec!["~".to_owned()]);
            } else {
                prop(&mut ipv6, "dns-data", self.custom_dns_v6.clone());
            }
        } else {
            prop(&mut ipv6, "method", "disabled".to_owned());
        }

        let mut vpn = PropMap::new();
        prop(&mut vpn, "service-type", PROTUN_SERVICE.to_owned());
        let mut data = HashMap::from([
            ("settings".to_owned(), self.settings_json.clone()),
            ("private-key-flags".to_owned(), "0".to_owned()),
            (
                PROTON_OMARCHY_OWNER_KEY.to_owned(),
                PROTON_OMARCHY_OWNER_VALUE.to_owned(),
            ),
        ]);
        if let Some(profile_id) = &self.profile_id {
            data.insert(PROTON_OMARCHY_PROFILE_ID_KEY.to_owned(), profile_id.clone());
        }
        prop(&mut vpn, "data", data);
        prop(
            &mut vpn,
            "secrets",
            HashMap::from([("private-key".to_owned(), self.private_key.to_string())]),
        );
        prop(&mut vpn, "persistent", false);

        HashMap::from([
            ("connection", connection),
            ("ipv4", ipv4),
            ("ipv6", ipv6),
            ("vpn", vpn),
        ])
    }
}

impl OpenVpnProfile {
    fn new(
        target: &ConnectionTarget,
        protocol: &str,
        session: &SessionData,
        client_config: &ClientConfig,
        settings: &NativeSettings,
        profile_id: Option<String>,
    ) -> NativeResult<Self> {
        let protocol = normalize_protocol(protocol);
        let ports = match protocol.as_str() {
            "openvpn-udp" => &client_config.default_ports.open_vpn.udp,
            "openvpn-tcp" => &client_config.default_ports.open_vpn.tcp,
            value => {
                return Err(NativeError::new(
                    "protocol_unavailable",
                    format!("The Rust backend cannot create an OpenVPN profile for {value}"),
                ));
            }
        };
        if ports.is_empty() {
            return Err(NativeError::new(
                "protocol_unavailable",
                "The Proton client configuration provides no ports for this OpenVPN protocol",
            ));
        }
        if target.logical.domain.trim().is_empty() {
            return Err(NativeError::new(
                "server_invalid",
                "The selected Proton server has no certificate domain",
            ));
        }

        if !session
            .vpn
            .certificate
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
        {
            return Err(NativeError::new(
                "vpn_credentials_invalid",
                "The stored Proton VPN certificate is missing or invalid",
            ));
        }

        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let passphrase = Zeroizing::new(hex_encode(&random));
        let private_key = encrypted_openvpn_private_key(
            &session.vpn.secrets.ed25519_privatekey,
            passphrase.as_bytes(),
        )?;

        let uuid = Uuid::new_v4().to_string();
        let credential_dir = openvpn_credential_dir(&uuid)?;
        let ca = credential_dir.join("ca.pem");
        let certificate = credential_dir.join("certificate.pem");
        let private_key_path = credential_dir.join("private-key.pem");
        let tls_crypt = credential_dir.join("tls-crypt.pem");
        let write_result = (|| {
            write_private_file(&ca, OPENVPN_CA.as_bytes())?;
            write_private_file(&certificate, session.vpn.certificate.certificate.as_bytes())?;
            write_private_file(&private_key_path, private_key.as_bytes())?;
            write_private_file(&tls_crypt, OPENVPN_TLS_CRYPT.as_bytes())?;
            Ok::<_, NativeError>(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_dir_all(&credential_dir);
            return Err(error);
        }

        let remote = ports
            .iter()
            .map(|port| format!("{}:{port}", target.physical.entry_ip))
            .collect::<Vec<_>>()
            .join(", ");
        let (custom_dns_v4, custom_dns_v6) = if settings.custom_dns.enabled {
            enabled_dns(&settings.custom_dns.ip_list)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Self {
            id: format!("ProtonVPN {}", target.logical.name),
            uuid,
            protocol,
            profile_id,
            remote,
            domain: target.logical.domain.clone(),
            passphrase,
            credential_dir,
            ca,
            certificate,
            private_key: private_key_path,
            tls_crypt,
            enable_ipv6: settings.ipv6 && target.logical.features & FEATURE_IPV6 != 0,
            custom_dns_v4,
            custom_dns_v6,
        })
    }

    fn dbus_settings(&self) -> HashMap<&str, PropMap> {
        let mut connection = PropMap::new();
        prop(&mut connection, "id", self.id.clone());
        prop(&mut connection, "uuid", self.uuid.clone());
        prop(&mut connection, "type", "vpn".to_owned());
        prop(
            &mut connection,
            "interface-name",
            PROTUN_INTERFACE.to_owned(),
        );
        prop(&mut connection, "autoconnect", false);
        prop(
            &mut connection,
            "stable-id",
            PROTON_OMARCHY_STABLE_ID.to_owned(),
        );
        let username = env::var("USER").unwrap_or_else(|_| "user".into());
        prop(
            &mut connection,
            "permissions",
            vec![format!("user:{username}:")],
        );

        let mut ipv4 = PropMap::new();
        prop(&mut ipv4, "method", "auto".to_owned());
        prop(&mut ipv4, "dns-priority", -1500_i32);
        if !self.custom_dns_v4.is_empty() {
            prop(&mut ipv4, "dns-data", self.custom_dns_v4.clone());
            prop(&mut ipv4, "ignore-auto-dns", true);
        }

        let mut ipv6 = PropMap::new();
        if self.enable_ipv6 {
            prop(&mut ipv6, "method", "auto".to_owned());
            prop(&mut ipv6, "dns-priority", -1500_i32);
            if !self.custom_dns_v6.is_empty() {
                prop(&mut ipv6, "dns-data", self.custom_dns_v6.clone());
                prop(&mut ipv6, "ignore-auto-dns", true);
            }
        } else {
            prop(&mut ipv6, "method", "disabled".to_owned());
        }
        let mut data = HashMap::from([
            ("ca".to_owned(), path_text(&self.ca)),
            ("cert".to_owned(), path_text(&self.certificate)),
            ("key".to_owned(), path_text(&self.private_key)),
            ("tls-crypt".to_owned(), path_text(&self.tls_crypt)),
            ("connection-type".to_owned(), "tls".to_owned()),
            ("remote".to_owned(), self.remote.clone()),
            ("remote-random".to_owned(), "yes".to_owned()),
            ("cipher".to_owned(), "AES-256-GCM".to_owned()),
            ("dev".to_owned(), PROTUN_INTERFACE.to_owned()),
            ("dev-type".to_owned(), "tun".to_owned()),
            ("mssfix".to_owned(), "0".to_owned()),
            ("tunnel-mtu".to_owned(), "1500".to_owned()),
            ("reneg-seconds".to_owned(), "0".to_owned()),
            ("remote-cert-tls".to_owned(), "server".to_owned()),
            (
                "verify-x509-name".to_owned(),
                format!("name:{}", self.domain),
            ),
            ("cert-pass-flags".to_owned(), "0".to_owned()),
        ]);
        if self.protocol == "openvpn-tcp" {
            data.insert("proto-tcp".to_owned(), "yes".to_owned());
        }
        if self.enable_ipv6 {
            data.insert("push-peer-info".to_owned(), "yes".to_owned());
            data.insert("tun-ipv6".to_owned(), "yes".to_owned());
        }
        if let Some(profile_id) = &self.profile_id {
            data.insert(PROTON_OMARCHY_PROFILE_ID_KEY.to_owned(), profile_id.clone());
        }

        let mut vpn = PropMap::new();
        prop(&mut vpn, "service-type", OPENVPN_SERVICE.to_owned());
        prop(&mut vpn, "data", data);
        prop(
            &mut vpn,
            "secrets",
            HashMap::from([("cert-pass".to_owned(), self.passphrase.to_string())]),
        );
        prop(&mut vpn, "persistent", false);

        HashMap::from([
            ("connection", connection),
            ("ipv4", ipv4),
            ("ipv6", ipv6),
            ("vpn", vpn),
        ])
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkManagerBackend;

impl NetworkManagerBackend {
    pub(super) fn wifi_security(&self) -> NativeResult<Option<WifiSecurityObservation>> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(5));
        let mut observations = Vec::new();
        for device_path in NetworkManager::devices(&root)
            .map_err(|error| nm_error("list NetworkManager devices", error))?
        {
            let device = connection.with_proxy(NM_BUS, device_path, Duration::from_secs(5));
            if Device::state(&device).unwrap_or(0) != 100
                || Device::device_type(&device).unwrap_or(0) != 2
            {
                continue;
            }
            let access_point_path = match DeviceWireless::active_access_point(&device) {
                Ok(path) if path != DBUS_ROOT => path,
                _ => continue,
            };
            let interface = Device::interface(&device)
                .map_err(|error| nm_error("read the active Wi-Fi interface", error))?;
            let access_point =
                connection.with_proxy(NM_BUS, access_point_path, Duration::from_secs(5));
            let ssid = AccessPoint::ssid(&access_point)
                .map_err(|error| nm_error("read the active Wi-Fi identity", error))?;
            let wpa_flags = AccessPoint::wpa_flags(&access_point)
                .map_err(|error| nm_error("read Wi-Fi WPA capabilities", error))?;
            let rsn_flags = AccessPoint::rsn_flags(&access_point)
                .map_err(|error| nm_error("read Wi-Fi RSN capabilities", error))?;
            let mut identity = interface.into_bytes();
            identity.push(0);
            identity.extend_from_slice(&ssid);
            observations.push(WifiSecurityObservation {
                identity,
                secure: wifi_is_secure(wpa_flags, rsn_flags),
            });
        }
        observations.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(observations.into_iter().next())
    }

    pub fn conflicting_interfaces(&self) -> NativeResult<Vec<String>> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(5));
        let mut conflicts = HashSet::new();
        for active_path in root
            .active_connections()
            .map_err(|error| nm_error("list active NetworkManager connections", error))?
        {
            let active = connection.with_proxy(NM_BUS, active_path, Duration::from_secs(5));
            if ConnectionActive::state(&active).unwrap_or(0) != 2 {
                continue;
            }
            let profile_path = match active.connection() {
                Ok(path) => path,
                Err(_) => continue,
            };
            let profile = connection.with_proxy(NM_BUS, profile_path, Duration::from_secs(5));
            let settings = match profile.get_settings() {
                Ok(settings) => settings,
                Err(_) => continue,
            };
            if profile_owned(&settings) || proton_system_profile(&settings) {
                continue;
            }
            let connection_type = active.type_().unwrap_or_default().to_ascii_lowercase();
            let is_vpn = active.vpn().unwrap_or(false)
                || matches!(connection_type.as_str(), "vpn" | "wireguard");
            if !is_vpn {
                continue;
            }
            let id = active.id().unwrap_or_else(|_| "VPN".into());
            let interfaces = ConnectionActive::devices(&active)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|path| {
                    let device = connection.with_proxy(NM_BUS, path, Duration::from_secs(3));
                    Device::interface(&device).ok()
                })
                .collect::<Vec<_>>();
            conflicts.insert(conflict_label(&id, interfaces.first().map(String::as_str)));
        }

        // Some VPNs (for example Tailscale and command-line WireGuard) create
        // unmanaged interfaces, so they do not appear as active NM profiles.
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !is_conflicting_tunnel_name(&name) {
                    continue;
                }
                let up = fs::read_to_string(entry.path().join("operstate"))
                    .map(|state| matches!(state.trim(), "up" | "unknown"))
                    .unwrap_or(false);
                if up {
                    conflicts.insert(name);
                }
            }
        }
        let mut conflicts = conflicts.into_iter().collect::<Vec<_>>();
        conflicts.sort_by_key(|value| value.to_ascii_lowercase());
        conflicts.truncate(16);
        Ok(conflicts)
    }

    pub fn physical_default_routes(&self) -> NativeResult<Vec<(String, String, String)>> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(5));
        let mut physical_interfaces = HashSet::new();
        for device_path in NetworkManager::devices(&root)
            .map_err(|error| nm_error("list NetworkManager devices", error))?
        {
            let device = connection.with_proxy(NM_BUS, device_path, Duration::from_secs(5));
            if Device::state(&device).unwrap_or(0) == 100
                && matches!(device.device_type().unwrap_or(0), 1 | 2)
            {
                if let Ok(interface) = Device::interface(&device) {
                    if !interface.is_empty() {
                        physical_interfaces.insert(interface);
                    }
                }
            }
        }
        let mut routes = Vec::new();
        for (family, flag) in [("ipv4", "-4"), ("ipv6", "-6")] {
            let output = Command::new("/usr/bin/ip")
                .args([flag, "-j", "route", "show", "table", "main", "default"])
                .output()
                .map_err(|error| {
                    NativeError::new(
                        "physical_route_unavailable",
                        "Unable to inspect the physical default route",
                    )
                    .with_source(error)
                })?;
            if !output.status.success() {
                return Err(NativeError::new(
                    "physical_route_unavailable",
                    "The kernel did not return the physical default route",
                )
                .with_details(json!({
                    "family": family,
                    "stderr": String::from_utf8_lossy(&output.stderr).trim(),
                })));
            }
            let values: Vec<Value> = serde_json::from_slice(&output.stdout).map_err(|error| {
                NativeError::new(
                    "physical_route_unavailable",
                    "The kernel returned an invalid default-route description",
                )
                .with_source(error)
            })?;
            let preferred = values
                .into_iter()
                .filter_map(|value| {
                    let interface = value.get("dev")?.as_str()?;
                    physical_interfaces.contains(interface).then(|| {
                        (
                            value
                                .get("metric")
                                .and_then(Value::as_u64)
                                .unwrap_or(u64::MAX),
                            value
                                .get("gateway")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            interface.to_owned(),
                        )
                    })
                })
                .min_by(|left, right| (left.0, &left.2).cmp(&(right.0, &right.2)));
            if let Some((_, gateway, interface)) = preferred {
                routes.push((family.into(), gateway, interface));
            }
        }
        if routes.is_empty() {
            return Err(NativeError::new(
                "physical_route_unavailable",
                "No active Ethernet or Wi-Fi default route is available for split tunneling",
            )
            .retryable(true));
        }
        Ok(routes)
    }

    pub fn physical_dns_servers(&self) -> NativeResult<Vec<String>> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(5));
        let mut servers = HashSet::new();
        for device_path in NetworkManager::devices(&root)
            .map_err(|error| nm_error("list NetworkManager devices", error))?
        {
            let device = connection.with_proxy(NM_BUS, device_path, Duration::from_secs(5));
            if Device::state(&device).unwrap_or(0) != 100
                || !matches!(device.device_type().unwrap_or(0), 1 | 2)
            {
                continue;
            }
            if let Ok(path) = Device::ip4_config(&device) {
                if path != DBUS_ROOT {
                    let config = connection.with_proxy(NM_BUS, path, Duration::from_secs(5));
                    for entry in IP4Config::nameserver_data(&config).unwrap_or_default() {
                        if let Some(address) = entry
                            .get("address")
                            .and_then(|value| value.0.as_str())
                            .and_then(|value| value.parse::<IpAddr>().ok())
                            .filter(is_local_resolver)
                        {
                            servers.insert(address.to_string());
                        }
                    }
                    for address in IP4Config::nameservers(&config).unwrap_or_default() {
                        let address = IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes()));
                        if is_local_resolver(&address) {
                            servers.insert(address.to_string());
                        }
                    }
                }
            }
            if let Ok(path) = Device::ip6_config(&device) {
                if path != DBUS_ROOT {
                    let config = connection.with_proxy(NM_BUS, path, Duration::from_secs(5));
                    for bytes in IP6Config::nameservers(&config).unwrap_or_default() {
                        if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
                            let address = IpAddr::V6(Ipv6Addr::from(octets));
                            if is_local_resolver(&address) {
                                servers.insert(address.to_string());
                            }
                        }
                    }
                }
            }
        }
        let mut servers = servers.into_iter().collect::<Vec<_>>();
        servers.sort();
        Ok(servers)
    }

    pub fn observe(&self) -> NativeResult<TunnelObservation> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(5));
        for active_path in root
            .active_connections()
            .map_err(|error| nm_error("list active NetworkManager connections", error))?
        {
            let active = connection.with_proxy(NM_BUS, active_path.clone(), Duration::from_secs(5));
            if !active.vpn().unwrap_or(false) {
                continue;
            }
            let connection_path = match active.connection() {
                Ok(path) => path,
                Err(_) => continue,
            };
            let profile =
                connection.with_proxy(NM_BUS, connection_path.clone(), Duration::from_secs(5));
            let settings = match profile.get_settings() {
                Ok(settings) => settings,
                Err(_) => continue,
            };
            if !matches!(
                service_type(&settings).as_deref(),
                Some(PROTUN_SERVICE | OPENVPN_SERVICE)
            ) {
                continue;
            }

            let vpn_state = connection
                .with_proxy(NM_BUS, active_path.clone(), Duration::from_secs(5))
                .vpn_state()
                .unwrap_or(0);
            let state = match vpn_state {
                VPN_STATE_ACTIVATED => TunnelState::Connected,
                VPN_STATE_PREPARE
                | VPN_STATE_NEED_AUTH
                | VPN_STATE_CONNECT
                | VPN_STATE_IP_CONFIG_GET => TunnelState::Connecting,
                VPN_STATE_FAILED => TunnelState::Error,
                _ => TunnelState::Disconnected,
            };
            let owned = profile_owned(&settings);
            return Ok(TunnelObservation {
                state,
                active_path: Some(active_path.to_string()),
                connection_path: Some(connection_path.to_string()),
                id: active.id().ok(),
                uuid: active.uuid().ok(),
                protocol: profile_protocol(&settings),
                endpoint: profile_endpoint(&settings),
                profile_id: owned.then(|| profile_store_id(&settings)).flatten(),
                owned,
            });
        }

        Ok(TunnelObservation {
            state: TunnelState::Disconnected,
            active_path: None,
            connection_path: None,
            id: None,
            uuid: None,
            protocol: None,
            endpoint: None,
            profile_id: None,
            owned: false,
        })
    }

    pub fn connect(&self, profile: &VpnProfile) -> NativeResult<TunnelObservation> {
        let connection = system_bus()?;
        let settings_proxy =
            connection.with_proxy(NM_BUS, NM_SETTINGS_PATH, Duration::from_secs(10));
        let connection_path = settings_proxy
            .add_connection_unsaved(profile.dbus_settings())
            .map_err(|error| {
                profile.cleanup_credentials();
                nm_error("create the temporary Proton VPN profile", error)
            })?;

        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        let specific_object = best_parent(&connection, &root)
            .unwrap_or_else(|| dbus::Path::from(DBUS_ROOT.to_owned()));
        let active_path = match root.activate_connection(
            connection_path.clone(),
            dbus::Path::from(DBUS_ROOT.to_owned()),
            specific_object,
        ) {
            Ok(path) => path,
            Err(error) => {
                let profile_proxy =
                    connection.with_proxy(NM_BUS, connection_path, Duration::from_secs(5));
                let _ = SettingsConnection::delete(&profile_proxy);
                profile.cleanup_credentials();
                return Err(nm_error("activate the Proton VPN profile", error));
            }
        };

        Ok(TunnelObservation {
            state: TunnelState::Connecting,
            active_path: Some(active_path.to_string()),
            connection_path: Some(connection_path.to_string()),
            id: Some(profile.id().to_owned()),
            uuid: Some(profile.uuid().to_owned()),
            protocol: Some(profile.protocol().to_owned()),
            endpoint: None,
            profile_id: profile.profile_id().map(str::to_owned),
            owned: true,
        })
    }

    pub fn ensure_ipv6_leak_protection(&self) -> NativeResult<()> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        if root.connectivity_check_enabled().unwrap_or(false) {
            root.set_connectivity_check_enabled(false)
                .map_err(|error| nm_error("disable NetworkManager connectivity checking", error))?;
        }
        if active_connection_by_id(&connection, &root, IPV6_LEAK_CONNECTION_ID)?.is_some() {
            return Ok(());
        }

        let settings = connection.with_proxy(NM_BUS, NM_SETTINGS_PATH, Duration::from_secs(10));
        let connection_path =
            match settings_connection_by_id_owned(&connection, &settings, IPV6_LEAK_CONNECTION_ID)?
            {
                Some(path) => path,
                None => settings
                    .add_connection_unsaved(ipv6_leak_settings())
                    .map_err(|error| nm_error("create IPv6 leak protection", error))?,
            };
        root.activate_connection(
            connection_path,
            dbus::Path::from(DBUS_ROOT.to_owned()),
            dbus::Path::from(DBUS_ROOT.to_owned()),
        )
        .map_err(|error| nm_error("activate IPv6 leak protection", error))?;
        Ok(())
    }

    pub fn remove_ipv6_leak_protection(&self) -> NativeResult<bool> {
        self.remove_owned_connections_by_id(IPV6_LEAK_CONNECTION_ID)
    }

    /// Reconciles the official NetworkManager dummy-profile kill switch.
    /// `mode`: 0=off, 1=standard (connected only), 2=advanced/permanent.
    pub fn network_blocked(&self) -> NativeResult<bool> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        let kill_switch_active =
            active_connection_by_id(&connection, &root, KILL_SWITCH_CONNECTION_ID)?.is_some()
                || active_connection_by_id(
                    &connection,
                    &root,
                    KILL_SWITCH_PERMANENT_CONNECTION_ID,
                )?
                .is_some();
        if !kill_switch_active {
            return Ok(false);
        }

        // The dummy default route is intentionally active while a protected
        // tunnel is up. It represents a blocked network only when no VPN route
        // is carrying traffic, which is the state surfaced by the Windows app
        // on its sign-in screen for Advanced Kill Switch.
        Ok(self.observe()?.state != TunnelState::Connected)
    }

    pub fn reconcile_kill_switch(
        &self,
        mode: u8,
        tunnel_active: bool,
        server_ip: Option<&str>,
        ipv6_leak_protection: bool,
    ) -> NativeResult<()> {
        if mode > 2 {
            return Err(NativeError::new(
                "invalid_kill_switch",
                "Kill Switch mode must be off, standard or advanced",
            ));
        }

        let should_block = mode == 2 || (mode == 1 && tunnel_active);
        if !should_block {
            self.remove_owned_connections_by_id(KILL_SWITCH_CONNECTION_ID)?;
            self.remove_owned_connections_by_id(KILL_SWITCH_PERMANENT_CONNECTION_ID)?;
            if mode != 0 {
                if let Some(server_ip) = server_ip {
                    self.modify_server_route(server_ip, false)?;
                }
            }
            if tunnel_active && ipv6_leak_protection {
                self.ensure_ipv6_leak_protection()?;
            } else {
                self.remove_ipv6_leak_protection()?;
            }
            return Ok(());
        }

        self.ensure_full_kill_switch(mode == 2)?;
        self.remove_ipv6_leak_protection()?;
        // Activating a dummy connection makes NetworkManager reapply physical
        // devices. Add the endpoint escape route afterwards so that reapply
        // cannot discard it while the blocking default route is already live.
        if let Some(server_ip) = server_ip {
            self.modify_server_route(server_ip, tunnel_active)?;
        }
        Ok(())
    }

    fn ensure_full_kill_switch(&self, permanent: bool) -> NativeResult<()> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        if root.connectivity_check_enabled().unwrap_or(false) {
            root.set_connectivity_check_enabled(false)
                .map_err(|error| nm_error("disable NetworkManager connectivity checking", error))?;
        }
        let (id, interface, opposite) = if permanent {
            (
                KILL_SWITCH_PERMANENT_CONNECTION_ID,
                KILL_SWITCH_PERMANENT_INTERFACE,
                KILL_SWITCH_CONNECTION_ID,
            )
        } else {
            (
                KILL_SWITCH_CONNECTION_ID,
                KILL_SWITCH_INTERFACE,
                KILL_SWITCH_PERMANENT_CONNECTION_ID,
            )
        };
        if active_connection_by_id(&connection, &root, id)?.is_none() {
            let settings = connection.with_proxy(NM_BUS, NM_SETTINGS_PATH, Duration::from_secs(10));
            let connection_path = match settings_connection_by_id_owned(&connection, &settings, id)?
            {
                Some(path) => path,
                None if permanent => settings
                    .add_connection(kill_switch_settings(id, interface, true))
                    .map_err(|error| nm_error("create permanent Kill Switch", error))?,
                None => settings
                    .add_connection_unsaved(kill_switch_settings(id, interface, false))
                    .map_err(|error| nm_error("create standard Kill Switch", error))?,
            };
            root.activate_connection(
                connection_path,
                dbus::Path::from(DBUS_ROOT.to_owned()),
                dbus::Path::from(DBUS_ROOT.to_owned()),
            )
            .map_err(|error| nm_error("activate Kill Switch", error))?;
        }
        self.remove_owned_connections_by_id(opposite)?;
        Ok(())
    }

    fn modify_server_route(&self, server_ip: &str, add: bool) -> NativeResult<()> {
        if server_ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(NativeError::new(
                "kill_switch_route_invalid",
                "The VPN server has no valid IPv4 endpoint for Kill Switch",
            ));
        }
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        let mut eligible = 0_u32;
        for device_path in NetworkManager::devices(&root)
            .map_err(|error| nm_error("list NetworkManager devices", error))?
        {
            let device = connection.with_proxy(NM_BUS, device_path, Duration::from_secs(10));
            if Device::state(&device).unwrap_or(0) != 100
                || !matches!(device.device_type().unwrap_or(0), 1 | 2)
            {
                continue;
            }
            let ip4_path = match Device::ip4_config(&device) {
                Ok(path) if path != DBUS_ROOT => path,
                _ => continue,
            };
            let gateway = IP4Config::gateway(&connection.with_proxy(
                NM_BUS,
                ip4_path,
                Duration::from_secs(5),
            ))
            .unwrap_or_default();
            if gateway.is_empty() {
                continue;
            }
            let interface = Device::interface(&device)
                .map_err(|error| nm_error("read the physical interface name", error))?;
            let route = format!("{server_ip}/32 {gateway}");
            let property = if add { "+ipv4.routes" } else { "-ipv4.routes" };
            let output = Command::new("/usr/bin/nmcli")
                .args(["device", "modify", &interface, property, &route])
                .output()
                .map_err(|error| {
                    NativeError::new(
                        "kill_switch_route_unavailable",
                        format!("Could not invoke NetworkManager: {error}"),
                    )
                })?;
            if !output.status.success() {
                let details = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                return Err(NativeError::new(
                    "kill_switch_route_unavailable",
                    if details.is_empty() {
                        "NetworkManager could not apply the VPN server bypass route".to_owned()
                    } else {
                        format!(
                            "NetworkManager could not apply the VPN server bypass route: {details}"
                        )
                    },
                ));
            }
            eligible += 1;
        }
        if add && eligible == 0 {
            return Err(NativeError::new(
                "kill_switch_route_unavailable",
                "No active Ethernet or Wi-Fi gateway can reach the VPN server",
            )
            .retryable(true));
        }
        Ok(())
    }

    fn remove_owned_connections_by_id(&self, id: &str) -> NativeResult<bool> {
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        let mut removed = false;
        while let Some(active_path) = active_owned_connection_by_id(&connection, &root, id)? {
            if let Err(error) = root.deactivate_connection(active_path) {
                // NetworkManager can remove an unsaved dummy profile together with
                // the VPN between listing it and this call. Treat that race as the
                // requested end state, but retain real deactivation failures.
                if active_owned_connection_by_id(&connection, &root, id)?.is_some() {
                    return Err(nm_error("deactivate Proton protection connection", error));
                }
            }
            removed = true;
        }

        let settings = connection.with_proxy(NM_BUS, NM_SETTINGS_PATH, Duration::from_secs(10));
        for path in settings
            .list_connections()
            .map_err(|error| nm_error("list NetworkManager profiles", error))?
        {
            let profile = connection.with_proxy(NM_BUS, path, Duration::from_secs(5));
            let profile_settings = match profile.get_settings() {
                Ok(settings) => settings,
                Err(_) => continue,
            };
            if connection_id(&profile_settings).as_deref() == Some(id)
                && connection_owned(&profile_settings)
            {
                SettingsConnection::delete(&profile)
                    .map_err(|error| nm_error("remove Proton protection connection", error))?;
                removed = true;
            }
        }
        Ok(removed)
    }

    pub fn disconnect_uuid(&self, expected_uuid: &str) -> NativeResult<bool> {
        let observation = self.observe()?;
        let disconnected = if observation.uuid.as_deref() == Some(expected_uuid) {
            self.disconnect_observation(observation)?
        } else {
            false
        };
        // The OpenVPN service can reject a profile before it remains visible
        // in ActiveConnections. Its protected credential set still belongs to
        // the attempted UUID and must be removed on every terminal cleanup.
        cleanup_openvpn_credentials(expected_uuid);
        Ok(disconnected)
    }

    fn disconnect_observation(&self, observation: TunnelObservation) -> NativeResult<bool> {
        let Some(active_path) = observation.active_path else {
            return Ok(false);
        };
        let connection = system_bus()?;
        let root = connection.with_proxy(NM_BUS, NM_PATH, Duration::from_secs(10));
        root.deactivate_connection(dbus::Path::from(active_path))
            .map_err(|error| nm_error("deactivate the Proton VPN connection", error))?;
        if let Some(connection_path) = observation.connection_path {
            let profile = connection.with_proxy(
                NM_BUS,
                dbus::Path::from(connection_path),
                Duration::from_secs(5),
            );
            let _ = SettingsConnection::delete(&profile);
        }
        Ok(true)
    }
}

fn is_local_resolver(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_link_local() || address.is_loopback()
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            address.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

fn ipv6_leak_settings() -> HashMap<&'static str, PropMap> {
    let mut connection = PropMap::new();
    prop(&mut connection, "id", IPV6_LEAK_CONNECTION_ID.to_owned());
    prop(&mut connection, "uuid", Uuid::new_v4().to_string());
    prop(&mut connection, "type", "dummy".to_owned());
    prop(
        &mut connection,
        "interface-name",
        IPV6_LEAK_INTERFACE.to_owned(),
    );
    prop(&mut connection, "autoconnect", true);
    let username = env::var("USER").unwrap_or_else(|_| "user".into());
    prop(
        &mut connection,
        "permissions",
        vec![format!("user:{username}:")],
    );
    prop(
        &mut connection,
        "stable-id",
        PROTON_OMARCHY_STABLE_ID.to_owned(),
    );

    let mut ipv4 = PropMap::new();
    prop(&mut ipv4, "method", "disabled".to_owned());

    let mut ipv6 = PropMap::new();
    prop(&mut ipv6, "method", "manual".to_owned());
    prop(
        &mut ipv6,
        "address-data",
        vec![address("fdeb:446c:912d:8da::", 64)],
    );
    prop(&mut ipv6, "dns-data", vec!["::1".to_owned()]);
    prop(&mut ipv6, "dns-priority", -1400_i32);
    prop(&mut ipv6, "route-metric", 95_i64);
    prop(&mut ipv6, "gateway", "fdeb:446c:912d:8da::1".to_owned());
    prop(&mut ipv6, "ignore-auto-dns", true);

    HashMap::from([
        ("connection", connection),
        ("dummy", PropMap::new()),
        ("ipv4", ipv4),
        ("ipv6", ipv6),
    ])
}

fn kill_switch_settings(
    id: &str,
    interface: &str,
    permanent: bool,
) -> HashMap<&'static str, PropMap> {
    let mut connection = PropMap::new();
    prop(&mut connection, "id", id.to_owned());
    prop(&mut connection, "uuid", Uuid::new_v4().to_string());
    prop(&mut connection, "type", "dummy".to_owned());
    prop(&mut connection, "interface-name", interface.to_owned());
    prop(&mut connection, "autoconnect", permanent);
    prop(
        &mut connection,
        "stable-id",
        PROTON_OMARCHY_STABLE_ID.to_owned(),
    );
    if !permanent {
        let username = env::var("USER").unwrap_or_else(|_| "user".into());
        prop(
            &mut connection,
            "permissions",
            vec![format!("user:{username}:")],
        );
    }

    let mut ipv4 = PropMap::new();
    prop(&mut ipv4, "method", "manual".to_owned());
    prop(&mut ipv4, "address-data", vec![address("100.85.0.1", 24)]);
    prop(&mut ipv4, "dns-data", vec!["0.0.0.0".to_owned()]);
    prop(&mut ipv4, "dns-priority", -1400_i32);
    prop(&mut ipv4, "route-metric", 98_i64);
    prop(&mut ipv4, "gateway", "100.85.0.1".to_owned());
    prop(&mut ipv4, "ignore-auto-dns", true);

    let mut ipv6 = PropMap::new();
    prop(&mut ipv6, "method", "manual".to_owned());
    prop(
        &mut ipv6,
        "address-data",
        vec![address("fdeb:446c:912d:8da::", 64)],
    );
    prop(&mut ipv6, "dns-data", vec!["::1".to_owned()]);
    prop(&mut ipv6, "dns-priority", -1400_i32);
    prop(&mut ipv6, "route-metric", 95_i64);
    prop(&mut ipv6, "gateway", "fdeb:446c:912d:8da::1".to_owned());
    prop(&mut ipv6, "ignore-auto-dns", true);

    HashMap::from([
        ("connection", connection),
        ("dummy", PropMap::new()),
        ("ipv4", ipv4),
        ("ipv6", ipv6),
    ])
}

fn settings_connection_by_id_owned<C>(
    connection: &Connection,
    settings: &dbus::blocking::Proxy<'_, C>,
    id: &str,
) -> NativeResult<Option<dbus::Path<'static>>>
where
    C: std::ops::Deref<Target = Connection>,
{
    for path in settings
        .list_connections()
        .map_err(|error| nm_error("list NetworkManager profiles", error))?
    {
        let profile = connection.with_proxy(NM_BUS, path.clone(), Duration::from_secs(5));
        let values = match profile.get_settings() {
            Ok(values) => values,
            Err(_) => continue,
        };
        if connection_id(&values).as_deref() == Some(id) && connection_owned(&values) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn active_owned_connection_by_id<C>(
    connection: &Connection,
    root: &dbus::blocking::Proxy<'_, C>,
    id: &str,
) -> NativeResult<Option<dbus::Path<'static>>>
where
    C: std::ops::Deref<Target = Connection>,
{
    for path in root
        .active_connections()
        .map_err(|error| nm_error("list active NetworkManager connections", error))?
    {
        let active = connection.with_proxy(NM_BUS, path.clone(), Duration::from_secs(5));
        if active.id().ok().as_deref() != Some(id) {
            continue;
        }
        let profile_path = match active.connection() {
            Ok(path) => path,
            Err(_) => continue,
        };
        let profile = connection.with_proxy(NM_BUS, profile_path, Duration::from_secs(5));
        if profile
            .get_settings()
            .map(|settings| connection_owned(&settings))
            .unwrap_or(false)
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn active_connection_by_id<C>(
    connection: &Connection,
    root: &dbus::blocking::Proxy<'_, C>,
    id: &str,
) -> NativeResult<Option<dbus::Path<'static>>>
where
    C: std::ops::Deref<Target = Connection>,
{
    for path in root
        .active_connections()
        .map_err(|error| nm_error("list active NetworkManager connections", error))?
    {
        let active = connection.with_proxy(NM_BUS, path.clone(), Duration::from_secs(5));
        if active.id().ok().as_deref() == Some(id) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn prop<T>(map: &mut PropMap, name: &str, value: T)
where
    T: RefArg + 'static,
{
    map.insert(name.to_owned(), Variant(Box::new(value)));
}

fn address(ip: &str, prefix: u32) -> PropMap {
    let mut address = PropMap::new();
    prop(&mut address, "address", ip.to_owned());
    prop(&mut address, "prefix", prefix);
    address
}

fn system_bus() -> NativeResult<Connection> {
    Connection::new_system().map_err(|error| nm_error("connect to NetworkManager", error))
}

fn service_type(settings: &HashMap<String, PropMap>) -> Option<String> {
    settings
        .get("vpn")?
        .get("service-type")?
        .0
        .as_str()
        .map(str::to_owned)
}

fn connection_id(settings: &HashMap<String, PropMap>) -> Option<String> {
    settings
        .get("connection")?
        .get("id")?
        .0
        .as_str()
        .map(str::to_owned)
}

fn profile_protocol(settings: &HashMap<String, PropMap>) -> Option<String> {
    if service_type(settings).as_deref() == Some(OPENVPN_SERVICE) {
        return Some(
            if vpn_data_string(settings, "proto-tcp").as_deref() == Some("yes") {
                "openvpn-tcp"
            } else {
                "openvpn-udp"
            }
            .to_owned(),
        );
    }
    let data = settings.get("vpn")?.get("data")?;
    let settings_value = dict_string(&*data.0, "settings")?;
    // NetworkManager escapes separators inside a{ss} values. Different
    // frontends may leave one or more escape layers, while the payload itself
    // contains no meaningful backslashes.
    let raw = settings_value
        .chars()
        .filter(|character| *character != '\\')
        .collect::<String>();
    let settings: Value = serde_json::from_str(&raw).ok()?;
    let peer = settings.get("peers")?.as_array()?.first()?;
    let has_udp = nonempty_ports(peer.get("udp-ports"));
    let has_tcp = nonempty_ports(peer.get("tcp-ports"));
    let has_tls = nonempty_ports(peer.get("tls-ports"));
    Some(
        match (has_udp, has_tcp, has_tls) {
            (false, false, true) => "protun-tls",
            (false, true, false) => "protun-tcp",
            (true, false, false) => "protun-udp",
            _ => "protun-smart",
        }
        .to_owned(),
    )
}

fn profile_endpoint(settings: &HashMap<String, PropMap>) -> Option<String> {
    if service_type(settings).as_deref() == Some(OPENVPN_SERVICE) {
        let remote = vpn_data_string(settings, "remote")?;
        let first = remote
            .split([',', ' ', '\t'])
            .find(|value| !value.is_empty())?;
        if let Some(bracketed) = first.strip_prefix('[') {
            return bracketed
                .split_once(']')
                .map(|(address, _)| address.to_owned());
        }
        return Some(first.split(':').next()?.to_owned());
    }
    let data = settings.get("vpn")?.get("data")?;
    let settings_value = dict_string(&*data.0, "settings")?;
    let raw = settings_value
        .chars()
        .filter(|character| *character != '\\')
        .collect::<String>();
    serde_json::from_str::<Value>(&raw)
        .ok()?
        .get("peers")?
        .as_array()?
        .first()?
        .get("endpoint")?
        .as_str()
        .map(str::to_owned)
}

fn vpn_data_string(settings: &HashMap<String, PropMap>, key: &str) -> Option<String> {
    let data = settings.get("vpn")?.get("data")?;
    dict_string(&*data.0, key)
}

fn profile_store_id(settings: &HashMap<String, PropMap>) -> Option<String> {
    vpn_data_string(settings, PROTON_OMARCHY_PROFILE_ID_KEY).filter(|value| {
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
    })
}

fn profile_owned(settings: &HashMap<String, PropMap>) -> bool {
    settings
        .get("vpn")
        .and_then(|vpn| vpn.get("data"))
        .and_then(|data| dict_string(&*data.0, PROTON_OMARCHY_OWNER_KEY))
        .as_deref()
        == Some(PROTON_OMARCHY_OWNER_VALUE)
        || connection_owned(settings)
}

fn proton_system_profile(settings: &HashMap<String, PropMap>) -> bool {
    matches!(
        connection_id(settings).as_deref(),
        Some(
            IPV6_LEAK_CONNECTION_ID
                | KILL_SWITCH_CONNECTION_ID
                | KILL_SWITCH_PERMANENT_CONNECTION_ID
        )
    ) || matches!(
        service_type(settings).as_deref(),
        Some(PROTUN_SERVICE | OPENVPN_SERVICE)
    )
}

fn conflict_label(id: &str, interface: Option<&str>) -> String {
    match interface.filter(|interface| !interface.is_empty()) {
        Some(interface) if !id.eq_ignore_ascii_case(interface) => format!("{id} ({interface})"),
        Some(interface) => interface.to_owned(),
        None => id.to_owned(),
    }
}

fn is_conflicting_tunnel_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        PROTUN_INTERFACE
            | IPV6_LEAK_INTERFACE
            | KILL_SWITCH_INTERFACE
            | KILL_SWITCH_PERMANENT_INTERFACE
    ) {
        return false;
    }
    [
        "tun",
        "tap",
        "wg",
        "tailscale",
        "warp",
        "zt",
        "ham",
        "nordlynx",
        "mullvad",
        "ivpn",
        "pia",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn connection_owned(settings: &HashMap<String, PropMap>) -> bool {
    settings
        .get("connection")
        .and_then(|connection| connection.get("stable-id"))
        .and_then(|value| value.0.as_str())
        == Some(PROTON_OMARCHY_STABLE_ID)
}

fn dict_string(value: &(dyn RefArg + 'static), key: &str) -> Option<String> {
    if let Some(data) = cast::<HashMap<String, String>>(value) {
        return data.get(key).cloned();
    }

    let mut entries = value.as_iter()?;
    loop {
        let entry_key = entries.next()?.as_str()?;
        let entry_value = entries.next()?.as_str()?;
        if entry_key == key {
            return Some(entry_value.to_owned());
        }
    }
}

fn nonempty_ports(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .map(|ports| !ports.is_empty())
        .unwrap_or(false)
}

fn openvpn_root() -> NativeResult<PathBuf> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        NativeError::new(
            "environment_invalid",
            "XDG_RUNTIME_DIR is required to protect temporary OpenVPN credentials",
        )
    })?;
    Ok(PathBuf::from(runtime).join("proton-omarchy/openvpn"))
}

fn openvpn_credential_dir(uuid: &str) -> NativeResult<PathBuf> {
    Uuid::parse_str(uuid).map_err(|error| {
        NativeError::new("profile_invalid", "The OpenVPN profile UUID is invalid")
            .with_source(error)
    })?;
    let root = openvpn_root()?;
    fs::create_dir_all(&root).map_err(|error| {
        NativeError::new(
            "vpn_credentials_unavailable",
            "Unable to create the protected OpenVPN credential directory",
        )
        .with_source(error)
    })?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|error| {
        NativeError::new(
            "vpn_credentials_unavailable",
            "Unable to protect the OpenVPN credential directory",
        )
        .with_source(error)
    })?;
    let directory = root.join(uuid);
    fs::create_dir(&directory).map_err(|error| {
        NativeError::new(
            "vpn_credentials_unavailable",
            "Unable to create the temporary OpenVPN credential set",
        )
        .with_source(error)
    })?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
        NativeError::new(
            "vpn_credentials_unavailable",
            "Unable to protect the temporary OpenVPN credential set",
        )
        .with_source(error)
    })?;
    Ok(directory)
}

fn write_private_file(path: &Path, contents: &[u8]) -> NativeResult<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            NativeError::new(
                "vpn_credentials_unavailable",
                format!(
                    "Unable to create protected VPN credential {}",
                    path.display()
                ),
            )
            .with_source(error)
        })?;
    file.write_all(contents).map_err(|error| {
        NativeError::new(
            "vpn_credentials_unavailable",
            format!(
                "Unable to write protected VPN credential {}",
                path.display()
            ),
        )
        .with_source(error)
    })
}

fn cleanup_openvpn_credentials(uuid: &str) {
    if Uuid::parse_str(uuid).is_err() {
        return;
    }
    if let Ok(root) = openvpn_root() {
        let _ = fs::remove_dir_all(root.join(uuid));
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn best_parent<C>(
    connection: &Connection,
    root: &dbus::blocking::Proxy<'_, C>,
) -> Option<dbus::Path<'static>>
where
    C: std::ops::Deref<Target = Connection>,
{
    let primary = root.primary_connection().ok()?;
    if primary == DBUS_ROOT {
        return None;
    }
    let active = connection.with_proxy(NM_BUS, primary.clone(), Duration::from_secs(5));
    let kind = active.type_().ok()?;
    if ["802-3-ethernet", "802-11-wireless", "gsm", "cdma", "bridge"].contains(&kind.as_str()) {
        Some(primary)
    } else {
        None
    }
}

fn wireguard_private_key(ed25519_seed_b64: &str) -> NativeResult<String> {
    let seed = BASE64.decode(ed25519_seed_b64).map_err(|error| {
        NativeError::new(
            "vpn_credentials_invalid",
            "The stored Proton VPN private key is not valid base64",
        )
        .with_source(error)
    })?;
    if seed.len() != 32 {
        return Err(NativeError::new(
            "vpn_credentials_invalid",
            "The stored Proton VPN private key has an invalid length",
        ));
    }
    let digest = Sha512::digest(&seed);
    let mut private_key = [0_u8; 32];
    private_key.copy_from_slice(&digest[..32]);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    Ok(BASE64.encode(private_key))
}

fn encrypted_openvpn_private_key(
    ed25519_seed_b64: &str,
    passphrase: &[u8],
) -> NativeResult<Zeroizing<String>> {
    let seed = BASE64.decode(ed25519_seed_b64).map_err(|error| {
        NativeError::new(
            "vpn_credentials_invalid",
            "The stored Proton VPN private key is not valid base64",
        )
        .with_source(error)
    })?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        NativeError::new(
            "vpn_credentials_invalid",
            "The stored Proton VPN private key must contain exactly 32 bytes",
        )
    })?;
    let plaintext = SigningKey::from_bytes(&seed)
        .to_pkcs8_der()
        .map_err(|error| {
            NativeError::new(
                "vpn_credentials_invalid",
                "Unable to encode the Proton VPN private key for OpenVPN",
            )
            .with_source(error)
        })?;
    let private_key = PrivateKeyInfo::try_from(plaintext.as_bytes()).map_err(|error| {
        NativeError::new(
            "vpn_credentials_invalid",
            "Unable to parse the encoded Proton VPN private key",
        )
        .with_source(error)
    })?;
    let mut salt = [0_u8; 16];
    let mut iv = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    // Proton credentials use a random 128-bit passphrase, so this KDF protects
    // the temporary key without the large latency and memory spike of a
    // human-password-oriented scrypt profile.
    let parameters = pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(100_000, &salt, &iv)
        .map_err(|error| {
            NativeError::new(
                "vpn_credentials_invalid",
                "Unable to configure OpenVPN private-key encryption",
            )
            .with_source(error)
        })?;
    let encrypted = private_key
        .encrypt_with_params(parameters, passphrase)
        .map_err(|error| {
            NativeError::new(
                "vpn_credentials_invalid",
                "Unable to encrypt the Proton VPN private key for OpenVPN",
            )
            .with_source(error)
        })?;
    encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .map_err(|error| {
            NativeError::new(
                "vpn_credentials_invalid",
                "Unable to serialize the encrypted Proton VPN private key",
            )
            .with_source(error)
        })
}

fn enabled_dns(entries: &[serde_json::Value]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for entry in entries {
        let (enabled, value) = match entry {
            serde_json::Value::String(value) => (true, value.as_str()),
            serde_json::Value::Object(object) => (
                object
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                object
                    .get("ip")
                    .or_else(|| object.get("address"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            ),
            _ => (false, ""),
        };
        if !enabled || value.is_empty() {
            continue;
        }
        match value.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => v4.push(value.to_owned()),
            Ok(std::net::IpAddr::V6(_)) => v6.push(value.to_owned()),
            Err(_) => {}
        }
    }
    (v4, v6)
}

fn normalize_protocol(protocol: &str) -> String {
    match protocol {
        "smart" => "protun-smart",
        "wireguard" | "wireguard-udp" => "protun-udp",
        "wireguard-tcp" => "protun-tcp",
        "wireguard-tls" | "stealth" => "protun-tls",
        value => value,
    }
    .to_owned()
}

fn wifi_is_secure(wpa_flags: u32, rsn_flags: u32) -> bool {
    // Open and legacy WEP access points expose neither WPA nor RSN key-management flags.
    wpa_flags != 0 || rsn_flags != 0
}

fn nm_error(action: &str, error: dbus::Error) -> NativeError {
    NativeError::new(
        "networkmanager_error",
        format!("Unable to {action} through NetworkManager"),
    )
    .with_source(error)
    .retryable(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_security_requires_wpa_or_rsn_key_management() {
        assert!(!wifi_is_secure(0, 0));
        assert!(wifi_is_secure(1, 0));
        assert!(wifi_is_secure(0, 1));
        assert!(wifi_is_secure(1, 1));
    }

    #[test]
    fn wireguard_key_conversion_is_deterministic_and_32_bytes() {
        let key = wireguard_private_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("conversion");
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
            .expect("base64");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded[0] & 7, 0);
        assert_eq!(decoded[31] & 0x80, 0);
        assert_ne!(decoded[31] & 0x40, 0);
    }

    #[test]
    fn openvpn_private_key_is_encrypted_pkcs8_pem() {
        let key = encrypted_openvpn_private_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            b"test-only-passphrase",
        )
        .expect("encrypted key");
        assert!(key.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(key.ends_with("-----END ENCRYPTED PRIVATE KEY-----\n"));
        assert!(!key.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    #[test]
    fn openvpn_networkmanager_profile_has_complete_tls_contract() {
        let root = PathBuf::from("/run/user/1000/proton-omarchy/openvpn/test");
        let profile = OpenVpnProfile {
            id: "ProtonVPN MX#1".into(),
            uuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
            protocol: "openvpn-tcp".into(),
            profile_id: Some("profile-work".into()),
            remote: "192.0.2.1:443, 192.0.2.1:8443".into(),
            domain: "node.example.test".into(),
            passphrase: Zeroizing::new("test-only-passphrase".into()),
            credential_dir: root.clone(),
            ca: root.join("ca.pem"),
            certificate: root.join("certificate.pem"),
            private_key: root.join("private-key.pem"),
            tls_crypt: root.join("tls-crypt.pem"),
            enable_ipv6: true,
            custom_dns_v4: vec!["1.1.1.1".into()],
            custom_dns_v6: vec!["2606:4700:4700::1111".into()],
        };
        let settings = profile
            .dbus_settings()
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<HashMap<_, _>>();
        assert_eq!(service_type(&settings).as_deref(), Some(OPENVPN_SERVICE));
        assert_eq!(profile_protocol(&settings).as_deref(), Some("openvpn-tcp"));
        assert_eq!(profile_endpoint(&settings).as_deref(), Some("192.0.2.1"));
        assert_eq!(profile_store_id(&settings).as_deref(), Some("profile-work"));
        for key in [
            "ca",
            "cert",
            "key",
            "tls-crypt",
            "connection-type",
            "remote",
            "cipher",
            "dev",
            "dev-type",
            "remote-cert-tls",
            "verify-x509-name",
            "cert-pass-flags",
            "proto-tcp",
        ] {
            assert!(vpn_data_string(&settings, key).is_some(), "missing {key}");
        }
        assert_eq!(
            vpn_data_string(&settings, "verify-x509-name").as_deref(),
            Some("name:node.example.test")
        );
    }

    #[test]
    fn local_dns_policy_accepts_only_non_public_resolvers() {
        for address in [
            "127.0.0.1",
            "10.0.0.53",
            "172.16.0.53",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::53",
            "fe80::53",
        ] {
            assert!(is_local_resolver(&address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"] {
            assert!(!is_local_resolver(&address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn conflict_detection_excludes_our_interfaces_and_recognizes_other_tunnels() {
        assert!(!is_conflicting_tunnel_name(PROTUN_INTERFACE));
        assert!(!is_conflicting_tunnel_name(KILL_SWITCH_INTERFACE));
        assert!(!is_conflicting_tunnel_name(IPV6_LEAK_INTERFACE));
        assert!(is_conflicting_tunnel_name("tun0"));
        assert!(is_conflicting_tunnel_name("wg-office"));
        assert!(is_conflicting_tunnel_name("tailscale0"));
        assert!(!is_conflicting_tunnel_name("wlp0s20f3"));
        assert_eq!(conflict_label("Work VPN", Some("tun0")), "Work VPN (tun0)");
    }
}
