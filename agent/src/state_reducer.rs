use crate::{operations::OperationCoordinator, store::StoreHandle};
use proton_omarchy_protocol::{
    AccountStatus, ConnectionStatus, KillSwitchMode, SplitTunnelingMode, StateSnapshot,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

pub(crate) fn apply_event(
    state_tx: &watch::Sender<StateSnapshot>,
    operations: &OperationCoordinator,
    store: &StoreHandle,
    event: &str,
    data: Value,
) {
    if event == "operation.stage" {
        let method = data.get("method").and_then(Value::as_str).unwrap_or("");
        let stage = data.get("stage").and_then(Value::as_str).unwrap_or("");
        let cancelable = data.get("cancelable").and_then(Value::as_bool);
        operations.update_stage(method, stage, cancelable);
        return;
    }

    let account_to_activate =
        if event == "account" && data.get("status").and_then(Value::as_str) == Some("signed_in") {
            data.get("name").and_then(Value::as_str).map(str::to_owned)
        } else {
            None
        };

    state_tx.send_modify(|state| {
        match event {
            "backend" => {
                state.backend.kind = data
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("proton_linux")
                    .to_owned();
                state.backend.core_available = data
                    .get("core_available")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.connection_available = data
                    .get("connection_available")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.connection_availability_known = data
                    .get("connection_availability_known")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.settings_known = data
                    .get("settings_known")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.connector_initialized = data
                    .get("connector_initialized")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.network_blocked_known = data
                    .get("network_blocked_known")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.network_blocked = data
                    .get("network_blocked")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.backend.core_version = data
                    .get("core_version")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                state.backend.error = data.get("error").and_then(Value::as_str).map(str::to_owned);
            }
            "account" => {
                state.account.status = match data
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                {
                    "signed_out" => AccountStatus::SignedOut,
                    "signing_in" => AccountStatus::SigningIn,
                    "two_factor_required" => AccountStatus::TwoFactorRequired,
                    "signed_in" => AccountStatus::SignedIn,
                    "error" => AccountStatus::Error,
                    _ => AccountStatus::Unknown,
                };
                state.account.name = data.get("name").and_then(Value::as_str).map(str::to_owned);
                state.account.tier = data
                    .get("tier")
                    .and_then(Value::as_u64)
                    .and_then(|tier| u8::try_from(tier).ok());
                state.account.credentialless = data
                    .get("credentialless")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.account.two_factor_code_supported = data
                    .get("two_factor_code_supported")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.account.two_factor_security_key_supported = data
                    .get("two_factor_security_key_supported")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.account.sso_supported = data
                    .get("sso_supported")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            }
            "device_location" => {
                state.device_location.known =
                    data.get("known").and_then(Value::as_bool).unwrap_or(false);
                state.device_location.ip_address = data
                    .get("ip_address")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.device_location.country_code = data
                    .get("country_code")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_ascii_uppercase());
                state.device_location.isp = data
                    .get("isp")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.device_location.latitude = data.get("latitude").and_then(Value::as_f64);
                state.device_location.longitude = data.get("longitude").and_then(Value::as_f64);
            }
            "features" => {
                state.features.known = data.get("known").and_then(Value::as_bool).unwrap_or(false);
                state.features.writable = data
                    .get("writable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if !state.features.known {
                    state.features.writes = Default::default();
                } else {
                    if let Some(protocol) = data.get("protocol").and_then(Value::as_object) {
                        state.features.protocol.selected = protocol
                            .get("selected")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        state.features.protocol.available = string_array(protocol, "available");
                        state.features.protocol.profile_available =
                            string_array(protocol, "profile_available");
                    }

                    if let Some(kill_switch) = data.get("kill_switch").and_then(Value::as_object) {
                        state.features.kill_switch.mode = match kill_switch
                            .get("mode")
                            .and_then(Value::as_str)
                            .unwrap_or("off")
                        {
                            "advanced" => KillSwitchMode::Advanced,
                            "standard" => KillSwitchMode::Standard,
                            _ => KillSwitchMode::Off,
                        };
                    }

                    if let Some(netshield) = data.get("netshield").and_then(Value::as_object) {
                        state.features.netshield.level = netshield
                            .get("level")
                            .and_then(Value::as_u64)
                            .and_then(|level| u8::try_from(level).ok())
                            .unwrap_or(0);
                        state.features.netshield.statistics_known = netshield
                            .get("statistics_known")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.netshield.malware_blocked = netshield
                            .get("malware_blocked")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(0);
                        state.features.netshield.ads_blocked = netshield
                            .get("ads_blocked")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(0);
                        state.features.netshield.trackers_blocked = netshield
                            .get("trackers_blocked")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(0);
                    }

                    if let Some(vpn_accelerator) =
                        data.get("vpn_accelerator").and_then(Value::as_object)
                    {
                        state.features.vpn_accelerator.enabled = vpn_accelerator
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }

                    if let Some(anonymous_crash_reports) = data
                        .get("anonymous_crash_reports")
                        .and_then(Value::as_object)
                    {
                        state.features.anonymous_crash_reports.enabled = anonymous_crash_reports
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }

                    if let Some(anonymous_usage_statistics) = data
                        .get("anonymous_usage_statistics")
                        .and_then(Value::as_object)
                    {
                        state.features.anonymous_usage_statistics.enabled =
                            anonymous_usage_statistics
                                .get("enabled")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                    }

                    if let Some(connection_feedback) =
                        data.get("connection_feedback").and_then(Value::as_object)
                    {
                        state.features.connection_feedback.available = connection_feedback
                            .get("available")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.connection_feedback.viewed = connection_feedback
                            .get("viewed")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.connection_feedback.sent = connection_feedback
                            .get("sent")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }

                    if let Some(moderate_nat) = data.get("moderate_nat").and_then(Value::as_object)
                    {
                        state.features.moderate_nat.enabled = moderate_nat
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                    if let Some(ipv6) = data.get("ipv6").and_then(Value::as_object) {
                        state.features.ipv6.enabled = ipv6
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                    if let Some(ipv6_leak_protection) =
                        data.get("ipv6_leak_protection").and_then(Value::as_object)
                    {
                        state.features.ipv6_leak_protection.enabled = ipv6_leak_protection
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                    if let Some(alternative_routing) =
                        data.get("alternative_routing").and_then(Value::as_object)
                    {
                        state.features.alternative_routing.enabled = alternative_routing
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                    if let Some(allow_lan) =
                        data.get("allow_lan_connections").and_then(Value::as_object)
                    {
                        state.features.allow_lan_connections.enabled = allow_lan
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                    if let Some(allow_local_dns) =
                        data.get("allow_local_dns").and_then(Value::as_object)
                    {
                        state.features.allow_local_dns.enabled = allow_local_dns
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }

                    if let Some(secure_core) = data.get("secure_core").and_then(Value::as_bool) {
                        state.features.secure_core = secure_core;
                    }

                    if let Some(split) = data.get("split_tunneling").and_then(Value::as_object) {
                        state.features.split_tunneling.availability_known = split
                            .get("availability_known")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.split_tunneling.mode =
                            match split.get("mode").and_then(Value::as_str).unwrap_or("off") {
                                "inverse" => SplitTunnelingMode::Inverse,
                                "standard" => SplitTunnelingMode::Standard,
                                _ => SplitTunnelingMode::Off,
                            };
                        state.features.split_tunneling.available = split
                            .get("available")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.split_tunneling.app_paths_supported = split
                            .get("app_paths_supported")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.split_tunneling.ip_ranges_supported = split
                            .get("ip_ranges_supported")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);

                        if let Some(standard) = split.get("standard").and_then(Value::as_object) {
                            state.features.split_tunneling.standard.app_paths =
                                string_array(standard, "app_paths");
                            state.features.split_tunneling.standard.ip_ranges =
                                string_array(standard, "ip_ranges");
                        }
                        if let Some(inverse) = split.get("inverse").and_then(Value::as_object) {
                            state.features.split_tunneling.inverse.app_paths =
                                string_array(inverse, "app_paths");
                            state.features.split_tunneling.inverse.ip_ranges =
                                string_array(inverse, "ip_ranges");
                        }
                    }

                    if let Some(port_forwarding) =
                        data.get("port_forwarding").and_then(Value::as_object)
                    {
                        state.features.port_forwarding.enabled = port_forwarding
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.port_forwarding.active_port = port_forwarding
                            .get("active_port")
                            .and_then(Value::as_u64)
                            .and_then(|port| u16::try_from(port).ok());
                    }

                    if let Some(custom_dns) = data.get("custom_dns").and_then(Value::as_object) {
                        state.features.custom_dns.enabled = custom_dns
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.custom_dns.servers = custom_dns
                            .get("servers")
                            .and_then(Value::as_array)
                            .map(|servers| {
                                servers
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                    }

                    if let Some(writes) = data.get("writes").and_then(Value::as_object) {
                        state.features.writes.protocol = writes
                            .get("protocol")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.kill_switch = writes
                            .get("kill_switch")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.netshield = writes
                            .get("netshield")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.vpn_accelerator = writes
                            .get("vpn_accelerator")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.anonymous_crash_reports = writes
                            .get("anonymous_crash_reports")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.anonymous_usage_statistics = writes
                            .get("anonymous_usage_statistics")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.moderate_nat = writes
                            .get("moderate_nat")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.ipv6 =
                            writes.get("ipv6").and_then(Value::as_bool).unwrap_or(false);
                        state.features.writes.ipv6_leak_protection = writes
                            .get("ipv6_leak_protection")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.alternative_routing = writes
                            .get("alternative_routing")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.allow_lan_connections = writes
                            .get("allow_lan_connections")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.allow_local_dns = writes
                            .get("allow_local_dns")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.custom_dns = writes
                            .get("custom_dns")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.secure_core = writes
                            .get("secure_core")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.split_tunneling = writes
                            .get("split_tunneling")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        state.features.writes.port_forwarding = writes
                            .get("port_forwarding")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                }
            }
            "connection" => {
                let previous_status = state.connection.status;
                state.connection.observation_known = data
                    .get("observation_known")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.connection.status = match data
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                {
                    "disconnected" => ConnectionStatus::Disconnected,
                    "connecting" => ConnectionStatus::Connecting,
                    "connected" => ConnectionStatus::Connected,
                    "error" => ConnectionStatus::Error,
                    _ => ConnectionStatus::Unknown,
                };

                let server = data.get("server").and_then(Value::as_object);
                state.connection.country_code = server
                    .and_then(|s| s.get("country_code"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                state.connection.country_name = server
                    .and_then(|s| s.get("country_name"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                state.connection.entry_country_code = server
                    .and_then(|s| s.get("entry_country_code"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.connection.entry_country_name = server
                    .and_then(|s| s.get("entry_country_name"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.connection.state = server
                    .and_then(|s| s.get("state"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.connection.city = server
                    .and_then(|s| s.get("city"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                state.connection.server_name = server
                    .and_then(|s| s.get("name"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                state.connection.server_load = server
                    .and_then(|s| s.get("load"))
                    .and_then(Value::as_u64)
                    .and_then(|load| u8::try_from(load).ok());
                state.connection.p2p = server
                    .and_then(|s| s.get("p2p"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                state.connection.tor = server
                    .and_then(|s| s.get("tor"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                state.connection.server_ip = server
                    .and_then(|s| s.get("server_ip"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.connection.latency_ms = None;
                state.connection.protocol = data
                    .get("protocol")
                    .and_then(Value::as_str)
                    .filter(|protocol| !protocol.is_empty())
                    .map(str::to_owned);
                state.connection.error =
                    data.get("error").and_then(Value::as_str).map(str::to_owned);
                state.connection.error_code = data
                    .get("error_code")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                state.connection.restriction_reason_code = data
                    .get("restriction_reason_code")
                    .and_then(Value::as_i64)
                    .and_then(|value| i32::try_from(value).ok());
                if let Some(conflicts) = data.get("network_conflicts").and_then(Value::as_array) {
                    state.connection.network_conflicts = conflicts
                        .iter()
                        .filter_map(Value::as_str)
                        .take(16)
                        .map(str::to_owned)
                        .collect();
                } else if matches!(
                    state.connection.status,
                    ConnectionStatus::Connected | ConnectionStatus::Disconnected
                ) {
                    state.connection.network_conflicts.clear();
                }

                if let Some(secure_core) = data.get("secure_core").and_then(Value::as_bool) {
                    state.features.secure_core = secure_core;
                }

                if state.connection.status == ConnectionStatus::Connected
                    && previous_status != ConnectionStatus::Connected
                {
                    state.connection.connected_at_unix_ms = Some(now_unix_ms());
                } else if state.connection.status == ConnectionStatus::Disconnected {
                    state.connection.connected_at_unix_ms = None;
                }
            }
            _ => return,
        }

        state.revision = state.revision.wrapping_add(1);
    });

    if let Some(account_name) = account_to_activate {
        let _ = store.activate_account(Some(&account_name));
    }
}

fn string_array(object: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
