use super::{
    api::{ApiSession, ProtonApi},
    catalog::ConnectionTarget,
    models::{
        NativeSettings, SessionData, FEATURE_B2B, FEATURE_IPV6, FEATURE_P2P, FEATURE_PARTNER,
        FEATURE_SECURE_CORE, FEATURE_STREAMING, FEATURE_TOR,
    },
    session_bootstrap, settings_store, NativeError, NativeResult,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;

const MAX_EVENTS: usize = 100;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ConnectionFeedbackSession {
    started_at: Instant,
    target: ConnectionTarget,
    protocol: String,
    trigger: String,
    user_feedback: String,
    viewed: bool,
    sent: bool,
}

impl ConnectionFeedbackSession {
    pub fn new(target: ConnectionTarget, protocol: String, trigger: String) -> Self {
        Self {
            started_at: Instant::now(),
            target,
            protocol,
            trigger,
            user_feedback: "unknown".into(),
            viewed: false,
            sent: false,
        }
    }

    pub fn viewed(&self) -> bool {
        self.viewed
    }

    pub fn sent(&self) -> bool {
        self.sent
    }

    pub fn update_feedback(&mut self, value: &str) {
        self.viewed = true;
        self.user_feedback = match value {
            "positive" => {
                self.sent = true;
                "positive"
            }
            "negative" => {
                self.sent = true;
                "negative"
            }
            _ if self.sent => return,
            _ => "ignore",
        }
        .into();
    }

    pub fn event(
        &self,
        session: &SessionData,
        settings: &NativeSettings,
        has_active_exclusions: bool,
    ) -> Value {
        let logical = &self.target.logical;
        let mut server_features = Vec::new();
        if logical.tier == 0 {
            server_features.push("free");
        }
        if logical.features & FEATURE_IPV6 != 0 {
            server_features.push("ipv6");
        }
        if logical.features & FEATURE_P2P != 0 {
            server_features.push("p2p");
        }
        if logical.features & (FEATURE_B2B | FEATURE_PARTNER) != 0 {
            server_features.push("partnership");
        }
        if logical.features & FEATURE_SECURE_CORE != 0 {
            server_features.push("secureCore");
        }
        if logical.features & FEATURE_STREAMING != 0 {
            server_features.push("streaming");
        }
        if logical.features & FEATURE_TOR != 0 {
            server_features.push("tor");
        }
        server_features.sort_unstable();

        let mut client_features = Vec::new();
        if settings.custom_dns.enabled {
            client_features.push("custom_dns");
        }
        if has_active_exclusions {
            client_features.push("connection_preferences");
        }
        if settings.killswitch != 0 {
            client_features.push("kill_switch");
        }
        if settings.features.moderate_nat {
            client_features.push("moderate_nat");
        }
        if settings.features.netshield != 0 {
            client_features.push("netshield");
        }
        if settings.features.port_forwarding {
            client_features.push("port_forwarding");
        }
        if settings.features.split_tunneling.enabled {
            client_features.push("split_tunneling");
        }
        client_features.sort_unstable();

        let user_tier = match session.tier() {
            0 => "free",
            1 | 2 => "paid",
            3 => "internal",
            _ => "n/a",
        };
        let client_features = if client_features.is_empty() {
            "none".into()
        } else {
            client_features.join(",")
        };
        let session_length = self.started_at.elapsed().as_secs_f64() * 1000.0;
        json!({
            "MeasurementGroup": "vpn.any.connection",
            "Event": "vpn_disconnection",
            "Values": { "session_length": session_length },
            "Dimensions": {
                "outcome": "success",
                "user_tier": user_tier,
                "vpn_status": "on",
                "vpn_trigger": self.trigger,
                "network_type": "n/a",
                "server_features": server_features.join(","),
                "vpn_country": string_dimension(&logical.exit_country),
                "user_country": string_dimension(&session.vpn.location.country),
                "protocol": protocol_dimension(&self.protocol),
                "server": string_dimension(&logical.name),
                "entry_ip": string_dimension(&self.target.physical.entry_ip),
                "port": "n/a",
                "isp": string_dimension(&session.vpn.location.isp),
                "is_ipv6_enabled": (settings.ipv6 && logical.features & FEATURE_IPV6 != 0).to_string(),
                "has_active_exclusions": has_active_exclusions.to_string(),
                "failure_reason": "n/a",
                "is_smart_protocol": matches!(settings.protocol.as_str(), "smart" | "protun-smart").to_string(),
                "client_features": client_features,
                "tenure": "unknown",
                "user_feedback": self.user_feedback
            }
        })
    }
}

pub async fn enqueue_and_flush(
    api: ProtonApi,
    session: SessionData,
    path: PathBuf,
    event: Value,
    write: Arc<Mutex<()>>,
) {
    let _guard = write.lock().await;
    let enqueue_path = path.clone();
    let events = match tokio::task::spawn_blocking(move || enqueue(&enqueue_path, event)).await {
        Ok(Ok(events)) => events,
        _ => return,
    };
    if events.is_empty() {
        return;
    }
    let api_session: ApiSession = session_bootstrap::stored_api_session(&session);
    if api
        .post(
            "/data/v1/stats/multiple",
            json!({ "EventInfo": events }),
            &api_session,
        )
        .await
        .is_ok()
    {
        let _ = tokio::task::spawn_blocking(move || clear(&path)).await;
    }
}

pub async fn flush_existing(
    api: ProtonApi,
    session: SessionData,
    path: PathBuf,
    write: Arc<Mutex<()>>,
) {
    let _guard = write.lock().await;
    let load_path = path.clone();
    let events = match tokio::task::spawn_blocking(move || load(&load_path)).await {
        Ok(Ok(events)) if !events.is_empty() => events,
        _ => return,
    };
    let api_session = session_bootstrap::stored_api_session(&session);
    if api
        .post(
            "/data/v1/stats/multiple",
            json!({ "EventInfo": events }),
            &api_session,
        )
        .await
        .is_ok()
    {
        let _ = tokio::task::spawn_blocking(move || clear(&path)).await;
    }
}

pub fn clear(path: &Path) -> NativeResult<()> {
    settings_store::save_value(path, &json!({ "StatisticalEvents": [] }))
}

fn enqueue(path: &Path, event: Value) -> NativeResult<Vec<Value>> {
    let mut events = load(path)?;
    events.push(event);
    if events.len() > MAX_EVENTS {
        let excess = events.len() - MAX_EVENTS;
        events.drain(..excess);
    }
    settings_store::save_value(path, &json!({ "StatisticalEvents": events }))?;
    Ok(events)
}

fn load(path: &Path) -> NativeResult<Vec<Value>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(queue_error(path, error)),
    };
    if metadata.len() > MAX_FILE_BYTES {
        return Err(NativeError::new(
            "statistics_queue_invalid",
            "The anonymous statistics queue is too large",
        ));
    }
    let raw = fs::read(path).map_err(|error| queue_error(path, error))?;
    let value: Value = serde_json::from_slice(&raw).map_err(|error| {
        NativeError::new(
            "statistics_queue_invalid",
            "The anonymous statistics queue is invalid",
        )
        .with_source(error)
    })?;
    Ok(value
        .get("StatisticalEvents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(valid_event)
        .take(MAX_EVENTS)
        .collect())
}

fn valid_event(value: &Value) -> bool {
    value.get("MeasurementGroup").and_then(Value::as_str) == Some("vpn.any.connection")
        && value.get("Event").and_then(Value::as_str) == Some("vpn_disconnection")
        && value.get("Values").and_then(Value::as_object).is_some()
        && value.get("Dimensions").and_then(Value::as_object).is_some()
}

fn protocol_dimension(value: &str) -> &'static str {
    match value {
        "openvpn-udp" => "openvpn_udp",
        "openvpn-tcp" => "openvpn_tcp",
        "protun-udp" | "wireguard-udp" | "wireguard" => "protun_udp",
        "protun-tcp" | "wireguard-tcp" => "protun_tcp",
        "protun-tls" | "wireguard-tls" | "stealth" => "protun_tls",
        _ => "n/a",
    }
}

fn string_dimension(value: &str) -> &str {
    if value.trim().is_empty() {
        "n/a"
    } else {
        value
    }
}

fn queue_error(path: &Path, error: std::io::Error) -> NativeError {
    NativeError::new(
        "statistics_queue_unavailable",
        format!("Unable to read anonymous statistics at {}", path.display()),
    )
    .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_backend::models::{LogicalServer, PhysicalServer};

    #[test]
    fn feedback_state_matches_windows_dimension_contract() {
        let mut feedback = ConnectionFeedbackSession::new(
            ConnectionTarget {
                logical: LogicalServer {
                    id: "logical".into(),
                    name: "CH#1".into(),
                    entry_country: "CH".into(),
                    exit_country: "CH".into(),
                    host_country: None,
                    city: "Zurich".into(),
                    state: String::new(),
                    region: None,
                    domain: "node.example".into(),
                    tier: 2,
                    features: FEATURE_P2P,
                    load: 20,
                    score: 1.0,
                    status: 1,
                    location: Default::default(),
                    servers: Vec::new(),
                    vpn_gateway_id: None,
                    gateway_name: String::new(),
                    extra: Default::default(),
                },
                physical: PhysicalServer {
                    id: "physical".into(),
                    entry_ip: "192.0.2.1".into(),
                    exit_ip: "192.0.2.2".into(),
                    domain: "node.example".into(),
                    status: 1,
                    x25519_public_key: String::new(),
                    label: String::new(),
                    extra: Default::default(),
                },
            },
            "protun-tls".into(),
            "connection_card".into(),
        );
        feedback.update_feedback("positive");
        assert!(feedback.viewed());
        assert!(feedback.sent());
        assert_eq!(feedback.user_feedback, "positive");
        assert_eq!(protocol_dimension("protun-tls"), "protun_tls");
    }
}
