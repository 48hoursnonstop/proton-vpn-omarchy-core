use super::{models::SessionData, NativeError, NativeResult};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey},
    SigningKey,
};
use local_agent_rs::{AgentFeatures, ConnectParams, Listener, State, StatusMessage};
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

const LOCAL_AGENT_TIMEOUT_SECONDS: u64 = 10;

#[derive(Clone, Debug, Default)]
pub struct AgentSnapshot {
    pub connected: bool,
    pub hard_jailed: bool,
    pub reason_code: Option<i32>,
    pub reason: Option<String>,
    pub forwarded_port: Option<u16>,
    pub device_ip: Option<String>,
    pub device_country: Option<String>,
    pub server_ipv4: Option<String>,
    pub server_ipv6: Option<String>,
    pub netshield_malware: Option<u32>,
    pub netshield_ads: Option<u32>,
    pub netshield_trackers: Option<u32>,
}

impl AgentSnapshot {
    pub fn from_status(status: &StatusMessage) -> Self {
        let details = status.connection_details.as_ref();
        Self {
            connected: status.state == State::Connected,
            hard_jailed: status.state == State::HardJailed,
            reason_code: status.reason.as_ref().map(|reason| reason.code),
            reason: status
                .reason
                .as_ref()
                .map(|reason| reason.description.clone()),
            forwarded_port: status
                .features
                .as_ref()
                .and_then(|features| features.forwarded_port),
            device_ip: details.and_then(|details| details.device_ip.clone()),
            device_country: details.and_then(|details| details.device_country.clone()),
            server_ipv4: details.and_then(|details| details.server_ipv4.clone()),
            server_ipv6: details.and_then(|details| details.server_ipv6.clone()),
            netshield_malware: status
                .features_statistics
                .as_ref()
                .and_then(|statistics| statistics.netshield_level.as_ref())
                .and_then(|statistics| statistics.malware),
            netshield_ads: status
                .features_statistics
                .as_ref()
                .and_then(|statistics| statistics.netshield_level.as_ref())
                .and_then(|statistics| statistics.ads),
            netshield_trackers: status
                .features_statistics
                .as_ref()
                .and_then(|statistics| statistics.netshield_level.as_ref())
                .and_then(|statistics| statistics.tracker),
        }
    }
}

#[derive(Debug)]
pub enum AgentUpdate {
    Status(StatusMessage),
    Error(String),
    Stopped,
}

pub struct RunningAgent {
    listener: Listener,
    listen_task: JoinHandle<()>,
}

impl RunningAgent {
    pub async fn request_features(&self, features: AgentFeatures) -> NativeResult<()> {
        self.listener
            .request_features(features, LOCAL_AGENT_TIMEOUT_SECONDS)
            .await
            .map_err(agent_error)
    }

    pub async fn request_statistics(&self) -> NativeResult<()> {
        self.listener
            .request_status(Some(true), LOCAL_AGENT_TIMEOUT_SECONDS)
            .await
            .map_err(agent_error)
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        self.listen_task.abort();
    }
}

pub async fn start(
    domain: &str,
    session: &SessionData,
    features: Option<AgentFeatures>,
) -> NativeResult<(RunningAgent, mpsc::UnboundedReceiver<AgentUpdate>)> {
    if domain.trim().is_empty() {
        return Err(NativeError::new(
            "local_agent_domain_missing",
            "The selected Proton server has no Local Agent domain",
        ));
    }
    let private_key = private_key_pem(session)?;
    let listener = Listener::connect(ConnectParams {
        domain: domain.to_owned(),
        key: private_key.to_string(),
        cert: session.vpn.certificate.certificate.clone(),
        timeout_in_seconds: LOCAL_AGENT_TIMEOUT_SECONDS,
    })
    .await
    .map_err(agent_error)?;

    if let Some(features) = features {
        listener
            .request_features(features, LOCAL_AGENT_TIMEOUT_SECONDS)
            .await
            .map_err(agent_error)?;
    }

    let (updates_tx, updates_rx) = mpsc::unbounded_channel();
    let listen_listener = listener.clone();
    let listen_task = tokio::spawn(async move {
        let callback_tx = updates_tx.clone();
        let result = listen_listener
            .listen(move |update| {
                let update = match update {
                    Ok(status) => AgentUpdate::Status(status),
                    Err(error) => AgentUpdate::Error(error.to_string()),
                };
                callback_tx
                    .send(update)
                    .map_err(|_| local_agent_rs::Error::Default)
            })
            .await;
        if let Err(error) = result {
            let _ = updates_tx.send(AgentUpdate::Error(error.to_string()));
        }
        let _ = updates_tx.send(AgentUpdate::Stopped);
    });

    Ok((
        RunningAgent {
            listener,
            listen_task,
        },
        updates_rx,
    ))
}

pub fn requested_features(
    netshield: u8,
    moderate_nat: bool,
    vpn_accelerator: bool,
    port_forwarding: bool,
    bouncing: &str,
) -> AgentFeatures {
    AgentFeatures {
        netshield_level: Some(netshield),
        randomized_nat: Some(!moderate_nat),
        split_tcp: Some(vpn_accelerator),
        port_forwarding: Some(port_forwarding),
        forwarded_port: None,
        jail: None,
        bouncing: (!bouncing.is_empty()).then(|| bouncing.to_owned()),
    }
}

fn private_key_pem(session: &SessionData) -> NativeResult<Zeroizing<String>> {
    let seed = BASE64
        .decode(session.vpn.secrets.ed25519_privatekey.trim())
        .map_err(|error| {
            NativeError::new(
                "vpn_private_key_invalid",
                "The Proton VPN Ed25519 private key is invalid",
            )
            .with_source(error)
        })?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        NativeError::new(
            "vpn_private_key_invalid",
            "The Proton VPN Ed25519 private key has an invalid length",
        )
    })?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pem = signing_key.to_pkcs8_pem(LineEnding::LF).map_err(|error| {
        NativeError::new(
            "vpn_private_key_invalid",
            "Unable to encode the Proton VPN private key for Local Agent",
        )
        .with_source(error)
    })?;
    Ok(Zeroizing::new(pem.to_string()))
}

fn agent_error(error: impl std::fmt::Display) -> NativeError {
    NativeError::new(
        "local_agent_failed",
        "The encrypted Proton Local Agent channel failed",
    )
    .with_source(error)
    .retryable(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_mapping_matches_official_linux_client() {
        let features = requested_features(2, true, false, true, "1");
        assert_eq!(features.netshield_level, Some(2));
        assert_eq!(features.randomized_nat, Some(false));
        assert_eq!(features.split_tcp, Some(false));
        assert_eq!(features.port_forwarding, Some(true));
        assert_eq!(features.bouncing.as_deref(), Some("1"));
    }
}
