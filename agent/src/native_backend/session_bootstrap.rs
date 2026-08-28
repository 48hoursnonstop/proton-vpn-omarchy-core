use super::{
    api::{ApiSession, ProtonApi},
    models::{
        ClientConfig, NativeSettings, ServerCatalog, SessionData, VpnCertificate, VpnLocation,
        VpnSecrets, VpnSessionData,
    },
    NativeError, NativeResult,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePublicKey},
    SigningKey,
};
use rand::Rng;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::pem::parse_x509_pem;

pub struct BootstrapData {
    pub session: SessionData,
    pub catalog: ServerCatalog,
    pub catalog_json: Value,
    pub client_config: ClientConfig,
    pub client_config_json: Value,
}

pub async fn fetch(
    api: &ProtonApi,
    auth: ApiSession,
    settings: &NativeSettings,
) -> NativeResult<BootstrapData> {
    let seed = rand::rng().random::<[u8; 32]>();
    let signing_key = SigningKey::from_bytes(&seed);
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| {
            NativeError::new(
                "vpn_key_generation_failed",
                "Unable to encode the Proton VPN public key",
            )
            .with_source(error)
        })?;
    let certificate_request = json!({
        "ClientPublicKey": public_pem,
        "Duration": "10080 min",
        "Features": certificate_features(settings),
    });

    let (vpn_info, certificate_value, location_value, mut client_config_json) = tokio::try_join!(
        api.get("/vpn/v2", &auth),
        api.post("/vpn/v1/certificate", certificate_request, &auth),
        api.get("/vpn/v1/location", &auth),
        api.get("/vpn/v2/clientconfig", &auth),
    )?;

    let certificate: VpnCertificate = decode_api_value(certificate_value, "VPN certificate")?;
    verify_certificate_key(
        &certificate.certificate,
        signing_key.verifying_key().as_bytes(),
    )?;
    let location: VpnLocation = decode_api_value(location_value, "VPN location")?;
    let now = unix_time()?;
    insert_number(
        &mut client_config_json,
        "ExpirationTime",
        now + 3.0 * 60.0 * 60.0,
    )?;
    let client_config: ClientConfig =
        decode_api_value(client_config_json.clone(), "VPN client configuration")?;

    let tier = vpn_info
        .get("VPN")
        .and_then(Value::as_object)
        .and_then(|vpn| vpn.get("MaxTier"))
        .and_then(Value::as_u64)
        .and_then(|tier| u8::try_from(tier).ok())
        .ok_or_else(|| {
            NativeError::new(
                "api_response_invalid",
                "Proton VPN account response is missing MaxTier",
            )
        })?;
    let mut catalog_json = api
        .get(
            "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true",
            &auth,
        )
        .await?;
    insert_number(&mut catalog_json, "ExpirationTime", now + 3.0 * 60.0 * 60.0)?;
    insert_number(&mut catalog_json, "LoadsExpirationTime", now + 15.0 * 60.0)?;
    insert_number(&mut catalog_json, "MaxTier", f64::from(tier))?;
    let catalog: ServerCatalog = decode_api_value(catalog_json.clone(), "VPN server catalog")?;

    let session = SessionData {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        scopes: auth.scopes,
        account_name: auth.account_name,
        environment: "prod".into(),
        vpn: VpnSessionData {
            vpninfo: without_api_code(vpn_info),
            certificate,
            secrets: VpnSecrets {
                ed25519_privatekey: BASE64.encode(seed),
            },
            location,
        },
        extra: serde_json::Map::from_iter([(
            "LastUseData".into(),
            json!({
                "2FA": null,
                "appversion": "linux-vpn-gui@5.5.11",
                "user_agent": "ProtonVPN/0.8.0 (Linux; Omarchy/4)",
                "refresh_revision": 0,
            }),
        )]),
    };
    Ok(BootstrapData {
        session,
        catalog,
        catalog_json,
        client_config,
        client_config_json: without_api_code(client_config_json),
    })
}

pub fn stored_api_session(session: &SessionData) -> ApiSession {
    ApiSession {
        uid: session.uid.clone(),
        access_token: session.access_token.clone(),
        refresh_token: session.refresh_token.clone(),
        scopes: session.scopes.clone(),
        account_name: session.account_name.clone(),
        two_factor: session
            .extra
            .get("LastUseData")
            .and_then(|value| value.get("2FA"))
            .filter(|value| !value.is_null())
            .cloned(),
    }
}

pub async fn refresh_certificate(
    api: &ProtonApi,
    session: &SessionData,
    settings: &NativeSettings,
) -> NativeResult<VpnCertificate> {
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
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| {
            NativeError::new(
                "vpn_key_generation_failed",
                "Unable to encode the Proton VPN public key",
            )
            .with_source(error)
        })?;
    let api_session = stored_api_session(session);
    let value = api
        .post(
            "/vpn/v1/certificate",
            json!({
                "ClientPublicKey": public_pem,
                "Duration": "10080 min",
                "Features": certificate_features(settings),
            }),
            &api_session,
        )
        .await?;
    let certificate: VpnCertificate = decode_api_value(value, "VPN certificate")?;
    verify_certificate_key(
        &certificate.certificate,
        signing_key.verifying_key().as_bytes(),
    )?;
    Ok(certificate)
}

fn certificate_features(settings: &NativeSettings) -> Value {
    let mut features = serde_json::Map::new();
    if !settings.features.moderate_nat {
        features.insert("RandomNAT".into(), Value::Bool(false));
    }
    if !settings.features.vpn_accelerator {
        features.insert("SplitTCP".into(), Value::Bool(false));
    }
    if settings.features.port_forwarding {
        features.insert("PortForwarding".into(), Value::Bool(true));
    }
    if settings.features.netshield != 0 {
        features.insert(
            "NetShieldLevel".into(),
            Value::Number(settings.features.netshield.into()),
        );
    }
    Value::Object(features)
}

fn verify_certificate_key(certificate_pem: &str, expected: &[u8; 32]) -> NativeResult<()> {
    let (_, pem) = parse_x509_pem(certificate_pem.as_bytes()).map_err(|error| {
        NativeError::new(
            "vpn_certificate_invalid",
            "Unable to parse the Proton VPN client certificate",
        )
        .with_source(error)
    })?;
    let certificate = pem.parse_x509().map_err(|error| {
        NativeError::new(
            "vpn_certificate_invalid",
            "Unable to validate the Proton VPN client certificate",
        )
        .with_source(error)
    })?;
    let public_key = certificate.public_key().subject_public_key.data.as_ref();
    if public_key != expected {
        return Err(NativeError::new(
            "vpn_certificate_key_mismatch",
            "Proton returned a VPN certificate for a different client key",
        ));
    }
    Ok(())
}

fn decode_api_value<T: serde::de::DeserializeOwned>(value: Value, name: &str) -> NativeResult<T> {
    serde_json::from_value(without_api_code(value)).map_err(|error| {
        NativeError::new(
            "api_response_invalid",
            format!("Proton returned an invalid {name}"),
        )
        .with_source(error)
    })
}

fn without_api_code(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("Code");
    }
    value
}

fn insert_number(value: &mut Value, key: &str, number: f64) -> NativeResult<()> {
    let object = value.as_object_mut().ok_or_else(|| {
        NativeError::new(
            "api_response_invalid",
            "Proton returned an API response that is not an object",
        )
    })?;
    object.insert(
        key.into(),
        serde_json::Number::from_f64(number)
            .map(Value::Number)
            .ok_or_else(|| NativeError::new("clock_invalid", "System clock is invalid"))?,
    );
    Ok(())
}

fn unix_time() -> NativeResult<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|error| {
            NativeError::new("clock_invalid", "System clock is before the Unix epoch")
                .with_source(error)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_features_match_official_linux_contract() {
        let mut settings = NativeSettings::default();
        settings.features.netshield = 2;
        settings.features.port_forwarding = true;
        let features = certificate_features(&settings);
        assert_eq!(features["NetShieldLevel"], 2);
        assert_eq!(features["PortForwarding"], true);
        assert_eq!(features["RandomNAT"], false);
    }
}
