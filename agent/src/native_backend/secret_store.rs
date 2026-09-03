use super::{models::SessionData, NativeError, NativeResult};
use data_encoding::BASE32_NOPAD;
use keyring::Entry;

const SERVICE: &str = "Proton";
const ACCOUNT_INDEX: &str = "proton-sso-accounts";
const MAX_ACCOUNTS: usize = 32;
const MAX_ACCOUNT_NAME_BYTES: usize = 256;
const MAX_SESSION_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct SecretStore;

impl SecretStore {
    pub fn load_default(&self) -> NativeResult<Option<SessionData>> {
        let accounts = match entry(ACCOUNT_INDEX)?.get_password() {
            // A corrupt legacy index must not prevent the agent from starting;
            // the next successful login rewrites a valid bounded index.
            Ok(value) => serde_json::from_str::<Vec<String>>(&value).unwrap_or_default(),
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => return Err(keyring_error("read account index", error)),
        };

        for account in accounts
            .into_iter()
            .filter(|account| valid_account_name(account))
            .take(MAX_ACCOUNTS)
        {
            let key = account_key(&account);
            let raw = match entry(&key)?.get_password() {
                Ok(value) => value,
                Err(keyring::Error::NoEntry) => continue,
                Err(error) => return Err(keyring_error("read Proton session", error)),
            };
            if raw.len() > MAX_SESSION_BYTES {
                continue;
            }
            let Some(session) = decode_session(&raw) else {
                continue;
            };
            if session.account_name == account && session.is_authenticated() {
                return Ok(Some(session));
            }
        }

        Ok(None)
    }

    pub fn save(&self, session: &SessionData) -> NativeResult<()> {
        if !valid_account_name(&session.account_name) {
            return Err(NativeError::new(
                "session_invalid",
                format!(
                    "A Proton account name must contain between 1 and {MAX_ACCOUNT_NAME_BYTES} bytes"
                ),
            ));
        }

        let mut accounts = match entry(ACCOUNT_INDEX)?.get_password() {
            Ok(value) => serde_json::from_str::<Vec<String>>(&value).unwrap_or_default(),
            Err(keyring::Error::NoEntry) => Vec::new(),
            Err(error) => return Err(keyring_error("read account index", error)),
        };
        accounts.retain(|account| account != &session.account_name && valid_account_name(account));
        accounts.truncate(MAX_ACCOUNTS - 1);
        accounts.insert(0, session.account_name.clone());

        let raw = serde_json::to_string(session).map_err(|error| {
            NativeError::new("session_invalid", "Unable to serialize the Proton session")
                .with_source(error)
        })?;
        if raw.len() > MAX_SESSION_BYTES {
            return Err(NativeError::new(
                "session_invalid",
                "The Proton session exceeds the storage size limit",
            ));
        }
        entry(&account_key(&session.account_name))?
            .set_password(&raw)
            .map_err(|error| keyring_error("store Proton session", error))?;
        entry(ACCOUNT_INDEX)?
            .set_password(&serde_json::to_string(&accounts).unwrap_or_else(|_| "[]".into()))
            .map_err(|error| keyring_error("store account index", error))?;
        Ok(())
    }

    pub fn delete(&self, account_name: &str) -> NativeResult<()> {
        match entry(&account_key(account_name))?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(keyring_error("delete Proton session", error)),
        }

        let mut accounts = match entry(ACCOUNT_INDEX)?.get_password() {
            Ok(value) => serde_json::from_str::<Vec<String>>(&value).unwrap_or_default(),
            Err(keyring::Error::NoEntry) => Vec::new(),
            Err(error) => return Err(keyring_error("read account index", error)),
        };
        accounts.retain(|account| account != account_name && valid_account_name(account));
        accounts.truncate(MAX_ACCOUNTS);
        entry(ACCOUNT_INDEX)?
            .set_password(&serde_json::to_string(&accounts).unwrap_or_else(|_| "[]".into()))
            .map_err(|error| keyring_error("store account index", error))?;
        Ok(())
    }
}

fn decode_session(raw: &str) -> Option<SessionData> {
    if let Ok(session) = serde_json::from_str(raw) {
        return Some(session);
    }

    // Omarchy's default passwordless GNOME Keyring stores secrets in a
    // GKeyFile. gnome-keyring writes textual secrets with
    // g_key_file_set_value(), but reads them with g_key_file_get_string().
    // Consequently, JSON escapes such as `\n` in Proton's PEM material are
    // returned as literal control characters after the daemon restarts. Our
    // session format is compact JSON, so it contains no formatting control
    // characters; escaping them again recovers only values changed by that
    // round trip. Keep the recovered representation in memory rather than
    // introducing a private storage envelope: these entries intentionally use
    // Proton SSO's shared key names and JSON contract.
    let repaired = escape_legacy_control_characters(raw);
    serde_json::from_str(&repaired).ok()
}

fn escape_legacy_control_characters(raw: &str) -> String {
    let mut repaired = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '\u{08}' => repaired.push_str("\\b"),
            '\u{0c}' => repaired.push_str("\\f"),
            '\n' => repaired.push_str("\\n"),
            '\r' => repaired.push_str("\\r"),
            '\t' => repaired.push_str("\\t"),
            character if character <= '\u{1f}' => {
                use std::fmt::Write;
                let _ = write!(repaired, "\\u{:04x}", u32::from(character));
            }
            character => repaired.push(character),
        }
    }
    repaired
}

fn valid_account_name(account_name: &str) -> bool {
    let trimmed = account_name.trim();
    !trimmed.is_empty()
        && account_name.len() <= MAX_ACCOUNT_NAME_BYTES
        && !account_name.contains('\0')
}

fn entry(username: &str) -> NativeResult<Entry> {
    Entry::new(SERVICE, username).map_err(|error| keyring_error("open Secret Service", error))
}

fn account_key(account_name: &str) -> String {
    let encoded = BASE32_NOPAD
        .encode(account_name.as_bytes())
        .to_ascii_lowercase();
    format!("proton-sso-account-{encoded}")
}

fn keyring_error(action: &str, error: keyring::Error) -> NativeError {
    NativeError::new(
        "secret_service_error",
        format!("Unable to {action} using the desktop Secret Service"),
    )
    .with_source(error)
    .retryable(true)
}

#[cfg(test)]
mod tests {
    use super::{account_key, decode_session, valid_account_name, MAX_ACCOUNT_NAME_BYTES};
    use crate::native_backend::models::{
        SessionData, VpnCertificate, VpnLocation, VpnSecrets, VpnSessionData,
    };
    use serde_json::json;

    fn session() -> SessionData {
        SessionData {
            uid: "uid".into(),
            access_token: "access-token".into(),
            refresh_token: "refresh-token".into(),
            scopes: vec!["vpn".into()],
            account_name: "test@example.test".into(),
            credentialless: false,
            environment: "prod".into(),
            vpn: VpnSessionData {
                vpninfo: json!({"VPN": {"MaxTier": 2}}),
                certificate: VpnCertificate {
                    certificate:
                        "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n-----END CERTIFICATE-----\n".into(),
                    client_key: "-----BEGIN PUBLIC KEY-----\nRkFLRQ==\n-----END PUBLIC KEY-----\n"
                        .into(),
                    client_key_fingerprint: "fingerprint".into(),
                    expiration_time: 2,
                    refresh_time: 1,
                    server_public_key: String::new(),
                    server_public_key_mode: "EC".into(),
                    extra: serde_json::Map::new(),
                },
                secrets: VpnSecrets {
                    ed25519_privatekey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                },
                location: VpnLocation::default(),
            },
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn account_key_matches_proton_sso_base32_contract() {
        assert_eq!(account_key("test"), "proton-sso-account-orsxg5a");
    }

    #[test]
    fn account_names_are_bounded_before_becoming_keyring_keys() {
        assert!(valid_account_name("test@example.test"));
        assert!(!valid_account_name("   "));
        assert!(!valid_account_name("bad\0name"));
        assert!(!valid_account_name(&"x".repeat(MAX_ACCOUNT_NAME_BYTES + 1)));
    }

    #[test]
    fn proton_sso_json_session_remains_compatible() {
        let raw = serde_json::to_string(&session()).expect("serialize session");
        let decoded = decode_session(&raw).expect("decode session");
        assert_eq!(decoded.account_name, "test@example.test");
        assert!(decoded.vpn.certificate.certificate.contains("\nRkFLRQ==\n"));
    }

    #[test]
    fn passwordless_gnome_keyring_round_trip_is_recovered() {
        let raw = serde_json::to_string(&session()).expect("serialize session");
        let damaged = raw.replace("\\n", "\n");
        assert!(serde_json::from_str::<SessionData>(&damaged).is_err());

        let decoded = decode_session(&damaged).expect("repair session");
        assert_eq!(decoded.account_name, "test@example.test");
        assert_eq!(
            decoded.vpn.certificate.certificate,
            session().vpn.certificate.certificate
        );
    }

    #[test]
    fn malformed_sessions_are_rejected() {
        assert!(decode_session("not a session").is_none());
    }
}
