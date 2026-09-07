use super::{models::SessionData, NativeError, NativeResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use data_encoding::BASE32_NOPAD;
use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE: &str = "Proton VPN for Omarchy";
const LEGACY_SERVICE: &str = "Proton";
const ACCOUNT_INDEX: &str = "accounts-v1";
const LEGACY_ACCOUNT_INDEX: &str = "proton-sso-accounts";
const LEGACY_IMPORT_MARKER: &str = "legacy-import-v1";
const LEGACY_IMPORT_COMPLETE: &str = "complete";
const SESSION_ENVELOPE_PREFIX: &str = "pvom1:";
const INDEX_ENVELOPE_PREFIX: &str = "pvom-index1:";
const MAX_ACCOUNTS: usize = 32;
const MAX_ACCOUNT_NAME_BYTES: usize = 256;
const MAX_SESSION_BYTES: usize = 1024 * 1024;
const MAX_SESSION_ENVELOPE_BYTES: usize = 1400 * 1024;
const MAX_INDEX_BYTES: usize = 16 * 1024;
const MAX_INDEX_ENVELOPE_BYTES: usize = 24 * 1024;

#[derive(Clone, Debug, Default)]
pub struct SecretStore;

impl SecretStore {
    pub fn load_default(&self) -> NativeResult<Option<SessionData>> {
        if let Some(session) = load_private_default()? {
            return Ok(Some(session));
        }

        if legacy_import_complete()? {
            return Ok(None);
        }

        let Some(session) = load_legacy_default()? else {
            return Ok(None);
        };

        // Import once, but never mutate the shared Proton SSO entry. From this
        // point forward the Omarchy agent owns a format that cannot be
        // reinterpreted by GNOME Keyring's passwordless GKeyFile backend.
        self.save(&session)?;
        Ok(Some(session))
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

        let mut accounts = load_private_accounts()?;
        accounts.retain(|account| account != &session.account_name && valid_account_name(account));
        accounts.truncate(MAX_ACCOUNTS - 1);
        accounts.insert(0, session.account_name.clone());

        let raw = encode_session(session)?;
        private_entry(&private_account_key(&session.account_name))?
            .set_password(raw.as_str())
            .map_err(|error| keyring_error("store Proton VPN for Omarchy session", error))?;

        store_private_accounts(&accounts)?;
        mark_legacy_import_complete()?;
        Ok(())
    }

    pub fn delete(&self, account_name: &str) -> NativeResult<()> {
        match private_entry(&private_account_key(account_name))?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(error) => {
                return Err(keyring_error(
                    "delete Proton VPN for Omarchy session",
                    error,
                ))
            }
        }

        let mut accounts = load_private_accounts()?;
        accounts.retain(|account| account != account_name && valid_account_name(account));
        accounts.truncate(MAX_ACCOUNTS);
        store_private_accounts(&accounts)?;

        // A deliberate sign-out must never cause a previously imported legacy
        // session to be silently imported again on the next agent start.
        mark_legacy_import_complete()?;
        Ok(())
    }
}

fn load_private_default() -> NativeResult<Option<SessionData>> {
    for account in load_private_accounts()?
        .into_iter()
        .filter(|account| valid_account_name(account))
        .take(MAX_ACCOUNTS)
    {
        let raw = match private_entry(&private_account_key(&account))?.get_password() {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => {
                return Err(keyring_error(
                    "read Proton VPN for Omarchy session",
                    error,
                ))
            }
        };

        let Some(session) = decode_session(&raw) else {
            continue;
        };
        if session.account_name == account && session.is_authenticated() {
            return Ok(Some(session));
        }
    }

    Ok(None)
}

fn load_legacy_default() -> NativeResult<Option<SessionData>> {
    let accounts = match legacy_entry(LEGACY_ACCOUNT_INDEX)?.get_password() {
        // A corrupt legacy index must not prevent the agent from starting.
        Ok(value) => serde_json::from_str::<Vec<String>>(&value).unwrap_or_default(),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(error) => return Err(keyring_error("read legacy Proton account index", error)),
    };

    for account in accounts
        .into_iter()
        .filter(|account| valid_account_name(account))
        .take(MAX_ACCOUNTS)
    {
        let raw = match legacy_entry(&legacy_account_key(&account))?.get_password() {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => return Err(keyring_error("read legacy Proton session", error)),
        };
        if raw.len() > MAX_SESSION_BYTES {
            continue;
        }

        let Some(session) = decode_legacy_session(&raw) else {
            continue;
        };
        if session.account_name == account && session.is_authenticated() {
            return Ok(Some(session));
        }
    }

    Ok(None)
}

fn load_private_accounts() -> NativeResult<Vec<String>> {
    let raw = match private_entry(ACCOUNT_INDEX)?.get_password() {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => return Ok(Vec::new()),
        Err(error) => return Err(keyring_error("read private account index", error)),
    };

    Ok(decode_account_index(&raw).unwrap_or_default())
}

fn store_private_accounts(accounts: &[String]) -> NativeResult<()> {
    let encoded = encode_account_index(accounts)?;
    private_entry(ACCOUNT_INDEX)?
        .set_password(encoded.as_str())
        .map_err(|error| keyring_error("store private account index", error))
}

fn legacy_import_complete() -> NativeResult<bool> {
    match private_entry(LEGACY_IMPORT_MARKER)?.get_password() {
        Ok(value) => Ok(value == LEGACY_IMPORT_COMPLETE),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(keyring_error("read legacy import marker", error)),
    }
}

fn mark_legacy_import_complete() -> NativeResult<()> {
    private_entry(LEGACY_IMPORT_MARKER)?
        .set_password(LEGACY_IMPORT_COMPLETE)
        .map_err(|error| keyring_error("store legacy import marker", error))
}

fn encode_session(session: &SessionData) -> NativeResult<Zeroizing<String>> {
    let json = Zeroizing::new(serde_json::to_vec(session).map_err(|error| {
        NativeError::new("session_invalid", "Unable to serialize the Proton session")
            .with_source(error)
    })?);

    if json.len() > MAX_SESSION_BYTES {
        return Err(NativeError::new(
            "session_invalid",
            "The Proton session exceeds the storage size limit",
        ));
    }

    let mut encoded = Zeroizing::new(String::with_capacity(
        SESSION_ENVELOPE_PREFIX.len() + json.len().saturating_mul(4).div_ceil(3),
    ));
    encoded.push_str(SESSION_ENVELOPE_PREFIX);
    URL_SAFE_NO_PAD.encode_string(json.as_slice(), &mut encoded);

    if encoded.len() > MAX_SESSION_ENVELOPE_BYTES {
        return Err(NativeError::new(
            "session_invalid",
            "The encoded Proton session exceeds the storage size limit",
        ));
    }

    Ok(encoded)
}

fn decode_session(raw: &str) -> Option<SessionData> {
    if raw.len() > MAX_SESSION_ENVELOPE_BYTES {
        return None;
    }

    let encoded = raw.strip_prefix(SESSION_ENVELOPE_PREFIX)?;
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).ok()?);
    if decoded.len() > MAX_SESSION_BYTES {
        return None;
    }

    serde_json::from_slice(decoded.as_slice()).ok()
}

fn encode_account_index(accounts: &[String]) -> NativeResult<Zeroizing<String>> {
    let json = Zeroizing::new(serde_json::to_vec(accounts).map_err(|error| {
        NativeError::new("session_invalid", "Unable to serialize the account index")
            .with_source(error)
    })?);

    if json.len() > MAX_INDEX_BYTES {
        return Err(NativeError::new(
            "session_invalid",
            "The Proton account index exceeds the storage size limit",
        ));
    }

    let mut encoded = Zeroizing::new(String::with_capacity(
        INDEX_ENVELOPE_PREFIX.len() + json.len().saturating_mul(4).div_ceil(3),
    ));
    encoded.push_str(INDEX_ENVELOPE_PREFIX);
    URL_SAFE_NO_PAD.encode_string(json.as_slice(), &mut encoded);

    if encoded.len() > MAX_INDEX_ENVELOPE_BYTES {
        return Err(NativeError::new(
            "session_invalid",
            "The encoded Proton account index exceeds the storage size limit",
        ));
    }

    Ok(encoded)
}

fn decode_account_index(raw: &str) -> Option<Vec<String>> {
    if raw.len() > MAX_INDEX_ENVELOPE_BYTES {
        return None;
    }

    let encoded = raw.strip_prefix(INDEX_ENVELOPE_PREFIX)?;
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).ok()?);
    if decoded.len() > MAX_INDEX_BYTES {
        return None;
    }

    serde_json::from_slice(decoded.as_slice()).ok()
}

fn decode_legacy_session(raw: &str) -> Option<SessionData> {
    if let Ok(session) = serde_json::from_str(raw) {
        return Some(session);
    }

    // Releases <= 0.9.5 wrote Proton's compact JSON directly to the shared
    // passwordless GNOME Keyring. The GKeyFile backend can turn JSON escapes
    // such as `\n` in PEM material into literal control characters after a
    // daemon restart. Recover that representation only while importing the
    // legacy entry. New writes never use this format.
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
        && !account_name.chars().any(char::is_control)
}

fn private_entry(username: &str) -> NativeResult<Entry> {
    Entry::new(SERVICE, username).map_err(|error| keyring_error("open Secret Service", error))
}

fn legacy_entry(username: &str) -> NativeResult<Entry> {
    Entry::new(LEGACY_SERVICE, username)
        .map_err(|error| keyring_error("open legacy Secret Service entry", error))
}

fn private_account_key(account_name: &str) -> String {
    let encoded = BASE32_NOPAD
        .encode(account_name.as_bytes())
        .to_ascii_lowercase();
    format!("account-v1-{encoded}")
}

fn legacy_account_key(account_name: &str) -> String {
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
    use super::{
        decode_account_index, decode_legacy_session, decode_session, encode_account_index,
        encode_session, legacy_account_key, private_account_key, valid_account_name,
        INDEX_ENVELOPE_PREFIX, MAX_ACCOUNT_NAME_BYTES, SESSION_ENVELOPE_PREFIX,
    };
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
    fn private_and_legacy_account_keys_are_namespaced() {
        assert_eq!(private_account_key("test"), "account-v1-orsxg5a");
        assert_eq!(
            legacy_account_key("test"),
            "proton-sso-account-orsxg5a"
        );
    }

    #[test]
    fn account_names_are_bounded_before_becoming_keyring_keys() {
        assert!(valid_account_name("test@example.test"));
        assert!(!valid_account_name("   "));
        assert!(!valid_account_name("bad\0name"));
        assert!(!valid_account_name("bad\nname"));
        assert!(!valid_account_name(&"x".repeat(MAX_ACCOUNT_NAME_BYTES + 1)));
    }

    #[test]
    fn private_session_round_trips_through_ascii_envelope() {
        let encoded = encode_session(&session()).expect("encode session");
        assert!(encoded.starts_with(SESSION_ENVELOPE_PREFIX));
        assert!(encoded
            .strip_prefix(SESSION_ENVELOPE_PREFIX)
            .expect("prefix")
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || character == '-'
                || character == '_'));

        let decoded = decode_session(encoded.as_str()).expect("decode session");
        assert_eq!(decoded.account_name, "test@example.test");
        assert_eq!(
            decoded.vpn.certificate.certificate,
            session().vpn.certificate.certificate
        );
    }

    #[test]
    fn private_account_index_round_trips_through_ascii_envelope() {
        let accounts = vec!["test@example.test".to_string(), "second".to_string()];
        let encoded = encode_account_index(&accounts).expect("encode index");
        assert!(encoded.starts_with(INDEX_ENVELOPE_PREFIX));
        assert!(encoded
            .strip_prefix(INDEX_ENVELOPE_PREFIX)
            .expect("prefix")
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || character == '-'
                || character == '_'));
        assert_eq!(
            decode_account_index(encoded.as_str()).expect("decode index"),
            accounts
        );
    }

    #[test]
    fn private_decoder_rejects_legacy_raw_json() {
        let raw = serde_json::to_string(&session()).expect("serialize session");
        assert!(decode_session(&raw).is_none());
    }

    #[test]
    fn legacy_proton_sso_json_session_remains_importable() {
        let raw = serde_json::to_string(&session()).expect("serialize session");
        let decoded = decode_legacy_session(&raw).expect("decode legacy session");
        assert_eq!(decoded.account_name, "test@example.test");
        assert!(decoded.vpn.certificate.certificate.contains("\nRkFLRQ==\n"));
    }

    #[test]
    fn legacy_passwordless_gnome_keyring_round_trip_is_recovered() {
        let raw = serde_json::to_string(&session()).expect("serialize session");
        let damaged = raw.replace("\\n", "\n");
        assert!(serde_json::from_str::<SessionData>(&damaged).is_err());

        let decoded = decode_legacy_session(&damaged).expect("repair legacy session");
        assert_eq!(decoded.account_name, "test@example.test");
        assert_eq!(
            decoded.vpn.certificate.certificate,
            session().vpn.certificate.certificate
        );
    }

    #[test]
    fn malformed_sessions_are_rejected() {
        assert!(decode_session("not a session").is_none());
        assert!(decode_legacy_session("not a session").is_none());
    }
}
