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
            let Ok(session) = serde_json::from_str::<SessionData>(&raw) else {
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
    use super::{account_key, valid_account_name, MAX_ACCOUNT_NAME_BYTES};

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
}
