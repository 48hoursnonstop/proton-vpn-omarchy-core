use super::{models::SessionData, NativeError, NativeResult};
use data_encoding::BASE32_NOPAD;
use keyring::Entry;

const SERVICE: &str = "Proton";
const ACCOUNT_INDEX: &str = "proton-sso-accounts";

#[derive(Clone, Debug, Default)]
pub struct SecretStore;

impl SecretStore {
    pub fn load_default(&self) -> NativeResult<Option<SessionData>> {
        let accounts = match entry(ACCOUNT_INDEX)?.get_password() {
            Ok(value) => serde_json::from_str::<Vec<String>>(&value).map_err(|error| {
                NativeError::new("session_invalid", "The Proton account index is invalid")
                    .with_source(error)
            })?,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => return Err(keyring_error("read account index", error)),
        };

        for account in accounts {
            let key = account_key(&account);
            let raw = match entry(&key)?.get_password() {
                Ok(value) => value,
                Err(keyring::Error::NoEntry) => continue,
                Err(error) => return Err(keyring_error("read Proton session", error)),
            };
            let session: SessionData = serde_json::from_str(&raw).map_err(|error| {
                NativeError::new("session_invalid", "The stored Proton session is invalid")
                    .with_source(error)
            })?;
            if session.account_name == account && session.is_authenticated() {
                return Ok(Some(session));
            }
        }

        Ok(None)
    }

    pub fn save(&self, session: &SessionData) -> NativeResult<()> {
        if session.account_name.trim().is_empty() {
            return Err(NativeError::new(
                "session_invalid",
                "A Proton session cannot be stored without an account name",
            ));
        }

        let mut accounts = match entry(ACCOUNT_INDEX)?.get_password() {
            Ok(value) => serde_json::from_str::<Vec<String>>(&value).unwrap_or_default(),
            Err(keyring::Error::NoEntry) => Vec::new(),
            Err(error) => return Err(keyring_error("read account index", error)),
        };
        accounts.retain(|account| account != &session.account_name);
        accounts.insert(0, session.account_name.clone());

        let raw = serde_json::to_string(session).map_err(|error| {
            NativeError::new("session_invalid", "Unable to serialize the Proton session")
                .with_source(error)
        })?;
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
        accounts.retain(|account| account != account_name);
        entry(ACCOUNT_INDEX)?
            .set_password(&serde_json::to_string(&accounts).unwrap_or_else(|_| "[]".into()))
            .map_err(|error| keyring_error("store account index", error))?;
        Ok(())
    }
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
    use super::account_key;

    #[test]
    fn account_key_matches_proton_sso_base32_contract() {
        assert_eq!(account_key("test"), "proton-sso-account-orsxg5a");
    }
}
