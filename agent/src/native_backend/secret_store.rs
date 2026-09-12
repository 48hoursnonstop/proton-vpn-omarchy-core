use super::{models::SessionData, NativeError, NativeResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use data_encoding::BASE32_NOPAD;
use dbus_secret_service::{EncryptionType, SecretService as DesktopSecretService};
use keyring::Entry;
use std::collections::HashMap;
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
        load_default(self)
    }

    pub fn save(&self, session: &SessionData) -> NativeResult<()> {
        save(self, session)
    }

    pub fn delete(&self, account_name: &str) -> NativeResult<()> {
        delete(self, account_name)
    }
}

// Mutation is deliberately limited to our private namespace. Keeping this
// boundary injectable lets failure/restart tests exercise the full lifecycle
// without replacing keyring's process-global builder or touching desktop data.
trait SecretService {
    fn read(&self, service: &str, username: &str) -> keyring::Result<Zeroizing<String>>;
    fn write_private(&self, username: &str, value: &str) -> keyring::Result<()>;
    fn delete_private(&self, username: &str) -> keyring::Result<()>;
}

impl SecretService for SecretStore {
    fn read(&self, service: &str, username: &str) -> keyring::Result<Zeroizing<String>> {
        // keyring::Entry::get_password automatically prompts to unlock locked
        // items. Startup/retry reads must never launch an unlock prompt. Match
        // keyring 3's target-aware search and default-collection legacy fallback,
        // A zero prompt timeout still permits silent passwordless unlocking,
        // but never shows a password dialog or waits for user input.
        let desktop = DesktopSecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
            .map_err(storage_access_error)?;
        let attributes = HashMap::from([("service", service), ("username", username)]);
        let mut targeted = attributes.clone();
        targeted.insert("target", "default");
        let found = desktop
            .search_items(targeted)
            .map_err(storage_access_error)?;
        let found: Vec<_> = found.unlocked.into_iter().chain(found.locked).collect();
        let collection;
        let items = if found.is_empty() {
            collection = match desktop.get_default_collection() {
                Ok(collection) => collection,
                // A reachable service with no default collection is a fresh
                // install. Do not create a collection just to check for a login.
                Err(dbus_secret_service::Error::NoResult) => return Err(keyring::Error::NoEntry),
                Err(error) => return Err(storage_access_error(error)),
            };
            collection.ensure_unlocked().map_err(storage_access_error)?;
            collection
                .search_items(attributes)
                .map_err(storage_access_error)?
        } else {
            found
        };
        if items.is_empty() {
            return Err(keyring::Error::NoEntry);
        }
        if items.len() > 1 {
            // Preserve ambiguity rather than choosing or deleting an entry.
            let credentials = items
                .iter()
                .map(|item| {
                    keyring::secret_service::SsCredential::new_from_item(item).map(|credential| {
                        Box::new(credential) as Box<keyring::credential::Credential>
                    })
                })
                .collect::<keyring::Result<Vec<_>>>()?;
            return Err(keyring::Error::Ambiguous(credentials));
        }
        items[0].ensure_unlocked().map_err(storage_access_error)?;
        keyring::secret_service::get_item_password(&items[0]).map(Zeroizing::new)
    }

    fn write_private(&self, username: &str, value: &str) -> keyring::Result<()> {
        Entry::new(SERVICE, username)?.set_password(value)
    }

    fn delete_private(&self, username: &str) -> keyring::Result<()> {
        Entry::new(SERVICE, username)?.delete_credential()
    }
}

fn storage_access_error(error: dbus_secret_service::Error) -> keyring::Error {
    keyring::Error::NoStorageAccess(Box::new(error))
}

fn load_default(store: &impl SecretService) -> NativeResult<Option<SessionData>> {
    if let Some(session) = load_private_default(store)? {
        return Ok(Some(session));
    }

    if legacy_import_complete(store)? {
        return Ok(None);
    }

    let Some(session) = load_legacy_default(store)? else {
        return Ok(None);
    };

    // Import once, but never mutate the shared Proton SSO entry. From this
    // point forward the Omarchy agent owns a format that cannot be
    // reinterpreted by GNOME Keyring's passwordless GKeyFile backend.
    save(store, &session)?;
    Ok(Some(session))
}

fn save(store: &impl SecretService, session: &SessionData) -> NativeResult<()> {
    validate_account_name(&session.account_name)?;
    if !session.is_authenticated() {
        return Err(NativeError::new(
            "session_invalid",
            "The Proton session is missing authentication fields",
        ));
    }

    let previous = load_private_accounts(store)?;
    let accounts = normalized_accounts(
        std::iter::once(session.account_name.clone()).chain(previous.iter().cloned()),
    );

    // Validate both payloads before the first mutation. A token refresh normally
    // changes only the session, so avoid rewriting unchanged index/marker items.
    let raw = encode_session(session)?;
    let index = encode_account_index(&accounts)?;
    store
        .write_private(&private_account_key(&session.account_name), raw.as_str())
        .map_err(|error| keyring_error("store Proton VPN for Omarchy session", error))?;
    if accounts != previous {
        store_private_accounts(store, &index)?;
    }
    mark_legacy_import_complete(store)?;
    Ok(())
}

fn delete(store: &impl SecretService, account_name: &str) -> NativeResult<()> {
    validate_account_name(account_name)?;
    let previous = load_private_accounts(store)?;
    let accounts = normalized_accounts(
        previous
            .iter()
            .filter(|account| *account != account_name)
            .cloned(),
    );
    let index = encode_account_index(&accounts)?;

    // Record deliberate sign-out BEFORE deleting anything. If a later delete
    // or index write fails, a restart must not reimport shared legacy tokens.
    // This also covers a session left behind by an interrupted initial import.
    mark_legacy_import_complete(store)?;
    match store.delete_private(&private_account_key(account_name)) {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(error) => {
            return Err(keyring_error(
                "delete Proton VPN for Omarchy session",
                error,
            ))
        }
    }
    if accounts != previous {
        store_private_accounts(store, &index)?;
    }
    Ok(())
}

fn normalized_accounts(accounts: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut result = Vec::new();
    for account in accounts {
        if valid_account_name(&account) && !result.contains(&account) {
            result.push(account);
            if result.len() == MAX_ACCOUNTS {
                break;
            }
        }
    }
    result
}

fn load_private_default(store: &impl SecretService) -> NativeResult<Option<SessionData>> {
    for account in normalized_accounts(load_private_accounts(store)?) {
        let raw = match store.read(SERVICE, &private_account_key(&account)) {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => return Err(keyring_error("read Proton VPN for Omarchy session", error)),
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

fn load_legacy_default(store: &impl SecretService) -> NativeResult<Option<SessionData>> {
    let accounts = match store.read(LEGACY_SERVICE, LEGACY_ACCOUNT_INDEX) {
        // A corrupt legacy index must not prevent the agent from starting.
        Ok(value) if value.len() <= MAX_INDEX_BYTES => {
            serde_json::from_str::<Vec<String>>(&value).unwrap_or_default()
        }
        Ok(_) => return Ok(None),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(error) => return Err(keyring_error("read legacy Proton account index", error)),
    };

    for account in normalized_accounts(accounts) {
        let raw = match store.read(LEGACY_SERVICE, &legacy_account_key(&account)) {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => return Err(keyring_error("read legacy Proton session", error)),
        };
        let Some(session) = decode_legacy_session(&raw) else {
            continue;
        };
        if session.account_name == account && session.is_authenticated() {
            return Ok(Some(session));
        }
    }

    Ok(None)
}

fn load_private_accounts(store: &impl SecretService) -> NativeResult<Vec<String>> {
    let raw = match store.read(SERVICE, ACCOUNT_INDEX) {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => return Ok(Vec::new()),
        Err(error) => return Err(keyring_error("read private account index", error)),
    };

    Ok(decode_account_index(&raw).unwrap_or_default())
}

fn store_private_accounts(store: &impl SecretService, encoded: &str) -> NativeResult<()> {
    store
        .write_private(ACCOUNT_INDEX, encoded)
        .map_err(|error| keyring_error("store private account index", error))
}

fn legacy_import_complete(store: &impl SecretService) -> NativeResult<bool> {
    match store.read(SERVICE, LEGACY_IMPORT_MARKER) {
        Ok(value) => Ok(value.as_str() == LEGACY_IMPORT_COMPLETE),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(keyring_error("read legacy import marker", error)),
    }
}

fn mark_legacy_import_complete(store: &impl SecretService) -> NativeResult<()> {
    if legacy_import_complete(store)? {
        return Ok(());
    }
    store
        .write_private(LEGACY_IMPORT_MARKER, LEGACY_IMPORT_COMPLETE)
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
    if raw.len() > MAX_SESSION_BYTES {
        return None;
    }
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

fn escape_legacy_control_characters(raw: &str) -> Zeroizing<String> {
    let mut repaired = Zeroizing::new(String::with_capacity(raw.len()));
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

fn validate_account_name(account_name: &str) -> NativeResult<()> {
    if valid_account_name(account_name) {
        return Ok(());
    }
    Err(NativeError::new(
        "session_invalid",
        format!(
            "A Proton account name must contain between 1 and {MAX_ACCOUNT_NAME_BYTES} bytes and no control characters"
        ),
    ))
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
    // keyring's Ambiguous Display includes Debug output for every matching
    // credential, including account labels/attributes. Keep those out of IPC
    // error details and diagnostics; duplicate items must never be auto-deleted.
    let source = match error {
        keyring::Error::Ambiguous(items) => {
            format!(
                "{} matching credentials found in secure storage",
                items.len()
            )
        }
        error => error.to_string(),
    };
    NativeError::new(
        "secret_service_error",
        format!("Unable to {action} using the desktop Secret Service"),
    )
    .with_source(source)
    .retryable(true)
}

#[cfg(test)]
#[path = "secret_store_tests.rs"]
mod tests;
