use crate::{
    backend::{BackendError, BackendResult},
    operations::OperationCoordinator,
};
use proton_omarchy_protocol::{CanonicalStoreState, StateSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const STORE_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 1024 * 1024;
const MAX_PROFILES: usize = 128;
const MAX_EXCLUDED_LOCATIONS: usize = 256;
const MAX_UNPINNED_RECENTS: usize = 6;
const MAX_PAGE_SIZE: usize = 100;
const LEGACY_SCOPE: &str = "legacy-unscoped";
const OFFICIAL_DEFAULT_PROFILE_IDS: [&str; 6] = [
    "proton-default-streaming-v1",
    "proton-default-gaming-v1",
    "proton-default-p2p-v1",
    "proton-default-max-security-v1",
    "proton-default-work-school-v1",
    "proton-default-random-v1",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct StoreFile {
    version: u32,
    revision: u64,
    onboarding: Onboarding,
    active_account_key: Option<String>,
    accounts: BTreeMap<String, AccountStore>,
    migration: MigrationState,
}

impl Default for StoreFile {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            revision: 0,
            onboarding: Onboarding::default(),
            active_account_key: None,
            accounts: BTreeMap::new(),
            migration: MigrationState::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Onboarding {
    complete: bool,
    locale: String,
    start_with_omarchy: bool,
    auto_connect: bool,
    notifications_enabled: bool,
    port_forwarding_notifications_enabled: bool,
}

impl Default for Onboarding {
    fn default() -> Self {
        Self {
            complete: false,
            locale: "en".into(),
            start_with_omarchy: true,
            auto_connect: false,
            notifications_enabled: true,
            port_forwarding_notifications_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct MigrationState {
    legacy_qt_store_imported: bool,
    copied_to_account_keys: Vec<String>,
    official_default_profiles_seeded_for_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct AccountStore {
    profiles: Vec<Value>,
    recents: Vec<Value>,
    excluded_locations: Vec<ExcludedLocation>,
    default_connection: Value,
    ui_preferences: Value,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            recents: Vec::new(),
            excluded_locations: Vec::new(),
            default_connection: json!({ "type": "fastest" }),
            ui_preferences: json!({}),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ExcludedLocation {
    pub kind: String,
    pub country_code: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub city: String,
}

struct StoreInner {
    path: PathBuf,
    lifecycle_path: PathBuf,
    data: StoreFile,
    state_tx: watch::Sender<StateSnapshot>,
}

#[derive(Clone)]
pub struct StoreHandle {
    inner: Arc<Mutex<StoreInner>>,
    operations: OperationCoordinator,
}

impl StoreHandle {
    pub fn open(
        path: PathBuf,
        legacy_path: &Path,
        lifecycle_path: PathBuf,
        state_tx: watch::Sender<StateSnapshot>,
        operations: OperationCoordinator,
    ) -> io::Result<Self> {
        let existed = path.exists();
        let mut data = if existed {
            load_store(&path)?
        } else {
            StoreFile::default()
        };

        let migrated = if !existed {
            import_legacy(legacy_path, &mut data)?
        } else {
            false
        };
        let default_profiles_seeded = seed_known_accounts_with_official_profiles(&mut data)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.message))?;

        let handle = Self {
            inner: Arc::new(Mutex::new(StoreInner {
                path,
                lifecycle_path,
                data,
                state_tx,
            })),
            operations,
        };

        if !existed || migrated || default_profiles_seeded {
            let inner = handle.lock();
            save_store(&inner.path, &inner.data)?;
        }
        {
            let inner = handle.lock();
            save_lifecycle(&inner.lifecycle_path, &inner.data.onboarding)?;
            sync_autostart_registration(
                &inner.lifecycle_path,
                inner.data.onboarding.start_with_omarchy,
            )?;
        }
        handle.publish();
        Ok(handle)
    }

    pub fn request(&self, client_instance_id: &str, method: &str, params: Value) -> BackendResult {
        let operation = self.operations.begin(client_instance_id, method)?;
        let result = self.request_inner(method, params);
        self.operations
            .finish(operation, result.as_ref().map(|_| ()));
        result
    }

    pub fn activate_account(&self, account_name: Option<&str>) -> BackendResult {
        let Some(account_name) = account_name.map(str::trim).filter(|name| !name.is_empty()) else {
            return Ok(json!({ "changed": false }));
        };
        let account_key = account_fingerprint(account_name);
        let mut inner = self.lock();
        if inner.data.active_account_key.as_deref() == Some(account_key.as_str()) {
            return Ok(json!({ "changed": false }));
        }

        let previous = inner.data.clone();
        if !inner.data.accounts.contains_key(&account_key) {
            let imported = inner.data.accounts.get(LEGACY_SCOPE).cloned();
            inner
                .data
                .accounts
                .insert(account_key.clone(), imported.unwrap_or_default());
            if inner.data.migration.legacy_qt_store_imported
                && !inner
                    .data
                    .migration
                    .copied_to_account_keys
                    .contains(&account_key)
            {
                inner
                    .data
                    .migration
                    .copied_to_account_keys
                    .push(account_key.clone());
            }
        }
        seed_account_with_official_profiles(&mut inner.data, &account_key)?;
        inner.data.active_account_key = Some(account_key);
        inner.data.revision = inner.data.revision.wrapping_add(1);
        if let Err(error) = save_store(&inner.path, &inner.data) {
            inner.data = previous;
            return Err(store_io_error(error));
        }
        publish_locked(&inner);
        Ok(json!({ "changed": true }))
    }

    pub fn locale(&self) -> String {
        self.lock().data.onboarding.locale.clone()
    }

    pub fn auto_connect_enabled(&self) -> bool {
        self.lock().data.onboarding.auto_connect
    }

    pub fn notifications_enabled(&self) -> bool {
        self.lock().data.onboarding.notifications_enabled
    }

    pub fn port_forwarding_notifications_enabled(&self) -> bool {
        self.lock()
            .data
            .onboarding
            .port_forwarding_notifications_enabled
    }

    pub fn excluded_locations(&self) -> Vec<ExcludedLocation> {
        let inner = self.lock();
        account_ref(&inner.data).excluded_locations.clone()
    }

    fn request_inner(&self, method: &str, params: Value) -> BackendResult {
        match method {
            "store.get" => {
                let inner = self.lock();
                Ok(summary_value(&inner.data))
            }
            "profiles.list" => self.list_collection(params, Collection::Profiles),
            "recents.list" => self.list_collection(params, Collection::Recents),
            "onboarding.complete" => self.mutate(|data| complete_onboarding(data, &params)),
            "preferences.set" => self.mutate(|data| set_preferences(data, &params)),
            "profiles.save" => self.mutate(|data| save_profile(data, &params)),
            "profiles.duplicate" => self.mutate(|data| duplicate_profile(data, &params)),
            "profiles.delete" => self.mutate(|data| delete_profile(data, &params)),
            "excluded_locations.get" => {
                let inner = self.lock();
                Ok(json!({ "items": account_ref(&inner.data).excluded_locations }))
            }
            "excluded_locations.set" => self.mutate(|data| set_excluded_locations(data, &params)),
            "recents.record" => self.mutate(|data| record_recent(data, &params)),
            "recents.pin" => self.mutate(|data| pin_recent(data, &params)),
            "recents.delete" => self.mutate(|data| delete_recent(data, &params)),
            "default_connection.set" => self.mutate(|data| set_default_connection(data, &params)),
            "connection.resolve" => {
                let inner = self.lock();
                resolve_connection(account_ref(&inner.data), &params)
            }
            _ => Err(BackendError::new(
                "method_not_found",
                "Unknown canonical-store method",
            )),
        }
    }

    fn list_collection(&self, params: Value, collection: Collection) -> BackendResult {
        let offset = bounded_usize(&params, "offset", 0, usize::MAX)?;
        let limit = bounded_usize(&params, "limit", 50, MAX_PAGE_SIZE)?;
        let inner = self.lock();
        let account = account_ref(&inner.data);
        let items = match collection {
            Collection::Profiles => &account.profiles,
            Collection::Recents => &account.recents,
        };
        let page = items
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        Ok(json!({
            "items": page,
            "offset": offset,
            "limit": limit,
            "total": items.len(),
            "has_more": offset.saturating_add(limit) < items.len(),
            "store_revision": inner.data.revision,
        }))
    }

    fn mutate<F>(&self, mutation: F) -> BackendResult
    where
        F: FnOnce(&mut StoreFile) -> BackendResult,
    {
        let mut inner = self.lock();
        let previous = inner.data.clone();
        let previous_onboarding = inner.data.onboarding.clone();
        let result = mutation(&mut inner.data)?;
        inner.data.revision = inner.data.revision.wrapping_add(1);
        if let Err(error) = save_store(&inner.path, &inner.data) {
            inner.data = previous;
            return Err(store_io_error(error));
        }
        if inner.data.onboarding.complete != previous_onboarding.complete
            || inner.data.onboarding.locale != previous_onboarding.locale
            || inner.data.onboarding.start_with_omarchy != previous_onboarding.start_with_omarchy
            || inner.data.onboarding.auto_connect != previous_onboarding.auto_connect
        {
            if let Err(error) = save_lifecycle(&inner.lifecycle_path, &inner.data.onboarding) {
                inner.data = previous;
                let _ = save_store(&inner.path, &inner.data);
                let _ = save_lifecycle(&inner.lifecycle_path, &inner.data.onboarding);
                return Err(store_io_error(error));
            }
        }
        if inner.data.onboarding.start_with_omarchy != previous_onboarding.start_with_omarchy {
            if let Err(error) = sync_autostart_registration(
                &inner.lifecycle_path,
                inner.data.onboarding.start_with_omarchy,
            ) {
                inner.data = previous;
                let _ = save_store(&inner.path, &inner.data);
                let _ = save_lifecycle(&inner.lifecycle_path, &inner.data.onboarding);
                let _ = sync_autostart_registration(
                    &inner.lifecycle_path,
                    inner.data.onboarding.start_with_omarchy,
                );
                return Err(store_io_error(error));
            }
        }
        publish_locked(&inner);
        Ok(result)
    }

    fn publish(&self) {
        let inner = self.lock();
        publish_locked(&inner);
    }

    fn lock(&self) -> MutexGuard<'_, StoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn set_excluded_locations(data: &mut StoreFile, params: &Value) -> BackendResult {
    let raw = object_params(params)?
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| BackendError::new("invalid_params", "items must be an array"))?;
    if raw.len() > MAX_EXCLUDED_LOCATIONS {
        return Err(BackendError::new(
            "excluded_location_limit_reached",
            "Too many excluded locations",
        ));
    }
    let mut locations = Vec::with_capacity(raw.len());
    let mut seen = std::collections::BTreeSet::new();
    for item in raw {
        let object = item.as_object().ok_or_else(|| {
            BackendError::new("invalid_params", "Each excluded location must be an object")
        })?;
        let kind = required_string(object, "kind", 16)?.to_ascii_lowercase();
        if !matches!(kind.as_str(), "country" | "state" | "city") {
            return Err(BackendError::new(
                "invalid_excluded_location",
                "Excluded location kind must be country, state or city",
            ));
        }
        let mut country_code = required_string(object, "country_code", 2)?;
        if country_code.len() != 2 || !country_code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(BackendError::new(
                "invalid_excluded_location",
                "Excluded locations require a two-letter country code",
            ));
        }
        country_code.make_ascii_uppercase();
        let state = string_value(object.get("state"), 128, true)?;
        let city = string_value(object.get("city"), 128, true)?;
        if kind == "state" && state.is_empty() || kind == "city" && city.is_empty() {
            return Err(BackendError::new(
                "invalid_excluded_location",
                "Excluded state and city entries require their location name",
            ));
        }
        let key = format!(
            "{}:{}:{}:{}",
            kind,
            country_code,
            state.to_ascii_lowercase(),
            city.to_ascii_lowercase()
        );
        if seen.insert(key) {
            locations.push(ExcludedLocation {
                kind,
                country_code,
                state,
                city,
            });
        }
    }
    account_mut(data).excluded_locations = locations.clone();
    Ok(json!({ "items": locations }))
}

enum Collection {
    Profiles,
    Recents,
}

fn complete_onboarding(data: &mut StoreFile, params: &Value) -> BackendResult {
    let object = object_params(params)?;
    data.onboarding.locale = locale_value(object.get("locale"))?;
    data.onboarding.start_with_omarchy = required_bool(object, "start_with_omarchy")?;
    data.onboarding.auto_connect = required_bool(object, "auto_connect")?;
    if data.onboarding.auto_connect {
        data.onboarding.start_with_omarchy = true;
    }
    data.onboarding.complete = true;
    Ok(json!({ "onboarding_complete": true }))
}

fn set_preferences(data: &mut StoreFile, params: &Value) -> BackendResult {
    let object = object_params(params)?;
    if let Some(locale) = object.get("locale") {
        data.onboarding.locale = locale_value(Some(locale))?;
    }
    if let Some(value) = object.get("start_with_omarchy") {
        data.onboarding.start_with_omarchy = value.as_bool().ok_or_else(|| {
            BackendError::new("invalid_params", "start_with_omarchy must be a boolean")
        })?;
    }
    if let Some(value) = object.get("auto_connect") {
        data.onboarding.auto_connect = value
            .as_bool()
            .ok_or_else(|| BackendError::new("invalid_params", "auto_connect must be a boolean"))?;
    }
    if let Some(value) = object.get("notifications_enabled") {
        data.onboarding.notifications_enabled = value.as_bool().ok_or_else(|| {
            BackendError::new("invalid_params", "notifications_enabled must be a boolean")
        })?;
    }
    if let Some(value) = object.get("port_forwarding_notifications_enabled") {
        data.onboarding.port_forwarding_notifications_enabled =
            value.as_bool().ok_or_else(|| {
                BackendError::new(
                    "invalid_params",
                    "port_forwarding_notifications_enabled must be a boolean",
                )
            })?;
    }
    if data.onboarding.auto_connect {
        data.onboarding.start_with_omarchy = true;
    }
    if !data.onboarding.start_with_omarchy {
        data.onboarding.auto_connect = false;
    }
    Ok(json!({ "updated": true }))
}

fn save_profile(data: &mut StoreFile, params: &Value) -> BackendResult {
    let raw = object_params(params)?
        .get("profile")
        .and_then(Value::as_object)
        .ok_or_else(|| BackendError::new("invalid_params", "profile must be an object"))?;
    let account = account_mut(data);
    let existing_id = string_value(raw.get("id"), 128, false)?;
    let id = if existing_id.is_empty() {
        if account.profiles.len() >= MAX_PROFILES {
            return Err(BackendError::new(
                "profile_limit_reached",
                "Maximum profile count reached",
            ));
        }
        unique_id("profile", &account.profiles)
    } else {
        existing_id
    };

    let existing = account
        .profiles
        .iter()
        .find(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .and_then(Value::as_object);
    let profile = normalize_profile(raw, existing, &id)?;
    let value = Value::Object(profile);
    if let Some(index) = account
        .profiles
        .iter()
        .position(|item| item.get("id").and_then(Value::as_str) == Some(id.as_str()))
    {
        account.profiles[index] = value.clone();
    } else {
        account.profiles.push(value.clone());
    }
    Ok(json!({ "profile": value }))
}

fn duplicate_profile(data: &mut StoreFile, params: &Value) -> BackendResult {
    let object = object_params(params)?;
    let source_id = required_string(object, "id", 128)?;
    let account = account_mut(data);
    if account.profiles.len() >= MAX_PROFILES {
        return Err(BackendError::new(
            "profile_limit_reached",
            "Maximum profile count reached",
        ));
    }

    let source = account
        .profiles
        .iter()
        .find(|value| value.get("id").and_then(Value::as_str) == Some(source_id.as_str()))
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| BackendError::new("profile_not_found", "Profile was not found"))?;
    let mut duplicate = source;
    duplicate.remove("id");
    duplicate.remove("createdAtMs");
    duplicate.remove("updatedAtMs");

    let requested_name = string_value(object.get("name"), 60, true)?;
    if requested_name.is_empty() {
        let source_name = required_string(&duplicate, "name", 60)?;
        duplicate.insert(
            "name".into(),
            Value::String(copy_name(&source_name, &account.profiles)),
        );
    } else {
        duplicate.insert("name".into(), Value::String(requested_name));
    }

    let id = unique_id("profile", &account.profiles);
    let profile = Value::Object(normalize_profile(&duplicate, None, &id)?);
    account.profiles.push(profile.clone());
    Ok(json!({ "profile": profile, "source_id": source_id }))
}

fn copy_name(source: &str, profiles: &[Value]) -> String {
    for sequence in 1..=MAX_PROFILES + 1 {
        let suffix = if sequence == 1 {
            " copy".to_owned()
        } else {
            format!(" copy {sequence}")
        };
        let keep = 60_usize.saturating_sub(suffix.chars().count());
        let candidate = format!(
            "{}{}",
            source.chars().take(keep).collect::<String>(),
            suffix
        );
        if !profiles.iter().any(|profile| {
            profile
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(&candidate))
        }) {
            return candidate;
        }
    }
    source.chars().take(60).collect()
}

fn delete_profile(data: &mut StoreFile, params: &Value) -> BackendResult {
    let id = required_string(object_params(params)?, "id", 128)?;
    let account = account_mut(data);
    let before = account.profiles.len();
    account
        .profiles
        .retain(|profile| profile.get("id").and_then(Value::as_str) != Some(id.as_str()));
    account.recents.retain(|recent| {
        !(recent.get("kind").and_then(Value::as_str) == Some("profile")
            && recent.get("profileId").and_then(Value::as_str) == Some(id.as_str()))
    });
    validate_default(account);
    Ok(json!({ "deleted": account.profiles.len() != before }))
}

fn record_recent(data: &mut StoreFile, params: &Value) -> BackendResult {
    let raw = object_params(params)?
        .get("recent")
        .and_then(Value::as_object)
        .ok_or_else(|| BackendError::new("invalid_params", "recent must be an object"))?;
    let mut recent = normalize_recent(raw)?;
    let kind = required_string(&recent, "kind", 32)?;

    let account = account_mut(data);
    if kind == "profile" {
        let profile_id = required_string(&recent, "profileId", 128)?;
        if !account
            .profiles
            .iter()
            .any(|profile| profile.get("id").and_then(Value::as_str) == Some(profile_id.as_str()))
        {
            return Err(BackendError::new(
                "profile_not_found",
                "Recent profile was not found",
            ));
        }
    }
    let key = recent_key(&recent);
    let reused = account
        .recents
        .iter()
        .find(|candidate| candidate.as_object().map(recent_key).as_deref() == Some(key.as_str()))
        .and_then(Value::as_object)
        .cloned();
    account
        .recents
        .retain(|candidate| candidate.as_object().map(recent_key).as_deref() != Some(key.as_str()));

    recent.insert(
        "id".into(),
        Value::String(
            reused
                .as_ref()
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| unique_id("recent", &account.recents)),
        ),
    );
    recent.insert(
        "pinned".into(),
        Value::Bool(
            reused
                .as_ref()
                .and_then(|value| value.get("pinned"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    recent.insert(
        "pinTimeMs".into(),
        json!(reused
            .as_ref()
            .and_then(|value| value.get("pinTimeMs"))
            .and_then(Value::as_u64)
            .unwrap_or(0)),
    );
    let newest = account
        .recents
        .iter()
        .filter_map(|value| value.get("lastConnectionTimeMs").and_then(Value::as_u64))
        .max()
        .unwrap_or(0);
    recent.insert(
        "lastConnectionTimeMs".into(),
        json!(now_ms().max(newest + 1)),
    );
    let output = Value::Object(recent);
    account.recents.insert(0, output.clone());
    trim_recents(account);
    validate_default(account);
    Ok(json!({ "recent": output }))
}

fn pin_recent(data: &mut StoreFile, params: &Value) -> BackendResult {
    let object = object_params(params)?;
    let id = required_string(object, "id", 128)?;
    let pinned = required_bool(object, "pinned")?;
    let account = account_mut(data);
    let Some(recent) = account
        .recents
        .iter_mut()
        .find(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .and_then(Value::as_object_mut)
    else {
        return Err(BackendError::new(
            "recent_not_found",
            "Recent connection was not found",
        ));
    };
    recent.insert("pinned".into(), Value::Bool(pinned));
    recent.insert("pinTimeMs".into(), json!(if pinned { now_ms() } else { 0 }));
    trim_recents(account);
    Ok(json!({ "updated": true }))
}

fn delete_recent(data: &mut StoreFile, params: &Value) -> BackendResult {
    let id = required_string(object_params(params)?, "id", 128)?;
    let account = account_mut(data);
    let before = account.recents.len();
    account
        .recents
        .retain(|recent| recent.get("id").and_then(Value::as_str) != Some(id.as_str()));
    validate_default(account);
    Ok(json!({ "deleted": account.recents.len() != before }))
}

fn set_default_connection(data: &mut StoreFile, params: &Value) -> BackendResult {
    let selection = object_params(params)?
        .get("selection")
        .and_then(Value::as_object)
        .ok_or_else(|| BackendError::new("invalid_params", "selection must be an object"))?;
    let account = account_mut(data);
    account.default_connection = normalize_default(selection, account)?;
    Ok(json!({ "default_connection": account.default_connection }))
}

fn resolve_connection(account: &AccountStore, params: &Value) -> BackendResult {
    let requested_selection = params.get("selection").and_then(Value::as_object);
    let stored_selection = account.default_connection.as_object();
    let selection = requested_selection.or(stored_selection).ok_or_else(|| {
        BackendError::new(
            "invalid_default_connection",
            "Default connection selection is invalid",
        )
    })?;
    let selection_type = selection
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("fastest");

    match selection_type {
        "fastest" => Ok(json!({
            "selection": { "type": "fastest" },
            "connect_params": {}
        })),
        "random" => Ok(json!({
            "selection": { "type": "random" },
            "connect_params": { "target": { "random": true } }
        })),
        "last" => match most_recent_connection(account) {
            Some(recent) => resolved_recent(account, recent, "last"),
            None => Ok(json!({
                "selection": { "type": "last" },
                "fallback": "fastest",
                "connect_params": {}
            })),
        },
        "recent" => {
            let id = required_string(selection, "recentId", 128)?;
            let recent = account
                .recents
                .iter()
                .find(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
                .ok_or_else(|| {
                    BackendError::new(
                        "recent_not_found",
                        "Default recent connection was not found",
                    )
                })?;
            resolved_recent(account, recent, "recent")
        }
        "profile" => {
            let id = required_string(selection, "profileId", 128)?;
            let profile = account
                .profiles
                .iter()
                .find(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
                .ok_or_else(|| {
                    BackendError::new("profile_not_found", "Default profile was not found")
                })?;
            resolved_profile(profile, "profile")
        }
        _ => Err(BackendError::new(
            "invalid_default_connection",
            "Unsupported default connection type",
        )),
    }
}

fn most_recent_connection(account: &AccountStore) -> Option<&Value> {
    account.recents.iter().max_by_key(|value| {
        value
            .get("lastConnectionTimeMs")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    })
}

fn resolved_recent(account: &AccountStore, recent: &Value, selection_type: &str) -> BackendResult {
    let object = recent.as_object().ok_or_else(|| {
        BackendError::new(
            "invalid_recent_target",
            "Recent connection target is invalid",
        )
    })?;
    let kind = required_string(object, "kind", 32)?;
    if kind == "profile" {
        let profile_id = required_string(object, "profileId", 128)?;
        let profile = account
            .profiles
            .iter()
            .find(|value| value.get("id").and_then(Value::as_str) == Some(profile_id.as_str()))
            .ok_or_else(|| {
                BackendError::new("profile_not_found", "Recent profile was not found")
            })?;
        return resolved_profile(profile, selection_type);
    }

    let mut target = Map::new();
    copy_nonempty_string(object, &mut target, "countryCode", "country_code");
    copy_nonempty_string(
        object,
        &mut target,
        "entryCountryCode",
        "entry_country_code",
    );
    copy_nonempty_string(object, &mut target, "state", "state");
    copy_nonempty_string(object, &mut target, "city", "city");
    copy_nonempty_string(object, &mut target, "serverName", "server_name");
    copy_nonempty_string(object, &mut target, "gatewayName", "gateway_name");
    match kind.as_str() {
        "country" | "state" | "city" => match object
            .get("feature")
            .and_then(Value::as_str)
            .unwrap_or("all")
        {
            "p2p" => {
                target.insert("p2p".into(), Value::Bool(true));
            }
            "tor" => {
                target.insert("tor".into(), Value::Bool(true));
            }
            "secure_core" => {
                target.insert("secure_core".into(), Value::Bool(true));
            }
            _ => {}
        },
        "secureCore" => {
            target.insert("secure_core".into(), Value::Bool(true));
        }
        "tor" => {
            target.insert("tor".into(), Value::Bool(true));
        }
        "server" | "gateway" | "gatewayServer" => {}
        _ => {
            return Err(BackendError::new(
                "invalid_recent_target",
                "Recent connection target is unsupported",
            ));
        }
    }

    Ok(json!({
        "selection": { "type": selection_type },
        "connect_params": { "target": target },
        "recent": recent
    }))
}

fn resolved_profile(profile: &Value, selection_type: &str) -> BackendResult {
    let object = profile.as_object().ok_or_else(|| {
        BackendError::new(
            "invalid_profile_target",
            "Profile connection target is invalid",
        )
    })?;
    let kind = required_string(object, "targetKind", 32)?;
    let mut target = Map::new();
    copy_nonempty_string(object, &mut target, "countryCode", "country_code");
    copy_nonempty_string(
        object,
        &mut target,
        "entryCountryCode",
        "entry_country_code",
    );
    copy_nonempty_string(object, &mut target, "state", "state");
    copy_nonempty_string(object, &mut target, "city", "city");
    copy_nonempty_string(object, &mut target, "serverName", "server_name");
    copy_nonempty_string(object, &mut target, "gatewayName", "gateway_name");
    match kind.as_str() {
        "fastest" | "country" | "state" | "city" | "server" | "gateway" | "gatewayServer" => {}
        "random" => {
            target.insert("random".into(), Value::Bool(true));
        }
        "p2p" => {
            target.insert("p2p".into(), Value::Bool(true));
        }
        "secureCore" => {
            target.insert("secure_core".into(), Value::Bool(true));
        }
        "tor" => {
            target.insert("tor".into(), Value::Bool(true));
        }
        _ => {
            return Err(BackendError::new(
                "invalid_profile_target",
                "Profile connection target is unsupported",
            ));
        }
    }

    let selection_strategy = object
        .get("selectionStrategy")
        .and_then(Value::as_str)
        .unwrap_or(if kind == "random" {
            "random"
        } else {
            "fastest"
        });
    if selection_strategy == "random" && kind != "random" {
        let explicitly_scoped = ["countryCode", "state", "city", "gatewayName"]
            .iter()
            .any(|key| nonempty(object, key));
        target.insert(
            if explicitly_scoped {
                "random_server"
            } else {
                "random"
            }
            .into(),
            Value::Bool(true),
        );
    }
    if object
        .get("excludeMyCountry")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        target.insert("exclude_my_country".into(), Value::Bool(true));
    }

    let profile_id = required_string(object, "id", 128)?;
    let profile_name = required_string(object, "name", 60)?;
    let description = object
        .get("countryName")
        .or_else(|| object.get("serverName"))
        .or_else(|| object.get("gatewayName"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("Profile");
    let post_connect = if object
        .get("connectAndGoEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        json!({
            "mode": object.get("connectAndGoMode").and_then(Value::as_str).unwrap_or("website"),
            "url": object.get("connectAndGoUrl").and_then(Value::as_str).unwrap_or(""),
            "private_browsing": object.get("connectAndGoUsePrivateBrowsingMode").and_then(Value::as_bool).unwrap_or(false),
            "desktop_id": object.get("connectAndGoAppId").and_then(Value::as_str).unwrap_or(""),
        })
    } else {
        Value::Null
    };
    Ok(json!({
        "selection": { "type": selection_type },
        "connect_params": {
            "profile_id": profile_id,
            "target": target,
            "profile_settings": {
                "protocol": object.get("profileProtocol").and_then(Value::as_str).unwrap_or("smart"),
                "netshield_enabled": object.get("profileNetShieldEnabled").and_then(Value::as_bool).unwrap_or(true),
                "netshield_level": object.get("profileNetShieldLevel").and_then(Value::as_u64).unwrap_or(2),
                "moderate_nat": object.get("profileNatType").and_then(Value::as_str) == Some("moderate"),
                "port_forwarding": object.get("profilePortForwardingEnabled").and_then(Value::as_bool).unwrap_or(false),
                "custom_dns": {
                    "mode": object.get("profileCustomDnsMode").and_then(Value::as_str).unwrap_or("inherit"),
                    "servers": object.get("profileCustomDnsServers").and_then(Value::as_array).cloned().unwrap_or_default()
                },
                "allow_lan_connections": profile_policy_value(object, "profileLanMode"),
                "allow_local_dns": profile_policy_value(object, "profileLocalDnsMode")
            }
        },
        "recent": {
            "kind": "profile",
            "profileId": profile_id,
            "header": profile_name,
            "description": description
        },
        "post_connect": post_connect
    }))
}

fn copy_nonempty_string(
    source: &Map<String, Value>,
    target: &mut Map<String, Value>,
    source_name: &str,
    target_name: &str,
) {
    if let Some(value) = source
        .get(source_name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        target.insert(target_name.into(), Value::String(value.into()));
    }
}

fn normalize_profile(
    raw: &Map<String, Value>,
    existing: Option<&Map<String, Value>>,
    id: &str,
) -> Result<Map<String, Value>, BackendError> {
    let mut profile = Map::new();
    let name = required_string(raw, "name", 60)?;
    let target_kind = string_or(raw, "targetKind", "fastest", 32)?;
    let selection_strategy = string_or(
        raw,
        "selectionStrategy",
        if target_kind == "random" {
            "random"
        } else {
            "fastest"
        },
        16,
    )?
    .to_ascii_lowercase();
    if !["fastest", "random"].contains(&selection_strategy.as_str()) {
        return Err(BackendError::new(
            "invalid_profile_target",
            "Profile selection strategy is unsupported",
        ));
    }
    insert_profile_string(raw, &mut profile, "countryCode", 2, true)?;
    insert_profile_string(raw, &mut profile, "countryName", 128, false)?;
    insert_profile_string(raw, &mut profile, "entryCountryCode", 2, true)?;
    insert_profile_string(raw, &mut profile, "entryCountryName", 128, false)?;
    insert_profile_string(raw, &mut profile, "state", 128, false)?;
    insert_profile_string(raw, &mut profile, "city", 128, false)?;
    insert_profile_string(raw, &mut profile, "serverName", 128, false)?;
    insert_profile_string(raw, &mut profile, "gatewayName", 128, false)?;
    if !profile_target_valid(&target_kind, &profile) {
        return Err(BackendError::new(
            "invalid_profile_target",
            "Profile target is incomplete or unsupported",
        ));
    }
    let protocol = string_or(raw, "profileProtocol", "smart", 32)?.to_ascii_lowercase();
    let supported_protocols = [
        "smart",
        "wireguard-udp",
        "wireguard-tcp",
        "wireguard-tls",
        "protun-udp",
        "protun-tcp",
        "protun-tls",
        "openvpn-udp",
        "openvpn-tcp",
    ];
    let protocol = if supported_protocols.contains(&protocol.as_str()) {
        protocol
    } else {
        "smart".into()
    };
    let now = now_ms();
    let created = existing
        .and_then(|value| value.get("createdAtMs"))
        .and_then(Value::as_u64)
        .or_else(|| raw.get("createdAtMs").and_then(Value::as_u64))
        .filter(|value| *value > 0)
        .unwrap_or(now);

    profile.insert("id".into(), Value::String(id.into()));
    profile.insert("name".into(), Value::String(name));
    profile.insert("targetKind".into(), Value::String(target_kind));
    profile.insert(
        "selectionStrategy".into(),
        Value::String(selection_strategy),
    );
    profile.insert(
        "excludeMyCountry".into(),
        Value::Bool(optional_bool(raw, "excludeMyCountry", false)?),
    );
    profile.insert(
        "iconName".into(),
        Value::String(string_or(raw, "iconName", "Speed", 64)?),
    );
    profile.insert(
        "color".into(),
        Value::String(string_or(raw, "color", "#C857E7", 32)?),
    );
    profile.insert("profileProtocol".into(), Value::String(protocol));
    profile.insert(
        "profileNetShieldEnabled".into(),
        Value::Bool(optional_bool(raw, "profileNetShieldEnabled", true)?),
    );
    profile.insert(
        "profileNetShieldLevel".into(),
        json!(raw
            .get("profileNetShieldLevel")
            .and_then(Value::as_u64)
            .unwrap_or(2)
            .min(2)),
    );
    let nat = string_or(raw, "profileNatType", "strict", 16)?.to_ascii_lowercase();
    let nat = if nat == "moderate" {
        "moderate"
    } else {
        "strict"
    };
    let mut port_forwarding = optional_bool(raw, "profilePortForwardingEnabled", false)?;
    if nat == "moderate" {
        port_forwarding = false;
    }
    profile.insert("profileNatType".into(), Value::String(nat.into()));
    profile.insert(
        "profilePortForwardingEnabled".into(),
        Value::Bool(port_forwarding),
    );
    let custom_dns_mode = profile_mode(raw, "profileCustomDnsMode", &["inherit", "off", "custom"])?;
    let custom_dns_servers = profile_dns_servers(raw.get("profileCustomDnsServers"))?;
    if custom_dns_mode == "custom" && custom_dns_servers.is_empty() {
        return Err(BackendError::new(
            "invalid_dns",
            "A custom DNS profile requires at least one DNS server",
        ));
    }
    if custom_dns_mode == "custom"
        && profile
            .get("profileNetShieldEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    {
        return Err(BackendError::new(
            "profile_settings_conflict",
            "Custom DNS and NetShield cannot be enabled in the same profile",
        ));
    }
    profile.insert(
        "profileCustomDnsMode".into(),
        Value::String(custom_dns_mode),
    );
    profile.insert(
        "profileCustomDnsServers".into(),
        Value::Array(custom_dns_servers.into_iter().map(Value::String).collect()),
    );
    profile.insert(
        "profileLanMode".into(),
        Value::String(profile_mode(
            raw,
            "profileLanMode",
            &["inherit", "allow", "block"],
        )?),
    );
    profile.insert(
        "profileLocalDnsMode".into(),
        Value::String(profile_mode(
            raw,
            "profileLocalDnsMode",
            &["inherit", "allow", "block"],
        )?),
    );
    let connect_and_go_enabled = optional_bool(raw, "connectAndGoEnabled", false)?;
    let connect_and_go_mode =
        string_or(raw, "connectAndGoMode", "website", 32)?.to_ascii_lowercase();
    let connect_and_go_mode = match connect_and_go_mode.as_str() {
        "website" => "website",
        "application" => "application",
        _ => {
            return Err(BackendError::new(
                "invalid_connect_and_go",
                "Connect and Go mode must be website or application",
            ));
        }
    };
    let connect_and_go_url = string_or(raw, "connectAndGoUrl", "", 2_048)?;
    let connect_and_go_app_id = string_or(raw, "connectAndGoAppId", "", 255)?;
    let connect_and_go_app_path = string_or(raw, "connectAndGoAppPath", "", 2_048)?;
    if connect_and_go_enabled
        && ((connect_and_go_mode == "website" && connect_and_go_url.is_empty())
            || (connect_and_go_mode == "application" && connect_and_go_app_id.is_empty()))
    {
        return Err(BackendError::new(
            "invalid_connect_and_go",
            "Connect and Go requires a website or installed application",
        ));
    }
    profile.insert(
        "connectAndGoEnabled".into(),
        Value::Bool(connect_and_go_enabled),
    );
    profile.insert(
        "connectAndGoMode".into(),
        Value::String(connect_and_go_mode.into()),
    );
    profile.insert("connectAndGoUrl".into(), Value::String(connect_and_go_url));
    profile.insert(
        "connectAndGoUsePrivateBrowsingMode".into(),
        Value::Bool(optional_bool(
            raw,
            "connectAndGoUsePrivateBrowsingMode",
            false,
        )?),
    );
    profile.insert(
        "connectAndGoAppId".into(),
        Value::String(connect_and_go_app_id),
    );
    profile.insert(
        "connectAndGoAppPath".into(),
        Value::String(connect_and_go_app_path),
    );
    profile.insert("createdAtMs".into(), json!(created));
    profile.insert("updatedAtMs".into(), json!(now));
    Ok(profile)
}

fn profile_mode(
    raw: &Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<String, BackendError> {
    let value = string_or(raw, key, "inherit", 16)?.to_ascii_lowercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(BackendError::new(
            "invalid_params",
            format!("{key} contains an unsupported policy"),
        ))
    }
}

fn profile_dns_servers(value: Option<&Value>) -> Result<Vec<String>, BackendError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        BackendError::new(
            "invalid_dns",
            "profileCustomDnsServers must be an array of IP addresses",
        )
    })?;
    if values.len() > 16 {
        return Err(BackendError::new(
            "invalid_dns",
            "A profile can contain at most 16 custom DNS servers",
        ));
    }
    let mut servers = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            BackendError::new("invalid_dns", "Profile DNS servers must be strings")
        })?;
        if value.trim().is_empty() {
            continue;
        }
        let address = value.trim().parse::<IpAddr>().map_err(|_| {
            BackendError::new(
                "invalid_dns",
                "Profile DNS servers must be valid IP addresses",
            )
        })?;
        let normalized = address.to_string();
        if seen.insert(normalized.clone()) {
            servers.push(normalized);
        }
    }
    Ok(servers)
}

fn profile_policy_value(object: &Map<String, Value>, key: &str) -> Value {
    match object.get(key).and_then(Value::as_str).unwrap_or("inherit") {
        "allow" => Value::Bool(true),
        "block" => Value::Bool(false),
        _ => Value::Null,
    }
}

fn insert_profile_string(
    source: &Map<String, Value>,
    target: &mut Map<String, Value>,
    key: &str,
    max_chars: usize,
    uppercase: bool,
) -> Result<(), BackendError> {
    let mut value = string_value(source.get(key), max_chars, true)?;
    if value.is_empty() {
        return Ok(());
    }
    if uppercase {
        if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(BackendError::new(
                "invalid_params",
                format!("{key} must be a two-letter country code"),
            ));
        }
        value.make_ascii_uppercase();
    }
    target.insert(key.into(), Value::String(value));
    Ok(())
}

fn profile_target_valid(kind: &str, value: &Map<String, Value>) -> bool {
    match kind {
        "fastest" | "random" | "p2p" | "tor" => true,
        "secureCore" => !nonempty(value, "entryCountryCode") || nonempty(value, "countryCode"),
        "country" => nonempty(value, "countryCode"),
        "state" => nonempty(value, "countryCode") && nonempty(value, "state"),
        "city" => nonempty(value, "countryCode") && nonempty(value, "city"),
        "server" => nonempty(value, "countryCode") && nonempty(value, "serverName"),
        "gateway" => nonempty(value, "gatewayName"),
        "gatewayServer" => nonempty(value, "gatewayName") && nonempty(value, "serverName"),
        _ => false,
    }
}

fn recent_target_valid(kind: &str, value: &Map<String, Value>) -> bool {
    match kind {
        "profile" => nonempty(value, "profileId"),
        "gateway" => nonempty(value, "gatewayName"),
        "gatewayServer" => nonempty(value, "gatewayName") && nonempty(value, "serverName"),
        "secureCore" => {
            nonempty(value, "serverName")
                || nonempty(value, "countryCode") && nonempty(value, "entryCountryCode")
        }
        "server" | "tor" => nonempty(value, "serverName"),
        "country" => nonempty(value, "countryCode"),
        "state" => nonempty(value, "countryCode") && nonempty(value, "state"),
        "city" => nonempty(value, "countryCode") && nonempty(value, "city"),
        _ => false,
    }
}

fn normalize_recent(raw: &Map<String, Value>) -> Result<Map<String, Value>, BackendError> {
    let kind = required_string(raw, "kind", 32)?;
    let mut recent = Map::new();
    recent.insert("kind".into(), Value::String(kind.clone()));

    insert_recent_string(raw, &mut recent, "profileId", 128, false)?;
    insert_recent_string(raw, &mut recent, "header", 128, false)?;
    insert_recent_string(raw, &mut recent, "description", 256, false)?;
    insert_recent_string(raw, &mut recent, "gatewayName", 128, false)?;
    insert_recent_string(raw, &mut recent, "countryCode", 2, true)?;
    insert_recent_string(raw, &mut recent, "countryName", 128, false)?;
    insert_recent_string(raw, &mut recent, "entryCountryCode", 2, true)?;
    insert_recent_string(raw, &mut recent, "entryCountryName", 128, false)?;
    insert_recent_string(raw, &mut recent, "state", 128, false)?;
    insert_recent_string(raw, &mut recent, "city", 128, false)?;
    insert_recent_string(raw, &mut recent, "serverName", 128, false)?;

    if matches!(kind.as_str(), "country" | "state" | "city") {
        let feature = string_or(raw, "feature", "standard", 32)?.to_ascii_lowercase();
        if !["standard", "all", "secure_core", "p2p", "tor"].contains(&feature.as_str()) {
            return Err(BackendError::new(
                "invalid_recent_target",
                "Recent location feature is unsupported",
            ));
        }
        recent.insert("feature".into(), Value::String(feature));
    }

    if let Some(load) = raw.get("load") {
        let load = load.as_u64().ok_or_else(|| {
            BackendError::new("invalid_params", "load must be an unsigned number")
        })?;
        recent.insert("load".into(), json!(load.min(100)));
    }

    if !recent_target_valid(&kind, &recent) {
        return Err(BackendError::new(
            "invalid_recent_target",
            "Recent connection target is incomplete or unsupported",
        ));
    }
    Ok(recent)
}

fn insert_recent_string(
    source: &Map<String, Value>,
    target: &mut Map<String, Value>,
    key: &str,
    max_chars: usize,
    uppercase_country_code: bool,
) -> Result<(), BackendError> {
    let mut value = string_value(source.get(key), max_chars, true)?;
    if value.is_empty() {
        return Ok(());
    }
    if uppercase_country_code {
        if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(BackendError::new(
                "invalid_params",
                format!("{key} must be a two-letter country code"),
            ));
        }
        value.make_ascii_uppercase();
    }
    target.insert(key.into(), Value::String(value));
    Ok(())
}

fn recent_key(value: &Map<String, Value>) -> String {
    let field = |name| value.get(name).and_then(Value::as_str).unwrap_or("");
    match field("kind") {
        "profile" => format!("profile:{}", field("profileId")),
        "gateway" | "gatewayServer" => {
            format!(
                "{}:{}:{}",
                field("kind"),
                field("gatewayName"),
                field("serverName")
            )
        }
        kind => format!(
            "{}:{}:{}:{}:{}:{}:{}",
            kind,
            value
                .get("feature")
                .and_then(Value::as_str)
                .unwrap_or("all"),
            field("entryCountryCode"),
            field("countryCode"),
            field("state"),
            field("city"),
            field("serverName")
        ),
    }
}

fn trim_recents(account: &mut AccountStore) {
    let mut pinned = Vec::new();
    let mut unpinned = Vec::new();
    for value in account.recents.drain(..) {
        if value
            .get("pinned")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            pinned.push(value);
        } else {
            unpinned.push(value);
        }
    }
    pinned.sort_by_key(|value| value.get("pinTimeMs").and_then(Value::as_u64).unwrap_or(0));
    unpinned.sort_by_key(|value| {
        std::cmp::Reverse(
            value
                .get("lastConnectionTimeMs")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        )
    });
    unpinned.truncate(MAX_UNPINNED_RECENTS);
    pinned.extend(unpinned);
    account.recents = pinned;
}

fn normalize_default(
    selection: &Map<String, Value>,
    account: &AccountStore,
) -> Result<Value, BackendError> {
    let kind = string_or(selection, "type", "fastest", 32)?;
    match kind.as_str() {
        "fastest" | "random" | "last" => Ok(json!({ "type": kind })),
        "recent" => {
            let id = required_string(selection, "recentId", 128)?;
            if account
                .recents
                .iter()
                .any(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
            {
                Ok(json!({ "type": "recent", "recentId": id }))
            } else {
                Err(BackendError::new(
                    "recent_not_found",
                    "Default recent connection was not found",
                ))
            }
        }
        "profile" => {
            let id = required_string(selection, "profileId", 128)?;
            if account
                .profiles
                .iter()
                .any(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
            {
                Ok(json!({ "type": "profile", "profileId": id }))
            } else {
                Err(BackendError::new(
                    "profile_not_found",
                    "Default profile was not found",
                ))
            }
        }
        _ => Err(BackendError::new(
            "invalid_default_connection",
            "Unsupported default connection type",
        )),
    }
}

fn validate_default(account: &mut AccountStore) {
    let Some(selection) = account.default_connection.as_object() else {
        account.default_connection = json!({ "type": "fastest" });
        return;
    };
    if normalize_default(selection, account).is_err() {
        account.default_connection = json!({ "type": "fastest" });
    }
}

fn import_legacy(path: &Path, data: &mut StoreFile) -> io::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_STORE_BYTES {
        return Ok(false);
    }
    let root: Value = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid legacy store: {error}"),
        )
    })?;
    let Some(object) = root.as_object() else {
        return Ok(false);
    };
    let version = object.get("version").and_then(Value::as_u64).unwrap_or(0);
    if !(1..=4).contains(&version) {
        return Ok(false);
    }
    let mut account = AccountStore {
        profiles: object
            .get("profiles")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        recents: object
            .get("recents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        ui_preferences: object
            .get("ui_preferences")
            .cloned()
            .unwrap_or_else(|| json!({})),
        ..AccountStore::default()
    };
    account.profiles.truncate(MAX_PROFILES);
    trim_recents(&mut account);
    if let Some(selection) = object.get("default_connection").and_then(Value::as_object) {
        account.default_connection =
            normalize_default(selection, &account).unwrap_or_else(|_| json!({ "type": "fastest" }));
    }
    data.accounts.insert(LEGACY_SCOPE.into(), account);
    data.migration.legacy_qt_store_imported = true;
    data.revision = data.revision.wrapping_add(1);
    Ok(true)
}

fn load_store(path: &Path) -> io::Result<StoreFile> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical store is not a regular file",
        ));
    }
    if metadata.len() > MAX_STORE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical store exceeds the size limit",
        ));
    }
    let data: StoreFile = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid canonical store: {error}"),
        )
    })?;
    if data.version != STORE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported canonical store version {}", data.version),
        ));
    }
    Ok(data)
}

fn save_store(path: &Path, data: &StoreFile) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical store has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let bytes = serde_json::to_vec_pretty(data)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical store exceeds the size limit",
        ));
    }
    let temporary = parent.join(format!(".state-v1.{}.{}.tmp", std::process::id(), now_ms()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn save_lifecycle(path: &Path, onboarding: &Onboarding) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "onboarding_complete": onboarding.complete,
        "locale": onboarding.locale,
        "start_with_omarchy": onboarding.start_with_omarchy,
        "auto_connect": onboarding.auto_connect,
        "notifications_enabled": onboarding.notifications_enabled,
        "port_forwarding_notifications_enabled": onboarding.port_forwarding_notifications_enabled,
    }))
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    save_private_bytes(path, &bytes)
}

fn save_private_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private state has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(
        ".lifecycle.{}.{}.tmp",
        std::process::id(),
        now_ms()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_autostart_registration(lifecycle_path: &Path, enabled: bool) -> io::Result<()> {
    let config_home = lifecycle_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid lifecycle path"))?;
    let wants_dir = config_home.join("systemd/user/default.target.wants");
    let link = wants_dir.join("proton-omarchy-agent.service");
    let unit = Path::new("/usr/lib/systemd/user/proton-omarchy-agent.service");

    match fs::symlink_metadata(&link) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace a non-symlink autostart registration",
                ));
            }
            let target = fs::read_link(&link)?;
            if target.file_name() != unit.file_name() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace an unrelated autostart registration",
                ));
            }
            if !enabled {
                fs::remove_file(&link)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if enabled {
                fs::create_dir_all(&wants_dir)?;
                std::os::unix::fs::symlink(unit, link)?;
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn publish_locked(inner: &StoreInner) {
    let store = store_state(&inner.data);
    inner.state_tx.send_modify(|state| {
        state.store = store;
        state.revision = state.revision.wrapping_add(1);
    });
}

fn store_state(data: &StoreFile) -> CanonicalStoreState {
    let account = account_ref(data);
    CanonicalStoreState {
        revision: data.revision,
        ready: true,
        onboarding_complete: data.onboarding.complete,
        locale: data.onboarding.locale.clone(),
        start_with_omarchy: data.onboarding.start_with_omarchy,
        auto_connect: data.onboarding.auto_connect,
        notifications_enabled: data.onboarding.notifications_enabled,
        port_forwarding_notifications_enabled: data
            .onboarding
            .port_forwarding_notifications_enabled,
        account_scope_known: data.active_account_key.is_some(),
        profile_count: account.profiles.len(),
        recent_count: account.recents.len(),
        default_connection: account.default_connection.clone(),
        migration_available: data.migration.legacy_qt_store_imported,
    }
}

fn summary_value(data: &StoreFile) -> Value {
    serde_json::to_value(store_state(data)).unwrap_or(Value::Null)
}

fn account_ref(data: &StoreFile) -> &AccountStore {
    data.active_account_key
        .as_ref()
        .and_then(|key| data.accounts.get(key))
        .or_else(|| data.accounts.get(LEGACY_SCOPE))
        .unwrap_or_else(|| {
            static EMPTY: std::sync::OnceLock<AccountStore> = std::sync::OnceLock::new();
            EMPTY.get_or_init(AccountStore::default)
        })
}

fn account_mut(data: &mut StoreFile) -> &mut AccountStore {
    let key = data
        .active_account_key
        .clone()
        .unwrap_or_else(|| LEGACY_SCOPE.into());
    data.accounts.entry(key).or_default()
}

fn seed_known_accounts_with_official_profiles(data: &mut StoreFile) -> Result<bool, BackendError> {
    let account_keys = data.accounts.keys().cloned().collect::<Vec<_>>();
    let mut changed = false;
    for account_key in account_keys {
        changed |= seed_account_with_official_profiles(data, &account_key)?;
    }
    Ok(changed)
}

fn seed_account_with_official_profiles(
    data: &mut StoreFile,
    account_key: &str,
) -> Result<bool, BackendError> {
    if data
        .migration
        .official_default_profiles_seeded_for_accounts
        .iter()
        .any(|key| key == account_key)
    {
        return Ok(false);
    }

    let templates = official_default_profiles(&data.onboarding.locale)?;
    let account = data.accounts.entry(account_key.into()).or_default();
    let mut changed = false;
    for profile in templates {
        let id = profile
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let already_exists = account
            .profiles
            .iter()
            .any(|existing| existing.get("id").and_then(Value::as_str) == Some(id));
        if !already_exists && account.profiles.len() < MAX_PROFILES {
            account.profiles.push(profile);
            changed = true;
        }
    }

    let complete = OFFICIAL_DEFAULT_PROFILE_IDS.iter().all(|id| {
        account
            .profiles
            .iter()
            .any(|profile| profile.get("id").and_then(Value::as_str) == Some(*id))
    });
    if complete {
        data.migration
            .official_default_profiles_seeded_for_accounts
            .push(account_key.into());
        changed = true;
    }
    Ok(changed)
}

// Mirrors ProtonVPN/win-app DefaultProfilesProvider.cs at upstream commit
// 4d9ac60d1db5d3f2908498470a9d1646723afcfd. Profiles stay ordinary user
// records so they can be edited or deleted after the one-time seed.
fn official_default_profiles(locale: &str) -> Result<Vec<Value>, BackendError> {
    let spanish = locale
        .replace('_', "-")
        .split('-')
        .next()
        .is_some_and(|language| language.eq_ignore_ascii_case("es"));
    let names = if spanish {
        [
            "Streaming EE. UU.",
            "Juegos",
            "P2P",
            "Seguridad máxima",
            "Trabajo/Escuela",
            "Conexión aleatoria",
        ]
    } else {
        [
            "Streaming US",
            "Gaming",
            "P2P",
            "Max security",
            "Work/School",
            "Random connection",
        ]
    };
    let united_states = if spanish {
        "Estados Unidos"
    } else {
        "United States"
    };
    let raw_profiles = [
        json!({
            "name": names[0],
            "targetKind": "country",
            "countryCode": "US",
            "countryName": united_states,
            "iconName": "Streaming"
        }),
        json!({
            "name": names[1],
            "targetKind": "p2p",
            "iconName": "Gaming",
            "profileNatType": "moderate"
        }),
        json!({
            "name": names[2],
            "targetKind": "p2p",
            "iconName": "Download",
            "profilePortForwardingEnabled": true
        }),
        json!({
            "name": names[3],
            "targetKind": "secureCore",
            "iconName": "Protection"
        }),
        json!({
            "name": names[4],
            "targetKind": "fastest",
            "iconName": "Business",
            "profileProtocol": "protun-tls",
            "profileNetShieldEnabled": true,
            "profileNetShieldLevel": 1,
            "profileNatType": "moderate"
        }),
        json!({
            "name": names[5],
            "targetKind": "random",
            "iconName": "Browsing"
        }),
    ];

    raw_profiles
        .iter()
        .zip(OFFICIAL_DEFAULT_PROFILE_IDS)
        .map(|(raw, id)| {
            let object = raw.as_object().ok_or_else(|| {
                BackendError::new(
                    "default_profile_invalid",
                    "An official default profile template is invalid",
                )
            })?;
            normalize_profile(object, None, id).map(Value::Object)
        })
        .collect()
}

fn account_fingerprint(account_name: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in account_name.trim().to_lowercase().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("account-{hash:016x}")
}

fn object_params(value: &Value) -> Result<&Map<String, Value>, BackendError> {
    value
        .as_object()
        .ok_or_else(|| BackendError::new("invalid_params", "params must be an object"))
}

fn required_string(
    object: &Map<String, Value>,
    key: &str,
    max_chars: usize,
) -> Result<String, BackendError> {
    let value = string_value(object.get(key), max_chars, true)?;
    if value.is_empty() {
        Err(BackendError::new(
            "invalid_params",
            format!("{key} is required"),
        ))
    } else {
        Ok(value)
    }
}

fn string_or(
    object: &Map<String, Value>,
    key: &str,
    fallback: &str,
    max_chars: usize,
) -> Result<String, BackendError> {
    if object.get(key).is_none() {
        return Ok(fallback.into());
    }
    let value = string_value(object.get(key), max_chars, true)?;
    Ok(if value.is_empty() {
        fallback.into()
    } else {
        value
    })
}

fn string_value(
    value: Option<&Value>,
    max_chars: usize,
    trim: bool,
) -> Result<String, BackendError> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    let raw = value
        .as_str()
        .ok_or_else(|| BackendError::new("invalid_params", "Expected a string value"))?;
    let raw = if trim { raw.trim() } else { raw };
    if raw.chars().count() > max_chars || raw.contains(['\0', '\n', '\r']) {
        return Err(BackendError::new(
            "invalid_params",
            "String value has an invalid length or characters",
        ));
    }
    Ok(raw.into())
}

fn required_bool(object: &Map<String, Value>, key: &str) -> Result<bool, BackendError> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| BackendError::new("invalid_params", format!("{key} must be a boolean")))
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    fallback: bool,
) -> Result<bool, BackendError> {
    match object.get(key) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| BackendError::new("invalid_params", format!("{key} must be a boolean"))),
        None => Ok(fallback),
    }
}

fn locale_value(value: Option<&Value>) -> Result<String, BackendError> {
    let raw = value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .replace('_', "-");
    let parts = raw.split('-').collect::<Vec<_>>();
    let valid = !raw.is_empty()
        && raw.len() <= 35
        && (2..=8).contains(&parts[0].len())
        && parts[0].bytes().all(|byte| byte.is_ascii_alphabetic())
        && parts.iter().skip(1).all(|part| {
            !part.is_empty()
                && part.len() <= 8
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        });
    if !valid {
        return Err(BackendError::new(
            "invalid_locale",
            "locale must be a valid bounded BCP 47 language tag",
        ));
    }

    let canonical = parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            if index == 0 {
                part.to_ascii_lowercase()
            } else if part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                part.to_ascii_uppercase()
            } else if part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                let mut value = part.to_ascii_lowercase();
                value[0..1].make_ascii_uppercase();
                value
            } else {
                part.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join("-");
    Ok(canonical)
}

fn bounded_usize(
    params: &Value,
    key: &str,
    fallback: usize,
    maximum: usize,
) -> Result<usize, BackendError> {
    let Some(value) = params.get(key) else {
        return Ok(fallback);
    };
    let value = value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| BackendError::new("invalid_params", format!("{key} must be an integer")))?;
    if value > maximum {
        return Err(BackendError::new(
            "invalid_params",
            format!("{key} exceeds the maximum"),
        ));
    }
    Ok(value)
}

fn nonempty(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn unique_id(prefix: &str, values: &[Value]) -> String {
    let now = now_ms();
    for sequence in 0_u64.. {
        let id = format!("{prefix}-{now:016x}-{sequence:04x}");
        if !values
            .iter()
            .any(|value| value.get("id").and_then(Value::as_str) == Some(id.as_str()))
        {
            return id;
        }
    }
    unreachable!()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn store_io_error(error: io::Error) -> BackendError {
    BackendError::new(
        "store_io",
        format!("Unable to persist canonical state: {error}"),
    )
    .retryable(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTree(PathBuf);

    impl TestTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "proton-omarchy-store-{label}-{}-{}",
                std::process::id(),
                now_ms()
            ));
            fs::create_dir_all(&path).expect("create isolated test tree");
            Self(path)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn initial_open_materializes_opt_out_autostart_and_private_files() {
        let tree = TestTree::new("initial-autostart");
        let store_path = tree.0.join("data/state-v1.json");
        let lifecycle_path = tree.0.join("config/proton-vpn-omarchy/lifecycle.json");
        let legacy_path = tree.0.join("legacy.json");
        let (state_tx, _state_rx) = watch::channel(StateSnapshot::default());
        let operations = OperationCoordinator::new(state_tx.clone());

        let store = StoreHandle::open(
            store_path.clone(),
            &legacy_path,
            lifecycle_path.clone(),
            state_tx,
            operations,
        )
        .expect("open a fresh canonical store");

        let autostart_link = tree
            .0
            .join("config/systemd/user/default.target.wants/proton-omarchy-agent.service");
        assert_eq!(
            fs::read_link(&autostart_link).expect("default-on autostart link"),
            PathBuf::from("/usr/lib/systemd/user/proton-omarchy-agent.service")
        );
        assert_eq!(
            fs::metadata(&store_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&lifecycle_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        store
            .request(
                "test-client",
                "preferences.set",
                json!({ "start_with_omarchy": false, "auto_connect": false }),
            )
            .expect("opt out of startup");
        assert!(!autostart_link.exists());

        store
            .request(
                "test-client",
                "preferences.set",
                json!({ "start_with_omarchy": false, "auto_connect": true }),
            )
            .expect("auto-connect implies startup");
        assert!(autostart_link.is_symlink());
        let summary = store
            .request("test-client", "store.get", json!({}))
            .expect("read canonical preferences");
        assert_eq!(summary.get("start_with_omarchy"), Some(&Value::Bool(true)));
        assert_eq!(summary.get("auto_connect"), Some(&Value::Bool(true)));
    }

    #[test]
    fn official_default_profiles_match_the_windows_contract() {
        let mut data = StoreFile::default();
        data.onboarding.locale = "es-MX".into();
        data.accounts
            .insert("account-test".into(), AccountStore::default());

        assert!(
            seed_account_with_official_profiles(&mut data, "account-test")
                .expect("seed official defaults")
        );
        let account = data.accounts.get("account-test").unwrap();
        assert_eq!(account.profiles.len(), 6);
        assert_eq!(account.profiles[0]["name"], "Streaming EE. UU.");
        assert_eq!(account.profiles[0]["countryCode"], "US");
        assert_eq!(account.profiles[0]["countryName"], "Estados Unidos");
        assert_eq!(account.profiles[1]["name"], "Juegos");
        assert_eq!(account.profiles[1]["targetKind"], "p2p");
        assert_eq!(account.profiles[1]["profileNatType"], "moderate");
        assert_eq!(account.profiles[2]["profilePortForwardingEnabled"], true);
        assert_eq!(account.profiles[3]["targetKind"], "secureCore");
        assert_eq!(account.profiles[4]["profileProtocol"], "protun-tls");
        assert_eq!(account.profiles[4]["profileNetShieldLevel"], 1);
        assert_eq!(account.profiles[4]["profileNatType"], "moderate");
        assert_eq!(account.profiles[5]["targetKind"], "random");

        let resolved = resolved_profile(&account.profiles[5], "profile")
            .expect("resolve random default profile");
        assert_eq!(resolved["connect_params"]["target"]["random"], true);
    }

    #[test]
    fn deleted_official_defaults_are_not_seeded_again() {
        let mut data = StoreFile::default();
        data.accounts
            .insert("account-test".into(), AccountStore::default());
        seed_account_with_official_profiles(&mut data, "account-test")
            .expect("seed official defaults");
        data.accounts
            .get_mut("account-test")
            .unwrap()
            .profiles
            .retain(|profile| profile["id"] != OFFICIAL_DEFAULT_PROFILE_IDS[0]);

        assert!(
            !seed_account_with_official_profiles(&mut data, "account-test")
                .expect("do not restore deleted defaults")
        );
        assert_eq!(data.accounts["account-test"].profiles.len(), 5);
    }

    #[test]
    fn recent_normalization_is_allowlisted_and_bounded() {
        let raw = json!({
            "kind": "country",
            "header": " Mexico ",
            "description": "Fastest server",
            "countryCode": "mx",
            "countryName": "Mexico",
            "feature": "tor",
            "load": 900,
            "unknownSecret": "must-not-persist"
        });
        let normalized = normalize_recent(raw.as_object().unwrap()).expect("normalize recent");

        assert_eq!(normalized.get("countryCode"), Some(&json!("MX")));
        assert_eq!(normalized.get("header"), Some(&json!("Mexico")));
        assert_eq!(normalized.get("load"), Some(&json!(100)));
        assert!(!normalized.contains_key("unknownSecret"));
    }

    #[test]
    fn profile_recents_require_a_real_profile() {
        let mut data = StoreFile::default();
        let error = record_recent(
            &mut data,
            &json!({
                "recent": {
                    "kind": "profile",
                    "profileId": "missing-profile",
                    "header": "Missing"
                }
            }),
        )
        .expect_err("dangling profile recent must be rejected");

        assert_eq!(error.code, "profile_not_found");
        assert!(account_ref(&data).recents.is_empty());
    }

    #[test]
    fn duplicating_profile_creates_a_new_identity_and_preserves_settings() {
        let mut data = StoreFile::default();
        let saved = save_profile(
            &mut data,
            &json!({
                "profile": {
                    "name": "Streaming",
                    "targetKind": "country",
                    "countryCode": "ch",
                    "profileProtocol": "protun-tls",
                    "profileNetShieldEnabled": true,
                    "profileNetShieldLevel": 2,
                    "profileNatType": "strict",
                    "profilePortForwardingEnabled": true
                }
            }),
        )
        .expect("save source profile");
        let source = saved.get("profile").unwrap();
        let source_id = source.get("id").and_then(Value::as_str).unwrap();
        let source_created = source.get("createdAtMs").cloned().unwrap();

        let copied = duplicate_profile(
            &mut data,
            &json!({ "id": source_id, "name": "Streaming copy" }),
        )
        .expect("duplicate profile");
        let copied = copied.get("profile").unwrap();
        assert_ne!(copied.get("id"), source.get("id"));
        assert_eq!(copied.get("name"), Some(&json!("Streaming copy")));
        assert_eq!(copied.get("countryCode"), Some(&json!("CH")));
        assert_eq!(copied.get("profileProtocol"), Some(&json!("protun-tls")));
        assert_eq!(
            copied.get("profilePortForwardingEnabled"),
            Some(&json!(true))
        );
        assert!(copied.get("createdAtMs").is_some());
        assert_eq!(account_ref(&data).profiles.len(), 2);
        assert_eq!(source.get("createdAtMs"), Some(&source_created));

        let generated = duplicate_profile(&mut data, &json!({ "id": source_id }))
            .expect("duplicate profile with generated name");
        assert_eq!(
            generated
                .get("profile")
                .and_then(|profile| profile.get("name")),
            Some(&json!("Streaming copy 2"))
        );
        assert_eq!(account_ref(&data).profiles.len(), 3);
    }

    #[test]
    fn older_profiles_inherit_new_dns_and_lan_policies() {
        let profile = normalize_profile(
            json!({
                "name": "Existing profile",
                "targetKind": "fastest",
                "profileNetShieldEnabled": false
            })
            .as_object()
            .unwrap(),
            None,
            "profile-existing",
        )
        .expect("normalize older profile");
        assert_eq!(profile["profileCustomDnsMode"], "inherit");
        assert_eq!(profile["profileCustomDnsServers"], json!([]));
        assert_eq!(profile["profileLanMode"], "inherit");
        assert_eq!(profile["profileLocalDnsMode"], "inherit");

        let resolved = resolved_profile(&Value::Object(profile), "profile")
            .expect("resolve inherited policies");
        assert_eq!(resolved["connect_params"]["profile_id"], "profile-existing");
        assert!(resolved["connect_params"]["profile_settings"]["allow_lan_connections"].is_null());
        assert!(resolved["connect_params"]["profile_settings"]["allow_local_dns"].is_null());
        assert_eq!(
            resolved["connect_params"]["profile_settings"]["custom_dns"]["mode"],
            "inherit"
        );
    }

    #[test]
    fn profile_dns_is_validated_normalized_and_deduplicated() {
        let profile = normalize_profile(
            json!({
                "name": "Private resolver",
                "targetKind": "fastest",
                "profileNetShieldEnabled": false,
                "profileCustomDnsMode": "custom",
                "profileCustomDnsServers": [" 1.1.1.1 ", "1.1.1.1", "2001:0db8::1"],
                "profileLanMode": "allow",
                "profileLocalDnsMode": "block"
            })
            .as_object()
            .unwrap(),
            None,
            "profile-dns",
        )
        .expect("normalize profile DNS");
        assert_eq!(
            profile["profileCustomDnsServers"],
            json!(["1.1.1.1", "2001:db8::1"])
        );
        let resolved =
            resolved_profile(&Value::Object(profile), "profile").expect("resolve profile DNS");
        assert_eq!(
            resolved["connect_params"]["profile_settings"]["allow_lan_connections"],
            true
        );
        assert_eq!(
            resolved["connect_params"]["profile_settings"]["allow_local_dns"],
            false
        );
    }

    #[test]
    fn profile_rejects_invalid_dns_and_netshield_conflict() {
        let invalid = normalize_profile(
            json!({
                "name": "Invalid DNS",
                "targetKind": "fastest",
                "profileNetShieldEnabled": false,
                "profileCustomDnsMode": "custom",
                "profileCustomDnsServers": ["not-an-ip"]
            })
            .as_object()
            .unwrap(),
            None,
            "profile-invalid-dns",
        )
        .expect_err("invalid DNS must fail");
        assert_eq!(invalid.code, "invalid_dns");

        let conflict = normalize_profile(
            json!({
                "name": "DNS and NetShield",
                "targetKind": "fastest",
                "profileNetShieldEnabled": true,
                "profileCustomDnsMode": "custom",
                "profileCustomDnsServers": ["9.9.9.9"]
            })
            .as_object()
            .unwrap(),
            None,
            "profile-conflict",
        )
        .expect_err("NetShield conflict must fail");
        assert_eq!(conflict.code, "profile_settings_conflict");
    }

    #[test]
    fn hierarchical_profiles_preserve_and_resolve_location_constraints() {
        let city = normalize_profile(
            json!({
                "name": "Seattle",
                "targetKind": "city",
                "countryCode": "us",
                "state": "Washington",
                "city": "Seattle"
            })
            .as_object()
            .unwrap(),
            None,
            "profile-city",
        )
        .expect("normalize city profile");
        let resolved =
            resolved_profile(&Value::Object(city), "profile").expect("resolve city profile");
        assert_eq!(resolved["connect_params"]["target"]["country_code"], "US");
        assert_eq!(resolved["connect_params"]["target"]["state"], "Washington");
        assert_eq!(resolved["connect_params"]["target"]["city"], "Seattle");

        let p2p_city = normalize_profile(
            json!({
                "name": "P2P Seattle",
                "targetKind": "p2p",
                "countryCode": "us",
                "state": "Washington",
                "city": "Seattle"
            })
            .as_object()
            .unwrap(),
            None,
            "profile-p2p-city",
        )
        .expect("normalize P2P city profile");
        let resolved = resolved_profile(&Value::Object(p2p_city), "profile")
            .expect("resolve P2P city profile");
        assert_eq!(resolved["connect_params"]["target"]["city"], "Seattle");
        assert_eq!(resolved["connect_params"]["target"]["p2p"], true);

        let secure_core = normalize_profile(
            json!({
                "name": "US via Switzerland",
                "targetKind": "secureCore",
                "countryCode": "us",
                "entryCountryCode": "ch"
            })
            .as_object()
            .unwrap(),
            None,
            "profile-secure-core",
        )
        .expect("normalize Secure Core profile");
        let resolved = resolved_profile(&Value::Object(secure_core), "profile")
            .expect("resolve Secure Core profile");
        assert_eq!(
            resolved["connect_params"]["target"]["entry_country_code"],
            "CH"
        );
        assert_eq!(resolved["connect_params"]["target"]["secure_core"], true);
    }

    #[test]
    fn profile_selection_strategy_is_independent_from_location_and_feature() {
        let country_random = normalize_profile(
            json!({
                "name": "Random Mexico",
                "targetKind": "country",
                "countryCode": "mx",
                "selectionStrategy": "random"
            })
            .as_object()
            .unwrap(),
            None,
            "profile-random-mx",
        )
        .expect("normalize scoped random profile");
        assert_eq!(country_random["countryCode"], "MX");
        assert_eq!(country_random["selectionStrategy"], "random");
        let resolved = resolved_profile(&Value::Object(country_random), "profile")
            .expect("resolve scoped random profile");
        assert_eq!(resolved["connect_params"]["target"]["country_code"], "MX");
        assert_eq!(resolved["connect_params"]["target"]["random_server"], true);
        assert!(resolved["connect_params"]["target"]["random"].is_null());

        let anti_censorship = normalize_profile(
            json!({
                "name": "Anti-censorship",
                "targetKind": "fastest",
                "excludeMyCountry": true
            })
            .as_object()
            .unwrap(),
            None,
            "profile-away",
        )
        .expect("normalize excluding profile");
        let resolved = resolved_profile(&Value::Object(anti_censorship), "profile")
            .expect("resolve excluding profile");
        assert_eq!(
            resolved["connect_params"]["target"]["exclude_my_country"],
            true
        );
    }

    #[test]
    fn hierarchical_recents_keep_state_and_city_in_their_identity() {
        let washington = normalize_recent(
            json!({
                "kind": "city",
                "header": "Seattle",
                "countryCode": "US",
                "state": "Washington",
                "city": "Seattle",
                "feature": "p2p"
            })
            .as_object()
            .unwrap(),
        )
        .expect("normalize Washington city");
        let resolved = resolved_recent(
            &AccountStore::default(),
            &Value::Object(washington.clone()),
            "last",
        )
        .expect("resolve P2P city");
        assert_eq!(resolved["connect_params"]["target"]["p2p"], true);
        let kansas = normalize_recent(
            json!({
                "kind": "city",
                "header": "Seattle",
                "countryCode": "US",
                "state": "Kansas",
                "city": "Seattle"
            })
            .as_object()
            .unwrap(),
        )
        .expect("normalize Kansas city");
        assert_ne!(recent_key(&washington), recent_key(&kansas));
    }

    #[test]
    fn locale_storage_accepts_bounded_bcp47_tags_and_canonicalizes_them() {
        assert_eq!(Onboarding::default().locale, "en");
        assert_eq!(locale_value(Some(&json!("es_mx"))).unwrap(), "es-MX");
        assert_eq!(
            locale_value(Some(&json!("zh-hant-tw"))).unwrap(),
            "zh-Hant-TW"
        );
        assert_eq!(locale_value(Some(&json!("pt-BR"))).unwrap(), "pt-BR");
        assert!(locale_value(Some(&json!("../locale"))).is_err());
        assert!(locale_value(Some(&json!("x"))).is_err());
        assert!(locale_value(Some(&json!("en-123456789"))).is_err());
    }
}
