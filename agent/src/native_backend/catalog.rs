use super::{
    models::{
        country_name, LogicalServer, PhysicalServer, ServerCatalog, FEATURE_P2P,
        FEATURE_SECURE_CORE, FEATURE_TOR,
    },
    NativeError, NativeResult, MAX_SERVER_CATALOG_BYTES,
};
use crate::store::ExcludedLocation;
use rand::prelude::IndexedRandom;
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

const MAX_SERVER_QUERY_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct ConnectionTarget {
    pub logical: LogicalServer,
    pub physical: PhysicalServer,
}

impl ServerCatalog {
    pub fn load(path: &Path) -> NativeResult<Self> {
        let max_catalog_bytes = MAX_SERVER_CATALOG_BYTES as u64;
        let metadata = fs::metadata(path).map_err(|error| {
            NativeError::new(
                "catalog_unavailable",
                format!(
                    "The Proton server catalog is unavailable at {}",
                    path.display()
                ),
            )
            .with_source(error)
            .retryable(true)
        })?;
        if metadata.len() > max_catalog_bytes {
            return Err(NativeError::new(
                "catalog_invalid",
                "The Proton server catalog exceeds the size limit",
            ));
        }
        let mut raw = Vec::with_capacity(metadata.len() as usize);
        fs::File::open(path)
            .and_then(|file| file.take(max_catalog_bytes + 1).read_to_end(&mut raw))
            .map_err(|error| {
                NativeError::new(
                    "catalog_unavailable",
                    format!(
                        "The Proton server catalog is unavailable at {}",
                        path.display()
                    ),
                )
                .with_source(error)
                .retryable(true)
            })?;
        if raw.len() > MAX_SERVER_CATALOG_BYTES {
            return Err(NativeError::new(
                "catalog_invalid",
                "The Proton server catalog exceeds the size limit",
            ));
        }
        serde_json::from_slice(&raw).map_err(|error| {
            NativeError::new("catalog_invalid", "The Proton server catalog is invalid")
                .with_source(error)
                .retryable(true)
        })
    }

    pub fn servers_page(&self, params: &Value, tier: u8) -> NativeResult<Value> {
        let offset = bounded_u64(params.get("offset"), 0, 1_000_000)? as usize;
        let limit = bounded_u64(params.get("limit"), 100, 100)? as usize;
        let raw_query = string(params, "query");
        if raw_query.len() > MAX_SERVER_QUERY_BYTES {
            return Err(NativeError::new(
                "invalid_params",
                format!("query must be at most {MAX_SERVER_QUERY_BYTES} bytes"),
            ));
        }
        let query = normalize_search(&raw_query);
        let compact_query = compact_server_name(&query);
        let country_code = string(params, "country_code").to_ascii_uppercase();
        let gateway_name = string(params, "gateway_name");
        let feature = string(params, "feature").to_ascii_lowercase();
        let scope = string(params, "scope").to_ascii_lowercase();
        if !["", "all", "standard", "secure_core", "p2p", "tor"].contains(&feature.as_str()) {
            return Err(NativeError::new(
                "invalid_params",
                "Unknown server feature filter",
            ));
        }
        if !gateway_name.is_empty() && !["", "all"].contains(&feature.as_str()) {
            return Err(NativeError::new(
                "invalid_params",
                "Gateway and consumer feature filters cannot be combined",
            ));
        }
        if !["", "all", "consumer", "gateways"].contains(&scope.as_str()) {
            return Err(NativeError::new(
                "invalid_params",
                "Unknown server search scope",
            ));
        }

        let mut servers = self
            .logical_servers
            .iter()
            .filter(|server| server.tier <= tier)
            .filter(|server| country_code.is_empty() || server.exit_country == country_code)
            .filter(|server| gateway_name.is_empty() || server.gateway_name() == gateway_name)
            .filter(|server| match scope.as_str() {
                "consumer" => server.gateway_name().is_empty(),
                "gateways" => !server.gateway_name().is_empty(),
                _ => true,
            })
            .filter(|server| match feature.as_str() {
                "standard" => server.standard(),
                "secure_core" => server.features & FEATURE_SECURE_CORE != 0,
                "p2p" => server.features & FEATURE_P2P != 0,
                "tor" => server.features & FEATURE_TOR != 0,
                _ => true,
            })
            .filter(|server| {
                if query.is_empty() {
                    return true;
                }
                server_name_match_rank(&server.name, &query, &compact_query).is_some()
            })
            .collect::<Vec<_>>();

        servers.sort_by(|left, right| {
            server_name_match_rank(&left.name, &query, &compact_query)
                .cmp(&server_name_match_rank(&right.name, &query, &compact_query))
                .then_with(|| {
                    country_name(&left.exit_country).cmp(&country_name(&right.exit_country))
                })
                .then_with(|| {
                    (left.features & FEATURE_SECURE_CORE == 0)
                        .cmp(&(right.features & FEATURE_SECURE_CORE == 0))
                })
                .then_with(|| {
                    country_name(&left.entry_country).cmp(&country_name(&right.entry_country))
                })
                .then_with(|| left.city.cmp(&right.city))
                .then_with(|| left.name.cmp(&right.name))
        });

        let total = servers.len();
        let page = servers
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(LogicalServer::serialized)
            .collect::<Vec<_>>();

        Ok(json!({
            "offset": offset,
            "limit": limit,
            "total": total,
            "query": query,
            "country_code": country_code,
            "gateway_name": gateway_name,
            "feature": feature,
            "scope": scope,
            "servers": page,
        }))
    }

    pub fn locations(&self, tier: u8) -> Value {
        let mut countries: BTreeMap<String, Value> = BTreeMap::new();
        let mut gateways: BTreeMap<String, Value> = BTreeMap::new();
        let mut subdivisions: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
            BTreeMap::new();
        let mut p2p_subdivisions: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
            BTreeMap::new();
        let mut secure_core_entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for server in self
            .logical_servers
            .iter()
            .filter(|server| server.tier <= tier)
        {
            let gateway_name = server.gateway_name();
            if !gateway_name.is_empty() {
                let entry = gateways.entry(gateway_name.to_owned()).or_insert_with(|| {
                    json!({
                        "name": gateway_name,
                        "server_count": 0,
                        "available_server_count": 0,
                    })
                });
                increment(entry, "server_count");
                if server.enabled() {
                    increment(entry, "available_server_count");
                }
                continue;
            }
            if server.features & super::models::FEATURE_B2B != 0
                || server.features & super::models::FEATURE_PARTNER != 0
                || server.exit_country.is_empty()
            {
                continue;
            }

            let code = server.exit_country.to_ascii_uppercase();
            if server.features & FEATURE_SECURE_CORE != 0 && !server.entry_country.is_empty() {
                secure_core_entries
                    .entry(code.clone())
                    .or_default()
                    .insert(server.entry_country.to_ascii_uppercase());
            }
            if server.standard() {
                insert_subdivision(&mut subdivisions, &code, server);
            }
            if server.features & FEATURE_P2P != 0 {
                insert_subdivision(&mut p2p_subdivisions, &code, server);
            }
            let entry = countries.entry(code.clone()).or_insert_with(|| {
                json!({
                    "code": code,
                    "name": country_name(&server.exit_country),
                    "server_count": 0,
                    "available_server_count": 0,
                    "standard": false,
                    "secure_core": false,
                    "p2p": false,
                    "tor": false,
                    "streaming": false,
                })
            });
            increment(entry, "server_count");
            if server.enabled() {
                increment(entry, "available_server_count");
            }
            set_feature(entry, "standard", server.standard());
            set_feature(
                entry,
                "secure_core",
                server.features & FEATURE_SECURE_CORE != 0,
            );
            set_feature(entry, "p2p", server.features & FEATURE_P2P != 0);
            set_feature(entry, "tor", server.features & FEATURE_TOR != 0);
            set_feature(
                entry,
                "streaming",
                server.features & super::models::FEATURE_STREAMING != 0,
            );
        }

        for (code, country_value) in &mut countries {
            let Some(country) = country_value.as_object_mut() else {
                continue;
            };
            let (states, country_cities) =
                serialized_subdivisions(subdivisions.remove(code).unwrap_or_default());
            country.insert("cities".into(), json!(country_cities));
            country.insert("states".into(), json!(states));
            let (p2p_states, p2p_cities) =
                serialized_subdivisions(p2p_subdivisions.remove(code).unwrap_or_default());
            country.insert("p2p_cities".into(), json!(p2p_cities));
            country.insert("p2p_states".into(), json!(p2p_states));
            let entries = secure_core_entries
                .remove(code)
                .unwrap_or_default()
                .into_iter()
                .map(|entry_code| {
                    json!({
                        "code": entry_code,
                        "name": country_name(&entry_code),
                    })
                })
                .collect::<Vec<_>>();
            country.insert("secure_core_entries".into(), json!(entries));
        }

        let mut countries = countries.into_values().collect::<Vec<_>>();
        countries.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        let gateways = gateways.into_values().collect::<Vec<_>>();
        json!({ "countries": countries, "gateways": gateways })
    }

    pub fn select(
        &self,
        params: &Value,
        tier: u8,
        excluded_locations: &[ExcludedLocation],
        device_country: &str,
    ) -> NativeResult<ConnectionTarget> {
        let target = params
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| NativeError::new("invalid_params", "target must be a JSON object"))?;
        let server_name = object_string(target, "server_name");
        let country_code = object_string(target, "country_code").to_ascii_uppercase();
        let entry_country_code = object_string(target, "entry_country_code").to_ascii_uppercase();
        let state_name = object_string(target, "state");
        let city_name = object_string(target, "city");
        let gateway_name = object_string(target, "gateway_name");
        let secure_core = object_bool(target, "secure_core");
        let p2p = object_bool(target, "p2p");
        let tor = object_bool(target, "tor");
        let random_target = object_bool(target, "random");
        let random_server = object_bool(target, "random_server");
        let exclude_my_country = object_bool(target, "exclude_my_country");
        let free_random = object_bool(target, "free_random");
        let exclude_server_name = object_string(target, "exclude_server_name");

        let feature_count = usize::from(secure_core) + usize::from(p2p) + usize::from(tor);
        if feature_count > 1 || (!gateway_name.is_empty() && feature_count > 0) {
            return Err(NativeError::new(
                "invalid_params",
                "Gateway, Secure Core, P2P and Tor target modes cannot be combined",
            ));
        }
        if (!state_name.is_empty() || !city_name.is_empty()) && country_code.is_empty() {
            return Err(NativeError::new(
                "invalid_params",
                "State/city connection targets require country_code",
            ));
        }
        if !entry_country_code.is_empty() && !secure_core {
            return Err(NativeError::new(
                "invalid_params",
                "Secure Core entry-country targets require secure_core",
            ));
        }
        if random_target && random_server {
            return Err(NativeError::new(
                "invalid_params",
                "Country-random and server-random selection cannot be combined",
            ));
        }
        let device_country = device_country.trim().to_ascii_uppercase();
        if exclude_my_country && device_country.is_empty() {
            return Err(NativeError::new(
                "device_location_unavailable",
                "The current country is unavailable, so it cannot be excluded",
            )
            .retryable(true));
        }

        let available = self
            .logical_servers
            .iter()
            .filter(|server| server.enabled() && server.tier <= tier)
            .collect::<Vec<_>>();

        let logical = if !server_name.is_empty() {
            available
                .iter()
                .copied()
                .find(|server| server.name.eq_ignore_ascii_case(&server_name))
        } else {
            let mut candidates = available
                .iter()
                .copied()
                .filter(|server| gateway_name.is_empty() || server.gateway_name() == gateway_name)
                .filter(|server| country_code.is_empty() || server.exit_country == country_code)
                .filter(|server| {
                    !exclude_my_country
                        || !server.exit_country.eq_ignore_ascii_case(&device_country)
                })
                .filter(|server| {
                    entry_country_code.is_empty()
                        || server
                            .entry_country
                            .eq_ignore_ascii_case(&entry_country_code)
                })
                .filter(|server| {
                    state_name.is_empty() || server.state.eq_ignore_ascii_case(&state_name)
                })
                .filter(|server| {
                    city_name.is_empty() || server.city.eq_ignore_ascii_case(&city_name)
                })
                .filter(|server| !secure_core || server.features & FEATURE_SECURE_CORE != 0)
                .filter(|server| !p2p || server.features & FEATURE_P2P != 0)
                .filter(|server| !tor || server.features & FEATURE_TOR != 0)
                .filter(|server| {
                    secure_core || p2p || tor || !gateway_name.is_empty() || server.standard()
                })
                .filter(|server| !free_random || server.tier == 0)
                .filter(|server| {
                    exclude_server_name.is_empty()
                        || !server.name.eq_ignore_ascii_case(&exclude_server_name)
                })
                .collect::<Vec<_>>();

            let explicit_location = !server_name.is_empty()
                || !country_code.is_empty()
                || !entry_country_code.is_empty()
                || !state_name.is_empty()
                || !city_name.is_empty()
                || !gateway_name.is_empty();
            if tier > 0 && !explicit_location && !excluded_locations.is_empty() {
                let before_exclusions = candidates.len();
                candidates.retain(|server| {
                    !excluded_locations
                        .iter()
                        .any(|location| excluded_location_matches(location, server))
                });
                if before_exclusions > 0 && candidates.is_empty() {
                    return Err(NativeError::new(
                        "all_candidates_excluded",
                        "Every available server for this connection is in Excluded locations",
                    ));
                }
            }

            if random_target || free_random {
                // Windows' "Random country" is uniform over eligible countries,
                // then selects that country's best server. Choosing a logical
                // server directly would bias countries with larger fleets.
                let countries = candidates
                    .iter()
                    .map(|server| server.exit_country.as_str())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let selected_country = countries.choose(&mut rand::rng()).copied();
                candidates.retain(|server| selected_country == Some(server.exit_country.as_str()));
            }
            if random_server {
                candidates.choose(&mut rand::rng()).copied()
            } else {
                candidates.sort_by(|left, right| {
                    left.score
                        .partial_cmp(&right.score)
                        .unwrap_or(Ordering::Equal)
                });
                candidates.first().copied()
            }
        }
        .ok_or_else(|| {
            NativeError::new(
                "server_not_found",
                "No available Proton server matches this target",
            )
        })?;

        if secure_core && logical.features & FEATURE_SECURE_CORE == 0
            || p2p && logical.features & FEATURE_P2P == 0
            || tor && logical.features & FEATURE_TOR == 0
        {
            return Err(NativeError::new(
                "server_feature_mismatch",
                "Selected server does not provide the requested feature",
            ));
        }

        let physical = logical
            .servers
            .iter()
            .filter(|server| {
                server.status == 1
                    && !server.entry_ip.is_empty()
                    && !server.x25519_public_key.is_empty()
            })
            .collect::<Vec<_>>()
            .choose(&mut rand::rng())
            .copied()
            .cloned()
            .ok_or_else(|| {
                NativeError::new(
                    "server_not_found",
                    "Selected Proton server has no available physical endpoint",
                )
            })?;

        Ok(ConnectionTarget {
            logical: logical.clone(),
            physical,
        })
    }
}

fn excluded_location_matches(location: &ExcludedLocation, server: &LogicalServer) -> bool {
    if server.features & FEATURE_SECURE_CORE != 0
        && location.kind == "country"
        && server
            .entry_country
            .eq_ignore_ascii_case(&location.country_code)
    {
        return true;
    }
    if !server
        .exit_country
        .eq_ignore_ascii_case(&location.country_code)
    {
        return false;
    }
    match location.kind.as_str() {
        "country" => true,
        "state" => server.state.eq_ignore_ascii_case(&location.state),
        "city" => {
            (location.state.is_empty() || server.state.eq_ignore_ascii_case(&location.state))
                && server.city.eq_ignore_ascii_case(&location.city)
        }
        _ => false,
    }
}

fn string(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned()
}

pub(crate) fn normalize_search(value: &str) -> String {
    value
        .trim()
        .nfd()
        .filter(|character| !is_combining_mark(*character))
        .flat_map(char::to_lowercase)
        .collect()
}

pub(crate) fn compact_server_name(value: &str) -> String {
    normalize_search(value)
        .chars()
        .filter(|character| !matches!(character, '#' | '-') && !character.is_whitespace())
        .collect()
}

pub(crate) fn canonical_server_lookup_query(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || !trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '#' | '-'))
    {
        return None;
    }
    let mut canonical = trimmed.to_ascii_uppercase();
    let digit_index = canonical.find(|character: char| character.is_ascii_digit())?;
    let prefix = &canonical[..digit_index];
    if prefix
        .chars()
        .filter(|character| character.is_ascii_alphabetic())
        .count()
        < 2
        || !prefix
            .chars()
            .all(|character| character.is_ascii_alphabetic() || matches!(character, '#' | '-'))
    {
        return None;
    }
    if !prefix.contains('#') {
        if prefix.ends_with('-') {
            canonical.replace_range(digit_index - 1..digit_index, "#");
        } else {
            canonical.insert(digit_index, '#');
        }
    }
    Some(canonical)
}

fn server_name_match_rank(name: &str, query: &str, compact_query: &str) -> Option<u8> {
    if query.is_empty() {
        return Some(0);
    }
    let normalized_name = normalize_search(name);
    let compact_name = compact_server_name(&normalized_name);
    if normalized_name == query || (!compact_query.is_empty() && compact_name == compact_query) {
        return Some(0);
    }
    if normalized_name.starts_with(query)
        || (!compact_query.is_empty() && compact_name.starts_with(compact_query))
    {
        return Some(1);
    }
    normalized_name
        .match_indices(query)
        .any(|(index, _)| {
            index == 0
                || normalized_name[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|character| {
                        character.is_whitespace() || matches!(character, '#' | '-')
                    })
        })
        .then_some(2)
}

fn object_string(params: &serde_json::Map<String, Value>, key: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn object_bool(params: &serde_json::Map<String, Value>, key: &str) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn bounded_u64(value: Option<&Value>, default: u64, maximum: u64) -> NativeResult<u64> {
    let value = value.and_then(Value::as_u64).unwrap_or(default);
    if value > maximum {
        Err(NativeError::new(
            "invalid_params",
            "Numeric request parameter is out of range",
        ))
    } else {
        Ok(value)
    }
}

fn increment(value: &mut Value, key: &str) {
    if let Some(object) = value.as_object_mut() {
        let current = object.get(key).and_then(Value::as_u64).unwrap_or(0);
        object.insert(key.into(), json!(current + 1));
    }
}

fn set_feature(value: &mut Value, key: &str, enabled: bool) {
    if !enabled {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(key.into(), Value::Bool(true));
    }
}

fn insert_subdivision(
    subdivisions: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    country_code: &str,
    server: &LogicalServer,
) {
    let cities = subdivisions
        .entry(country_code.to_owned())
        .or_default()
        .entry(server.state.clone())
        .or_default();
    if !server.city.is_empty() {
        cities.insert(server.city.clone());
    }
}

fn serialized_subdivisions(
    subdivisions: BTreeMap<String, BTreeSet<String>>,
) -> (Vec<Value>, Vec<String>) {
    let mut country_cities = Vec::new();
    let mut states = Vec::new();
    for (state, cities) in subdivisions {
        let cities = cities.into_iter().collect::<Vec<_>>();
        if state.is_empty() {
            country_cities.extend(cities);
        } else {
            states.push(json!({ "name": state, "cities": cities }));
        }
    }
    (states, country_cities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_backend::models::{ServerLocation, FEATURE_PARTNER};

    fn logical(name: &str, country: &str, features: u32, score: f64) -> LogicalServer {
        LogicalServer {
            id: name.into(),
            name: name.into(),
            entry_country: country.into(),
            exit_country: country.into(),
            host_country: None,
            city: "City".into(),
            state: String::new(),
            region: None,
            domain: String::new(),
            tier: 0,
            features,
            load: 10,
            score,
            status: 1,
            location: ServerLocation::default(),
            servers: vec![PhysicalServer {
                id: format!("{name}-physical"),
                entry_ip: "192.0.2.1".into(),
                exit_ip: "192.0.2.2".into(),
                domain: "example.test".into(),
                status: 1,
                x25519_public_key: "key".into(),
                label: String::new(),
                extra: Default::default(),
            }],
            vpn_gateway_id: None,
            gateway_name: String::new(),
            extra: Default::default(),
        }
    }

    #[test]
    fn fastest_standard_excludes_secure_core_and_partner() {
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 0,
            logical_servers: vec![
                logical("SC", "CH", FEATURE_SECURE_CORE, 0.1),
                logical("Partner", "CH", FEATURE_PARTNER, 0.2),
                logical("Standard", "CH", 0, 0.3),
            ],
            extra: Default::default(),
        };
        let selected = catalog.select(&json!({"target": {}}), 0, &[], "").unwrap();
        assert_eq!(selected.logical.name, "Standard");
    }

    #[test]
    fn generic_paid_selection_respects_exclusions_but_explicit_targets_do_not() {
        let mut us = logical("US", "US", 0, 0.1);
        us.tier = 1;
        let mut ch = logical("CH", "CH", 0, 0.2);
        ch.tier = 1;
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 1,
            logical_servers: vec![us, ch],
            extra: Default::default(),
        };
        let excluded = vec![ExcludedLocation {
            kind: "country".into(),
            country_code: "US".into(),
            state: String::new(),
            city: String::new(),
        }];
        let selected = catalog
            .select(&json!({"target": {}}), 1, &excluded, "")
            .unwrap();
        assert_eq!(selected.logical.name, "CH");
        let explicit = catalog
            .select(&json!({"target": {"country_code": "US"}}), 1, &excluded, "")
            .unwrap();
        assert_eq!(explicit.logical.name, "US");
    }

    #[test]
    fn random_country_always_uses_the_best_server_in_the_chosen_country() {
        let mut us_best = logical("US-best", "US", 0, 0.1);
        us_best.tier = 1;
        let mut us_worse = logical("US-worse", "US", 0, 99.0);
        us_worse.tier = 1;
        let mut ch_best = logical("CH-best", "CH", 0, 0.2);
        ch_best.tier = 1;
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 1,
            logical_servers: vec![us_worse, ch_best, us_best],
            extra: Default::default(),
        };

        for _ in 0..64 {
            let selected = catalog
                .select(&json!({"target": {"random": true}}), 1, &[], "")
                .unwrap();
            assert!(matches!(
                selected.logical.name.as_str(),
                "US-best" | "CH-best"
            ));
        }
    }

    #[test]
    fn secure_core_can_target_an_entry_country_without_pinning_a_server() {
        let mut via_ch = logical("SC-via-CH", "US", FEATURE_SECURE_CORE, 0.5);
        via_ch.entry_country = "CH".into();
        via_ch.tier = 1;
        let mut via_se = logical("SC-via-SE", "US", FEATURE_SECURE_CORE, 0.1);
        via_se.entry_country = "SE".into();
        via_se.tier = 1;
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 1,
            logical_servers: vec![via_se, via_ch],
            extra: Default::default(),
        };

        let selected = catalog
            .select(
                &json!({"target": {
                    "country_code": "US",
                    "entry_country_code": "CH",
                    "secure_core": true
                }}),
                1,
                &[],
                "",
            )
            .unwrap();
        assert_eq!(selected.logical.name, "SC-via-CH");

        let error = catalog
            .select(&json!({"target": {"entry_country_code": "CH"}}), 1, &[], "")
            .unwrap_err();
        assert_eq!(error.code, "invalid_params");
    }

    #[test]
    fn automatic_selection_can_exclude_the_device_country() {
        let mut mx = logical("MX-best", "MX", 0, 0.01);
        mx.tier = 1;
        let mut us = logical("US-best", "US", 0, 0.50);
        us.tier = 1;
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 1,
            logical_servers: vec![mx, us],
            extra: Default::default(),
        };

        let selected = catalog
            .select(
                &json!({"target": {"exclude_my_country": true}}),
                1,
                &[],
                "MX",
            )
            .unwrap();
        assert_eq!(selected.logical.name, "US-best");
    }

    #[test]
    fn random_server_is_scoped_after_location_filters() {
        let mut mx_one = logical("MX#1", "MX", 0, 0.01);
        mx_one.tier = 1;
        let mut mx_two = logical("MX#2", "MX", 0, 0.99);
        mx_two.tier = 1;
        let mut us = logical("US#1", "US", 0, 0.01);
        us.tier = 1;
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 1,
            logical_servers: vec![mx_one, mx_two, us],
            extra: Default::default(),
        };

        for _ in 0..32 {
            let selected = catalog
                .select(
                    &json!({"target": {
                        "country_code": "MX",
                        "random_server": true
                    }}),
                    1,
                    &[],
                    "",
                )
                .unwrap();
            assert!(matches!(selected.logical.name.as_str(), "MX#1" | "MX#2"));
        }
    }

    #[test]
    fn locations_keep_standard_and_p2p_subdivisions_separate() {
        let mut standard = logical("Standard", "US", 0, 0.2);
        standard.state = "California".into();
        standard.city = "Los Angeles".into();
        let mut p2p = logical("P2P", "US", FEATURE_P2P, 0.1);
        p2p.state = "New York".into();
        p2p.city = "New York".into();
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 0,
            logical_servers: vec![standard, p2p],
            extra: Default::default(),
        };

        let locations = catalog.locations(0);
        let country = &locations["countries"][0];
        assert_eq!(country["states"][0]["name"], "California");
        assert_eq!(country["states"][0]["cities"][0], "Los Angeles");
        assert_eq!(country["p2p_states"][0]["name"], "New York");
        assert_eq!(country["p2p_states"][0]["cities"][0], "New York");
    }

    #[test]
    fn server_search_normalizes_accents_and_common_name_variants() {
        assert_eq!(normalize_search("  México  "), "mexico");
        assert_eq!(compact_server_name("US-FREE#42"), "usfree42");
        assert_eq!(server_name_match_rank("US#42", "us42", "us42"), Some(0));
        assert_eq!(
            server_name_match_rank("US-FREE#42", "free", "free"),
            Some(2)
        );
        assert_eq!(
            canonical_server_lookup_query("us42").as_deref(),
            Some("US#42")
        );
        assert_eq!(
            canonical_server_lookup_query("ch-us#12-a").as_deref(),
            Some("CH-US#12-A")
        );
        assert_eq!(
            canonical_server_lookup_query("us-ca-42").as_deref(),
            Some("US-CA#42")
        );
        assert_eq!(canonical_server_lookup_query("Mexico"), None);
    }

    #[test]
    fn server_search_does_not_turn_a_country_query_into_server_results() {
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 0,
            logical_servers: vec![logical("MX#1", "MX", 0, 0.1)],
            extra: Default::default(),
        };
        let result = catalog
            .servers_page(&json!({ "query": "Mexico", "feature": "standard" }), 0)
            .unwrap();
        assert_eq!(result["total"], 0);
    }

    #[test]
    fn server_search_scopes_gateways_away_from_consumer_servers() {
        let consumer = logical("US#1", "US", 0, 0.1);
        let mut gateway = logical("ACME#1", "US", 0, 0.2);
        gateway.gateway_name = "ACME".into();
        let catalog = ServerCatalog {
            expiration_time: 0.0,
            loads_expiration_time: 0.0,
            max_tier: 0,
            logical_servers: vec![consumer, gateway],
            extra: Default::default(),
        };

        let consumer_result = catalog
            .servers_page(&json!({ "query": "", "scope": "consumer" }), 0)
            .unwrap();
        let gateway_result = catalog
            .servers_page(&json!({ "query": "", "scope": "gateways" }), 0)
            .unwrap();
        assert_eq!(consumer_result["total"], 1);
        assert_eq!(gateway_result["total"], 1);
        assert_eq!(gateway_result["servers"][0]["name"], "ACME#1");
    }
}
