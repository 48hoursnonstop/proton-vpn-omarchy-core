use super::{
    models::{
        country_name, LogicalServer, PhysicalServer, ServerCatalog, FEATURE_P2P,
        FEATURE_SECURE_CORE, FEATURE_TOR,
    },
    NativeError, NativeResult,
};
use crate::store::ExcludedLocation;
use rand::prelude::IndexedRandom;
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Clone, Debug)]
pub struct ConnectionTarget {
    pub logical: LogicalServer,
    pub physical: PhysicalServer,
}

impl ServerCatalog {
    pub fn load(path: &Path) -> NativeResult<Self> {
        let raw = fs::read(path).map_err(|error| {
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
        serde_json::from_slice(&raw).map_err(|error| {
            NativeError::new("catalog_invalid", "The Proton server catalog is invalid")
                .with_source(error)
                .retryable(true)
        })
    }

    pub fn servers_page(&self, params: &Value, tier: u8) -> NativeResult<Value> {
        let offset = bounded_u64(params.get("offset"), 0, 1_000_000)? as usize;
        let limit = bounded_u64(params.get("limit"), 100, 100)? as usize;
        let query = string(params, "query").to_ascii_lowercase();
        let country_code = string(params, "country_code").to_ascii_uppercase();
        let gateway_name = string(params, "gateway_name");
        let feature = string(params, "feature").to_ascii_lowercase();
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

        let mut servers = self
            .logical_servers
            .iter()
            .filter(|server| server.tier <= tier)
            .filter(|server| country_code.is_empty() || server.exit_country == country_code)
            .filter(|server| gateway_name.is_empty() || server.gateway_name() == gateway_name)
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
                let haystack = format!(
                    "{} {} {} {} {} {} {} {}",
                    server.name,
                    server.exit_country,
                    country_name(&server.exit_country),
                    server.entry_country,
                    country_name(&server.entry_country),
                    server.state,
                    server.city,
                    server.region.as_deref().unwrap_or_default(),
                )
                .to_ascii_lowercase();
                haystack.contains(&query)
            })
            .collect::<Vec<_>>();

        servers.sort_by(|left, right| {
            country_name(&left.exit_country)
                .cmp(&country_name(&right.exit_country))
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
            "servers": page,
        }))
    }

    pub fn locations(&self, tier: u8) -> Value {
        let mut countries: BTreeMap<String, Value> = BTreeMap::new();
        let mut gateways: BTreeMap<String, Value> = BTreeMap::new();
        let mut subdivisions: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
            BTreeMap::new();

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
            let by_state = subdivisions.entry(code.clone()).or_default();
            let cities = by_state.entry(server.state.clone()).or_default();
            if !server.city.is_empty() {
                cities.insert(server.city.clone());
            }
            let entry = countries.entry(code.clone()).or_insert_with(|| {
                json!({
                    "code": code,
                    "name": country_name(&server.exit_country),
                    "server_count": 0,
                    "available_server_count": 0,
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

        for (code, by_state) in subdivisions {
            let Some(country) = countries.get_mut(&code).and_then(Value::as_object_mut) else {
                continue;
            };
            let mut country_cities = Vec::new();
            let mut states = Vec::new();
            for (state, cities) in by_state {
                let cities = cities.into_iter().collect::<Vec<_>>();
                if state.is_empty() {
                    country_cities.extend(cities);
                } else {
                    states.push(json!({ "name": state, "cities": cities }));
                }
            }
            country.insert("cities".into(), json!(country_cities));
            country.insert("states".into(), json!(states));
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
    ) -> NativeResult<ConnectionTarget> {
        let target = params
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| NativeError::new("invalid_params", "target must be a JSON object"))?;
        let server_name = object_string(target, "server_name");
        let country_code = object_string(target, "country_code").to_ascii_uppercase();
        let state_name = object_string(target, "state");
        let city_name = object_string(target, "city");
        let gateway_name = object_string(target, "gateway_name");
        let secure_core = object_bool(target, "secure_core");
        let p2p = object_bool(target, "p2p");
        let tor = object_bool(target, "tor");
        let random_target = object_bool(target, "random");
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
        let selected = catalog.select(&json!({"target": {}}), 0, &[]).unwrap();
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
            .select(&json!({"target": {}}), 1, &excluded)
            .unwrap();
        assert_eq!(selected.logical.name, "CH");
        let explicit = catalog
            .select(&json!({"target": {"country_code": "US"}}), 1, &excluded)
            .unwrap();
        assert_eq!(explicit.logical.name, "US");
    }
}
