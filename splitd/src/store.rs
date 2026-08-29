use crate::{
    model::{validate_ip_ranges, ConfigMap, PolicyMap, MAX_CONFIGS},
    routing::PhysicalRoute,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const SCHEMA_VERSION: u32 = 2;
const MAX_STATE_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_STATE_PATH: &str = "/var/lib/proton-vpn-omarchy/split-tunneling-v1.json";

#[derive(Clone, Debug)]
pub struct StateStore {
    path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    schema_version: u32,
    configs: ConfigMap,
    #[serde(default)]
    destination_policies: PolicyMap,
    #[serde(default)]
    kill_switch_bypass: std::collections::BTreeMap<u16, Vec<PhysicalRoute>>,
}

#[derive(Debug, Default)]
pub struct LoadedState {
    pub configs: ConfigMap,
    pub destination_policies: PolicyMap,
    pub kill_switch_bypass: std::collections::BTreeMap<u16, Vec<PhysicalRoute>>,
}

impl StateStore {
    pub fn system() -> Self {
        Self {
            path: Some(PathBuf::from(DEFAULT_STATE_PATH)),
        }
    }

    pub fn ephemeral() -> Self {
        Self { path: None }
    }

    #[cfg(test)]
    pub fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn load(&self) -> io::Result<LoadedState> {
        let Some(path) = &self.path else {
            return Ok(LoadedState::default());
        };
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LoadedState::default())
            }
            Err(error) => return Err(with_path("open state", path, error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| with_path("inspect state", path, error))?;
        if metadata.len() > MAX_STATE_BYTES {
            return Err(invalid_state(path, "state file exceeds the 2 MiB limit"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| with_path("read state", path, error))?;
        let stored: StoredState = serde_json::from_slice(&bytes)
            .map_err(|error| invalid_state(path, &format!("invalid JSON: {error}")))?;
        if !matches!(stored.schema_version, 1 | SCHEMA_VERSION) {
            return Err(invalid_state(
                path,
                &format!("unsupported schema version {}", stored.schema_version),
            ));
        }
        if stored.configs.len().max(stored.destination_policies.len()) > MAX_CONFIGS {
            return Err(invalid_state(path, "too many configured users"));
        }
        let configs = stored
            .configs
            .into_iter()
            .map(|(uid, config)| {
                config
                    .validate()
                    .map(|config| (uid, config))
                    .map_err(|error| invalid_state(path, &format!("UID {uid}: {error}")))
            })
            .collect::<io::Result<ConfigMap>>()?;
        let destination_policies = stored
            .destination_policies
            .into_iter()
            .map(|(uid, ranges)| {
                validate_ip_ranges(ranges)
                    .map(|ranges| (uid, ranges))
                    .map_err(|error| invalid_state(path, &format!("UID {uid} policy: {error}")))
            })
            .collect::<io::Result<PolicyMap>>()?;
        let kill_switch_bypass = stored
            .kill_switch_bypass
            .into_iter()
            .map(|(uid, routes)| {
                if routes.is_empty() || routes.len() > 2 {
                    return Err(invalid_state(
                        path,
                        &format!("UID {uid} has an invalid bypass-route count"),
                    ));
                }
                if !configs.get(&uid).is_some_and(|config| config.has_rules()) {
                    return Err(invalid_state(
                        path,
                        &format!("UID {uid} has bypass routes without a split policy"),
                    ));
                }
                let routes = routes
                    .iter()
                    .map(PhysicalRoute::validated)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| invalid_state(path, &format!("UID {uid}: {error}")))?;
                let families = routes
                    .iter()
                    .map(|route| route.family)
                    .collect::<std::collections::BTreeSet<_>>();
                if families.len() != routes.len() {
                    return Err(invalid_state(
                        path,
                        &format!("UID {uid} has duplicate bypass-route families"),
                    ));
                }
                Ok((uid, routes))
            })
            .collect::<io::Result<std::collections::BTreeMap<_, _>>>()?;
        Ok(LoadedState {
            configs,
            destination_policies,
            kill_switch_bypass,
        })
    }

    pub fn save(
        &self,
        configs: &ConfigMap,
        destination_policies: &PolicyMap,
        kill_switch_bypass: &std::collections::BTreeMap<u16, Vec<PhysicalRoute>>,
    ) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent")
        })?;
        fs::create_dir_all(parent)
            .map_err(|error| with_path("create state directory", parent, error))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| with_path("secure state directory", parent, error))?;

        let stored = StoredState {
            schema_version: SCHEMA_VERSION,
            configs: configs.clone(),
            destination_policies: destination_policies.clone(),
            kill_switch_bypass: kill_switch_bypass.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serialized split-tunneling state exceeds the 2 MiB limit",
            ));
        }

        let temporary = temporary_path(path);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|error| with_path("create temporary state", &temporary, error))?;
            file.write_all(&bytes)
                .map_err(|error| with_path("write temporary state", &temporary, error))?;
            file.write_all(b"\n")
                .map_err(|error| with_path("finish temporary state", &temporary, error))?;
            file.sync_all()
                .map_err(|error| with_path("sync temporary state", &temporary, error))?;
            fs::rename(&temporary, path)
                .map_err(|error| with_path("replace state", path, error))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| with_path("sync state directory", parent, error))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("split-tunneling-state");
    path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

fn invalid_state(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid split-tunneling state {}: {detail}", path.display()),
    )
}

fn with_path(action: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("unable to {action} {}: {error}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SplitConfig, SplitMode};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "proton-omarchy-splitd-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn durable_round_trip_preserves_validated_configs() {
        let directory = test_path("round-trip");
        let path = directory.join("state.json");
        let store = StateStore::at(path.clone());
        let configs = ConfigMap::from([(
            1000,
            SplitConfig {
                mode: SplitMode::Exclude,
                app_paths: vec!["/usr/bin/firefox".into()],
                ip_ranges: vec!["192.0.2.0/24".into()],
            },
        )]);
        let policies = PolicyMap::from([(1000, vec!["192.168.0.0/16".into(), "fe80::/10".into()])]);
        let bypass = std::collections::BTreeMap::from([(
            1000,
            vec![PhysicalRoute::parse("ipv4", "192.0.2.1", "wlan0").unwrap()],
        )]);
        store.save(&configs, &policies, &bypass).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.configs, configs);
        assert_eq!(loaded.destination_policies, policies);
        assert_eq!(loaded.kill_switch_bypass, bypass);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_state_fails_closed_without_overwriting_it() {
        let directory = test_path("malformed");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.json");
        fs::write(&path, b"{ definitely not json").unwrap();
        let original = fs::read(&path).unwrap();
        assert_eq!(
            StateStore::at(path.clone()).load().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }
}
