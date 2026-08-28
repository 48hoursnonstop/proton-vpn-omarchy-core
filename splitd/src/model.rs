use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use ipnet::IpNet;

pub const MAX_CONFIGS: usize = 64;
pub const MAX_PATHS: usize = 256;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_IP_RANGES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    Exclude,
    Include,
}

impl SplitMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "exclude" => Ok(Self::Exclude),
            "include" => Ok(Self::Include),
            _ => Err("mode must be 'exclude' or 'include'".into()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exclude => "exclude",
            Self::Include => "include",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SplitConfig {
    pub mode: SplitMode,
    pub app_paths: Vec<String>,
    pub ip_ranges: Vec<String>,
}

impl SplitConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.app_paths.len() > MAX_PATHS {
            return Err(format!("at most {MAX_PATHS} application paths are allowed"));
        }
        if self.ip_ranges.len() > MAX_IP_RANGES {
            return Err(format!("at most {MAX_IP_RANGES} IP ranges are allowed"));
        }
        if self
            .app_paths
            .iter()
            .chain(self.ip_ranges.iter())
            .any(|value| value.len() > MAX_PATH_BYTES || value.contains('\0'))
        {
            return Err(format!(
                "configuration values must be at most {MAX_PATH_BYTES} bytes"
            ));
        }
        let ip_ranges = validate_ip_ranges(self.ip_ranges)?;
        Ok(Self {
            mode: self.mode,
            app_paths: normalize(self.app_paths),
            ip_ranges,
        })
    }

    pub fn has_app_rules(&self) -> bool {
        self.app_paths.iter().any(|path| !path.is_empty())
    }

    pub fn has_rules(&self) -> bool {
        self.has_app_rules() || !self.ip_ranges.is_empty()
    }

    pub fn matches(&self, identities: &[String]) -> bool {
        if self.mode == SplitMode::Include
            && identities.iter().any(|identity| {
                identity.contains("protonvpn-app") || identity.contains("proton-omarchy-agent")
            })
        {
            return true;
        }
        self.app_paths
            .iter()
            .filter(|path| !path.is_empty())
            .any(|path| identities.iter().any(|identity| identity.starts_with(path)))
    }

    pub fn excludes(&self, matched: bool) -> bool {
        match self.mode {
            SplitMode::Exclude => matched,
            SplitMode::Include => !matched,
        }
    }
}

pub type ConfigMap = BTreeMap<u16, SplitConfig>;
pub type PolicyMap = BTreeMap<u16, Vec<String>>;

pub fn validate_ip_ranges(values: Vec<String>) -> Result<Vec<String>, String> {
    if values.len() > MAX_IP_RANGES {
        return Err(format!("at most {MAX_IP_RANGES} IP ranges are allowed"));
    }
    if values
        .iter()
        .any(|value| value.len() > MAX_PATH_BYTES || value.contains('\0'))
    {
        return Err(format!(
            "configuration values must be at most {MAX_PATH_BYTES} bytes"
        ));
    }
    let values = values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| canonical_ip_range(&value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(normalize(values))
}

fn normalize(values: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    normalized
}

pub fn parse_ip_range(value: &str) -> Result<IpNet, String> {
    let value = value.trim();
    IpNet::from_str(value)
        .or_else(|_| {
            IpAddr::from_str(value).map(|address| match address {
                IpAddr::V4(address) => IpNet::new(address.into(), 32).expect("valid IPv4 prefix"),
                IpAddr::V6(address) => IpNet::new(address.into(), 128).expect("valid IPv6 prefix"),
            })
        })
        .map(|network| network.trunc())
        .map_err(|_| format!("invalid IP address or CIDR range: {value}"))
}

fn canonical_ip_range(value: &str) -> Result<String, String> {
    parse_ip_range(value).map(|network| network.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_controls_marking_semantics() {
        let exclude = SplitConfig {
            mode: SplitMode::Exclude,
            app_paths: vec!["/usr/bin/firefox".into()],
            ip_ranges: vec![],
        };
        let include = SplitConfig {
            mode: SplitMode::Include,
            app_paths: exclude.app_paths.clone(),
            ip_ranges: vec![],
        };
        let firefox = vec!["/usr/bin/firefox --new-window".into()];
        assert!(exclude.excludes(exclude.matches(&firefox)));
        assert!(!include.excludes(include.matches(&firefox)));
        assert!(include.excludes(include.matches(&["/usr/bin/steam".into()])));
    }

    #[test]
    fn native_agent_is_never_excluded_in_include_mode() {
        let config = SplitConfig {
            mode: SplitMode::Include,
            app_paths: vec!["/usr/bin/firefox".into()],
            ip_ranges: vec![],
        };
        assert!(config.matches(&["/usr/bin/proton-omarchy-agent".into()]));
        assert!(!config.excludes(true));
    }

    #[test]
    fn ip_ranges_are_validated_deduplicated_and_canonicalized() {
        let config = SplitConfig {
            mode: SplitMode::Exclude,
            app_paths: vec![],
            ip_ranges: vec![
                "192.0.2.42/24".into(),
                "192.0.2.0/24".into(),
                "2001:db8::1".into(),
            ],
        }
        .validate()
        .unwrap();
        assert_eq!(config.ip_ranges, ["192.0.2.0/24", "2001:db8::1/128"]);
        assert!(SplitConfig {
            mode: SplitMode::Exclude,
            app_paths: vec![],
            ip_ranges: vec!["not-an-address".into()],
        }
        .validate()
        .is_err());
    }
}
