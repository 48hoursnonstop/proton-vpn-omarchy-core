use crate::bpf::FWMARK_VALUE;
use std::{
    collections::BTreeSet,
    io,
    net::IpAddr,
    process::{Command, Output},
};

const ROUTE_TABLE_BASE: u32 = 30_000;
const RULE_PRIORITY_BASE: u32 = 12_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalRoute {
    pub family: AddressFamily,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl PhysicalRoute {
    pub fn parse(family: &str, gateway: &str, interface: &str) -> Result<Self, String> {
        let family = match family {
            "ipv4" => AddressFamily::Ipv4,
            "ipv6" => AddressFamily::Ipv6,
            _ => return Err("route family must be ipv4 or ipv6".into()),
        };
        if interface.is_empty()
            || interface.len() > libc::IFNAMSIZ - 1
            || !interface.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err("route interface name is invalid".into());
        }
        if is_proton_interface(interface) {
            return Err("the bypass route must use a physical interface".into());
        }
        let gateway = if gateway.trim().is_empty() {
            None
        } else {
            Some(
                gateway
                    .parse::<IpAddr>()
                    .map_err(|_| "route gateway is not an IP address")?,
            )
        };
        if gateway.is_some_and(|gateway| {
            matches!(
                (family, gateway),
                (AddressFamily::Ipv4, IpAddr::V6(_)) | (AddressFamily::Ipv6, IpAddr::V4(_))
            )
        }) {
            return Err("route gateway family does not match".into());
        }
        Ok(Self {
            family,
            gateway,
            interface: interface.into(),
        })
    }
}

pub fn enable(uid: u16, routes: &[PhysicalRoute]) -> io::Result<Vec<PhysicalRoute>> {
    let routes = preferred_routes(routes);
    if routes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no physical default route is available for split tunneling",
        ));
    }
    disable(uid)?;
    for route in &routes {
        if let Err(error) = install_route(uid, route) {
            let _ = disable(uid);
            return Err(error);
        }
    }
    Ok(routes)
}

pub fn disable(uid: u16) -> io::Result<()> {
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let spec = rule_spec(uid, family);
        // Deletion is intentionally exact. A missing rule is already the
        // desired state, while unrelated rules at the same priority survive.
        loop {
            match run_ip(&spec.delete_rule) {
                Ok(_) => continue,
                Err(error) if command_state_absent(&error) => break,
                Err(error) => return Err(error),
            }
        }
        let _ = run_ip(&spec.flush_table);
    }
    Ok(())
}

fn install_route(uid: u16, route: &PhysicalRoute) -> io::Result<()> {
    let spec = rule_spec(uid, route.family);
    if let Some(gateway) = route.gateway {
        let prefix = if gateway.is_ipv4() { 32 } else { 128 };
        run_ip(&[
            spec.family,
            "route",
            "replace",
            "table",
            &spec.table,
            &format!("{gateway}/{prefix}"),
            "dev",
            &route.interface,
            "scope",
            "link",
        ])?;
        run_ip(&[
            spec.family,
            "route",
            "replace",
            "table",
            &spec.table,
            "default",
            "via",
            &gateway.to_string(),
            "dev",
            &route.interface,
        ])?;
    } else {
        run_ip(&[
            spec.family,
            "route",
            "replace",
            "table",
            &spec.table,
            "default",
            "dev",
            &route.interface,
        ])?;
    }
    run_ip(&spec.add_rule)?;
    Ok(())
}

struct RuleSpec {
    family: &'static str,
    table: String,
    add_rule: Vec<String>,
    delete_rule: Vec<String>,
    flush_table: Vec<String>,
}

fn rule_spec(uid: u16, family: AddressFamily) -> RuleSpec {
    let family = match family {
        AddressFamily::Ipv4 => "-4",
        AddressFamily::Ipv6 => "-6",
    };
    let table = (ROUTE_TABLE_BASE + u32::from(uid)).to_string();
    let priority = (RULE_PRIORITY_BASE + u32::from(uid)).to_string();
    let mark = format!("{FWMARK_VALUE:#x}/0xffffffff");
    let uid_range = format!("{uid}-{uid}");
    let rule = vec![
        family.into(),
        "rule".into(),
        "priority".into(),
        priority,
        "fwmark".into(),
        mark,
        "uidrange".into(),
        uid_range,
        "lookup".into(),
        table.clone(),
    ];
    let mut add_rule = rule.clone();
    add_rule.insert(2, "add".into());
    let mut delete_rule = rule;
    delete_rule.insert(2, "delete".into());
    RuleSpec {
        family,
        table: table.clone(),
        add_rule,
        delete_rule,
        flush_table: vec![
            family.into(),
            "route".into(),
            "flush".into(),
            "table".into(),
            table,
        ],
    }
}

fn preferred_routes(routes: &[PhysicalRoute]) -> Vec<PhysicalRoute> {
    let unique = routes.iter().cloned().collect::<BTreeSet<_>>();
    [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .into_iter()
        .filter_map(|family| unique.iter().find(|route| route.family == family).cloned())
        .collect()
}

fn run_ip<S: AsRef<str>>(args: &[S]) -> io::Result<Output> {
    let output = Command::new("/usr/bin/ip")
        .args(args.iter().map(AsRef::as_ref))
        .output()
        .map_err(|error| io::Error::new(error.kind(), format!("unable to invoke ip: {error}")))?;
    if output.status.success() {
        return Ok(output);
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(io::Error::other(if detail.is_empty() {
        format!("ip exited with {}", output.status)
    } else {
        detail
    }))
}

fn command_state_absent(error: &io::Error) -> bool {
    let value = error.to_string().to_ascii_lowercase();
    value.contains("no such file") || value.contains("no such process")
}

fn is_proton_interface(interface: &str) -> bool {
    matches!(
        interface,
        "proton0" | "pvpnksintrf0" | "pvpnksintrf1" | "ipv6leakintrf0" | "ipv6leakintrf1"
    ) || interface.starts_with("pvpnrouteintrf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_physical_route_boundaries() {
        assert!(PhysicalRoute::parse("ipv4", "192.0.2.1", "wlan0").is_ok());
        assert!(PhysicalRoute::parse("ipv6", "fe80::1", "enp2s0").is_ok());
        assert!(PhysicalRoute::parse("ipv4", "fe80::1", "wlan0").is_err());
        assert!(PhysicalRoute::parse("ipv4", "192.0.2.1", "proton0").is_err());
        assert!(PhysicalRoute::parse("ipv4", "192.0.2.1", "bad name").is_err());
    }

    #[test]
    fn rule_is_scoped_to_mark_and_uid() {
        let spec = rule_spec(1000, AddressFamily::Ipv4);
        assert_eq!(spec.family, "-4");
        assert!(spec
            .add_rule
            .windows(2)
            .any(|pair| pair == ["uidrange", "1000-1000"]));
        assert!(spec
            .add_rule
            .windows(2)
            .any(|pair| pair == ["fwmark", "0xea13b2c/0xffffffff"]));
        assert!(spec
            .add_rule
            .windows(2)
            .any(|pair| pair == ["lookup", "31000"]));
    }
}
