use crate::bpf::FWMARK_VALUE;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io,
    net::IpAddr,
    process::{Command, Output},
};

const ROUTE_TABLE_BASE: u32 = 30_000;
const RULE_PRIORITY_BASE: u32 = 12_000;
// Private protocol tag used only as an additional ownership assertion. 242 is
// outside iproute2's named routing protocols; cleanup still deletes each exact
// tracked route and never treats this value as globally exclusive.
const ROUTE_PROTOCOL: u32 = 242;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalRoute {
    pub family: AddressFamily,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
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

    pub fn validated(&self) -> Result<Self, String> {
        Self::parse(
            match self.family {
                AddressFamily::Ipv4 => "ipv4",
                AddressFamily::Ipv6 => "ipv6",
            },
            &self
                .gateway
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &self.interface,
        )
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
    let families = route_families(&routes);
    for family in &families {
        ensure_family_available(uid, *family)?;
    }

    for route in &routes {
        if let Err(error) = install_route(uid, route) {
            let _ = disable(uid, &routes);
            return Err(error);
        }
    }
    for family in &families {
        let spec = rule_spec(uid, *family);
        if let Err(error) = run_ip(&spec.add_rule) {
            let _ = disable(uid, &routes);
            return Err(error);
        }
    }
    for family in &families {
        if let Err(error) = verify_family_ownership(uid, *family, &routes) {
            let _ = disable(uid, &routes);
            return Err(error);
        }
    }
    Ok(routes)
}

pub fn disable(uid: u16, routes: &[PhysicalRoute]) -> io::Result<()> {
    for family in route_families(routes) {
        let spec = rule_spec(uid, family);
        match run_ip(&spec.delete_rule) {
            Ok(_) => {}
            Err(error) if command_state_absent(&error) => {}
            Err(error) => return Err(error),
        }
    }
    for route in routes.iter().rev() {
        for command in route_commands(uid, route).into_iter().rev() {
            match run_ip(&command.delete) {
                Ok(_) => {}
                Err(error) if command_state_absent(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn install_route(uid: u16, route: &PhysicalRoute) -> io::Result<()> {
    let commands = route_commands(uid, route);
    let mut installed: Vec<Vec<String>> = Vec::new();
    for command in &commands {
        if let Err(error) = run_ip(&command.add) {
            for rollback in installed.into_iter().rev() {
                let _ = run_ip(&rollback);
            }
            return Err(error);
        }
        installed.push(command.delete.clone());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteCommand {
    add: Vec<String>,
    delete: Vec<String>,
}

fn route_commands(uid: u16, route: &PhysicalRoute) -> Vec<RouteCommand> {
    let spec = rule_spec(uid, route.family);
    let protocol = ROUTE_PROTOCOL.to_string();
    let mut commands = Vec::new();
    if let Some(gateway) = route.gateway {
        let prefix = if gateway.is_ipv4() { 32 } else { 128 };
        let destination = format!("{gateway}/{prefix}");
        commands.push(route_command(
            spec.family,
            &spec.table,
            &[&destination, "dev", &route.interface, "scope", "link"],
            &protocol,
        ));
        let gateway = gateway.to_string();
        commands.push(route_command(
            spec.family,
            &spec.table,
            &["default", "via", &gateway, "dev", &route.interface],
            &protocol,
        ));
    } else {
        commands.push(route_command(
            spec.family,
            &spec.table,
            &["default", "dev", &route.interface],
            &protocol,
        ));
    }
    commands
}

fn route_command(family: &str, table: &str, route: &[&str], protocol: &str) -> RouteCommand {
    let build = |verb: &str| {
        [family, "route", verb, "table", table]
            .into_iter()
            .chain(route.iter().copied())
            .chain(["proto", protocol])
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    RouteCommand {
        add: build("add"),
        delete: build("delete"),
    }
}

struct RuleSpec {
    family: &'static str,
    table: String,
    add_rule: Vec<String>,
    delete_rule: Vec<String>,
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
        table,
        add_rule,
        delete_rule,
    }
}

fn route_families(routes: &[PhysicalRoute]) -> BTreeSet<AddressFamily> {
    routes.iter().map(|route| route.family).collect()
}

fn ensure_family_available(uid: u16, family: AddressFamily) -> io::Result<()> {
    let spec = rule_spec(uid, family);
    let routes = route_inventory(spec.family, &spec.table)?;
    let rules = run_ip_json(&[
        spec.family,
        "-json",
        "rule",
        "show",
        "priority",
        &rule_priority(uid),
    ])?;
    if !inventory_is_empty(&routes)? || !inventory_is_empty(&rules)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "routing table or rule priority collision for UID {uid}; no routes were changed"
            ),
        ));
    }
    Ok(())
}

fn verify_family_ownership(
    uid: u16,
    family: AddressFamily,
    routes: &[PhysicalRoute],
) -> io::Result<()> {
    let spec = rule_spec(uid, family);
    let route_inventory = route_inventory(spec.family, &spec.table)?;
    let rule_inventory = run_ip_json(&[
        spec.family,
        "-json",
        "rule",
        "show",
        "priority",
        &rule_priority(uid),
    ])?;
    let expected_routes = routes
        .iter()
        .filter(|route| route.family == family)
        .map(|route| route_commands(uid, route).len())
        .sum();
    if !route_inventory_is_owned(&route_inventory, expected_routes)?
        || inventory_len(&rule_inventory)? != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("routing ownership changed while configuring UID {uid}"),
        ));
    }
    Ok(())
}

fn run_ip_json<S: AsRef<str>>(args: &[S]) -> io::Result<Vec<u8>> {
    run_ip(args).map(|output| output.stdout)
}

fn route_inventory(family: &str, table: &str) -> io::Result<Vec<u8>> {
    match run_ip_json(&[family, "-json", "route", "show", "table", table]) {
        Ok(value) => Ok(value),
        Err(error) if routing_table_absent(&error) => Ok(b"[]".to_vec()),
        Err(error) => Err(error),
    }
}

fn inventory(value: &[u8]) -> io::Result<Vec<Value>> {
    serde_json::from_slice::<Vec<Value>>(value).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ip returned an invalid JSON inventory: {error}"),
        )
    })
}

fn inventory_len(value: &[u8]) -> io::Result<usize> {
    inventory(value).map(|items| items.len())
}

fn inventory_is_empty(value: &[u8]) -> io::Result<bool> {
    inventory_len(value).map(|length| length == 0)
}

fn route_inventory_is_owned(value: &[u8], expected: usize) -> io::Result<bool> {
    let routes = inventory(value)?;
    Ok(routes.len() == expected
        && routes.iter().all(|route| {
            route.get("protocol").is_some_and(|protocol| {
                protocol.as_u64() == Some(u64::from(ROUTE_PROTOCOL))
                    || protocol
                        .as_str()
                        .and_then(|value| value.parse::<u32>().ok())
                        == Some(ROUTE_PROTOCOL)
            })
        }))
}

fn rule_priority(uid: u16) -> String {
    (RULE_PRIORITY_BASE + u32::from(uid)).to_string()
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

fn routing_table_absent(error: &io::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("fib table does not exist")
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

    #[test]
    fn cleanup_commands_delete_only_exact_owned_routes() {
        let route = PhysicalRoute::parse("ipv4", "192.0.2.1", "wlan0").unwrap();
        let commands = route_commands(1000, &route);
        assert_eq!(commands.len(), 2);
        for command in commands {
            assert!(command.add.iter().any(|value| value == "add"));
            assert!(command.delete.iter().any(|value| value == "delete"));
            assert!(command
                .delete
                .windows(2)
                .any(|pair| pair == ["table", "31000"]));
            assert!(command
                .delete
                .windows(2)
                .any(|pair| pair == ["proto", "242"]));
            assert!(!command.delete.iter().any(|value| value == "flush"));
        }
    }

    #[test]
    fn preexisting_routes_and_rules_are_collisions_not_owned_state() {
        let foreign_route =
            br#"[{"dst":"default","gateway":"192.0.2.254","dev":"eth0","protocol":"static"}]"#;
        let foreign_rule = br#"[{"priority":13000,"table":31000}]"#;
        assert!(!inventory_is_empty(foreign_route).unwrap());
        assert!(!inventory_is_empty(foreign_rule).unwrap());
        assert!(!route_inventory_is_owned(foreign_route, 1).unwrap());
    }

    #[test]
    fn ownership_verification_rejects_extra_or_foreign_routes() {
        let owned = br#"[
          {"dst":"192.0.2.1/32","dev":"wlan0","protocol":242},
          {"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"242"}
        ]"#;
        let with_foreign = br#"[
          {"dst":"192.0.2.1/32","dev":"wlan0","protocol":242},
          {"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"242"},
          {"dst":"203.0.113.0/24","dev":"eth0","protocol":"static"}
        ]"#;
        assert!(route_inventory_is_owned(owned, 2).unwrap());
        assert!(!route_inventory_is_owned(owned, 1).unwrap());
        assert!(!route_inventory_is_owned(with_foreign, 2).unwrap());
    }

    #[test]
    fn an_absent_kernel_table_is_empty_not_a_collision() {
        let error = io::Error::other("Error: ipv4: FIB table does not exist. Dump terminated");
        assert!(routing_table_absent(&error));
    }
}
