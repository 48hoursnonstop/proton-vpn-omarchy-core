mod bpf;
mod engine;
mod model;
mod proc_events;
mod procfs;
mod store;

use engine::Engine;
use model::{validate_ip_ranges, SplitConfig, SplitMode};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
};
use zbus::{
    fdo,
    message::Header,
    zvariant::{OwnedValue, Str, Value},
    Connection,
};

const SERVICE: &str = "me.proton.vpn.split_tunneling";
const PATH: &str = "/me/proton/vpn/split_tunneling";

struct SplitTunnelService {
    connection: Connection,
    engine: Arc<Engine>,
}

#[zbus::interface(name = "me.proton.vpn.split_tunneling")]
impl SplitTunnelService {
    #[zbus(name = "SetConfig")]
    async fn set_config(
        &self,
        uid: u16,
        config: HashMap<String, OwnedValue>,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        self.authorize(&header, uid).await?;
        let config = config_from_dbus(config).map_err(fdo::Error::InvalidArgs)?;
        self.engine
            .set_config(uid, config)
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(name = "GetConfig")]
    async fn get_config(
        &self,
        uid: u16,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<HashMap<String, OwnedValue>> {
        self.authorize(&header, uid).await?;
        self.engine
            .get_config(uid)
            .await
            .map(config_to_dbus)
            .transpose()
            .map(|config| config.unwrap_or_default())
    }

    #[zbus(name = "ClearConfig")]
    async fn clear_config(&self, uid: u16, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        self.authorize(&header, uid).await?;
        self.engine
            .clear_config(uid)
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(name = "LogStatus")]
    async fn log_status(&self) {
        let (configs, processes, attached) = self.engine.status().await;
        eprintln!(
            "proton-omarchy-splitd: configs={configs} tracked_processes={processes} ebpf_attached={attached}"
        );
    }

    /// Project extension kept separate from Proton's frozen SetConfig ABI.
    /// These destinations always bypass the VPN and back LAN/local-DNS policy.
    #[zbus(name = "SetDestinationPolicy")]
    async fn set_destination_policy(
        &self,
        uid: u16,
        ranges: Vec<String>,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        self.authorize(&header, uid).await?;
        let ranges = validate_ip_ranges(ranges).map_err(fdo::Error::InvalidArgs)?;
        self.engine
            .set_destination_policy(uid, ranges)
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(name = "GetDestinationPolicy")]
    async fn get_destination_policy(
        &self,
        uid: u16,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<Vec<String>> {
        self.authorize(&header, uid).await?;
        Ok(self.engine.destination_policy(uid).await)
    }

    #[zbus(name = "GetAllConfigs")]
    async fn get_all_configs(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<Vec<(u16, HashMap<String, OwnedValue>)>> {
        let caller = self.caller_uid(&header).await?;
        let configs = self.engine.get_all_configs().await;
        configs
            .into_iter()
            .filter(|(uid, _)| caller == 0 || u32::from(*uid) == caller)
            .map(|(uid, config)| config_to_dbus(config).map(|config| (uid, config)))
            .collect()
    }
}

impl SplitTunnelService {
    async fn authorize(&self, header: &Header<'_>, requested_uid: u16) -> fdo::Result<()> {
        let caller = self.caller_uid(header).await?;
        if caller == 0 || caller == u32::from(requested_uid) {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "split-tunneling configuration may only target the calling user".into(),
            ))
        }
    }

    async fn caller_uid(&self, header: &Header<'_>) -> fdo::Result<u32> {
        let sender = header
            .sender()
            .cloned()
            .ok_or_else(|| fdo::Error::AccessDenied("D-Bus sender identity missing".into()))?;
        let proxy = fdo::DBusProxy::new(&self.connection).await?;
        proxy.get_connection_unix_user(sender.into()).await
    }
}

fn config_from_dbus(mut values: HashMap<String, OwnedValue>) -> Result<SplitConfig, String> {
    let mode = values
        .remove("mode")
        .ok_or_else(|| "mode is required".to_owned())
        .and_then(|value| String::try_from(value).map_err(|_| "mode must be a string".into()))?;
    let app_paths = values
        .remove("app_paths")
        .ok_or_else(|| "app_paths is required".to_owned())
        .and_then(|value| {
            Vec::<String>::try_from(value)
                .map_err(|_| "app_paths must be an array of strings".into())
        })?;
    let ip_ranges = values
        .remove("ip_ranges")
        .ok_or_else(|| "ip_ranges is required".to_owned())
        .and_then(|value| {
            Vec::<String>::try_from(value)
                .map_err(|_| "ip_ranges must be an array of strings".into())
        })?;
    if !values.is_empty() {
        return Err("unknown split-tunneling configuration key".into());
    }
    SplitConfig {
        mode: SplitMode::parse(&mode)?,
        app_paths,
        ip_ranges,
    }
    .validate()
}

fn config_to_dbus(config: SplitConfig) -> fdo::Result<HashMap<String, OwnedValue>> {
    let mut values = HashMap::new();
    values.insert(
        "mode".into(),
        OwnedValue::from(Str::from(config.mode.as_str())),
    );
    values.insert(
        "app_paths".into(),
        OwnedValue::try_from(Value::from(config.app_paths))
            .map_err(|error| fdo::Error::Failed(error.to_string()))?,
    );
    values.insert(
        "ip_ranges".into(),
        OwnedValue::try_from(Value::from(config.ip_ranges))
            .map_err(|error| fdo::Error::Failed(error.to_string()))?,
    );
    Ok(values)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proton-omarchy-splitd must run as root",
        ));
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--kernel-self-test")) {
        return kernel_self_test().await;
    }
    let engine = Arc::new(Engine::new()?);
    let connection = Connection::system().await.map_err(io::Error::other)?;
    connection
        .object_server()
        .at(
            PATH,
            SplitTunnelService {
                connection: connection.clone(),
                engine,
            },
        )
        .await
        .map_err(io::Error::other)?;
    connection
        .request_name(SERVICE)
        .await
        .map_err(io::Error::other)?;
    eprintln!("proton-omarchy-splitd: serving {SERVICE}");

    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = signal.recv().await;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate => {},
    }
    Ok(())
}

async fn kernel_self_test() -> io::Result<()> {
    const ROOT_UID: u16 = 0;
    let engine = Engine::ephemeral()?;
    engine
        .set_destination_policy(
            ROOT_UID,
            vec!["198.51.100.0/24".into(), "2001:db8:ffff::/48".into()],
        )
        .await?;
    let (_, _, attached) = engine.status().await;
    if !attached {
        return Err(io::Error::other("eBPF programs did not attach"));
    }
    assert_destination_mark(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        bpf::FWMARK_VALUE,
        "IPv4 connect",
    )?;
    assert_sendmsg_mark(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        bpf::FWMARK_VALUE,
        "IPv4 UDP sendmsg",
    )?;
    assert_destination_mark(
        IpAddr::V6("2001:db8:ffff::1".parse().expect("literal IPv6")),
        bpf::FWMARK_VALUE,
        "IPv6 connect",
    )?;
    assert_sendmsg_mark(
        IpAddr::V6("2001:db8:ffff::2".parse().expect("literal IPv6")),
        bpf::FWMARK_VALUE,
        "IPv6 UDP sendmsg",
    )?;

    engine.set_destination_policy(ROOT_UID, vec![]).await?;
    engine
        .set_config(
            ROOT_UID,
            SplitConfig {
                mode: SplitMode::Include,
                app_paths: vec![],
                ip_ranges: vec!["192.0.2.0/24".into()],
            },
        )
        .await?;
    let socket = udp_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED))?;
    assert_mark(&socket, bpf::FWMARK_VALUE, "Include-mode socket create")?;
    let _ = socket.connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9));
    assert_mark(&socket, 0, "Include-mode matching destination")?;

    engine.clear_config(ROOT_UID).await?;
    engine.set_destination_policy(ROOT_UID, vec![]).await?;
    eprintln!("proton-omarchy-splitd: kernel self-test passed (IPv4/IPv6 connect+sendmsg, include mark clearing)");
    Ok(())
}

fn assert_destination_mark(address: IpAddr, expected: u32, stage: &str) -> io::Result<()> {
    let socket = udp_socket(address)?;
    let _ = socket.connect(SocketAddr::new(address, 9));
    assert_mark(&socket, expected, stage)
}

fn assert_sendmsg_mark(address: IpAddr, expected: u32, stage: &str) -> io::Result<()> {
    let socket = udp_socket(address)?;
    let _ = socket.send_to(&[], SocketAddr::new(address, 9));
    assert_mark(&socket, expected, stage)
}

fn udp_socket(address: IpAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::new(
        match address {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    ))
}

fn assert_mark(socket: &UdpSocket, expected: u32, stage: &str) -> io::Result<()> {
    let mut actual = 0_u32;
    let mut length = std::mem::size_of::<u32>() as libc::socklen_t;
    // SAFETY: the socket fd is live, and both output pointers reference valid
    // writable values whose size is supplied to getsockopt.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut actual as *mut u32).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if actual != expected {
        return Err(io::Error::other(format!(
            "{stage} mark mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbus_round_trip_preserves_the_official_shape() {
        let original = SplitConfig {
            mode: SplitMode::Exclude,
            app_paths: vec!["/usr/bin/firefox".into()],
            ip_ranges: vec!["192.0.2.0/24".into()],
        };
        let decoded = config_from_dbus(config_to_dbus(original.clone()).unwrap()).unwrap();
        assert_eq!(decoded, original);
    }
}
