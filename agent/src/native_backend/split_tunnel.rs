use super::{models::SplitTunnelingConfig, NativeError, NativeResult};
use nmdbus::dbus::{
    arg::{PropMap, RefArg, Variant},
    blocking::Connection,
};
use std::time::Duration;

const SERVICE: &str = "me.proton.vpn.split_tunneling";
const PATH: &str = "/me/proton/vpn/split_tunneling";
const INTERFACE: &str = "me.proton.vpn.split_tunneling";

#[derive(Clone, Debug, Default)]
pub struct SplitTunnelBackend;

impl SplitTunnelBackend {
    pub fn available(&self) -> bool {
        self.get_config().is_ok()
    }

    pub fn destination_policy_available(&self) -> bool {
        self.get_destination_policy().is_ok()
    }

    pub fn apply(&self, enabled: bool, config: &SplitTunnelingConfig) -> NativeResult<()> {
        let connection = system_bus()?;
        let proxy = connection.with_proxy(SERVICE, PATH, Duration::from_secs(8));
        let uid = current_uid()?;
        if enabled {
            let mut payload = PropMap::new();
            prop(&mut payload, "mode", config.mode.clone());
            prop(&mut payload, "app_paths", config.app_paths.clone());
            prop(&mut payload, "ip_ranges", config.ip_ranges.clone());
            let _: () = proxy
                .method_call(INTERFACE, "SetConfig", (uid, payload))
                .map_err(|error| split_error("apply", error))?;
        } else {
            let _: () = proxy
                .method_call(INTERFACE, "ClearConfig", (uid,))
                .map_err(|error| split_error("clear", error))?;
        }
        Ok(())
    }

    pub fn apply_destination_policy(&self, ranges: Vec<String>) -> NativeResult<()> {
        let connection = system_bus()?;
        let proxy = connection.with_proxy(SERVICE, PATH, Duration::from_secs(8));
        let _: () = proxy
            .method_call(INTERFACE, "SetDestinationPolicy", (current_uid()?, ranges))
            .map_err(|error| split_error("apply destination policy through", error))?;
        Ok(())
    }

    pub fn set_kill_switch_bypass(
        &self,
        enabled: bool,
        routes: Vec<(String, String, String)>,
    ) -> NativeResult<()> {
        let connection = system_bus()?;
        let proxy = connection.with_proxy(SERVICE, PATH, Duration::from_secs(8));
        let _: () = proxy
            .method_call(
                INTERFACE,
                "SetKillSwitchBypass",
                (current_uid()?, enabled, routes),
            )
            .map_err(|error| split_error("configure Kill Switch bypass through", error))?;
        Ok(())
    }

    fn get_config(&self) -> NativeResult<PropMap> {
        let connection = system_bus()?;
        let proxy = connection.with_proxy(SERVICE, PATH, Duration::from_secs(5));
        let (config,): (PropMap,) = proxy
            .method_call(INTERFACE, "GetConfig", (current_uid()?,))
            .map_err(|error| split_error("query", error))?;
        Ok(config)
    }

    fn get_destination_policy(&self) -> NativeResult<Vec<String>> {
        let connection = system_bus()?;
        let proxy = connection.with_proxy(SERVICE, PATH, Duration::from_secs(5));
        let (ranges,): (Vec<String>,) = proxy
            .method_call(INTERFACE, "GetDestinationPolicy", (current_uid()?,))
            .map_err(|error| split_error("query destination policy from", error))?;
        Ok(ranges)
    }
}

fn prop<T>(map: &mut PropMap, name: &str, value: T)
where
    T: RefArg + 'static,
{
    map.insert(name.to_owned(), Variant(Box::new(value)));
}

fn current_uid() -> NativeResult<u16> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    u16::try_from(uid).map_err(|_| {
        NativeError::new(
            "split_tunneling_uid_unsupported",
            "The Proton-compatible split tunneling service only supports 16-bit user IDs",
        )
    })
}

fn system_bus() -> NativeResult<Connection> {
    Connection::new_system().map_err(|error| split_error("connect to", error))
}

fn split_error(action: &str, error: nmdbus::dbus::Error) -> NativeError {
    NativeError::new(
        "split_tunneling_unavailable",
        format!("Unable to {action} the Proton-compatible split tunneling service"),
    )
    .with_source(error)
    .retryable(true)
}
