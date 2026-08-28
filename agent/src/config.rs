use proton_omarchy_protocol::SOCKET_FILE_NAME;
use std::{env, io, path::PathBuf};

pub const INSTALLED_NOTIFICATION_COMMAND: &str = "/usr/bin/omarchy-notification-send";
pub const INSTALLED_STATUS_ICON_DIR: &str = "/usr/share/proton-vpn-omarchy/status";

#[derive(Debug, Clone)]
pub struct Config {
    pub socket_path: PathBuf,
    pub store_path: PathBuf,
    pub legacy_store_path: PathBuf,
    pub lifecycle_path: PathBuf,
    pub notification_command: PathBuf,
    pub status_icon_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> io::Result<Self> {
        let runtime_dir = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "XDG_RUNTIME_DIR is required; refusing an insecure /tmp fallback",
            )
        })?;

        let runtime_dir = PathBuf::from(runtime_dir);
        if !runtime_dir.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDG_RUNTIME_DIR must be an absolute path",
            ));
        }

        let socket_path = match env::var_os("PROTON_OMARCHY_SOCKET_PATH") {
            Some(value) => {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "PROTON_OMARCHY_SOCKET_PATH must be an absolute path",
                    ));
                }
                path
            }
            None => runtime_dir.join(SOCKET_FILE_NAME),
        };

        let data_home = match env::var_os("XDG_DATA_HOME") {
            Some(value) => absolute_path(value, "XDG_DATA_HOME")?,
            None => {
                let home = env::var_os("HOME").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "HOME or XDG_DATA_HOME is required for the canonical store",
                    )
                })?;
                absolute_path(home, "HOME")?.join(".local/share")
            }
        };

        let store_path = match env::var_os("PROTON_OMARCHY_STORE_PATH") {
            Some(value) => absolute_path(value, "PROTON_OMARCHY_STORE_PATH")?,
            None => data_home.join("proton-vpn-omarchy/state-v1.json"),
        };
        let legacy_store_path =
            data_home.join("Proton VPN for Omarchy/Proton VPN/connection-store.json");
        let config_home = match env::var_os("XDG_CONFIG_HOME") {
            Some(value) => absolute_path(value, "XDG_CONFIG_HOME")?,
            None => {
                let home = env::var_os("HOME").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "HOME or XDG_CONFIG_HOME is required for lifecycle settings",
                    )
                })?;
                absolute_path(home, "HOME")?.join(".config")
            }
        };
        let lifecycle_path = config_home.join("proton-vpn-omarchy/lifecycle.json");
        let notification_command = match env::var_os("PROTON_OMARCHY_NOTIFICATION_COMMAND") {
            Some(value) => absolute_path(value, "PROTON_OMARCHY_NOTIFICATION_COMMAND")?,
            None => PathBuf::from(INSTALLED_NOTIFICATION_COMMAND),
        };
        let status_icon_dir = match env::var_os("PROTON_OMARCHY_STATUS_ICON_DIR") {
            Some(value) => absolute_path(value, "PROTON_OMARCHY_STATUS_ICON_DIR")?,
            None => PathBuf::from(INSTALLED_STATUS_ICON_DIR),
        };

        Ok(Self {
            socket_path,
            store_path,
            legacy_store_path,
            lifecycle_path,
            notification_command,
            status_icon_dir,
        })
    }
}

fn absolute_path(value: std::ffi::OsString, name: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an absolute path"),
        ))
    }
}
