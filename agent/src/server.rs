use crate::{backend::BackendHandle, session, store::StoreHandle};
use proton_omarchy_protocol::{ConnectionStatus, StateSnapshot};
use std::{
    env, fs, io,
    os::fd::FromRawFd,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    os::unix::net::UnixListener as StdUnixListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    time::{self, Duration, Instant},
};

const IDLE_EXIT_AFTER: Duration = Duration::from_secs(30);

pub async fn bind_socket(path: &Path) -> io::Result<UnixListener> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("refusing to replace non-socket path {}", path.display()),
            ));
        }

        match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another proton-omarchy-agent is already listening",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        }
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn acquire_socket(path: &Path) -> io::Result<(UnixListener, SocketCleanup)> {
    if let Some(listener) = activated_socket(path)? {
        return Ok((listener, SocketCleanup::systemd_owned()));
    }
    let listener = bind_socket(path).await?;
    Ok((listener, SocketCleanup::agent_owned(path.to_path_buf())))
}

fn activated_socket(expected_path: &Path) -> io::Result<Option<UnixListener>> {
    let Some(pid) = env::var_os("LISTEN_PID") else {
        return Ok(None);
    };
    let listen_pid = pid.to_string_lossy().parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "LISTEN_PID is not a valid process ID",
        )
    })?;
    if listen_pid != std::process::id() {
        return Ok(None);
    }
    let listen_fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    if listen_fds != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "systemd activation requires exactly one listener",
        ));
    }

    // systemd's socket-activation ABI starts descriptors at SD_LISTEN_FDS_START (3).
    // PID and descriptor-count validation above make ownership unambiguous.
    let listener = unsafe { StdUnixListener::from_raw_fd(3) };
    let address = listener.local_addr()?;
    if address.as_pathname() != Some(expected_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activated socket path does not match PROTON_OMARCHY_SOCKET_PATH",
        ));
    }
    listener.set_nonblocking(true)?;
    env::remove_var("LISTEN_PID");
    env::remove_var("LISTEN_FDS");
    env::remove_var("LISTEN_FDNAMES");
    UnixListener::from_std(listener).map(Some)
}

pub async fn serve(
    listener: UnixListener,
    state_rx: watch::Receiver<StateSnapshot>,
    backend: BackendHandle,
    store: StoreHandle,
) -> io::Result<()> {
    let active_sessions = Arc::new(AtomicUsize::new(0));
    let mut idle_since: Option<Instant> = None;
    let mut idle_tick = time::interval(Duration::from_secs(1));
    idle_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                idle_since = None;
                active_sessions.fetch_add(1, Ordering::Relaxed);
                let session_count = active_sessions.clone();
                let session_state = state_rx.clone();
                let session_backend = backend.clone();
                let session_store = store.clone();
                tokio::spawn(async move {
                    let _ = session::run(
                        stream,
                        session_state,
                        session_backend,
                        session_store,
                    ).await;
                    session_count.fetch_sub(1, Ordering::Relaxed);
                });
            }
            _ = idle_tick.tick() => {
                let has_clients = active_sessions.load(Ordering::Relaxed) > 0;
                let stay_resident = should_stay_resident(&state_rx.borrow());
                if has_clients || stay_resident {
                    idle_since = None;
                } else if idle_since
                    .get_or_insert_with(Instant::now)
                    .elapsed() >= IDLE_EXIT_AFTER
                {
                    // With startup opted out, systemd socket activation remains the
                    // cheap on-demand entry point. Never exit around a live tunnel or
                    // observable operation.
                    return Ok(());
                }
            }
        }
    }
}

fn should_stay_resident(snapshot: &StateSnapshot) -> bool {
    snapshot.store.start_with_omarchy
        || matches!(
            snapshot.connection.status,
            ConnectionStatus::Connecting | ConnectionStatus::Connected
        )
        || !snapshot.operations.active.is_empty()
}

pub struct SocketCleanup {
    path: Option<PathBuf>,
}

impl SocketCleanup {
    pub fn agent_owned(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn systemd_owned() -> Self {
        Self { path: None }
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_socket() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_out_can_idle_exit_but_live_work_keeps_agent_resident() {
        let mut snapshot = StateSnapshot::default();
        snapshot.store.start_with_omarchy = false;
        assert!(!should_stay_resident(&snapshot));

        snapshot.connection.status = ConnectionStatus::Connected;
        assert!(should_stay_resident(&snapshot));

        snapshot.connection.status = ConnectionStatus::Disconnected;
        snapshot.store.start_with_omarchy = true;
        assert!(should_stay_resident(&snapshot));
    }
}
