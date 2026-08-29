mod autoconnect;
mod backend;
mod config;
mod ipc_bridge;
mod native_backend;
mod notifications;
mod operations;
mod server;
mod session;
mod state_reducer;
mod store;

use config::Config;
use operations::OperationCoordinator;
use proton_omarchy_protocol::StateSnapshot;
use std::{io, time::Duration};
use store::StoreHandle;
use tokio::{signal, sync::watch};

fn main() -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run());
    // Keyring/FIDO work uses Tokio's blocking pool. A wedged device or portal
    // must not keep systemd waiting until it escalates to SIGKILL.
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

async fn run() -> io::Result<()> {
    let config = Config::from_env()?;
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--ipc-bridge")) {
        if std::env::args_os().nth(2).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--ipc-bridge accepts no additional arguments",
            ));
        }
        return ipc_bridge::run(&config.socket_path).await;
    }
    let (listener, _socket_cleanup) = server::acquire_socket(&config.socket_path).await?;

    let (state_tx, state_rx) = watch::channel(StateSnapshot::default());
    let operations = OperationCoordinator::new(state_tx.clone());
    let store = StoreHandle::open(
        config.store_path,
        &config.legacy_store_path,
        config.lifecycle_path,
        state_tx.clone(),
        operations.clone(),
    )?;
    notifications::spawn(
        state_rx.clone(),
        store.clone(),
        config.notification_command,
        config.status_icon_dir,
    );
    let backend = native_backend::spawn(state_tx.clone(), operations.clone(), store.clone());
    native_backend::spawn_lifecycle(state_tx, backend.clone(), store.clone());
    autoconnect::spawn(backend.clone(), store.clone(), state_rx.clone());

    tokio::select! {
        result = server::serve(listener, state_rx, backend, store) => result?,
        _ = shutdown_signal() => {},
    }

    Ok(())
}

async fn shutdown_signal() {
    let terminate = async {
        if let Ok(mut signal) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            let _ = signal.recv().await;
        }
    };

    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = terminate => {},
    }
}
