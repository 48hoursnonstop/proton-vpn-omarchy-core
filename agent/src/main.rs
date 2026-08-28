mod autoconnect;
mod backend;
mod config;
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
use std::io;
use store::StoreHandle;
use tokio::{signal, sync::watch};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = Config::from_env()?;
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
    let backend = native_backend::spawn(state_tx, operations.clone(), store.clone());
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
