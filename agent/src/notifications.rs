use crate::store::StoreHandle;
use proton_omarchy_protocol::{
    ConnectionStatus, OperationDomain, OperationRecord, OperationStatus, StateSnapshot,
};
use std::path::{Path, PathBuf};
use tokio::{process::Command, sync::watch};

// Route through the shell host so multi-monitor sessions choose the panel on
// the focused output instead of whichever widget instance owns the IPC name.
const NOTIFICATION_OPEN_ACTION: &str = "omarchy-shell shell summon proton.omarchy '{}'";

pub fn spawn(
    state_rx: watch::Receiver<StateSnapshot>,
    store: StoreHandle,
    command: PathBuf,
    icon_dir: PathBuf,
) {
    tokio::spawn(run(state_rx, store, command, icon_dir));
}

async fn run(
    mut state_rx: watch::Receiver<StateSnapshot>,
    store: StoreHandle,
    command: PathBuf,
    icon_dir: PathBuf,
) {
    let initial = state_rx.borrow().clone();
    let mut emitter = NotificationEmitter::new(command, icon_dir, &initial);
    while state_rx.changed().await.is_ok() {
        let snapshot = state_rx.borrow_and_update().clone();
        emitter
            .observe(
                &snapshot,
                &store.locale(),
                store.notifications_enabled(),
                store.port_forwarding_notifications_enabled(),
            )
            .await;
    }
}

struct NotificationEmitter {
    command: PathBuf,
    icon_dir: PathBuf,
    connection_id: Option<u32>,
    general_id: Option<u32>,
    last_connection_status: ConnectionStatus,
    last_connection_signature: String,
    last_connection_error_code: String,
    last_forwarded_port: Option<u16>,
    last_operation_id: String,
    last_attention_stage: String,
}

impl NotificationEmitter {
    fn new(command: PathBuf, icon_dir: PathBuf, initial: &StateSnapshot) -> Self {
        Self {
            command,
            icon_dir,
            connection_id: None,
            general_id: None,
            last_connection_status: initial.connection.status,
            last_connection_signature: connection_signature(initial),
            last_connection_error_code: initial.connection.error_code.clone().unwrap_or_default(),
            last_forwarded_port: initial.features.port_forwarding.active_port,
            last_operation_id: initial
                .operations
                .recent
                .first()
                .map(|operation| operation.id.clone())
                .unwrap_or_default(),
            last_attention_stage: String::new(),
        }
    }

    async fn observe(
        &mut self,
        snapshot: &StateSnapshot,
        locale: &str,
        enabled: bool,
        port_forwarding_enabled: bool,
    ) {
        self.observe_connection(snapshot, locale, enabled).await;
        self.observe_port_forwarding(snapshot, locale, enabled && port_forwarding_enabled)
            .await;
        self.observe_attention_operation(snapshot, locale, enabled)
            .await;
        self.observe_failed_operation(snapshot, locale, enabled)
            .await;
    }

    async fn observe_port_forwarding(
        &mut self,
        snapshot: &StateSnapshot,
        locale: &str,
        enabled: bool,
    ) {
        let port = snapshot.features.port_forwarding.active_port;
        let changed = port != self.last_forwarded_port;
        self.last_forwarded_port = port;
        let Some(port) = port.filter(|_| changed && enabled) else {
            return;
        };
        let spanish = is_spanish(locale);
        let message = NotificationMessage {
            icon: StatusIcon::Information,
            urgency: "normal",
            summary: if spanish {
                "Reenvío de puertos activo"
            } else {
                "Port forwarding is active"
            },
            body: if spanish {
                format!("Proton VPN asignó el puerto {port}.")
            } else {
                format!("Proton VPN assigned port {port}.")
            },
        };
        self.general_id =
            send_notification(&self.command, &self.icon_dir, self.general_id, message)
                .await
                .or(self.general_id);
    }

    async fn observe_connection(&mut self, snapshot: &StateSnapshot, locale: &str, enabled: bool) {
        let status = snapshot.connection.status;
        let previous = self.last_connection_status;
        let signature = connection_signature(snapshot);
        let changed = status != previous;
        let details_changed = signature != self.last_connection_signature;
        let error_code = snapshot.connection.error_code.as_deref().unwrap_or("");
        let restriction_changed = error_code != self.last_connection_error_code;
        self.last_connection_status = status;
        self.last_connection_signature = signature;
        self.last_connection_error_code = error_code.to_owned();

        let spanish = is_spanish(locale);
        let message = if error_code == "p2p_not_allowed" && restriction_changed {
            Some(NotificationMessage {
                icon: StatusIcon::Information,
                urgency: "critical",
                summary: if spanish {
                    "Tráfico P2P detectado"
                } else {
                    "P2P traffic detected"
                },
                body: if spanish {
                    "Este servidor no permite P2P para tu plan. Conéctate a un servidor P2P.".into()
                } else {
                    "This server does not allow P2P for your plan. Connect to a P2P server.".into()
                },
            })
        } else {
            match status {
                ConnectionStatus::Connecting if changed => Some(NotificationMessage {
                    icon: StatusIcon::Connecting,
                    urgency: "normal",
                    summary: if spanish {
                        "Proton VPN está conectando"
                    } else {
                        "Proton VPN is connecting"
                    },
                    body: if spanish {
                        "Preparando una conexión segura…".into()
                    } else {
                        "Preparing a secure connection…".into()
                    },
                }),
                ConnectionStatus::Connected if changed || details_changed => {
                    let destination = connection_destination(snapshot, spanish);
                    Some(NotificationMessage {
                        icon: StatusIcon::Connected,
                        urgency: "normal",
                        summary: if spanish {
                            "Proton VPN está conectado"
                        } else {
                            "Proton VPN is connected"
                        },
                        body: if spanish {
                            format!("Conectado a {destination}")
                        } else {
                            format!("Connected to {destination}")
                        },
                    })
                }
                ConnectionStatus::Disconnected
                    if changed
                        && matches!(
                            previous,
                            ConnectionStatus::Connecting
                                | ConnectionStatus::Connected
                                | ConnectionStatus::Error
                        ) =>
                {
                    Some(NotificationMessage {
                        icon: StatusIcon::Disconnected,
                        urgency: "normal",
                        summary: if spanish {
                            "Proton VPN está desconectado"
                        } else {
                            "Proton VPN is disconnected"
                        },
                        body: if spanish {
                            "El tráfico ya no usa el túnel VPN.".into()
                        } else {
                            "Traffic is no longer using the VPN tunnel.".into()
                        },
                    })
                }
                ConnectionStatus::Error if changed => Some(NotificationMessage {
                    icon: StatusIcon::Disconnected,
                    urgency: "critical",
                    summary: if spanish {
                        "Error de conexión de Proton VPN"
                    } else {
                        "Proton VPN connection error"
                    },
                    body: if spanish {
                        "Abre el panel para ver el error y volver a intentarlo.".into()
                    } else {
                        "Open the panel to review the error and try again.".into()
                    },
                }),
                _ => None,
            }
        };

        if enabled {
            if let Some(message) = message {
                self.connection_id =
                    send_notification(&self.command, &self.icon_dir, self.connection_id, message)
                        .await
                        .or(self.connection_id);
            }
        }
    }

    async fn observe_attention_operation(
        &mut self,
        snapshot: &StateSnapshot,
        locale: &str,
        enabled: bool,
    ) {
        let attention = snapshot.operations.active.iter().find(|operation| {
            matches!(
                operation.stage.as_str(),
                "auth.waiting_for_two_factor"
                    | "auth.security_key_pin_required"
                    | "auth.touch_security_key"
                    | "auth.waiting_for_human_verification"
                    | "auth.waiting_for_sso"
            )
        });
        let Some(operation) = attention else {
            self.last_attention_stage.clear();
            return;
        };
        let key = format!("{}:{}", operation.id, operation.stage);
        if key == self.last_attention_stage {
            return;
        }
        self.last_attention_stage = key;
        if !enabled {
            return;
        }

        let spanish = is_spanish(locale);
        let (summary, body) = match operation.stage.as_str() {
            "auth.waiting_for_two_factor" => (
                if spanish {
                    "Verificación en dos pasos"
                } else {
                    "Two-factor authentication"
                },
                if spanish {
                    "Proton VPN está esperando tu código en el panel."
                } else {
                    "Proton VPN is waiting for your code in the panel."
                },
            ),
            "auth.security_key_pin_required" => (
                if spanish {
                    "Tu llave necesita un PIN"
                } else {
                    "Your security key needs a PIN"
                },
                if spanish {
                    "Vuelve al panel de Proton VPN para ingresarlo."
                } else {
                    "Return to the Proton VPN panel to enter it."
                },
            ),
            "auth.touch_security_key" => (
                if spanish {
                    "Toca tu llave de seguridad"
                } else {
                    "Touch your security key"
                },
                if spanish {
                    "La autenticación continúa en el panel de Proton VPN."
                } else {
                    "Authentication is continuing in the Proton VPN panel."
                },
            ),
            _ => (
                if spanish {
                    "Proton VPN necesita tu atención"
                } else {
                    "Proton VPN needs your attention"
                },
                if spanish {
                    "Abre el panel para continuar la autenticación."
                } else {
                    "Open the panel to continue authentication."
                },
            ),
        };
        self.general_id = send_notification(
            &self.command,
            &self.icon_dir,
            self.general_id,
            NotificationMessage {
                icon: StatusIcon::Information,
                urgency: "normal",
                summary,
                body: body.into(),
            },
        )
        .await
        .or(self.general_id);
    }

    async fn observe_failed_operation(
        &mut self,
        snapshot: &StateSnapshot,
        locale: &str,
        enabled: bool,
    ) {
        let Some(operation) = snapshot.operations.recent.first() else {
            return;
        };
        if operation.id == self.last_operation_id {
            return;
        }
        self.last_operation_id = operation.id.clone();
        if !enabled
            || operation.state != OperationStatus::Failed
            || is_connection_operation(operation)
            || operation.error.is_none()
        {
            return;
        }

        let spanish = is_spanish(locale);
        self.general_id = send_notification(
            &self.command,
            &self.icon_dir,
            self.general_id,
            NotificationMessage {
                icon: StatusIcon::Information,
                urgency: "critical",
                summary: if spanish {
                    "La operación de Proton VPN falló"
                } else {
                    "Proton VPN operation failed"
                },
                body: if spanish {
                    "Abre el panel para revisar el error y volver a intentarlo.".into()
                } else {
                    "Open the panel to review the error and try again.".into()
                },
            },
        )
        .await
        .or(self.general_id);
    }
}

fn is_connection_operation(operation: &OperationRecord) -> bool {
    operation.domain == OperationDomain::TunnelConfiguration
        && operation.kind.starts_with("connection.")
}

fn connection_signature(snapshot: &StateSnapshot) -> String {
    format!(
        "{}:{}:{}",
        snapshot.connection.country_code.as_deref().unwrap_or(""),
        snapshot.connection.server_name.as_deref().unwrap_or(""),
        snapshot.connection.protocol.as_deref().unwrap_or("")
    )
}

fn connection_destination(snapshot: &StateSnapshot, spanish: bool) -> String {
    snapshot
        .connection
        .country_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            snapshot
                .connection
                .country_code
                .as_deref()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            snapshot
                .connection
                .server_name
                .as_deref()
                .filter(|value| !value.is_empty())
        })
        .unwrap_or(if spanish {
            "un servidor seguro"
        } else {
            "a secure server"
        })
        .to_owned()
}

fn is_spanish(locale: &str) -> bool {
    locale.to_ascii_lowercase().starts_with("es")
}

#[derive(Clone, Copy)]
enum StatusIcon {
    Information,
    Disconnected,
    Connecting,
    Connected,
}

impl StatusIcon {
    fn file_name(self) -> &'static str {
        match self {
            Self::Information => "ic_vpn_status_information.webp",
            Self::Disconnected => "ic_vpn_status_disconnected.webp",
            Self::Connecting => "ic_vpn_status_connecting.webp",
            Self::Connected => "ic_vpn_status_connected.webp",
        }
    }
}

struct NotificationMessage {
    icon: StatusIcon,
    urgency: &'static str,
    summary: &'static str,
    body: String,
}

async fn send_notification(
    command_path: &Path,
    icon_dir: &Path,
    replacement_id: Option<u32>,
    message: NotificationMessage,
) -> Option<u32> {
    let mut command = Command::new(command_path);
    command
        .arg("--app-name")
        .arg("Proton VPN")
        .arg("--image")
        .arg(icon_dir.join(message.icon.file_name()))
        .arg("--urgency")
        .arg(message.urgency)
        .arg("--exec")
        .arg(NOTIFICATION_OPEN_ACTION)
        .arg(message.summary)
        .arg(message.body)
        .arg("-p")
        .arg("-t")
        .arg("7000");
    if let Some(id) = replacement_id {
        command.arg("-r").arg(id.to_string());
    }

    let output = command.output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}
