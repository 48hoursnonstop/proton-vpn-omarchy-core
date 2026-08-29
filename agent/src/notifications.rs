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
    last_network_generation: u64,
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
            last_network_generation: initial.network_security.generation,
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
        self.observe_network_security(snapshot, locale, enabled)
            .await;
        self.observe_attention_operation(snapshot, locale, enabled)
            .await;
        self.observe_failed_operation(snapshot, locale, enabled)
            .await;
    }

    async fn observe_network_security(
        &mut self,
        snapshot: &StateSnapshot,
        locale: &str,
        enabled: bool,
    ) {
        let generation = snapshot.network_security.generation;
        let changed = generation != self.last_network_generation;
        if !changed
            || !enabled
            || !snapshot.network_security.known
            || !snapshot.network_security.wifi_connected
            || !snapshot.network_security.insecure_wifi
        {
            if changed
                && (!snapshot.network_security.wifi_connected
                    || !snapshot.network_security.insecure_wifi)
            {
                self.last_network_generation = generation;
            }
            return;
        }
        if matches!(
            snapshot.connection.status,
            ConnectionStatus::Connecting | ConnectionStatus::Connected
        ) {
            // Keep this generation pending so a subsequent unprotected state
            // can still warn without requiring the Wi-Fi network to change.
            return;
        }
        self.last_network_generation = generation;

        let text = notification_catalog(locale);
        let message = NotificationMessage {
            icon: StatusIcon::Information,
            urgency: "critical",
            summary: text.insecure_wifi_summary,
            body: text.insecure_wifi_body.into(),
        };
        self.general_id =
            send_notification(&self.command, &self.icon_dir, self.general_id, message)
                .await
                .or(self.general_id);
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
        let text = notification_catalog(locale);
        let message = NotificationMessage {
            icon: StatusIcon::Information,
            urgency: "normal",
            summary: text.port_forwarding_summary,
            body: text
                .port_forwarding_body
                .replace("{port}", &port.to_string()),
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

        let text = notification_catalog(locale);
        let message = if error_code == "p2p_not_allowed" && restriction_changed {
            Some(NotificationMessage {
                icon: StatusIcon::Information,
                urgency: "critical",
                summary: text.p2p_detected_summary,
                body: text.p2p_detected_body.into(),
            })
        } else {
            match status {
                ConnectionStatus::Connecting if changed => Some(NotificationMessage {
                    icon: StatusIcon::Connecting,
                    urgency: "normal",
                    summary: text.connecting_summary,
                    body: text.connecting_body.into(),
                }),
                ConnectionStatus::Connected if changed || details_changed => {
                    let destination = connection_destination(snapshot, text);
                    Some(NotificationMessage {
                        icon: StatusIcon::Connected,
                        urgency: "normal",
                        summary: text.connected_summary,
                        body: text.connected_body.replace("{destination}", &destination),
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
                        summary: text.disconnected_summary,
                        body: text.disconnected_body.into(),
                    })
                }
                ConnectionStatus::Error if changed => Some(NotificationMessage {
                    icon: StatusIcon::Disconnected,
                    urgency: "critical",
                    summary: text.connection_error_summary,
                    body: text.connection_error_body.into(),
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

        let text = notification_catalog(locale);
        let (summary, body) = match operation.stage.as_str() {
            "auth.waiting_for_two_factor" => (text.two_factor_summary, text.two_factor_body),
            "auth.security_key_pin_required" => {
                (text.security_key_pin_summary, text.security_key_pin_body)
            }
            "auth.touch_security_key" => (
                text.touch_security_key_summary,
                text.touch_security_key_body,
            ),
            _ => (text.attention_summary, text.attention_body),
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

        let text = notification_catalog(locale);
        self.general_id = send_notification(
            &self.command,
            &self.icon_dir,
            self.general_id,
            NotificationMessage {
                icon: StatusIcon::Information,
                urgency: "critical",
                summary: text.operation_failed_summary,
                body: text.operation_failed_body.into(),
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

fn connection_destination(snapshot: &StateSnapshot, text: &NotificationCatalog) -> String {
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
        .unwrap_or(text.secure_server)
        .to_owned()
}

// Each native-notification locale is one complete, compile-time checked
// catalog. New UI locales safely fall back to English until a catalog is
// added here; no notification call site needs language-specific branches.
struct NotificationCatalog {
    insecure_wifi_summary: &'static str,
    insecure_wifi_body: &'static str,
    port_forwarding_summary: &'static str,
    port_forwarding_body: &'static str,
    p2p_detected_summary: &'static str,
    p2p_detected_body: &'static str,
    connecting_summary: &'static str,
    connecting_body: &'static str,
    connected_summary: &'static str,
    connected_body: &'static str,
    disconnected_summary: &'static str,
    disconnected_body: &'static str,
    connection_error_summary: &'static str,
    connection_error_body: &'static str,
    two_factor_summary: &'static str,
    two_factor_body: &'static str,
    security_key_pin_summary: &'static str,
    security_key_pin_body: &'static str,
    touch_security_key_summary: &'static str,
    touch_security_key_body: &'static str,
    attention_summary: &'static str,
    attention_body: &'static str,
    operation_failed_summary: &'static str,
    operation_failed_body: &'static str,
    secure_server: &'static str,
}

const ENGLISH_NOTIFICATIONS: NotificationCatalog = NotificationCatalog {
    insecure_wifi_summary: "The Wi-Fi network is not secure",
    insecure_wifi_body:
        "This network does not use WPA encryption. Connect to Proton VPN to protect your traffic.",
    port_forwarding_summary: "Port forwarding is active",
    port_forwarding_body: "Proton VPN assigned port {port}.",
    p2p_detected_summary: "P2P traffic detected",
    p2p_detected_body: "This server does not allow P2P for your plan. Connect to a P2P server.",
    connecting_summary: "Proton VPN is connecting",
    connecting_body: "Preparing a secure connection…",
    connected_summary: "Proton VPN is connected",
    connected_body: "Connected to {destination}",
    disconnected_summary: "Proton VPN is disconnected",
    disconnected_body: "Traffic is no longer using the VPN tunnel.",
    connection_error_summary: "Proton VPN connection error",
    connection_error_body: "Open the panel to review the error and try again.",
    two_factor_summary: "Two-factor authentication",
    two_factor_body: "Proton VPN is waiting for your code in the panel.",
    security_key_pin_summary: "Your security key needs a PIN",
    security_key_pin_body: "Return to the Proton VPN panel to enter it.",
    touch_security_key_summary: "Touch your security key",
    touch_security_key_body: "Authentication is continuing in the Proton VPN panel.",
    attention_summary: "Proton VPN needs your attention",
    attention_body: "Open the panel to continue authentication.",
    operation_failed_summary: "Proton VPN operation failed",
    operation_failed_body: "Open the panel to review the error and try again.",
    secure_server: "a secure server",
};

const SPANISH_NOTIFICATIONS: NotificationCatalog = NotificationCatalog {
    insecure_wifi_summary: "La red Wi-Fi no es segura",
    insecure_wifi_body:
        "Esta red no usa cifrado WPA. Conéctate a Proton VPN para proteger tu tráfico.",
    port_forwarding_summary: "Reenvío de puertos activo",
    port_forwarding_body: "Proton VPN asignó el puerto {port}.",
    p2p_detected_summary: "Tráfico P2P detectado",
    p2p_detected_body: "Este servidor no permite P2P para tu plan. Conéctate a un servidor P2P.",
    connecting_summary: "Proton VPN está conectando",
    connecting_body: "Preparando una conexión segura…",
    connected_summary: "Proton VPN está conectado",
    connected_body: "Conectado a {destination}",
    disconnected_summary: "Proton VPN está desconectado",
    disconnected_body: "El tráfico ya no usa el túnel VPN.",
    connection_error_summary: "Error de conexión de Proton VPN",
    connection_error_body: "Abre el panel para ver el error y volver a intentarlo.",
    two_factor_summary: "Verificación en dos pasos",
    two_factor_body: "Proton VPN está esperando tu código en el panel.",
    security_key_pin_summary: "Tu llave necesita un PIN",
    security_key_pin_body: "Vuelve al panel de Proton VPN para ingresarlo.",
    touch_security_key_summary: "Toca tu llave de seguridad",
    touch_security_key_body: "La autenticación continúa en el panel de Proton VPN.",
    attention_summary: "Proton VPN necesita tu atención",
    attention_body: "Abre el panel para continuar la autenticación.",
    operation_failed_summary: "La operación de Proton VPN falló",
    operation_failed_body: "Abre el panel para revisar el error y volver a intentarlo.",
    secure_server: "un servidor seguro",
};

fn notification_catalog(locale: &str) -> &'static NotificationCatalog {
    match locale
        .split(['-', '_'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "es" => &SPANISH_NOTIFICATIONS,
        _ => &ENGLISH_NOTIFICATIONS,
    }
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
