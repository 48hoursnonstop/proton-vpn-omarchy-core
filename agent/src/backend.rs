use crate::operations::OperationCoordinator;
use serde_json::Value;
use std::{error::Error, fmt};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFlavor {
    Native,
}

const NATIVE_METHODS: &[&str] = &[
    "account.get",
    "account.upgrade_url",
    "report_issue.categories.get",
    "report_issue.submit",
    "diagnostics.get",
    "account.login",
    "account.submit_2fa",
    "account.authenticate_fido2",
    "account.submit_fido2_pin",
    "account.cancel_fido2",
    "account.logout",
    "locations.get",
    "servers.get",
    "feature.set",
    "protocol.set",
    "dns.set",
    "apps.get",
    "system.launch",
    "split_tunneling.set",
    "connection.observe",
    "connection.network_conflict_detection",
    "connection.connect",
    "connection.cancel",
    "connection.disconnect",
    "connection.feedback",
    "netshield.stats.get",
    "traffic.get",
];

const NATIVE_CAPABILITIES: &[&str] = &[
    "state.push",
    "operations.push",
    "operations.conflicts",
    "requests.concurrent",
    "device_location.read",
    "account.session",
    "account.login",
    "account.sso",
    "account.human_verification",
    "account.2fa",
    "account.2fa.security_key",
    "account.2fa.security_key_pin",
    "account.2fa.security_key_cancel",
    "account.web_upgrade",
    "report_issue.categories",
    "report_issue.submit",
    "servers.page",
    "connection.observe",
    "connection.fastest",
    "connection.country",
    "connection.server",
    "connection.gateway",
    "connection.gateway_server",
    "connection.secure_core",
    "connection.p2p",
    "connection.tor",
    "feature.kill_switch",
    "feature.kill_switch_split_tunneling",
    "feature.netshield",
    "feature.vpn_accelerator",
    "feature.port_forwarding",
    "feature.anonymous_crash_reports",
    "feature.anonymous_usage_statistics",
    "feature.moderate_nat",
    "feature.ipv6",
    "feature.ipv6_leak_protection",
    "feature.alternative_routing",
    "connection.feedback",
    "netshield.statistics",
    "protocol.settings",
    "dns.custom",
    "apps.catalog",
    "profiles.connect_and_go",
    "system.private_browsing",
    "split_tunneling.apps",
    "store.canonical",
    "store.migration.qt",
    "profiles.crud",
    "profiles.duplicate",
    "recents.canonical",
    "default_connection.canonical",
    "onboarding.preferences",
    "notifications.freedesktop",
];

impl BackendFlavor {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "proton_rust",
        }
    }

    pub fn methods(self) -> &'static [&'static str] {
        match self {
            Self::Native => NATIVE_METHODS,
        }
    }

    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Native => NATIVE_CAPABILITIES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub retryable: bool,
}

impl BackendError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
            retryable: false,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for BackendError {}

pub type BackendResult = Result<Value, BackendError>;

pub struct BackendRequest {
    pub method: String,
    pub params: Value,
    pub reply: oneshot::Sender<BackendResult>,
}

#[derive(Clone)]
pub struct BackendHandle {
    tx: mpsc::Sender<BackendRequest>,
    operations: OperationCoordinator,
    flavor: BackendFlavor,
}

impl BackendHandle {
    pub fn new(
        tx: mpsc::Sender<BackendRequest>,
        operations: OperationCoordinator,
        flavor: BackendFlavor,
    ) -> Self {
        Self {
            tx,
            operations,
            flavor,
        }
    }

    pub fn flavor(&self) -> BackendFlavor {
        self.flavor
    }

    pub fn supports(&self, method: &str) -> bool {
        self.flavor.methods().contains(&method)
    }

    pub async fn request(
        &self,
        client_instance_id: impl Into<String>,
        method: impl Into<String>,
        params: Value,
    ) -> BackendResult {
        let client_instance_id = client_instance_id.into();
        let method = method.into();
        let operation = self.operations.begin(&client_instance_id, &method)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_result = self
            .tx
            .send(BackendRequest {
                method,
                params,
                reply: reply_tx,
            })
            .await;

        if send_result.is_err() {
            let error = BackendError::new("backend_unavailable", "Proton backend task stopped")
                .retryable(true);
            self.operations.finish(operation, Err(&error));
            return Err(error);
        }

        let result = match reply_rx.await {
            Ok(result) => result,
            Err(_) => {
                let error =
                    BackendError::new("backend_unavailable", "Proton backend reply was dropped")
                        .retryable(true);
                self.operations.finish(operation, Err(&error));
                return Err(error);
            }
        };
        self.operations
            .finish(operation, result.as_ref().map(|_| ()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_contract_advertises_only_migrated_methods() {
        let native = BackendFlavor::Native;
        assert_eq!(native.name(), "proton_rust");
        assert!(native.methods().contains(&"connection.connect"));
        assert!(native.methods().contains(&"account.upgrade_url"));
        assert!(native.capabilities().contains(&"feature.netshield"));
        assert!(native.methods().contains(&"account.authenticate_fido2"));
        assert!(native
            .capabilities()
            .contains(&"account.2fa.security_key_cancel"));
        assert!(native.methods().contains(&"report_issue.submit"));
        assert!(native.capabilities().contains(&"feature.kill_switch"));
    }
}
