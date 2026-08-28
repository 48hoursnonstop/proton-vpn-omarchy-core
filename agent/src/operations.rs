use crate::backend::BackendError;
use proton_omarchy_protocol::{
    OperationDomain, OperationError, OperationRecord, OperationStatus, StateSnapshot,
};
use serde_json::json;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const RECENT_OPERATION_LIMIT: usize = 16;

#[derive(Clone)]
pub struct OperationCoordinator {
    inner: Arc<Mutex<OperationRegistry>>,
    state_tx: watch::Sender<StateSnapshot>,
}

struct OperationRegistry {
    next_id: u64,
    active: Vec<OperationRecord>,
    recent: VecDeque<OperationRecord>,
}

#[derive(Clone)]
pub struct OperationLease {
    id: String,
    owns_completion: bool,
    control_failure_stage: Option<&'static str>,
    control_failure_cancelable: bool,
}

#[derive(Clone, Copy)]
struct OperationSpec {
    domain: OperationDomain,
    stage: &'static str,
    cancelable: bool,
    control: Option<ControlSpec>,
}

#[derive(Clone, Copy)]
struct ControlSpec {
    target_kind: &'static str,
    stage: &'static str,
    cancelable: bool,
    failure_stage: &'static str,
    failure_cancelable: bool,
    requires_target: bool,
}

impl OperationCoordinator {
    pub fn new(state_tx: watch::Sender<StateSnapshot>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(OperationRegistry {
                next_id: 1,
                active: Vec::new(),
                recent: VecDeque::new(),
            })),
            state_tx,
        }
    }

    pub fn begin(
        &self,
        client_instance_id: &str,
        method: &str,
    ) -> Result<Option<OperationLease>, BackendError> {
        let Some(spec) = operation_spec(method) else {
            self.guard_read(method)?;
            return Ok(None);
        };

        let now = now_unix_ms();
        let mut registry = self.registry();

        if let Some(control) = spec.control {
            if let Some(active) = registry.active.iter_mut().find(|operation| {
                operation.domain == spec.domain
                    && operation.kind == control.target_kind
                    && operation.state == OperationStatus::Running
            }) {
                active.stage = control.stage.into();
                active.updated_at_unix_ms = now;
                active.cancelable = control.cancelable;
                active.error = None;
                let lease = OperationLease {
                    id: active.id.clone(),
                    owns_completion: false,
                    control_failure_stage: Some(control.failure_stage),
                    control_failure_cancelable: control.failure_cancelable,
                };
                self.publish(&registry);
                return Ok(Some(lease));
            }

            if control.requires_target {
                return Err(BackendError::new(
                    "operation_not_active",
                    "The operation controlled by this request is not active",
                ));
            }
        }

        if let Some(active) = registry
            .active
            .iter()
            .find(|active| domains_conflict(spec.domain, active.domain))
        {
            let details = serde_json::to_value(active).unwrap_or_else(|_| {
                json!({
                    "domain": "unknown",
                    "kind": "unknown"
                })
            });
            return Err(BackendError::new(
                "operation_conflict",
                "Another incompatible Proton VPN operation is already running",
            )
            .with_details(json!({ "active_operation": details }))
            .retryable(true));
        }

        let id = format!("op-{:016x}", registry.next_id);
        registry.next_id = registry.next_id.wrapping_add(1);
        registry.active.push(OperationRecord {
            id: id.clone(),
            initiator_client_instance_id: client_instance_id.to_owned(),
            domain: spec.domain,
            kind: method.to_owned(),
            state: OperationStatus::Running,
            stage: spec.stage.into(),
            started_at_unix_ms: now,
            updated_at_unix_ms: now,
            finished_at_unix_ms: None,
            cancelable: spec.cancelable,
            error: None,
        });
        self.publish(&registry);

        Ok(Some(OperationLease {
            id,
            owns_completion: true,
            control_failure_stage: None,
            control_failure_cancelable: false,
        }))
    }

    pub fn finish(&self, lease: Option<OperationLease>, result: Result<(), &BackendError>) {
        let Some(lease) = lease else {
            return;
        };

        let now = now_unix_ms();
        let mut registry = self.registry();

        if !lease.owns_completion {
            if let (Some(operation), Err(error)) = (
                registry
                    .active
                    .iter_mut()
                    .find(|operation| operation.id == lease.id),
                result,
            ) {
                operation.stage = lease
                    .control_failure_stage
                    .unwrap_or("operation.control_failed")
                    .into();
                operation.updated_at_unix_ms = now;
                operation.cancelable = lease.control_failure_cancelable;
                operation.error = Some(operation_error(error));
                self.publish(&registry);
            }
            return;
        }

        let Some(index) = registry
            .active
            .iter()
            .position(|operation| operation.id == lease.id)
        else {
            return;
        };

        let mut operation = registry.active.remove(index);
        let cancellation_requested = matches!(
            operation.stage.as_str(),
            "tunnel.cancelling" | "auth.cancelling_security_key"
        );
        operation.updated_at_unix_ms = now;
        operation.finished_at_unix_ms = Some(now);
        operation.cancelable = false;

        match result {
            Ok(()) if cancellation_requested => {
                operation.state = OperationStatus::Cancelled;
                operation.stage = cancelled_stage(&operation.kind).into();
            }
            Ok(()) => {
                operation.state = OperationStatus::Succeeded;
                operation.stage = completion_stage(&operation.kind).into();
            }
            Err(error) if cancellation_requested || is_cancelled_error(&error.code) => {
                operation.state = OperationStatus::Cancelled;
                operation.stage = cancelled_stage(&operation.kind).into();
                operation.error = None;
            }
            Err(error) => {
                operation.state = OperationStatus::Failed;
                operation.stage = failure_stage(&operation.kind).into();
                operation.error = Some(operation_error(error));
            }
        }

        registry.recent.push_front(operation);
        registry.recent.truncate(RECENT_OPERATION_LIMIT);
        self.publish(&registry);
    }

    pub fn update_stage(&self, method: &str, stage: &str, cancelable: Option<bool>) {
        if method.is_empty() || method.len() > 128 || stage.is_empty() || stage.len() > 128 {
            return;
        }

        let now = now_unix_ms();
        let mut registry = self.registry();
        let Some(operation) = registry.active.iter_mut().find(|operation| {
            operation.kind == method && operation.state == OperationStatus::Running
        }) else {
            return;
        };

        operation.stage = stage.to_owned();
        operation.updated_at_unix_ms = now;
        if let Some(cancelable) = cancelable {
            operation.cancelable = cancelable;
        }
        self.publish(&registry);
    }

    pub fn update_domain_stage(
        &self,
        domain: OperationDomain,
        stage: &str,
        cancelable: Option<bool>,
    ) {
        if stage.is_empty() || stage.len() > 128 {
            return;
        }
        let now = now_unix_ms();
        let mut registry = self.registry();
        let Some(operation) = registry.active.iter_mut().find(|operation| {
            operation.domain == domain && operation.state == OperationStatus::Running
        }) else {
            return;
        };
        operation.stage = stage.to_owned();
        operation.updated_at_unix_ms = now;
        if let Some(cancelable) = cancelable {
            operation.cancelable = cancelable;
        }
        self.publish(&registry);
    }

    fn guard_read(&self, method: &str) -> Result<(), BackendError> {
        if !requires_stable_session(method) {
            return Ok(());
        }

        let registry = self.registry();
        if let Some(active) = registry
            .active
            .iter()
            .find(|operation| operation.domain == OperationDomain::AuthSession)
        {
            let details = serde_json::to_value(active).unwrap_or_default();
            return Err(BackendError::new(
                "operation_conflict",
                "Authentication state is changing; retry this request afterwards",
            )
            .with_details(json!({ "active_operation": details }))
            .retryable(true));
        }
        Ok(())
    }

    fn registry(&self) -> MutexGuard<'_, OperationRegistry> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish(&self, registry: &OperationRegistry) {
        let active = registry.active.clone();
        let recent = registry.recent.iter().cloned().collect();
        self.state_tx.send_modify(|state| {
            state.operations.active = active;
            state.operations.recent = recent;
            state.revision = state.revision.wrapping_add(1);
        });
    }
}

fn operation_spec(method: &str) -> Option<OperationSpec> {
    let spec = match method {
        "account.login" => (
            OperationDomain::AuthSession,
            "auth.submitting_credentials",
            false,
            None,
        ),
        "account.submit_2fa" => (
            OperationDomain::AuthSession,
            "auth.submitting_two_factor",
            false,
            None,
        ),
        "account.authenticate_fido2" => (
            OperationDomain::AuthSession,
            "auth.scanning_security_keys",
            true,
            None,
        ),
        "account.submit_fido2_pin" => (
            OperationDomain::AuthSession,
            "auth.submitting_security_key_pin",
            false,
            Some(ControlSpec {
                target_kind: "account.authenticate_fido2",
                stage: "auth.submitting_security_key_pin",
                cancelable: true,
                failure_stage: "auth.security_key_pin_failed",
                failure_cancelable: true,
                requires_target: true,
            }),
        ),
        "account.cancel_fido2" => (
            OperationDomain::AuthSession,
            "auth.cancelling_security_key",
            false,
            Some(ControlSpec {
                target_kind: "account.authenticate_fido2",
                stage: "auth.cancelling_security_key",
                cancelable: false,
                failure_stage: "auth.security_key_cancel_failed",
                failure_cancelable: true,
                requires_target: true,
            }),
        ),
        "account.logout" => (
            OperationDomain::AuthSession,
            "auth.signing_out",
            false,
            None,
        ),
        "connection.connect" => (
            OperationDomain::TunnelConfiguration,
            "tunnel.preparing_connection",
            true,
            None,
        ),
        "connection.disconnect" => (
            OperationDomain::TunnelConfiguration,
            "tunnel.disconnecting",
            false,
            Some(ControlSpec {
                target_kind: "connection.connect",
                stage: "tunnel.cancelling",
                cancelable: false,
                failure_stage: "tunnel.cancel_failed",
                failure_cancelable: true,
                requires_target: false,
            }),
        ),
        "connection.cancel" => (
            OperationDomain::TunnelConfiguration,
            "tunnel.cancelling",
            false,
            Some(ControlSpec {
                target_kind: "connection.connect",
                stage: "tunnel.cancelling",
                cancelable: false,
                failure_stage: "tunnel.cancel_failed",
                failure_cancelable: true,
                requires_target: false,
            }),
        ),
        "feature.set" => (
            OperationDomain::TunnelConfiguration,
            "settings.applying_feature",
            false,
            None,
        ),
        "protocol.set" => (
            OperationDomain::TunnelConfiguration,
            "settings.applying_protocol",
            false,
            None,
        ),
        "dns.set" => (
            OperationDomain::TunnelConfiguration,
            "settings.applying_dns",
            false,
            None,
        ),
        "split_tunneling.set" => (
            OperationDomain::TunnelConfiguration,
            "settings.applying_split_tunneling",
            false,
            None,
        ),
        "report_issue.submit" => (
            OperationDomain::Support,
            "support.submitting_report",
            false,
            None,
        ),
        "connection.feedback" => (
            OperationDomain::Support,
            "support.submitting_connection_feedback",
            false,
            None,
        ),
        "netshield.stats.get" => (
            OperationDomain::Support,
            "support.requesting_netshield_statistics",
            false,
            None,
        ),
        "onboarding.complete"
        | "preferences.set"
        | "profiles.save"
        | "profiles.delete"
        | "recents.record"
        | "recents.pin"
        | "recents.delete"
        | "default_connection.set" => (OperationDomain::Store, "store.saving", false, None),
        _ => return None,
    };

    Some(OperationSpec {
        domain: spec.0,
        stage: spec.1,
        cancelable: spec.2,
        control: spec.3,
    })
}

fn domains_conflict(left: OperationDomain, right: OperationDomain) -> bool {
    use OperationDomain::{AuthSession, Store, Support, TunnelConfiguration};
    match (left, right) {
        (Store, Store) => true,
        (Store, _) | (_, Store) => false,
        (Support, TunnelConfiguration) | (TunnelConfiguration, Support) => false,
        (Support, Support) => true,
        (AuthSession, _) | (_, AuthSession) => true,
        (TunnelConfiguration, TunnelConfiguration) => true,
    }
}

fn requires_stable_session(method: &str) -> bool {
    matches!(
        method,
        "account.upgrade_url"
            | "report_issue.categories.get"
            | "locations.get"
            | "servers.get"
            | "apps.get"
            | "connection.observe"
            | "traffic.get"
    )
}

fn completion_stage(method: &str) -> &'static str {
    match method {
        "account.login" | "account.submit_2fa" | "account.authenticate_fido2" => "auth.complete",
        "account.logout" => "auth.signed_out",
        "connection.connect" => "tunnel.connected",
        "connection.disconnect" | "connection.cancel" => "tunnel.disconnected",
        "report_issue.submit" => "support.report_submitted",
        "onboarding.complete"
        | "preferences.set"
        | "profiles.save"
        | "profiles.delete"
        | "recents.record"
        | "recents.pin"
        | "recents.delete"
        | "default_connection.set" => "store.saved",
        _ => "settings.applied",
    }
}

fn failure_stage(method: &str) -> &'static str {
    match method {
        "account.login" => "auth.credentials_failed",
        "account.submit_2fa" => "auth.two_factor_failed",
        "account.authenticate_fido2" => "auth.security_key_failed",
        "account.logout" => "auth.logout_failed",
        "connection.connect" => "tunnel.connection_failed",
        "connection.disconnect" | "connection.cancel" => "tunnel.disconnect_failed",
        "report_issue.submit" => "support.report_failed",
        "onboarding.complete"
        | "preferences.set"
        | "profiles.save"
        | "profiles.delete"
        | "recents.record"
        | "recents.pin"
        | "recents.delete"
        | "default_connection.set" => "store.save_failed",
        _ => "settings.apply_failed",
    }
}

fn cancelled_stage(method: &str) -> &'static str {
    match method {
        "account.authenticate_fido2" => "auth.security_key_cancelled",
        _ => "tunnel.cancelled",
    }
}

fn operation_error(error: &BackendError) -> OperationError {
    OperationError {
        code: error.code.clone(),
        details: error.details.clone(),
        retryable: error.retryable,
    }
}

fn is_cancelled_error(code: &str) -> bool {
    matches!(
        code,
        "cancelled" | "operation_cancelled" | "connection_cancelled" | "fido2_cancelled"
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
