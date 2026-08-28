use super::{api::ApiSession, EventSink, NativeError, NativeResult};
use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::{
        client_data::{Challenge, CollectedClientData, WebauthnType},
        commands::client_pin::Pin,
        server::{
            AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
            UserVerificationRequirement,
        },
    },
    errors::AuthenticatorError,
    statecallback::StateCallback,
    StatusPinUv, StatusUpdate,
};
use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex as StdMutex,
};
use std::time::Duration;
use tokio::sync::oneshot;

const SECURITY_KEY_TIMEOUT_MS: u64 = 60_000;
const PIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(65);

#[derive(Clone, Debug)]
pub struct FidoRequest {
    authentication_options: Value,
    challenge: Vec<u8>,
    rp_id: String,
    allow_list: Vec<PublicKeyCredentialDescriptor>,
    user_verification: UserVerificationRequirement,
}

impl FidoRequest {
    pub fn from_session(session: &ApiSession) -> NativeResult<Self> {
        let options = session
            .two_factor
            .as_ref()
            .and_then(|two_factor| two_factor.get("FIDO2"))
            .and_then(|fido| fido.get("AuthenticationOptions"))
            .filter(|options| !options.is_null())
            .ok_or_else(|| {
                NativeError::new(
                    "fido2_not_supported",
                    "This Proton authentication session does not offer a security key",
                )
            })?;
        let public_key = options
            .get("publicKey")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_options("publicKey"))?;
        let challenge = decode_bytes(
            public_key
                .get("challenge")
                .ok_or_else(|| invalid_options("challenge"))?,
            "challenge",
        )?;
        if challenge.is_empty() || challenge.len() > 1024 {
            return Err(invalid_options("challenge"));
        }
        let rp_id = public_key
            .get("rpId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|rp_id| valid_rp_id(rp_id))
            .ok_or_else(|| invalid_options("rpId"))?
            .to_ascii_lowercase();
        let allow_list = public_key
            .get("allowCredentials")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_options("allowCredentials"))?
            .iter()
            .map(parse_credential)
            .collect::<NativeResult<Vec<_>>>()?;
        if allow_list.is_empty() || allow_list.len() > 128 {
            return Err(invalid_options("allowCredentials"));
        }
        let user_verification = match public_key
            .get("userVerification")
            .and_then(Value::as_str)
            .unwrap_or("preferred")
        {
            "required" => UserVerificationRequirement::Required,
            "preferred" => UserVerificationRequirement::Preferred,
            "discouraged" => UserVerificationRequirement::Discouraged,
            _ => return Err(invalid_options("userVerification")),
        };
        Ok(Self {
            authentication_options: options.clone(),
            challenge,
            rp_id,
            allow_list,
            user_verification,
        })
    }
}

#[derive(Debug)]
pub struct FidoAssertion {
    pub authentication_options: Value,
    pub client_data: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
}

enum PinOutcome {
    Accepted,
    Invalid(Option<u8>),
    Failed(&'static str, &'static str),
}

struct PendingPin {
    authenticator: mpsc::Sender<Pin>,
}

pub struct FidoOperation {
    manager: StdMutex<Option<AuthenticatorService>>,
    pending_pin: StdMutex<Option<PendingPin>>,
    pin_reply: StdMutex<Option<oneshot::Sender<PinOutcome>>>,
    cancelled: AtomicBool,
}

impl FidoOperation {
    pub fn new() -> Self {
        Self {
            manager: StdMutex::new(None),
            pending_pin: StdMutex::new(None),
            pin_reply: StdMutex::new(None),
            cancelled: AtomicBool::new(false),
        }
    }

    pub async fn submit_pin(&self, pin: &str) -> NativeResult<()> {
        if pin.len() > 255 {
            return Err(NativeError::new(
                "invalid_params",
                "The security-key PIN is too long",
            ));
        }
        let pending = lock(&self.pending_pin).take().ok_or_else(|| {
            NativeError::new(
                "fido2_pin_not_requested",
                "The security key is not requesting a PIN",
            )
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        if lock(&self.pin_reply).replace(reply_tx).is_some() {
            return Err(NativeError::new(
                "fido2_pin_already_submitted",
                "A security-key PIN is already being checked",
            ));
        }
        if pending.authenticator.send(Pin::new(pin)).is_err() {
            lock(&self.pin_reply).take();
            return Err(NativeError::new(
                "fido2_pin_not_requested",
                "The security key stopped requesting a PIN",
            ));
        }
        match tokio::time::timeout(PIN_RESPONSE_TIMEOUT, reply_rx).await {
            Ok(Ok(PinOutcome::Accepted)) => Ok(()),
            Ok(Ok(PinOutcome::Invalid(retries))) => Err(NativeError::new(
                "fido2_pin_invalid",
                "The security-key PIN was not accepted",
            )
            .with_details(serde_json::json!({ "retries_remaining": retries }))
            .retryable(true)),
            Ok(Ok(PinOutcome::Failed(code, message))) => Err(NativeError::new(code, message)),
            Ok(Err(_)) => Err(NativeError::new(
                "fido2_operation_ended",
                "Security-key authentication ended before the PIN was checked",
            )),
            Err(_) => {
                lock(&self.pin_reply).take();
                Err(
                    NativeError::new("fido2_timeout", "The security key did not answer in time")
                        .retryable(true),
                )
            }
        }
    }

    pub fn cancel(&self) -> NativeResult<()> {
        self.cancelled.store(true, Ordering::Release);
        self.reply(PinOutcome::Failed(
            "fido2_cancelled",
            "Security-key authentication was cancelled",
        ));
        let mut manager = lock(&self.manager);
        let manager = manager.as_mut().ok_or_else(|| {
            NativeError::new(
                "fido2_operation_not_active",
                "Security-key authentication is no longer waiting for a device",
            )
        })?;
        manager.cancel().map_err(|error| {
            NativeError::new(
                "fido2_cancel_failed",
                "The security-key operation could not be cancelled",
            )
            .with_source(error)
        })
    }

    fn set_manager(&self, manager: AuthenticatorService) {
        *lock(&self.manager) = Some(manager);
    }

    fn clear_manager(&self) {
        lock(&self.manager).take();
    }

    fn request_pin(&self, sender: mpsc::Sender<Pin>) {
        *lock(&self.pending_pin) = Some(PendingPin {
            authenticator: sender,
        });
    }

    fn clear_pin(&self) {
        lock(&self.pending_pin).take();
    }

    fn reply(&self, outcome: PinOutcome) {
        if let Some(reply) = lock(&self.pin_reply).take() {
            let _ = reply.send(outcome);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub fn authenticate(
    request: FidoRequest,
    operation: Arc<FidoOperation>,
    events: EventSink,
) -> NativeResult<FidoAssertion> {
    let origin = format!("https://{}", request.rp_id);
    let client_data = serde_json::to_vec(&CollectedClientData {
        webauthn_type: WebauthnType::Get,
        challenge: Challenge::new(request.challenge),
        origin: origin.clone(),
        cross_origin: false,
        token_binding: None,
    })
    .map_err(|error| {
        NativeError::new(
            "fido2_client_data_invalid",
            "Unable to serialize the WebAuthn request",
        )
        .with_source(error)
    })?;
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data).into();
    let fallback_credential_id =
        (request.allow_list.len() == 1).then(|| request.allow_list[0].id.clone());
    let args = SignArgs {
        client_data_hash,
        origin,
        relying_party_id: request.rp_id,
        allow_list: request.allow_list,
        user_verification_req: request.user_verification,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: true,
    };

    let mut manager = AuthenticatorService::new().map_err(fido_error)?;
    manager.add_u2f_usb_hid_platform_transports();
    operation.set_manager(manager);

    let (status_tx, status_rx) = mpsc::channel();
    let status_operation = Arc::clone(&operation);
    let status_events = events.clone();
    let status_worker = std::thread::spawn(move || {
        while let Ok(status) = status_rx.recv() {
            handle_status(status, &status_operation, &status_events);
        }
    });
    let (result_tx, result_rx) = mpsc::channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));
    let start_result = lock(&operation.manager)
        .as_mut()
        .ok_or_else(|| {
            NativeError::new(
                "fido2_unavailable",
                "The security-key transport could not be initialized",
            )
        })?
        .sign(SECURITY_KEY_TIMEOUT_MS, args, status_tx, callback);
    if let Err(error) = start_result {
        operation.clear_manager();
        let _ = status_worker.join();
        return Err(fido_error(error));
    }

    let result = result_rx.recv().map_err(|error| {
        NativeError::new(
            "fido2_worker_failed",
            "The security-key transport stopped unexpectedly",
        )
        .with_source(error)
    });
    operation.clear_manager();
    operation.clear_pin();
    let _ = status_worker.join();

    if operation.is_cancelled() {
        operation.reply(PinOutcome::Failed(
            "fido2_cancelled",
            "Security-key authentication was cancelled",
        ));
        return Err(NativeError::new(
            "fido2_cancelled",
            "Security-key authentication was cancelled",
        ));
    }
    let result = result?.map_err(fido_error)?;
    operation.reply(PinOutcome::Accepted);
    let credential_id = result
        .assertion
        .credentials
        .as_ref()
        .map(|credential| credential.id.clone())
        .or(fallback_credential_id)
        .ok_or_else(|| {
            NativeError::new(
                "fido2_response_invalid",
                "The security key did not return a credential identifier",
            )
        })?;
    Ok(FidoAssertion {
        authentication_options: request.authentication_options,
        client_data,
        authenticator_data: result.assertion.auth_data.to_vec(),
        signature: result.assertion.signature,
        credential_id,
    })
}

fn handle_status(status: StatusUpdate, operation: &FidoOperation, events: &EventSink) {
    match status {
        StatusUpdate::PresenceRequired => {
            operation.reply(PinOutcome::Accepted);
            events.stage(
                "account.authenticate_fido2",
                "auth.touch_security_key",
                true,
            );
        }
        StatusUpdate::SelectDeviceNotice => events.stage(
            "account.authenticate_fido2",
            "auth.select_security_key",
            true,
        ),
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
            operation.request_pin(sender);
            events.stage(
                "account.authenticate_fido2",
                "auth.security_key_pin_required",
                true,
            );
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, retries)) => {
            operation.reply(PinOutcome::Invalid(retries));
            operation.request_pin(sender);
            events.stage(
                "account.authenticate_fido2",
                "auth.security_key_pin_required",
                true,
            );
        }
        StatusUpdate::PinUvError(StatusPinUv::PinNotSet) => {
            operation.reply(PinOutcome::Failed(
                "fido2_pin_not_set",
                "The security key needs a PIN before it can be used",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
            operation.reply(PinOutcome::Failed(
                "fido2_pin_blocked",
                "The security key PIN is blocked",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
            operation.reply(PinOutcome::Failed(
                "fido2_pin_auth_blocked",
                "Too many PIN attempts; reconnect the security key",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::UvBlocked) => {
            operation.reply(PinOutcome::Failed(
                "fido2_user_verification_blocked",
                "Security-key user verification is blocked",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::PinIsTooShort) => {
            operation.reply(PinOutcome::Failed(
                "fido2_pin_too_short",
                "The security-key PIN is too short",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::PinIsTooLong(_)) => {
            operation.reply(PinOutcome::Failed(
                "fido2_pin_too_long",
                "The security-key PIN is too long",
            ));
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidUv(_)) => events.stage(
            "account.authenticate_fido2",
            "auth.verifying_security_key_user",
            true,
        ),
        StatusUpdate::SelectResultNotice(sender, _) => {
            let _ = sender.send(Some(0));
            events.stage(
                "account.authenticate_fido2",
                "auth.verifying_security_key",
                true,
            );
        }
        StatusUpdate::InteractiveManagement(_) => {}
    }
}

fn parse_credential(value: &Value) -> NativeResult<PublicKeyCredentialDescriptor> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_options("allowCredentials"))?;
    if object.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(invalid_options("allowCredentials.type"));
    }
    let id = decode_bytes(
        object
            .get("id")
            .ok_or_else(|| invalid_options("allowCredentials.id"))?,
        "allowCredentials.id",
    )?;
    if id.is_empty() || id.len() > 1024 {
        return Err(invalid_options("allowCredentials.id"));
    }
    let transports = object
        .get("transports")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|transport| match transport {
                    "usb" => Some(Transport::USB),
                    "nfc" => Some(Transport::NFC),
                    "ble" => Some(Transport::BLE),
                    "internal" => Some(Transport::Internal),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(PublicKeyCredentialDescriptor { id, transports })
}

fn decode_bytes(value: &Value, field: &str) -> NativeResult<Vec<u8>> {
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| invalid_options(field))
            })
            .collect();
    }
    let encoded = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_options(field))?;
    for engine in [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD,
    ] {
        if let Ok(decoded) = engine.decode(encoded) {
            return Ok(decoded);
        }
    }
    Err(invalid_options(field))
}

fn valid_rp_id(rp_id: &str) -> bool {
    rp_id.len() <= 253
        && rp_id.is_ascii()
        && !rp_id.starts_with('.')
        && !rp_id.ends_with('.')
        && rp_id.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_options(field: &str) -> NativeError {
    NativeError::new(
        "fido2_options_invalid",
        format!("Proton returned invalid WebAuthn {field}"),
    )
}

fn fido_error(error: AuthenticatorError) -> NativeError {
    let source = error.to_string();
    let lower = source.to_ascii_lowercase();
    let (code, message, retryable) = if matches!(error, AuthenticatorError::CancelledByUser) {
        (
            "fido2_cancelled",
            "Security-key authentication was cancelled",
            false,
        )
    } else if lower.contains("timeout") || lower.contains("not allowed") {
        (
            "fido2_timeout",
            "No eligible security key answered in time",
            true,
        )
    } else if lower.contains("pin") {
        (
            "fido2_pin_failed",
            "The security key could not verify its PIN",
            true,
        )
    } else if lower.contains("not supported") || lower.contains("unsupported") {
        (
            "fido2_unsupported",
            "The security key does not support this Proton request",
            false,
        )
    } else {
        (
            "fido2_device_error",
            "The security key could not complete authentication",
            true,
        )
    };
    NativeError::new(code, message)
        .with_source(source)
        .retryable(retryable)
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session(options: Value) -> ApiSession {
        ApiSession {
            uid: "uid".into(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            scopes: vec!["twofactor".into()],
            account_name: "test".into(),
            two_factor: Some(json!({
                "FIDO2": { "AuthenticationOptions": options }
            })),
        }
    }

    #[test]
    fn parses_array_and_base64url_webauthn_values() {
        let request = FidoRequest::from_session(&session(json!({
            "publicKey": {
                "challenge": [1, 2, 3, 254],
                "rpId": "Account.Proton.Me",
                "allowCredentials": [{
                    "type": "public-key",
                    "id": "AQID_g",
                    "transports": ["usb", "hybrid"]
                }],
                "userVerification": "required"
            }
        })))
        .unwrap();
        assert_eq!(request.challenge, vec![1, 2, 3, 254]);
        assert_eq!(request.rp_id, "account.proton.me");
        assert_eq!(request.allow_list[0].id, vec![1, 2, 3, 254]);
        assert_eq!(request.allow_list[0].transports, vec![Transport::USB]);
        assert_eq!(
            request.user_verification,
            UserVerificationRequirement::Required
        );
    }

    #[test]
    fn rejects_origin_injection_in_relying_party() {
        let error = FidoRequest::from_session(&session(json!({
            "publicKey": {
                "challenge": [1],
                "rpId": "proton.me/evil",
                "allowCredentials": [{ "type": "public-key", "id": [1] }]
            }
        })))
        .unwrap_err();
        assert_eq!(error.code, "fido2_options_invalid");
    }

    #[test]
    fn collected_client_data_matches_webauthn_get_contract() {
        let data = serde_json::to_string(&CollectedClientData {
            webauthn_type: WebauthnType::Get,
            challenge: Challenge::new(vec![1, 2, 3, 254]),
            origin: "https://account.proton.me".into(),
            cross_origin: false,
            token_binding: None,
        })
        .unwrap();
        assert_eq!(
            data,
            r#"{"type":"webauthn.get","challenge":"AQID_g","origin":"https://account.proton.me","crossOrigin":false}"#
        );
    }
}
