use super::alternative_routing::{self, AlternativeRoute};
use super::fido2::FidoAssertion;
use super::{web_auth, EventSink, NativeError, NativeResult};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};
use reqwest::{cookie::Jar, header, Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

const API_BASE: &str = "https://vpn-api.proton.me";
const API_CORE_COMPAT_VERSION: &str = "5.5.11";
const MAX_API_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const TLS_PINS: &[&str] = &[
    "CT56BhOTmj5ZIPgb/xD5mH8rY3BLo/MlhP7oPyJUEDo=",
    "35Dx28/uzN3LeltkCBQ8RHK0tlNSa2kCpCRGNp34Gxc=",
    "qYIukVc63DEITct8sFT7ebIq5qsWmuscaIKeJx+5J5A=",
];
const ALTERNATIVE_TLS_PINS: &[&str] = &[
    "EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
    "iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
    "MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
    "C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=",
];

#[derive(Clone, Debug)]
struct CachedAlternativeRoute {
    host: String,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
enum ApiRoute {
    Direct,
    Alternative(String),
}

impl ApiRoute {
    fn url(&self, endpoint: &str) -> String {
        match self {
            Self::Direct => format!("{API_BASE}{endpoint}"),
            Self::Alternative(host) => format!("https://{host}{endpoint}"),
        }
    }

    fn pins(&self) -> &'static [&'static str] {
        match self {
            Self::Direct => TLS_PINS,
            Self::Alternative(_) => ALTERNATIVE_TLS_PINS,
        }
    }

    fn is_alternative(&self) -> bool {
        matches!(self, Self::Alternative(_))
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Alternative(_) => "alternative",
        }
    }
}

pub struct ApiSession {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    pub account_name: String,
    pub two_factor: Option<Value>,
}

impl ApiSession {
    pub fn needs_two_factor(&self) -> bool {
        self.scopes.iter().any(|scope| scope == "twofactor")
    }
}

#[derive(Clone)]
pub struct ProtonApi {
    client: reqwest::Client,
    alternative_client: reqwest::Client,
    events: EventSink,
    human_verification: Arc<tokio::sync::Mutex<()>>,
    alternative_routing_enabled: Arc<AtomicBool>,
    alternative_route: Arc<tokio::sync::Mutex<Option<CachedAlternativeRoute>>>,
}

impl ProtonApi {
    pub fn new(events: EventSink) -> NativeResult<Self> {
        let app_version = format!(
            "linux-vpn-gui@{API_CORE_COMPAT_VERSION}+{}",
            std::env::consts::ARCH
        );
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-pm-appversion",
            header::HeaderValue::from_str(&app_version).map_err(|error| {
                NativeError::new("api_client_invalid", "Invalid Proton API version header")
                    .with_source(error)
            })?,
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("ProtonVPN/0.8.0 (Linux; Omarchy/4)"),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let cookie_jar = Arc::new(Jar::default());
        let client = build_api_client(headers.clone(), Arc::clone(&cookie_jar), false)?;
        // Proton's alternative hosts intentionally use certificates whose DNS
        // names do not match their IP-valued TXT records. The official clients
        // therefore authenticate these endpoints solely with the dedicated
        // alternative-routing SPKI pins. This client is never used for direct
        // API traffic and every response is pin-checked before its body is read.
        let alternative_client = build_api_client(headers, cookie_jar, true)?;
        Ok(Self {
            client,
            alternative_client,
            events,
            human_verification: Arc::new(tokio::sync::Mutex::new(())),
            alternative_routing_enabled: Arc::new(AtomicBool::new(true)),
            alternative_route: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub async fn set_alternative_routing(&self, enabled: bool) {
        self.alternative_routing_enabled
            .store(enabled, Ordering::Release);
        if !enabled {
            *self.alternative_route.lock().await = None;
        }
    }

    pub async fn authenticate_sso(&self, username: String) -> NativeResult<ApiSession> {
        let unauth_response = self
            .request(Method::POST, "/auth/v4/sessions", None, None)
            .await?;
        let unauth = ApiSession {
            uid: required_string(&unauth_response, "UID")?,
            access_token: required_string(&unauth_response, "AccessToken")?,
            refresh_token: required_string(&unauth_response, "RefreshToken")?,
            scopes: Vec::new(),
            account_name: username.clone(),
            two_factor: None,
        };
        let info = self
            .request(
                Method::POST,
                "/auth/info",
                Some(json!({ "Username": username, "Intent": "SSO" })),
                Some(&unauth),
            )
            .await?;
        let challenge = required_string(&info, "SSOChallengeToken")?;
        self.events.stage_auth("auth.waiting_for_sso");
        let response_token =
            web_auth::complete_sso(&challenge, &unauth.uid, &unauth.access_token).await?;
        self.events.stage_auth("auth.completing_sso");
        let response = self
            .request(
                Method::POST,
                "/auth",
                Some(json!({ "SSOResponseToken": response_token })),
                Some(&unauth),
            )
            .await?;
        api_session_from_auth(response, username)
    }

    pub async fn authenticate(
        &self,
        username: String,
        password: Zeroizing<String>,
    ) -> NativeResult<ApiSession> {
        let info = self
            .request(
                Method::POST,
                "/auth/info",
                Some(json!({ "Username": username })),
                None,
            )
            .await?;
        let version = info
            .get("Version")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| invalid_api_response("SRP version"))?;
        let version = SrpHashVersion::try_from(version).map_err(|error| {
            NativeError::new(
                "srp_unsupported",
                "Proton returned an unsupported SRP version",
            )
            .with_source(error)
        })?;
        let salt = required_string(&info, "Salt")?;
        let modulus = required_string(&info, "Modulus")?;
        let server_ephemeral = required_string(&info, "ServerEphemeral")?;
        let srp_session = required_string(&info, "SRPSession")?;
        let username_for_srp = username.clone();
        let proof: SRPProofB64 = tokio::task::spawn_blocking(move || {
            SRPAuth::with_pgp(
                Some(&username_for_srp),
                password.as_str(),
                version,
                &salt,
                &modulus,
                &server_ephemeral,
            )
            .and_then(|auth| auth.generate_proofs())
            .map(SRPProofB64::from)
        })
        .await
        .map_err(|error| {
            NativeError::new("srp_task_failed", "The SRP authentication worker stopped")
                .with_source(error)
        })?
        .map_err(|error| {
            NativeError::new(
                "srp_verification_failed",
                "Unable to verify Proton's signed SRP challenge",
            )
            .with_source(error)
        })?;

        let response = self
            .request(
                Method::POST,
                "/auth",
                Some(json!({
                    "Username": username,
                    "ClientEphemeral": proof.client_ephemeral,
                    "ClientProof": proof.client_proof,
                    "SRPSession": srp_session,
                })),
                None,
            )
            .await?;
        let server_proof = required_string(&response, "ServerProof")?;
        if !proof.compare_server_proof(&server_proof) {
            return Err(NativeError::new(
                "srp_server_proof_invalid",
                "Proton's SRP server proof did not match",
            ));
        }
        api_session_from_auth(response, username)
    }

    pub async fn submit_2fa(&self, session: &mut ApiSession, code: &str) -> NativeResult<()> {
        let response = self
            .request(
                Method::POST,
                "/auth/2fa",
                Some(json!({ "TwoFactorCode": code })),
                Some(session),
            )
            .await?;
        session.scopes = string_array(&response, "Scopes")?;
        session.two_factor = None;
        Ok(())
    }

    pub async fn submit_fido2(
        &self,
        session: &mut ApiSession,
        assertion: &FidoAssertion,
    ) -> NativeResult<()> {
        let response = self
            .request(
                Method::POST,
                "/auth/2fa",
                Some(json!({
                    "FIDO2": {
                        "AuthenticationOptions": assertion.authentication_options,
                        "ClientData": BASE64.encode(&assertion.client_data),
                        "AuthenticatorData": BASE64.encode(&assertion.authenticator_data),
                        "Signature": BASE64.encode(&assertion.signature),
                        "CredentialID": assertion.credential_id,
                    }
                })),
                Some(session),
            )
            .await?;
        session.scopes = string_array(&response, "Scopes")?;
        session.two_factor = None;
        Ok(())
    }

    pub async fn refresh(&self, session: &mut ApiSession) -> NativeResult<()> {
        let response = self
            .request(
                Method::POST,
                "/auth/refresh",
                Some(json!({
                    "ResponseType": "token",
                    "GrantType": "refresh_token",
                    "RefreshToken": session.refresh_token,
                    "RedirectURI": "http://protonmail.ch",
                })),
                Some(session),
            )
            .await?;
        session.access_token = required_string(&response, "AccessToken")?;
        session.refresh_token = required_string(&response, "RefreshToken")?;
        session.scopes = string_array(&response, "Scopes")?;
        Ok(())
    }

    pub async fn logout(&self, session: &ApiSession) -> NativeResult<()> {
        self.request(Method::DELETE, "/auth", None, Some(session))
            .await?;
        Ok(())
    }

    pub async fn get(&self, endpoint: &str, session: &ApiSession) -> NativeResult<Value> {
        self.request(Method::GET, endpoint, None, Some(session))
            .await
    }

    pub async fn public_get(&self, endpoint: &str) -> NativeResult<Value> {
        self.request(Method::GET, endpoint, None, None).await
    }

    pub async fn post(
        &self,
        endpoint: &str,
        body: Value,
        session: &ApiSession,
    ) -> NativeResult<Value> {
        self.request(Method::POST, endpoint, Some(body), Some(session))
            .await
    }

    pub async fn post_multipart(
        &self,
        endpoint: &str,
        fields: &[(String, String)],
        files: &[(String, String, Vec<u8>)],
        session: Option<&ApiSession>,
    ) -> NativeResult<Value> {
        let mut transient_attempt = 0_u64;
        let mut human_verification_token = None;
        let mut route = self.initial_route().await;
        let mut tried_alternative = route.is_alternative();
        loop {
            let url = route.url(endpoint);
            let mut form = reqwest::multipart::Form::new();
            for (name, value) in fields {
                form = form.text(name.clone(), value.clone());
            }
            for (field, filename, data) in files {
                form = form.part(
                    field.clone(),
                    reqwest::multipart::Part::bytes(data.clone()).file_name(filename.clone()),
                );
            }
            let mut request = self.client_for_route(&route).post(&url).multipart(form);
            if let Some(session) = session {
                request = request
                    .header("x-pm-uid", &session.uid)
                    .bearer_auth(&session.access_token);
            }
            if let Some(token) = &human_verification_token {
                request = request
                    .header("x-pm-human-verification-token-type", "captcha")
                    .header("x-pm-human-verification-token", token);
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => {
                    let native =
                        NativeError::new("api_unreachable", "The Proton API could not be reached")
                            .with_source(error)
                            .retryable(true);
                    if let Some(next) = self
                        .route_after_transport_failure(&route, tried_alternative)
                        .await
                    {
                        tried_alternative |= next.is_alternative();
                        route = next;
                        continue;
                    }
                    if transient_attempt < 2 {
                        transient_attempt += 1;
                        tokio::time::sleep(Duration::from_millis(250 * transient_attempt)).await;
                        continue;
                    }
                    return Err(native);
                }
            };
            if let Err(error) = validate_tls_pin(&response, route.pins()) {
                if let Some(next) = self
                    .route_after_transport_failure(&route, tried_alternative)
                    .await
                {
                    tried_alternative |= next.is_alternative();
                    route = next;
                    continue;
                }
                return Err(error);
            }
            let (status, _, payload) = match decode_api_response(response, &route).await {
                Ok(decoded) => decoded,
                Err(error) => {
                    if let Some(next) = self
                        .route_after_transport_failure(&route, tried_alternative)
                        .await
                    {
                        tried_alternative |= next.is_alternative();
                        route = next;
                        continue;
                    }
                    return Err(error);
                }
            };
            let code = payload.get("Code").and_then(Value::as_i64).unwrap_or(0);
            if status.is_success() && matches!(code, 1000 | 1001) {
                return Ok(payload);
            }
            if human_verification_token.is_none() {
                if let Some(challenge) = human_verification_challenge(code, &payload) {
                    human_verification_token =
                        Some(self.solve_human_verification(challenge).await?);
                    continue;
                }
            }
            let error = api_error(status, code, &payload);
            if transient_attempt < 2
                && matches!(
                    status,
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::SERVICE_UNAVAILABLE
                )
            {
                transient_attempt += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Err(error);
        }
    }

    async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Value>,
        session: Option<&ApiSession>,
    ) -> NativeResult<Value> {
        let mut transient_attempt = 0_u64;
        let mut human_verification_token = None;
        let mut route = self.initial_route().await;
        let mut tried_alternative = route.is_alternative();
        loop {
            let url = route.url(endpoint);
            let mut request = self.client_for_route(&route).request(method.clone(), &url);
            if let Some(body) = &body {
                request = request.json(body);
            }
            if let Some(session) = session {
                request = request
                    .header("x-pm-uid", &session.uid)
                    .bearer_auth(&session.access_token);
            }
            if let Some(token) = &human_verification_token {
                request = request
                    .header("x-pm-human-verification-token-type", "captcha")
                    .header("x-pm-human-verification-token", token);
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => {
                    let native =
                        NativeError::new("api_unreachable", "The Proton API could not be reached")
                            .with_source(error)
                            .retryable(true);
                    if let Some(next) = self
                        .route_after_transport_failure(&route, tried_alternative)
                        .await
                    {
                        tried_alternative |= next.is_alternative();
                        route = next;
                        continue;
                    }
                    if transient_attempt < 2 {
                        transient_attempt += 1;
                        tokio::time::sleep(Duration::from_millis(250 * transient_attempt)).await;
                        continue;
                    }
                    return Err(native);
                }
            };
            if let Err(error) = validate_tls_pin(&response, route.pins()) {
                if let Some(next) = self
                    .route_after_transport_failure(&route, tried_alternative)
                    .await
                {
                    tried_alternative |= next.is_alternative();
                    route = next;
                    continue;
                }
                return Err(error);
            }
            let (status, retry_after, payload) = match decode_api_response(response, &route).await {
                Ok(decoded) => decoded,
                Err(error) => {
                    if let Some(next) = self
                        .route_after_transport_failure(&route, tried_alternative)
                        .await
                    {
                        tried_alternative |= next.is_alternative();
                        route = next;
                        continue;
                    }
                    return Err(error);
                }
            };
            let code = payload.get("Code").and_then(Value::as_i64).unwrap_or(0);
            if status.is_success() && matches!(code, 1000 | 1001) {
                return Ok(payload);
            }
            if human_verification_token.is_none() {
                if let Some(challenge) = human_verification_challenge(code, &payload) {
                    human_verification_token =
                        Some(self.solve_human_verification(challenge).await?);
                    continue;
                }
            }
            let error = api_error(status, code, &payload);
            if transient_attempt < 2
                && (matches!(
                    status,
                    StatusCode::REQUEST_TIMEOUT | StatusCode::BAD_GATEWAY
                ) || matches!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                ))
            {
                transient_attempt += 1;
                tokio::time::sleep(Duration::from_secs(retry_after.unwrap_or(1))).await;
                continue;
            }
            return Err(error);
        }
    }

    async fn initial_route(&self) -> ApiRoute {
        if !self.alternative_routing_enabled.load(Ordering::Acquire) {
            return ApiRoute::Direct;
        }
        let mut cached = self.alternative_route.lock().await;
        match cached.as_ref() {
            Some(route) if route.expires_at > Instant::now() => {
                ApiRoute::Alternative(route.host.clone())
            }
            Some(_) => {
                *cached = None;
                ApiRoute::Direct
            }
            None => ApiRoute::Direct,
        }
    }

    fn client_for_route(&self, route: &ApiRoute) -> &reqwest::Client {
        match route {
            ApiRoute::Direct => &self.client,
            ApiRoute::Alternative(_) => &self.alternative_client,
        }
    }

    async fn route_after_transport_failure(
        &self,
        current: &ApiRoute,
        tried_alternative: bool,
    ) -> Option<ApiRoute> {
        if current.is_alternative() {
            *self.alternative_route.lock().await = None;
            return Some(ApiRoute::Direct);
        }
        if tried_alternative || !self.alternative_routing_enabled.load(Ordering::Acquire) {
            return None;
        }
        let AlternativeRoute { host, valid_for } = alternative_routing::resolve().await.ok()?;
        let cached = CachedAlternativeRoute {
            host: host.clone(),
            expires_at: Instant::now() + valid_for,
        };
        *self.alternative_route.lock().await = Some(cached);
        Some(ApiRoute::Alternative(host))
    }

    async fn solve_human_verification(&self, challenge: &str) -> NativeResult<String> {
        let _guard = self.human_verification.try_lock().map_err(|_| {
            NativeError::new(
                "human_verification_in_progress",
                "Another Proton human verification is already in progress",
            )
        })?;
        self.events
            .stage_auth("auth.waiting_for_human_verification");
        let token = web_auth::solve_captcha(challenge).await?;
        if token.is_empty() || token.len() > 8192 {
            return Err(NativeError::new(
                "human_verification_failed",
                "Proton returned an invalid human-verification token",
            ));
        }
        self.events.stage_auth("auth.completing_human_verification");
        Ok(token)
    }
}

fn build_api_client(
    headers: header::HeaderMap,
    cookie_jar: Arc<Jar>,
    accept_pinned_name_mismatch: bool,
) -> NativeResult<reqwest::Client> {
    reqwest::Client::builder()
        .default_headers(headers)
        .https_only(true)
        .cookie_provider(cookie_jar)
        .tls_info(true)
        .danger_accept_invalid_certs(accept_pinned_name_mismatch)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| {
            NativeError::new(
                "api_client_unavailable",
                "Unable to initialize Proton API client",
            )
            .with_source(error)
        })
}

async fn decode_api_response(
    mut response: reqwest::Response,
    route: &ApiRoute,
) -> NativeResult<(StatusCode, Option<u64>, Value)> {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.min(8));
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(80)
        .collect::<String>();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_API_RESPONSE_BYTES as u64)
    {
        return Err(invalid_response_error(
            status,
            route,
            &content_type,
            MAX_API_RESPONSE_BYTES + 1,
            "response exceeds the size limit",
        ));
    }

    let mut body = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            invalid_response_error(
                status,
                route,
                &content_type,
                body.len(),
                "response body could not be read",
            )
            .with_source(error)
        })?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_API_RESPONSE_BYTES {
            return Err(invalid_response_error(
                status,
                route,
                &content_type,
                body.len().saturating_add(chunk.len()),
                "response exceeds the size limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    let payload = serde_json::from_slice(&body).map_err(|error| {
        invalid_response_error(
            status,
            route,
            &content_type,
            body.len(),
            "response body is not valid JSON",
        )
        .with_source(error)
    })?;
    Ok((status, retry_after, payload))
}

fn invalid_response_error(
    status: StatusCode,
    route: &ApiRoute,
    content_type: &str,
    body_bytes: usize,
    reason: &str,
) -> NativeError {
    NativeError::new(
        "api_response_invalid",
        "Proton returned an invalid API response",
    )
    .with_details(json!({
        "http_status": status.as_u16(),
        "content_type": content_type,
        "body_bytes": body_bytes,
        "route": route.label(),
        "reason": reason,
    }))
    .retryable(true)
}

fn human_verification_challenge(code: i64, payload: &Value) -> Option<&str> {
    if !matches!(code, 9001 | 12087) {
        return None;
    }
    let details = payload.get("Details")?;
    let supports_captcha = details
        .get("HumanVerificationMethods")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .filter_map(Value::as_str)
                .any(|method| method.eq_ignore_ascii_case("captcha"))
        })
        .unwrap_or(false);
    if !supports_captcha {
        return None;
    }
    details
        .get("HumanVerificationToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 8192)
}

fn validate_tls_pin(response: &reqwest::Response, expected_pins: &[&str]) -> NativeResult<()> {
    let certificate = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .ok_or_else(|| {
            NativeError::new(
                "tls_pinning_unavailable",
                "The Proton API peer certificate was not available for pinning",
            )
        })?;
    let (_, certificate) = parse_x509_certificate(certificate).map_err(|error| {
        NativeError::new(
            "tls_certificate_invalid",
            "Unable to parse Proton's TLS certificate",
        )
        .with_source(error)
    })?;
    let subject_public_key_info = certificate.tbs_certificate.subject_pki.raw;
    let pin = BASE64.encode(Sha256::digest(subject_public_key_info));
    if !expected_pins.contains(&pin.as_str()) {
        return Err(NativeError::new(
            "tls_pin_mismatch",
            "Proton API TLS pin verification failed",
        ));
    }
    Ok(())
}

fn api_session_from_auth(response: Value, account_name: String) -> NativeResult<ApiSession> {
    Ok(ApiSession {
        uid: required_string(&response, "UID")?,
        access_token: required_string(&response, "AccessToken")?,
        refresh_token: required_string(&response, "RefreshToken")?,
        scopes: string_array(&response, "Scopes")?,
        account_name,
        two_factor: response.get("2FA").cloned(),
    })
}

fn api_error(status: StatusCode, code: i64, payload: &Value) -> NativeError {
    let (native_code, fallback, retryable) = match (status.as_u16(), code) {
        (_, 8002) => (
            "authentication_failed",
            "Incorrect Proton credentials or verification code",
            false,
        ),
        (_, 8100) => (
            "sso_required",
            "This Proton account must sign in with organization SSO",
            false,
        ),
        (422, 9001) | (_, 12087) => (
            "human_verification_required",
            "Proton requires additional human verification",
            false,
        ),
        (401, _) => (
            "authentication_expired",
            "The Proton session has expired",
            false,
        ),
        (403, _) => (
            "api_scope_missing",
            "The Proton session lacks a required scope",
            false,
        ),
        (429, _) => (
            "api_rate_limited",
            "The Proton API rate limit was reached",
            true,
        ),
        (500..=599, _) => (
            "api_server_error",
            "The Proton API is temporarily unavailable",
            true,
        ),
        _ => ("api_error", "The Proton API rejected the request", false),
    };
    let message = payload
        .get("Error")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 240)
        .unwrap_or(fallback);
    NativeError::new(native_code, message)
        .with_details(json!({ "api_code": code, "http_status": status.as_u16() }))
        .retryable(retryable)
}

fn required_string(value: &Value, key: &str) -> NativeResult<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_api_response(key))
}

fn string_array(value: &Value, key: &str) -> NativeResult<Vec<String>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .ok_or_else(|| invalid_api_response(key))
}

fn invalid_api_response(field: &str) -> NativeError {
    NativeError::new(
        "api_response_invalid",
        format!("Proton API response is missing {field}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "contacts Proton DNS-over-HTTPS and API endpoints"]
    async fn live_alternative_auth_info_is_pinned_json() {
        let AlternativeRoute { host, .. } = alternative_routing::resolve().await.unwrap();
        let route = ApiRoute::Alternative(host);
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-pm-appversion",
            header::HeaderValue::from_static("linux-vpn-gui@5.5.11+x86_64"),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let client = build_api_client(headers, Arc::new(Jar::default()), true).unwrap();
        let response = client
            .post(route.url("/auth/info"))
            .json(&json!({ "Username": "proton-omarchy-live-probe-does-not-exist" }))
            .send()
            .await
            .unwrap();
        validate_tls_pin(&response, route.pins()).unwrap();
        let (_, _, payload) = decode_api_response(response, &route).await.unwrap();
        assert!(payload.get("Code").and_then(Value::as_i64).is_some());
    }
}
