use super::{NativeError, NativeResult};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Stdio, time::Duration};
use tokio::{net::TcpListener, process::Child};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

const BROWSER_START_TIMEOUT: Duration = Duration::from_secs(12);
const SSO_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CAPTCHA_TIMEOUT: Duration = Duration::from_secs(10 * 60);

type DevToolsSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub async fn complete_sso(challenge: &str, uid: &str, access_token: &str) -> NativeResult<String> {
    let mut url = reqwest::Url::parse("https://vpn-api.proton.me/auth/sso/")
        .map_err(|error| web_error("sso_unavailable", "Invalid Proton SSO URL", error))?;
    url.path_segments_mut()
        .map_err(|_| NativeError::new("sso_unavailable", "Invalid Proton SSO URL"))?
        .push(challenge);
    let initial_url = url.to_string();
    let (mut browser, mut cdp) = BrowserSession::open().await?;

    cdp.command("Page.enable", json!({})).await?;
    cdp.command(
        "Fetch.enable",
        json!({
            "patterns": [{
                "urlPattern": initial_url,
                "resourceType": "Document",
                "requestStage": "Request"
            }]
        }),
    )
    .await?;
    cdp.command("Network.enable", json!({})).await?;
    cdp.send("Page.navigate", json!({ "url": initial_url }))
        .await?;

    let result = tokio::time::timeout(SSO_TIMEOUT, async {
        loop {
            let message = cdp.next_event().await?;
            let method = message.get("method").and_then(Value::as_str).unwrap_or("");
            let params = message.get("params").cloned().unwrap_or(Value::Null);
            if method == "Fetch.requestPaused" {
                let request_id = params
                    .get("requestId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| NativeError::new("sso_failed", "Invalid browser request"))?;
                let request = params.get("request").cloned().unwrap_or(Value::Null);
                let request_url = request.get("url").and_then(Value::as_str).unwrap_or("");
                let mut headers = header_array(request.get("headers"));
                if request_url == initial_url {
                    set_header(&mut headers, "x-pm-uid", uid);
                    set_header(
                        &mut headers,
                        "Authorization",
                        &format!("Bearer {access_token}"),
                    );
                }
                cdp.send(
                    "Fetch.continueRequest",
                    json!({ "requestId": request_id, "headers": headers }),
                )
                .await?;
                continue;
            }

            for candidate in navigation_urls(method, &params) {
                if let Some(token) = sso_callback_token(candidate, uid) {
                    return Ok(token);
                }
            }
        }
    })
    .await
    .map_err(|_| NativeError::new("sso_timeout", "Organization SSO timed out"))
    .and_then(|result| result);
    browser.cleanup().await;
    result
}

pub async fn solve_captcha(token: &str) -> NativeResult<String> {
    let mut url = reqwest::Url::parse("https://vpn-api.proton.me/core/v4/captcha")
        .map_err(|error| web_error("human_verification_failed", "Invalid CAPTCHA URL", error))?;
    url.query_pairs_mut()
        .append_pair("Token", token)
        .append_pair("Dark", "1");
    let (mut browser, mut cdp) = BrowserSession::open().await?;
    cdp.command("Page.enable", json!({})).await?;
    cdp.command("Runtime.enable", json!({})).await?;
    cdp.command("Page.setBypassCSP", json!({ "enabled": true }))
        .await?;
    cdp.command(
        "Runtime.addBinding",
        json!({ "name": "__protonOmarchyWebMessage" }),
    )
    .await?;
    cdp.command(
        "Page.addScriptToEvaluateOnNewDocument",
        json!({
            "source": r#"
                (() => {
                  const send = message => {
                    try {
                      window.__protonOmarchyWebMessage(JSON.stringify(message));
                    } catch (_) {}
                  };
                  window.chrome = window.chrome || {};
                  window.chrome.webview = window.chrome.webview || {};
                  window.chrome.webview.postMessage = send;
                })();
            "#
        }),
    )
    .await?;
    cdp.send("Page.navigate", json!({ "url": url.to_string() }))
        .await?;

    let result = tokio::time::timeout(CAPTCHA_TIMEOUT, async {
        loop {
            let message = cdp.next_event().await?;
            if message.get("method").and_then(Value::as_str) != Some("Runtime.bindingCalled") {
                continue;
            }
            let params = message.get("params").cloned().unwrap_or(Value::Null);
            if params.get("name").and_then(Value::as_str) != Some("__protonOmarchyWebMessage") {
                continue;
            }
            let payload = params.get("payload").and_then(Value::as_str).unwrap_or("");
            if let Some(token) = captcha_response_token(payload) {
                return Ok(token);
            }
        }
    })
    .await
    .map_err(|_| NativeError::new("human_verification_timeout", "Human verification timed out"))
    .and_then(|result| result);
    browser.cleanup().await;
    result
}

struct BrowserSession {
    child: Child,
    profile_dir: PathBuf,
}

impl BrowserSession {
    async fn open() -> NativeResult<(Self, CdpClient)> {
        let port = available_local_port().await?;
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let profile_dir = runtime_dir.join(format!(
            "proton-omarchy-web-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&profile_dir).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to create the isolated browser profile",
                error,
            )
        })?;
        fs::set_permissions(&profile_dir, fs::Permissions::from_mode(0o700)).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to secure the isolated browser profile",
                error,
            )
        })?;

        let mut child = tokio::process::Command::new("/usr/bin/brave-origin")
            .arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg(format!("--remote-debugging-port={port}"))
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-sync")
            .arg("--app=about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                web_error(
                    "web_auth_unavailable",
                    "Unable to start the isolated Brave window",
                    error,
                )
            })?;

        let websocket_url = match discover_page(port, &mut child).await {
            Ok(value) => value,
            Err(error) => {
                let _ = child.start_kill();
                let _ = fs::remove_dir_all(&profile_dir);
                return Err(error);
            }
        };
        let (socket, _) = match connect_async(&websocket_url).await {
            Ok(socket) => socket,
            Err(error) => {
                let _ = child.start_kill();
                let _ = fs::remove_dir_all(&profile_dir);
                return Err(web_error(
                    "web_auth_unavailable",
                    "Unable to control the isolated Brave window",
                    error,
                ));
            }
        };
        Ok((
            Self { child, profile_dir },
            CdpClient { socket, next_id: 1 },
        ))
    }

    async fn cleanup(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        let _ = fs::remove_dir_all(&self.profile_dir);
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = fs::remove_dir_all(&self.profile_dir);
    }
}

struct CdpClient {
    socket: DevToolsSocket,
    next_id: u64,
}

impl CdpClient {
    async fn command(&mut self, method: &str, params: Value) -> NativeResult<Value> {
        let id = self.send(method, params).await?;
        loop {
            let message = self.next_message().await?;
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(NativeError::new(
                    "web_auth_failed",
                    format!("Browser automation failed: {error}"),
                ));
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    async fn send(&mut self, method: &str, params: Value) -> NativeResult<u64> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.socket
            .send(Message::Text(
                json!({ "id": id, "method": method, "params": params })
                    .to_string()
                    .into(),
            ))
            .await
            .map_err(|error| web_error("web_auth_failed", "Browser channel failed", error))?;
        Ok(id)
    }

    async fn next_event(&mut self) -> NativeResult<Value> {
        loop {
            let message = self.next_message().await?;
            if message.get("method").is_some() {
                return Ok(message);
            }
        }
    }

    async fn next_message(&mut self) -> NativeResult<Value> {
        while let Some(message) = self.socket.next().await {
            let message = message
                .map_err(|error| web_error("web_auth_failed", "Browser channel failed", error))?;
            if let Message::Text(text) = message {
                return serde_json::from_str(text.as_str()).map_err(|error| {
                    web_error(
                        "web_auth_failed",
                        "Browser returned an invalid control message",
                        error,
                    )
                });
            }
        }
        Err(NativeError::new(
            "web_auth_cancelled",
            "The isolated browser window was closed",
        ))
    }
}

async fn available_local_port() -> NativeResult<u16> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to allocate a local browser control port",
                error,
            )
        })?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| web_error("web_auth_unavailable", "Invalid local control port", error))
}

async fn discover_page(port: u16, child: &mut Child) -> NativeResult<String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|error| web_error("web_auth_unavailable", "Local browser client failed", error))?;
    let endpoint = format!("http://127.0.0.1:{port}/json/list");
    tokio::time::timeout(BROWSER_START_TIMEOUT, async {
        loop {
            if let Some(status) = child.try_wait().map_err(|error| {
                web_error("web_auth_unavailable", "Unable to inspect Brave", error)
            })? {
                return Err(NativeError::new(
                    "web_auth_unavailable",
                    format!("The isolated Brave window exited with {status}"),
                ));
            }
            if let Ok(response) = client.get(&endpoint).send().await {
                if let Ok(targets) = response.json::<Vec<Value>>().await {
                    if let Some(url) = targets.iter().find_map(|target| {
                        (target.get("type").and_then(Value::as_str) == Some("page"))
                            .then(|| target.get("webSocketDebuggerUrl").and_then(Value::as_str))
                            .flatten()
                            .map(str::to_owned)
                    }) {
                        return Ok(url);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| {
        NativeError::new(
            "web_auth_unavailable",
            "The isolated Brave window did not become ready",
        )
    })?
}

fn header_array(headers: Option<&Value>) -> Vec<Value> {
    headers
        .and_then(Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .as_str()
                        .map(|value| json!({ "name": name, "value": value }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn set_header(headers: &mut Vec<Value>, name: &str, value: &str) {
    headers.retain(|header| {
        !header
            .get("name")
            .and_then(Value::as_str)
            .map(|candidate| candidate.eq_ignore_ascii_case(name))
            .unwrap_or(false)
    });
    headers.push(json!({ "name": name, "value": value }));
}

fn navigation_urls<'a>(method: &str, params: &'a Value) -> Vec<&'a str> {
    match method {
        "Page.frameNavigated" => params
            .get("frame")
            .and_then(|frame| frame.get("url"))
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        "Page.navigatedWithinDocument" => params
            .get("url")
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        "Network.requestWillBeSent" => params
            .get("request")
            .and_then(|request| request.get("url"))
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn sso_callback_token(candidate: &str, expected_uid: &str) -> Option<String> {
    let url = reqwest::Url::parse(candidate).ok()?;
    if !url.path().ends_with("/sso/login") {
        return None;
    }
    let values = url::form_urlencoded::parse(url.fragment()?.as_bytes())
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    (values.get("uid").map(String::as_str) == Some(expected_uid))
        .then(|| values.get("token").cloned())
        .flatten()
        .filter(|token| !token.is_empty())
}

fn captcha_response_token(payload: &str) -> Option<String> {
    let mut value: Value = serde_json::from_str(payload).ok()?;
    if let Some(encoded) = value.as_str() {
        value = serde_json::from_str(encoded).ok()?;
    }
    let kind = value
        .get("type")
        .or_else(|| value.get("Type"))
        .and_then(Value::as_str)?;
    if kind != "pm_captcha" {
        return None;
    }
    value
        .get("token")
        .or_else(|| value.get("Token"))
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

fn web_error(
    code: &'static str,
    message: &'static str,
    error: impl std::fmt::Display,
) -> NativeError {
    NativeError::new(code, message).with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sso_callback_requires_matching_uid() {
        let url = "https://vpn-api.proton.me/sso/login#token=response%2Btoken&uid=uid-1";
        assert_eq!(
            sso_callback_token(url, "uid-1").as_deref(),
            Some("response+token")
        );
        assert!(sso_callback_token(url, "uid-2").is_none());
    }

    #[test]
    fn captcha_bridge_accepts_the_webview_message_contract() {
        assert_eq!(
            captcha_response_token(r#"{"type":"pm_captcha","token":"ok"}"#).as_deref(),
            Some("ok")
        );
        assert!(captcha_response_token(r#"{"type":"height","height":400}"#).is_none());
    }
}
