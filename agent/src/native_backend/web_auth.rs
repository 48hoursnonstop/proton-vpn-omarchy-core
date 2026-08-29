use super::{NativeError, NativeResult};
use serde_json::{json, Value};
use std::{
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, net::UnixStream as StdUnixStream},
    },
    path::PathBuf,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    process::Child,
};

const BROWSER_START_TIMEOUT: Duration = Duration::from_secs(30);
const SSO_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CAPTCHA_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_CDP_MESSAGE_BYTES: usize = 1024 * 1024;

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

        let (command_parent, command_child) = StdUnixStream::pair().map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to create the private browser command pipe",
                error,
            )
        })?;
        let (response_parent, response_child) = StdUnixStream::pair().map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to create the private browser response pipe",
                error,
            )
        })?;
        command_parent.set_nonblocking(true).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser command pipe",
                error,
            )
        })?;
        response_parent.set_nonblocking(true).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser response pipe",
                error,
            )
        })?;
        let command_child = duplicate_above_stdio(&command_child).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser command pipe",
                error,
            )
        })?;
        let response_child = duplicate_above_stdio(&response_child).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser response pipe",
                error,
            )
        })?;

        let mut command = tokio::process::Command::new("/usr/bin/brave-origin");
        command
            .arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg("--remote-debugging-pipe")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-sync")
            .arg("--app=about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // Chromium reserves fd 3 for CDP commands and fd 4 for responses when
        // --remote-debugging-pipe is used. The source descriptors are >= 5 so
        // stdio setup cannot overwrite them before this child-only hook runs.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(command_child.as_raw_fd(), 3) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::dup2(response_child.as_raw_fd(), 4) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Unable to start the isolated Brave window",
                error,
            )
        })?;
        let command_writer = UnixStream::from_std(command_parent).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser command pipe",
                error,
            )
        })?;
        let response_reader = UnixStream::from_std(response_parent).map_err(|error| {
            web_error(
                "web_auth_unavailable",
                "Invalid browser response pipe",
                error,
            )
        })?;
        let mut cdp = CdpClient::new(response_reader, command_writer);
        if let Err(error) = attach_page(&mut cdp, &mut child).await {
            let _ = child.start_kill();
            let _ = fs::remove_dir_all(&profile_dir);
            return Err(error);
        }
        Ok((Self { child, profile_dir }, cdp))
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
    reader: UnixStream,
    writer: UnixStream,
    read_buffer: Vec<u8>,
    next_id: u64,
    session_id: Option<String>,
}

impl CdpClient {
    fn new(reader: UnixStream, writer: UnixStream) -> Self {
        Self {
            reader,
            writer,
            read_buffer: Vec::new(),
            next_id: 1,
            session_id: None,
        }
    }

    async fn command(&mut self, method: &str, params: Value) -> NativeResult<Value> {
        if self.session_id.is_none() {
            return Err(NativeError::new(
                "web_auth_failed",
                "The browser page is not attached",
            ));
        }
        self.command_with_session(method, params, self.session_id.clone())
            .await
    }

    async fn root_command(&mut self, method: &str, params: Value) -> NativeResult<Value> {
        self.command_with_session(method, params, None).await
    }

    async fn command_with_session(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<String>,
    ) -> NativeResult<Value> {
        let id = self.send_with_session(method, params, session_id).await?;
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
        if self.session_id.is_none() {
            return Err(NativeError::new(
                "web_auth_failed",
                "The browser page is not attached",
            ));
        }
        self.send_with_session(method, params, self.session_id.clone())
            .await
    }

    async fn send_with_session(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<String>,
    ) -> NativeResult<u64> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session_id) = session_id {
            message["sessionId"] = Value::String(session_id);
        }
        let payload = serde_json::to_vec(&message)
            .map_err(|error| web_error("web_auth_failed", "Invalid browser command", error))?;
        write_pipe_message(&mut self.writer, &payload)
            .await
            .map_err(|error| web_error("web_auth_failed", "Browser channel failed", error))?;
        Ok(id)
    }

    async fn next_event(&mut self) -> NativeResult<Value> {
        loop {
            let message = self.next_message().await?;
            if message.get("method").is_some()
                && message.get("sessionId").and_then(Value::as_str) == self.session_id.as_deref()
            {
                return Ok(message);
            }
        }
    }

    async fn next_message(&mut self) -> NativeResult<Value> {
        let bytes = read_pipe_message(&mut self.reader, &mut self.read_buffer).await?;
        serde_json::from_slice(&bytes).map_err(|error| {
            web_error(
                "web_auth_failed",
                "Browser returned an invalid control message",
                error,
            )
        })
    }
}

fn duplicate_above_stdio(stream: &StdUnixStream) -> io::Result<OwnedFd> {
    let descriptor = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

async fn attach_page(cdp: &mut CdpClient, child: &mut Child) -> NativeResult<()> {
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
            let targets = cdp.root_command("Target.getTargets", json!({})).await?;
            if let Some(target_id) = page_target_id(&targets) {
                let attached = cdp
                    .root_command(
                        "Target.attachToTarget",
                        json!({ "targetId": target_id, "flatten": true }),
                    )
                    .await?;
                if let Some(session_id) = attached.get("sessionId").and_then(Value::as_str) {
                    cdp.session_id = Some(session_id.to_owned());
                    return Ok(());
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

fn page_target_id(targets: &Value) -> Option<&str> {
    targets
        .get("targetInfos")?
        .as_array()?
        .iter()
        .find(|target| target.get("type").and_then(Value::as_str) == Some("page"))?
        .get("targetId")?
        .as_str()
}

async fn write_pipe_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_CDP_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "browser command exceeds the size limit",
        ));
    }
    writer.write_all(payload).await?;
    writer.write_all(&[0]).await?;
    writer.flush().await
}

async fn read_pipe_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> NativeResult<Vec<u8>> {
    loop {
        if let Some(end) = buffer.iter().position(|byte| *byte == 0) {
            let mut message = buffer.drain(..=end).collect::<Vec<_>>();
            message.pop();
            if message.is_empty() {
                continue;
            }
            return Ok(message);
        }
        let mut chunk = [0_u8; 8192];
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(|error| web_error("web_auth_failed", "Browser channel failed", error))?;
        if read == 0 {
            return Err(NativeError::new(
                "web_auth_cancelled",
                "The isolated browser window was closed",
            ));
        }
        if buffer.len().saturating_add(read) > MAX_CDP_MESSAGE_BYTES {
            return Err(NativeError::new(
                "web_auth_failed",
                "Browser control message exceeds the size limit",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
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
    if url.scheme() != "https"
        || url.host_str() != Some("vpn-api.proton.me")
        || url.port_or_known_default() != Some(443)
        || url.path() != "/sso/login"
    {
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
        assert!(sso_callback_token(
            "https://example.test/sso/login#token=forged&uid=uid-1",
            "uid-1"
        )
        .is_none());
        assert!(sso_callback_token(
            "http://vpn-api.proton.me/sso/login#token=forged&uid=uid-1",
            "uid-1"
        )
        .is_none());
    }

    #[test]
    fn captcha_bridge_accepts_the_webview_message_contract() {
        assert_eq!(
            captcha_response_token(r#"{"type":"pm_captcha","token":"ok"}"#).as_deref(),
            Some("ok")
        );
        assert!(captcha_response_token(r#"{"type":"height","height":400}"#).is_none());
    }

    #[test]
    fn page_target_selection_ignores_non_page_targets() {
        let targets = json!({
            "targetInfos": [
                { "type": "service_worker", "targetId": "worker" },
                { "type": "page", "targetId": "page-1" }
            ]
        });
        assert_eq!(page_target_id(&targets), Some("page-1"));
    }

    #[tokio::test]
    async fn pipe_messages_are_nul_delimited_and_bounded() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_pipe_message(&mut writer, br#"{"id":1}"#)
            .await
            .expect("write frame");
        let mut buffer = Vec::new();
        assert_eq!(
            read_pipe_message(&mut reader, &mut buffer)
                .await
                .expect("read frame"),
            br#"{"id":1}"#
        );
    }

    #[tokio::test]
    #[ignore = "launches the installed Brave browser"]
    async fn browser_pipe_attaches_without_opening_a_debug_port() {
        let (mut browser, mut cdp) = BrowserSession::open().await.expect("open Brave pipe");
        let result = cdp
            .command(
                "Runtime.evaluate",
                json!({ "expression": "6 * 7", "returnByValue": true }),
            )
            .await
            .expect("evaluate expression");
        assert_eq!(result["result"]["value"], 42);
        browser.cleanup().await;
    }
}
