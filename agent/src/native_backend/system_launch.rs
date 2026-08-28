use super::{apps, NativeError, NativeResult};
use serde_json::{json, Value};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::Command;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_URL_CHARS: usize = 2_048;

pub async fn launch(params: &Value) -> NativeResult<Value> {
    let mode = string(params, "mode", 32)?;
    match mode.as_str() {
        "website" => {
            let url = normalized_web_url(&string(params, "url", MAX_URL_CHARS)?)?;
            let private = params
                .get("private_browsing")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if private {
                launch_private_browser(&url).await?;
            } else {
                spawn_detached("/usr/bin/gio", &["open", &url])?;
            }
            Ok(json!({ "launched": true, "mode": mode, "private_browsing": private }))
        }
        "application" => {
            let desktop_id = string(params, "desktop_id", 255)?;
            if !apps::desktop_id_exists(&desktop_id) {
                return Err(NativeError::new(
                    "application_unavailable",
                    "The selected desktop application is no longer installed",
                ));
            }
            spawn_detached("/usr/bin/gtk-launch", &[&desktop_id])?;
            Ok(json!({ "launched": true, "mode": mode, "desktop_id": desktop_id }))
        }
        _ => Err(NativeError::new(
            "invalid_params",
            "mode must be website or application",
        )),
    }
}

fn normalized_web_url(raw: &str) -> NativeResult<String> {
    let raw = raw.trim();
    let formatted = if raw.contains(":/") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = reqwest::Url::parse(&formatted)
        .map_err(|_| NativeError::new("invalid_url", "Connect and Go requires a valid web URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(NativeError::new(
            "invalid_url",
            "Connect and Go supports HTTP and HTTPS websites",
        ));
    }
    Ok(url.to_string())
}

async fn launch_private_browser(url: &str) -> NativeResult<()> {
    let output = tokio::time::timeout(
        PROCESS_TIMEOUT,
        Command::new("/usr/bin/xdg-settings")
            .args(["get", "default-web-browser"])
            .output(),
    )
    .await
    .map_err(|_| {
        NativeError::new(
            "private_browsing_unavailable",
            "Browser detection timed out",
        )
    })?
    .map_err(|error| {
        NativeError::new(
            "private_browsing_unavailable",
            "Unable to detect the default web browser",
        )
        .with_source(error)
    })?;
    if !output.status.success() {
        return Err(NativeError::new(
            "private_browsing_unavailable",
            "Unable to detect the default web browser",
        ));
    }
    let desktop_id = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    let (candidates, private_flag) = private_browser_command(&desktop_id).ok_or_else(|| {
        NativeError::new(
            "private_browsing_unavailable",
            "The default browser has no known private-window command",
        )
    })?;
    let browser = candidates
        .iter()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or_else(|| {
            NativeError::new(
                "private_browsing_unavailable",
                "The default browser executable could not be found",
            )
        })?;
    spawn_detached(browser, &[private_flag, url])
}

fn private_browser_command(desktop_id: &str) -> Option<(&'static [&'static str], &'static str)> {
    const BRAVE: &[&str] = &[
        "/usr/bin/brave-origin",
        "/usr/bin/brave-browser",
        "/usr/bin/brave",
    ];
    const CHROMIUM: &[&str] = &["/usr/bin/chromium", "/usr/bin/chromium-browser"];
    const CHROME: &[&str] = &["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome"];
    const EDGE: &[&str] = &["/usr/bin/microsoft-edge-stable", "/usr/bin/microsoft-edge"];
    const VIVALDI: &[&str] = &["/usr/bin/vivaldi-stable", "/usr/bin/vivaldi"];
    const FIREFOX: &[&str] = &["/usr/bin/firefox", "/usr/bin/librewolf", "/usr/bin/floorp"];

    if desktop_id.contains("brave") {
        Some((BRAVE, "--incognito"))
    } else if desktop_id.contains("chromium") {
        Some((CHROMIUM, "--incognito"))
    } else if desktop_id.contains("google-chrome") || desktop_id == "chrome.desktop" {
        Some((CHROME, "--incognito"))
    } else if desktop_id.contains("microsoft-edge") {
        Some((EDGE, "--inprivate"))
    } else if desktop_id.contains("vivaldi") {
        Some((VIVALDI, "--incognito"))
    } else if desktop_id.contains("firefox")
        || desktop_id.contains("librewolf")
        || desktop_id.contains("floorp")
    {
        Some((FIREFOX, "--private-window"))
    } else {
        None
    }
}

fn spawn_detached(program: &str, args: &[&str]) -> NativeResult<()> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()
        .map(|_| ())
        .map_err(|error| {
            NativeError::new(
                "launch_failed",
                "Unable to launch the Connect and Go target",
            )
            .with_source(error)
        })
}

fn string(params: &Value, key: &str, max_chars: usize) -> NativeResult<String> {
    let value = params.get(key).and_then(Value::as_str).unwrap_or("").trim();
    if value.chars().count() > max_chars {
        return Err(NativeError::new(
            "invalid_params",
            format!("{key} exceeds {max_chars} characters"),
        ));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_urls_are_normalized_and_restricted() {
        assert_eq!(
            normalized_web_url("protonvpn.com").unwrap(),
            "https://protonvpn.com/"
        );
        assert!(normalized_web_url("file:///etc/passwd").is_err());
        assert!(normalized_web_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn private_browser_flags_match_linux_browser_families() {
        assert_eq!(
            private_browser_command("brave-origin.desktop").unwrap().1,
            "--incognito"
        );
        assert_eq!(
            private_browser_command("firefox.desktop").unwrap().1,
            "--private-window"
        );
        assert!(private_browser_command("unknown.desktop").is_none());
    }
}
