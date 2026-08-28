use super::{NativeError, NativeResult};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fs, process::Command};

pub const CATEGORY_ENDPOINT: &str = "/vpn/v1/featureconfig/dynamic-bug-reports";
pub const REPORT_ENDPOINT: &str = "/core/v4/reports/bug";
pub const REPORT_TITLE: &str = "Report from Proton VPN for Omarchy (unofficial community client)";
pub const REPORT_CLIENT: &str = "Linux GUI";
pub const REPORT_CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMUNITY_REPOSITORY: &str = "https://github.com/48hoursnonstop/proton-vpn-omarchy";
const MAX_FIELDS: usize = 32;
const MAX_LOG_BYTES: usize = 2 * 1024 * 1024;
const REPORT_LOG_LINES: usize = 5_000;
const DIAGNOSTIC_LOG_LINES: usize = 1;
const FALLBACK_CATEGORIES: &str =
    include_str!("../../../bridge/report_issue_default_categories.json");

#[derive(Clone, Debug)]
pub struct ReportRequest {
    pub category: String,
    pub email: String,
    pub fields: BTreeMap<String, String>,
    pub include_logs: bool,
}

#[derive(Clone, Debug)]
pub struct LogAttachment {
    pub source: &'static str,
    pub filename: String,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct LogCollection {
    pub attachments: Vec<LogAttachment>,
    pub failures: Vec<String>,
}

pub fn normalize_categories(value: &Value) -> NativeResult<Vec<Value>> {
    let categories = value.as_array().ok_or_else(|| {
        NativeError::new(
            "report_categories_invalid",
            "Report issue Categories must be a list",
        )
    })?;
    let mut normalized = Vec::with_capacity(categories.len());
    for category in categories {
        let category = category.as_object().ok_or_else(invalid_category)?;
        let label = alias_string(category, "Label", "label");
        let submit_label = alias_string(category, "SubmitLabel", "submit_label");
        let suggestions = alias_array(category, "Suggestions", "suggestions")?;
        let fields = alias_array(category, "InputFields", "input_fields")?;
        if label.is_empty() || submit_label.is_empty() {
            return Err(invalid_category());
        }

        let mut normalized_suggestions = Vec::with_capacity(suggestions.len());
        for suggestion in suggestions {
            let suggestion = suggestion.as_object().ok_or_else(invalid_category)?;
            let text = alias_string(suggestion, "Text", "text");
            if text.is_empty() {
                return Err(invalid_category());
            }
            normalized_suggestions.push(json!({
                "text": text,
                "link": alias_string(suggestion, "Link", "link"),
            }));
        }

        let mut normalized_fields = Vec::with_capacity(fields.len());
        for field in fields {
            let field = field.as_object().ok_or_else(invalid_category)?;
            let field_label = alias_string(field, "Label", "label");
            let field_submit = alias_string(field, "SubmitLabel", "submit_label");
            let field_type = alias_string(field, "Type", "type");
            if field_label.is_empty()
                || field_submit.is_empty()
                || !matches!(field_type.as_str(), "TextSingleLine" | "TextMultiLine")
            {
                return Err(invalid_category());
            }
            normalized_fields.push(json!({
                "label": field_label,
                "submit_label": field_submit,
                "type": field_type,
                "placeholder": alias_string(field, "Placeholder", "placeholder"),
                "is_mandatory": alias_value(field, "IsMandatory", "is_mandatory")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            }));
        }
        normalized.push(json!({
            "label": label,
            "submit_label": submit_label,
            "suggestions": normalized_suggestions,
            "input_fields": normalized_fields,
        }));
    }
    if normalized.is_empty() {
        return Err(invalid_category());
    }
    Ok(normalized)
}

pub fn fallback_categories() -> NativeResult<Vec<Value>> {
    let payload: Value = serde_json::from_str(FALLBACK_CATEGORIES).map_err(|error| {
        NativeError::new(
            "report_categories_invalid",
            "Bundled report categories are invalid",
        )
        .with_source(error)
    })?;
    normalize_categories(payload.get("categories").unwrap_or(&Value::Null))
}

pub fn report_request(params: &Value) -> NativeResult<ReportRequest> {
    let category = required_string(params, "category", 256)?;
    let email = required_string(params, "email", 320)?;
    if !valid_email(&email) {
        return Err(NativeError::new(
            "invalid_params",
            "email must be a valid email address",
        ));
    }
    let raw_fields = params
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            NativeError::new(
                "invalid_params",
                "fields must be an object with at most 32 entries",
            )
        })?;
    if raw_fields.len() > MAX_FIELDS {
        return Err(NativeError::new(
            "invalid_params",
            "fields must be an object with at most 32 entries",
        ));
    }
    let mut fields = BTreeMap::new();
    for (raw_key, raw_value) in raw_fields {
        let key = raw_key.trim();
        let value = raw_value.as_str().ok_or_else(|| {
            NativeError::new(
                "invalid_params",
                "report field keys and values must be strings",
            )
        })?;
        if key.is_empty() || key.len() > 512 || value.len() > 8192 {
            return Err(NativeError::new(
                "invalid_params",
                "report field has an invalid length",
            ));
        }
        fields.insert(key.to_owned(), value.to_owned());
    }
    let include_logs = params
        .get("include_logs")
        .map(Value::as_bool)
        .unwrap_or(Some(false))
        .ok_or_else(|| NativeError::new("invalid_params", "include_logs must be a boolean"))?;
    Ok(ReportRequest {
        category,
        email,
        fields,
        include_logs,
    })
}

pub fn report_description(request: &ReportRequest) -> String {
    let mut lines = vec![
        "Client: Proton VPN for Omarchy".to_owned(),
        "Distribution: unofficial community client".to_owned(),
        format!("Core version: {REPORT_CLIENT_VERSION}"),
        format!("Repository: {COMMUNITY_REPOSITORY}"),
        String::new(),
        format!("Category: {}", request.category),
        String::new(),
    ];
    for (key, value) in &request.fields {
        if value.trim().is_empty() {
            continue;
        }
        lines.extend([key.clone(), value.clone(), String::new()]);
    }
    format!("{}\n", lines.join("\n").trim_end())
}

#[derive(Clone, Debug)]
pub struct DiagnosticSummary<'a> {
    pub os: &'a str,
    pub os_version: &'a str,
    pub backend_version: &'a str,
    pub signed_in: bool,
    pub catalog_loaded: bool,
    pub client_config_loaded: bool,
    pub tunnel_state: &'a str,
    pub protocol: Option<&'a str>,
    pub protocols: &'a [&'a str],
    pub api_reachable: bool,
    pub tls_pin_verified: bool,
    pub log_sources_available: usize,
    pub log_source_failures: usize,
}

pub fn diagnostic_summary(details: &DiagnosticSummary<'_>) -> String {
    let os = if details.os_version.is_empty() {
        details.os.to_owned()
    } else {
        format!("{} {}", details.os, details.os_version)
    };
    let protocol = details
        .protocol
        .filter(|value| !value.is_empty())
        .unwrap_or("none");
    format!(
        concat!(
            "Proton VPN for Omarchy diagnostics (sanitized)\n",
            "Core: {}\n",
            "OS: {}\n",
            "Signed in: {}\n",
            "Catalog loaded: {}\n",
            "Client config loaded: {}\n",
            "Tunnel state: {}\n",
            "Active protocol: {}\n",
            "Available protocols: {}\n",
            "Proton API reachable: {}\n",
            "TLS pin verified: {}\n",
            "Diagnostic sources available: {}/{}\n",
            "Raw journals: not included"
        ),
        details.backend_version,
        os,
        yes_no(details.signed_in),
        yes_no(details.catalog_loaded),
        yes_no(details.client_config_loaded),
        details.tunnel_state,
        protocol,
        details.protocols.join(", "),
        yes_no(details.api_reachable),
        yes_no(details.tls_pin_verified),
        details.log_sources_available,
        details.log_sources_available + details.log_source_failures,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub fn collect_logs() -> LogCollection {
    collect_logs_bounded(REPORT_LOG_LINES)
}

pub fn collect_log_metadata() -> LogCollection {
    collect_logs_bounded(DIAGNOSTIC_LOG_LINES)
}

fn collect_logs_bounded(max_lines: usize) -> LogCollection {
    let specs: &[(&str, &str, &[&str])] = &[
        (
            "agent",
            "ProtonOmarchyAgent.log",
            &[
                "--user",
                "-u",
                "proton-omarchy-agent.service",
                "--no-pager",
                "--utc",
                "--since=-1d",
                "--no-hostname",
            ],
        ),
        (
            "network_manager",
            "NetworkManager.log",
            &[
                "-u",
                "NetworkManager",
                "--no-pager",
                "--utc",
                "--since=-1d",
                "--no-hostname",
            ],
        ),
        (
            "split_tunneling",
            "SplitTunneling.log",
            &[
                "-u",
                "proton.VPN.service",
                "--no-pager",
                "--utc",
                "--since=-1d",
                "--no-hostname",
            ],
        ),
    ];
    let mut result = LogCollection::default();
    for (source, filename, args) in specs {
        match Command::new("/usr/bin/journalctl")
            .args(["--lines", &max_lines.to_string()])
            .args(*args)
            .output()
        {
            Ok(output) if output.status.success() => {
                let start = output.stdout.len().saturating_sub(MAX_LOG_BYTES);
                result.attachments.push(LogAttachment {
                    source,
                    filename: (*filename).to_owned(),
                    data: output.stdout[start..].to_vec(),
                });
            }
            Ok(output) => {
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                result.failures.push(if detail.is_empty() {
                    format!("{source}: journal capture failed")
                } else {
                    format!("{source}: {detail}")
                });
            }
            Err(error) => result.failures.push(format!("{source}: {error}")),
        }
    }
    result
}

pub fn os_release() -> (String, String) {
    let values = fs::read_to_string("/etc/os-release")
        .ok()
        .map(|content| {
            content
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.trim().trim_matches('"').to_owned()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let distribution = values.get("ID").cloned().unwrap_or_else(|| "linux".into());
    let version = values
        .get("VERSION_ID")
        .cloned()
        .or_else(|| values.get("BUILD_ID").cloned())
        .unwrap_or_default();
    (format!("{distribution} (Hyprland)"), version)
}

fn required_string(params: &Value, name: &str, maximum: usize) -> NativeResult<String> {
    let value = params
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if value.is_empty() || value.len() > maximum {
        return Err(NativeError::new(
            "invalid_params",
            format!("{name} must contain between 1 and {maximum} bytes"),
        ));
    }
    Ok(value.to_owned())
}

fn valid_email(value: &str) -> bool {
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain
            .rsplit_once('.')
            .is_some_and(|(name, suffix)| !name.is_empty() && !suffix.is_empty())
}

fn alias_value<'a>(object: &'a Map<String, Value>, first: &str, second: &str) -> Option<&'a Value> {
    object.get(first).or_else(|| object.get(second))
}

fn alias_string(object: &Map<String, Value>, first: &str, second: &str) -> String {
    alias_value(object, first, second)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned()
}

fn alias_array<'a>(
    object: &'a Map<String, Value>,
    first: &str,
    second: &str,
) -> NativeResult<&'a Vec<Value>> {
    alias_value(object, first, second)
        .and_then(Value::as_array)
        .ok_or_else(invalid_category)
}

fn invalid_category() -> NativeError {
    NativeError::new(
        "report_categories_invalid",
        "Proton returned an invalid report issue category",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_categories_are_valid_and_complete() {
        let categories = fallback_categories().expect("fallback categories");
        assert_eq!(categories.len(), 6);
        assert!(categories.iter().all(|category| category["label"]
            .as_str()
            .is_some_and(|label| !label.is_empty())));
    }

    #[test]
    fn report_validation_is_bounded() {
        let request = report_request(&json!({
            "category": "Using the app",
            "email": "person@example.com",
            "fields": { "What went wrong?": "It stopped." },
            "include_logs": false,
        }))
        .expect("report request");
        assert!(!request.include_logs);
        assert!(report_description(&request).contains("Category: Using the app"));
        assert!(report_description(&request).contains("unofficial community client"));
        assert!(report_request(&json!({
            "category": "Other",
            "email": "invalid",
            "fields": {},
        }))
        .is_err());
    }

    #[test]
    fn reports_do_not_include_logs_without_explicit_consent() {
        let request = report_request(&json!({
            "category": "Other",
            "email": "person@example.com",
            "fields": {},
        }))
        .expect("report request");
        assert!(!request.include_logs);
    }

    #[test]
    fn diagnostic_summary_is_shareable_and_excludes_identifiers() {
        let summary = diagnostic_summary(&DiagnosticSummary {
            os: "arch (Hyprland)",
            os_version: "rolling",
            backend_version: "0.8.1/rust-v2",
            signed_in: true,
            catalog_loaded: true,
            client_config_loaded: true,
            tunnel_state: "connected",
            protocol: Some("wireguard"),
            protocols: &["wireguard", "openvpn-tcp"],
            api_reachable: true,
            tls_pin_verified: true,
            log_sources_available: 3,
            log_source_failures: 0,
        });
        assert!(summary.contains("Raw journals: not included"));
        assert!(!summary.contains("UUID"));
        assert!(!summary.contains("IP address"));
    }
}
