use super::{NativeError, NativeResult};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_RESULTS: usize = 100;
const MAX_QUERY_BYTES: usize = 256;
const MAX_DESKTOP_FILES: usize = 10_000;
const MAX_DESKTOP_DEPTH: usize = 32;
const MAX_DESKTOP_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstalledApp {
    desktop_id: String,
    name: String,
    executable: String,
}

pub fn list(params: &Value) -> NativeResult<Value> {
    let offset = unsigned_param(params, "offset", 0, 100_000)?;
    let limit = unsigned_param(params, "limit", 100, MAX_RESULTS)?;
    let query = params
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if query.len() > MAX_QUERY_BYTES {
        return Err(NativeError::new(
            "invalid_params",
            format!("query must be at most {MAX_QUERY_BYTES} bytes"),
        ));
    }
    let query = query.to_lowercase();

    let mut by_executable = HashMap::new();
    for path in desktop_files() {
        let Some(app) = parse_desktop_file(&path) else {
            continue;
        };
        let probe = format!("{} {}", app.name, app.executable).to_lowercase();
        if probe.contains("proton vpn")
            || probe.contains("proton-vpn")
            || probe.contains("proton-omarchy")
            || (!query.is_empty() && !probe.contains(&query))
        {
            continue;
        }
        by_executable.entry(app.executable.clone()).or_insert(app);
    }

    let mut apps = by_executable.into_values().collect::<Vec<_>>();
    apps.sort_by_key(|app| app.name.to_lowercase());
    let total = apps.len();
    let page = apps
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|app| {
            json!({
                "id": app.desktop_id,
                "name": app.name,
                "executable": app.executable
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "offset": offset,
        "limit": limit,
        "total": total,
        "query": query,
        "apps": page,
    }))
}

fn desktop_files() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
        roots.push(PathBuf::from(data_home).join("applications"));
    } else if let Some(home) = env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".local/share/applications"));
    }
    let data_dirs =
        env::var_os("XDG_DATA_DIRS").unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    roots.extend(env::split_paths(&data_dirs).map(|path| path.join("applications")));

    let mut files = Vec::new();
    let mut seen_files = HashSet::new();
    let mut seen_directories = HashSet::new();
    for root in roots {
        let root = fs::canonicalize(&root).unwrap_or(root);
        collect_desktop_files(&root, &mut files, &mut seen_files, &mut seen_directories, 0);
        if files.len() >= MAX_DESKTOP_FILES {
            break;
        }
    }
    files
}

fn collect_desktop_files(
    root: &Path,
    files: &mut Vec<PathBuf>,
    seen_files: &mut HashSet<PathBuf>,
    seen_directories: &mut HashSet<(u64, u64)>,
    depth: usize,
) {
    if depth > MAX_DESKTOP_DEPTH || files.len() >= MAX_DESKTOP_FILES {
        return;
    }
    let Ok(metadata) = fs::metadata(root) else {
        return;
    };
    if !metadata.is_dir() || !seen_directories.insert((metadata.dev(), metadata.ino())) {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= MAX_DESKTOP_FILES {
            break;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Do not follow directory symlinks found below a trusted XDG root.
        // They can form cycles or make a desktop scan traverse arbitrary trees.
        if file_type.is_dir() {
            collect_desktop_files(&path, files, seen_files, seen_directories, depth + 1);
        } else if path.extension().and_then(|value| value.to_str()) == Some("desktop")
            && seen_files.insert(path.clone())
        {
            files.push(path);
        }
    }
}

fn parse_desktop_file(path: &Path) -> Option<InstalledApp> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_DESKTOP_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .ok()?
        .take(MAX_DESKTOP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_DESKTOP_FILE_BYTES as usize {
        return None;
    }
    let raw = String::from_utf8(bytes).ok()?;
    let mut in_desktop_entry = false;
    let mut values = HashMap::<String, String>::new();
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.to_owned(), desktop_unescape(value));
        }
    }
    if values
        .get("Type")
        .map(String::as_str)
        .unwrap_or("Application")
        != "Application"
        || truthy(values.get("Hidden"))
        || truthy(values.get("NoDisplay"))
    {
        return None;
    }

    let name = localized_name(&values)?;
    let command = values.get("Exec")?.trim();
    let executable = app_executable(command)?;
    let desktop_id = path.file_name()?.to_str()?.to_owned();
    Some(InstalledApp {
        desktop_id,
        name,
        executable,
    })
}

pub fn desktop_id_exists(desktop_id: &str) -> bool {
    let desktop_id = desktop_id.trim();
    if desktop_id.is_empty()
        || desktop_id.len() > 255
        || desktop_id.contains('/')
        || !desktop_id.ends_with(".desktop")
    {
        return false;
    }
    desktop_files().into_iter().any(|path| {
        path.file_name().and_then(|value| value.to_str()) == Some(desktop_id)
            && parse_desktop_file(&path).is_some()
    })
}

fn localized_name(values: &HashMap<String, String>) -> Option<String> {
    for locale in locale_preferences() {
        let key = format!("Name[{locale}]");
        if let Some(value) = values.get(&key).filter(|value| !value.is_empty()) {
            return Some(value.clone());
        }
    }
    values
        .get("Name")
        .filter(|value| !value.is_empty())
        .cloned()
}

fn locale_preferences() -> Vec<String> {
    let raw = env::var("LC_MESSAGES")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("LANG").ok())
        .unwrap_or_default();
    let locale = raw.split('.').next().unwrap_or("").replace('-', "_");
    let mut locales = Vec::new();
    if !locale.is_empty() && locale != "C" && locale != "POSIX" {
        locales.push(locale.clone());
        if let Some((language, _)) = locale.split_once('_') {
            locales.push(language.to_owned());
        }
    }
    locales
}

fn app_executable(command: &str) -> Option<String> {
    if command.starts_with("flatpak ") || command.starts_with("/usr/bin/flatpak ") {
        return Some(
            command
                .split_once("@@")
                .map(|(prefix, _)| prefix)
                .unwrap_or(command)
                .trim()
                .to_owned(),
        );
    }
    let argv = shell_words::split(command).ok()?;
    let first = argv.first()?.as_str();
    if let Some(name) = first.strip_prefix("/snap/bin/") {
        let name = name.split_whitespace().next().unwrap_or(name);
        return Some(format!("/snap/{name}/"));
    }
    resolve_executable(first)
}

fn resolve_executable(command: &str) -> Option<String> {
    if command.contains('/') {
        return executable_file(Path::new(command)).then(|| command.to_owned());
    }
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(command))
        .find(|candidate| executable_file(candidate))
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

fn executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn truthy(value: Option<&String>) -> bool {
    value
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn desktop_unescape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('s') => output.push(' '),
            Some('n') => output.push('\n'),
            Some('t') => output.push('\t'),
            Some('r') => output.push('\r'),
            Some('\\') => output.push('\\'),
            Some(other) => output.push(other),
            None => output.push('\\'),
        }
    }
    output
}

fn unsigned_param(params: &Value, name: &str, default: usize, max: usize) -> NativeResult<usize> {
    let value = params
        .get(name)
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| invalid_page(name, max))?;
    if value > max || (name == "limit" && value == 0) {
        return Err(invalid_page(name, max));
    }
    Ok(value)
}

fn invalid_page(name: &str, max: usize) -> NativeError {
    NativeError::new(
        "invalid_params",
        format!(
            "{name} must be an integer between {} and {max}",
            if name == "limit" { 1 } else { 0 }
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_native_flatpak_and_snap_commands() {
        assert_eq!(
            app_executable("/usr/bin/sh %U").as_deref(),
            Some("/usr/bin/sh")
        );
        assert_eq!(
            app_executable("/snap/bin/firefox %U").as_deref(),
            Some("/snap/firefox/")
        );
        assert_eq!(
            app_executable("/usr/bin/flatpak run org.example.App @@u %U @@").as_deref(),
            Some("/usr/bin/flatpak run org.example.App")
        );
    }

    #[test]
    fn desktop_escapes_are_decoded() {
        assert_eq!(desktop_unescape("Hello\\sWorld\\\\App"), "Hello World\\App");
    }

    #[test]
    fn desktop_scan_ignores_symlinked_directory_cycles() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "proton-omarchy-app-scan-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(root.join("nested")).expect("create test tree");
        fs::write(
            root.join("nested/example.desktop"),
            "[Desktop Entry]\nName=Example\nExec=/usr/bin/sh\n",
        )
        .expect("write desktop file");
        symlink(&root, root.join("nested/cycle")).expect("create cycle");

        let mut files = Vec::new();
        collect_desktop_files(
            &root,
            &mut files,
            &mut HashSet::new(),
            &mut HashSet::new(),
            0,
        );
        assert_eq!(files.len(), 1);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn oversized_desktop_files_are_rejected() {
        let path = std::env::temp_dir().join(format!(
            "proton-omarchy-oversized-{}.desktop",
            uuid::Uuid::new_v4().simple()
        ));
        let file = fs::File::create(&path).expect("create file");
        file.set_len(MAX_DESKTOP_FILE_BYTES + 1)
            .expect("extend file");
        assert!(parse_desktop_file(&path).is_none());
        fs::remove_file(path).expect("cleanup");
    }
}
