use super::{models::NativeSettings, NativeError, NativeResult};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn save(path: &Path, settings: &NativeSettings) -> NativeResult<()> {
    save_serialized(path, settings)
}

pub fn save_value(path: &Path, value: &serde_json::Value) -> NativeResult<()> {
    save_serialized(path, value)
}

fn save_serialized<T: serde::Serialize>(path: &Path, settings: &T) -> NativeResult<()> {
    let parent = path.parent().ok_or_else(|| {
        NativeError::new(
            "settings_path_invalid",
            "The Proton settings path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| settings_error("create", path, error))?;

    let bytes = serde_json::to_vec_pretty(settings).map_err(|error| {
        NativeError::new("settings_invalid", "Unable to serialize Proton settings")
            .with_source(error)
    })?;
    let temp = temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| settings_error("create temporary", &temp, error))?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|error| settings_error("write", &temp, error))?;

        let mode = fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode))
            .map_err(|error| settings_error("set permissions on", &temp, error))?;
        fs::rename(&temp, path).map_err(|error| settings_error("replace", path, error))?;

        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("settings.json");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence))
}

fn settings_error(action: &str, path: &Path, error: std::io::Error) -> NativeError {
    NativeError::new(
        "settings_write_failed",
        format!("Unable to {action} Proton settings at {}", path.display()),
    )
    .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_save_round_trips_and_preserves_unknown_fields() {
        let root = std::env::temp_dir().join(format!(
            "proton-omarchy-settings-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("settings.json");
        let mut settings = NativeSettings::default();
        settings
            .extra
            .insert("FutureSetting".into(), serde_json::json!({"enabled": true}));
        save(&path, &settings).expect("save");
        let loaded: NativeSettings =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse");
        assert_eq!(loaded.extra["FutureSetting"]["enabled"], true);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
