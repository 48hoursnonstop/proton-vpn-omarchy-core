use std::{fs, io, path::Path};

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub uid: u16,
    pub pid: u32,
    pub ppid: u32,
    pub identities: Vec<String>,
}

pub fn scan() -> io::Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Ok(process) = read_process(pid) {
            processes.push(process);
        }
    }
    Ok(processes)
}

pub fn read_process(pid: u32) -> io::Result<ProcessInfo> {
    let base = Path::new("/proc").join(pid.to_string());
    let status = fs::read_to_string(base.join("status"))?;
    let uid = parse_uid(&status)?;
    let stat = fs::read_to_string(base.join("stat"))?;
    let ppid = parse_ppid(&stat)?;
    let mut identities = Vec::new();
    if let Ok(executable) = fs::read_link(base.join("exe")) {
        let value = executable.to_string_lossy().into_owned();
        if !value.is_empty() {
            identities.push(value);
        }
    }
    if let Ok(cmdline) = fs::read(base.join("cmdline")) {
        let value = parse_cmdline(&cmdline);
        if !value.is_empty() && !identities.contains(&value) {
            identities.push(value);
        }
    }
    Ok(ProcessInfo {
        uid,
        pid,
        ppid,
        identities,
    })
}

fn parse_uid(status: &str) -> io::Result<u16> {
    let raw = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process UID missing"))?;
    raw.parse::<u32>()
        .ok()
        .and_then(|uid| u16::try_from(uid).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process UID unsupported"))
}

fn parse_ppid(stat: &str) -> io::Result<u32> {
    let suffix = stat
        .rsplit_once(") ")
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process stat malformed"))?;
    suffix
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process parent missing"))
}

fn parse_cmdline(bytes: &[u8]) -> String {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_parent_after_a_comm_with_spaces_and_parens() {
        assert_eq!(parse_ppid("42 (odd ) name) S 17 0 0 0").unwrap(), 17);
    }

    #[test]
    fn cmdline_matches_the_official_joined_argv_contract() {
        assert_eq!(
            parse_cmdline(b"/usr/bin/firefox\0--private-window\0"),
            "/usr/bin/firefox --private-window"
        );
    }
}
