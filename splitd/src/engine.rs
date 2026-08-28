use crate::{
    bpf::SocketMarker,
    model::{ConfigMap, PolicyMap, SplitConfig, MAX_CONFIGS},
    proc_events::{ProcessConnector, ProcessEvent},
    procfs::{self, ProcessInfo},
    store::StateStore,
};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle, time::MissedTickBehavior};

const PROCESS_EVENT_CAPACITY: usize = 4096;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
const SAFETY_RECONCILE_TICKS: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrackedProcess {
    uid: u16,
    matched: bool,
    excluded: bool,
}

#[derive(Default)]
struct Inner {
    configs: ConfigMap,
    destination_policies: PolicyMap,
    marker: Option<SocketMarker>,
    tracked: HashMap<u32, TrackedProcess>,
}

pub struct Engine {
    inner: Arc<Mutex<Inner>>,
    store: StateStore,
    _connector: ProcessConnector,
    event_task: JoinHandle<()>,
    reconcile_task: JoinHandle<()>,
}

impl Engine {
    pub fn new() -> io::Result<Self> {
        Self::with_store(StateStore::system())
    }

    pub fn ephemeral() -> io::Result<Self> {
        Self::with_store(StateStore::ephemeral())
    }

    fn with_store(store: StateStore) -> io::Result<Self> {
        let loaded = store.load()?;
        let mut initial = Inner {
            configs: loaded.configs,
            destination_policies: loaded.destination_policies,
            ..Inner::default()
        };
        reconcile(&mut initial)?;
        let inner = Arc::new(Mutex::new(initial));
        let reconciliation_needed = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(PROCESS_EVENT_CAPACITY);
        let connector = ProcessConnector::spawn(sender, Arc::clone(&reconciliation_needed))?;
        let event_inner = Arc::clone(&inner);
        let event_dirty = Arc::clone(&reconciliation_needed);
        let event_task = tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                let inner = Arc::clone(&event_inner);
                let result = tokio::task::spawn_blocking(move || {
                    let mut inner = lock_inner(&inner)?;
                    handle_event(&mut inner, event)
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        event_dirty.store(true, Ordering::Release);
                        eprintln!("proton-omarchy-splitd: process update failed: {error}");
                    }
                    Err(error) => {
                        event_dirty.store(true, Ordering::Release);
                        eprintln!("proton-omarchy-splitd: process worker failed: {error}");
                    }
                }
            }
        });
        let reconcile_inner = Arc::clone(&inner);
        let reconcile_dirty = Arc::clone(&reconciliation_needed);
        let reconcile_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            let mut safety_ticks = 0_u8;
            loop {
                interval.tick().await;
                safety_ticks = safety_ticks.saturating_add(1);
                let event_loss = reconcile_dirty.swap(false, Ordering::AcqRel);
                if !event_loss && safety_ticks < SAFETY_RECONCILE_TICKS {
                    continue;
                }
                safety_ticks = 0;
                let inner = Arc::clone(&reconcile_inner);
                let result = tokio::task::spawn_blocking(move || {
                    let mut inner = lock_inner(&inner)?;
                    reconcile(&mut inner)
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        reconcile_dirty.store(true, Ordering::Release);
                        eprintln!("proton-omarchy-splitd: periodic reconciliation failed: {error}");
                    }
                    Err(error) => {
                        reconcile_dirty.store(true, Ordering::Release);
                        eprintln!("proton-omarchy-splitd: reconciliation worker failed: {error}");
                    }
                }
            }
        });
        Ok(Self {
            inner,
            store,
            _connector: connector,
            event_task,
            reconcile_task,
        })
    }

    pub async fn set_config(&self, uid: u16, config: SplitConfig) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut inner = lock_inner(&inner)?;
            if !inner.configs.contains_key(&uid)
                && !inner.destination_policies.contains_key(&uid)
                && configured_user_count(&inner) >= MAX_CONFIGS
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("at most {MAX_CONFIGS} users may configure split tunneling"),
                ));
            }
            let previous = inner.configs.insert(uid, config);
            if let Err(error) = reconcile(&mut inner)
                .and_then(|()| store.save(&inner.configs, &inner.destination_policies))
            {
                match previous {
                    Some(config) => {
                        inner.configs.insert(uid, config);
                    }
                    None => {
                        inner.configs.remove(&uid);
                    }
                }
                let _ = reconcile(&mut inner);
                return Err(error);
            }
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    pub async fn clear_config(&self, uid: u16) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut inner = lock_inner(&inner)?;
            let previous = inner.configs.remove(&uid);
            if let Err(error) = reconcile(&mut inner)
                .and_then(|()| store.save(&inner.configs, &inner.destination_policies))
            {
                if let Some(config) = previous {
                    inner.configs.insert(uid, config);
                    let _ = reconcile(&mut inner);
                }
                return Err(error);
            }
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    pub async fn get_config(&self, uid: u16) -> Option<SplitConfig> {
        lock_inner(&self.inner)
            .ok()
            .and_then(|inner| inner.configs.get(&uid).cloned())
    }

    pub async fn set_destination_policy(&self, uid: u16, ranges: Vec<String>) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut inner = lock_inner(&inner)?;
            if !inner.configs.contains_key(&uid)
                && !inner.destination_policies.contains_key(&uid)
                && configured_user_count(&inner) >= MAX_CONFIGS
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("at most {MAX_CONFIGS} users may configure destination policies"),
                ));
            }
            let previous = if ranges.is_empty() {
                inner.destination_policies.remove(&uid)
            } else {
                inner.destination_policies.insert(uid, ranges)
            };
            if let Err(error) = reconcile(&mut inner)
                .and_then(|()| store.save(&inner.configs, &inner.destination_policies))
            {
                match previous {
                    Some(ranges) => {
                        inner.destination_policies.insert(uid, ranges);
                    }
                    None => {
                        inner.destination_policies.remove(&uid);
                    }
                }
                let _ = reconcile(&mut inner);
                return Err(error);
            }
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    pub async fn destination_policy(&self, uid: u16) -> Vec<String> {
        lock_inner(&self.inner)
            .ok()
            .and_then(|inner| inner.destination_policies.get(&uid).cloned())
            .unwrap_or_default()
    }

    pub async fn get_all_configs(&self) -> Vec<(u16, SplitConfig)> {
        lock_inner(&self.inner)
            .map(|inner| {
                inner
                    .configs
                    .iter()
                    .map(|(uid, config)| (*uid, config.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn status(&self) -> (usize, usize, bool) {
        lock_inner(&self.inner)
            .map(|inner| {
                (
                    inner.configs.len(),
                    inner.tracked.len(),
                    inner.marker.is_some(),
                )
            })
            .unwrap_or_default()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.event_task.abort();
        self.reconcile_task.abort();
    }
}

fn lock_inner(inner: &Mutex<Inner>) -> io::Result<std::sync::MutexGuard<'_, Inner>> {
    inner
        .lock()
        .map_err(|_| io::Error::other("split-tunneling engine lock poisoned"))
}

fn join_error(error: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("split-tunneling worker failed: {error}"))
}

fn configured_user_count(inner: &Inner) -> usize {
    inner
        .configs
        .keys()
        .chain(inner.destination_policies.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

fn reconcile(inner: &mut Inner) -> io::Result<()> {
    if !inner.configs.values().any(SplitConfig::has_rules)
        && !inner
            .destination_policies
            .values()
            .any(|ranges| !ranges.is_empty())
    {
        inner.tracked.clear();
        inner.marker.take();
        return Ok(());
    }
    if inner.marker.is_none() {
        inner.marker = Some(SocketMarker::attach()?);
    }
    inner
        .marker
        .as_mut()
        .expect("marker initialized")
        .sync_configs(&inner.configs, &inner.destination_policies)?;
    if !inner.configs.values().any(needs_process_tracking) {
        let marker = inner.marker.as_ref().expect("marker initialized");
        for (pid, tracked) in &inner.tracked {
            if tracked.excluded {
                marker.set_excluded(*pid, false)?;
            }
        }
        inner.tracked.clear();
        return Ok(());
    }
    let processes = procfs::scan()?;
    let next = build_tracking(&inner.configs, &processes);
    let marker = inner.marker.as_ref().expect("marker initialized");
    for (pid, tracked) in &inner.tracked {
        if tracked.excluded && !next.get(pid).is_some_and(|process| process.excluded) {
            marker.set_excluded(*pid, false)?;
        }
    }
    for (pid, tracked) in &next {
        if tracked.excluded {
            marker.set_excluded(*pid, true)?;
        }
    }
    inner.tracked = next;
    Ok(())
}

fn needs_process_tracking(config: &SplitConfig) -> bool {
    config.has_app_rules()
        || (config.mode == crate::model::SplitMode::Include && config.has_rules())
}

fn build_tracking(configs: &ConfigMap, processes: &[ProcessInfo]) -> HashMap<u32, TrackedProcess> {
    let mut matches: HashMap<u32, bool> = processes
        .iter()
        .filter_map(|process| {
            configs
                .get(&process.uid)
                .map(|config| (process.pid, config.matches(&process.identities)))
        })
        .collect();
    for _ in 0..processes.len() {
        let mut changed = false;
        for process in processes {
            if matches.get(&process.pid) == Some(&false)
                && matches.get(&process.ppid) == Some(&true)
            {
                matches.insert(process.pid, true);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    processes
        .iter()
        .filter_map(|process| {
            let config = configs.get(&process.uid)?;
            let matched = matches.get(&process.pid).copied().unwrap_or(false);
            Some((
                process.pid,
                TrackedProcess {
                    uid: process.uid,
                    matched,
                    excluded: config.excludes(matched),
                },
            ))
        })
        .collect()
}

fn handle_event(inner: &mut Inner, event: ProcessEvent) -> io::Result<()> {
    let Some(marker) = inner.marker.as_ref() else {
        return Ok(());
    };
    match event {
        ProcessEvent::Exit { pid } => {
            if inner
                .tracked
                .remove(&pid)
                .is_some_and(|process| process.excluded)
            {
                marker.set_excluded(pid, false)?;
            }
        }
        ProcessEvent::Fork { parent, child } => {
            let process = match inner.tracked.get(&parent).copied() {
                Some(parent) => inner.configs.get(&parent.uid).map(|config| TrackedProcess {
                    uid: parent.uid,
                    matched: parent.matched,
                    excluded: config.excludes(parent.matched),
                }),
                None => procfs::read_process(child).ok().and_then(|info| {
                    inner.configs.get(&info.uid).map(|config| {
                        let matched = config.matches(&info.identities);
                        TrackedProcess {
                            uid: info.uid,
                            matched,
                            excluded: config.excludes(matched),
                        }
                    })
                }),
            };
            if let Some(process) = process {
                marker.set_excluded(child, process.excluded)?;
                inner.tracked.insert(child, process);
            }
        }
        ProcessEvent::Exec { pid } => {
            let Ok(info) = procfs::read_process(pid) else {
                return Ok(());
            };
            let Some(config) = inner.configs.get(&info.uid) else {
                if inner
                    .tracked
                    .remove(&pid)
                    .is_some_and(|process| process.excluded)
                {
                    marker.set_excluded(pid, false)?;
                }
                return Ok(());
            };
            let matched = inner
                .tracked
                .get(&pid)
                .is_some_and(|process| process.matched)
                || config.matches(&info.identities);
            let process = TrackedProcess {
                uid: info.uid,
                matched,
                excluded: config.excludes(matched),
            };
            marker.set_excluded(pid, process.excluded)?;
            inner.tracked.insert(pid, process);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SplitMode;

    #[test]
    fn descendants_inherit_a_matched_application() {
        let configs = ConfigMap::from([(
            1000,
            SplitConfig {
                mode: SplitMode::Exclude,
                app_paths: vec!["/usr/bin/firefox".into()],
                ip_ranges: vec![],
            },
        )]);
        let processes = vec![
            ProcessInfo {
                uid: 1000,
                pid: 10,
                ppid: 1,
                identities: vec!["/usr/bin/firefox".into()],
            },
            ProcessInfo {
                uid: 1000,
                pid: 11,
                ppid: 10,
                identities: vec!["/usr/lib/firefox/contentproc".into()],
            },
        ];
        let tracked = build_tracking(&configs, &processes);
        assert!(tracked[&10].excluded);
        assert!(tracked[&11].matched);
        assert!(tracked[&11].excluded);
    }
}
