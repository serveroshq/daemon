//! Runs every source under one time budget at low priority, assembles
//! the report, and diffs it against the last one to emit change events.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use daemon_protocol::{DiscoveredService, Event, EventKind, InventoryReport, Severity};
use tracing::debug;

use crate::classify::{self, Findings};
use crate::{cron, docker, listeners, systemd, tls, webservers};

pub struct Scanner {
    pub budget: Duration,
    pub proc_root: std::path::PathBuf,
    pub docker_socket: std::path::PathBuf,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(60),
            proc_root: "/proc".into(),
            docker_socket: docker::SOCKET.into(),
        }
    }
}

impl Scanner {
    /// One full scan. Never fails: a source that errors or overruns is
    /// noted in `warnings` and the rest of the report stands.
    pub async fn scan(&self) -> InventoryReport {
        let started = Instant::now();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut warnings = Vec::new();
        let mut complete = true;

        lower_priority();

        let per_source = self.budget / 4;

        let (found_listeners, processes) = if self.proc_root.join("net/tcp").exists() {
            listeners::discover(&self.proc_root)
        } else {
            warnings.push("no procfs: listeners and processes were not scanned".into());
            (Vec::new(), Default::default())
        };

        let units = match tokio::time::timeout(per_source, systemd::discover(per_source)).await {
            Ok(Some(units)) => units,
            Ok(None) => {
                warnings.push("systemd was not reachable; units were not scanned".into());
                Vec::new()
            }
            Err(_) => {
                complete = false;
                warnings.push("systemd scan overran its budget".into());
                Vec::new()
            }
        };

        let (containers, docker_version) = match tokio::time::timeout(
            per_source,
            docker::discover(&self.docker_socket, Duration::from_secs(5)),
        )
        .await
        {
            Ok(Some((c, v))) => (c, v),
            Ok(None) => (Vec::new(), None),
            Err(_) => {
                complete = false;
                warnings.push("docker scan overran its budget".into());
                (Vec::new(), None)
            }
        };

        let vhosts = tokio::task::spawn_blocking(webservers::discover)
            .await
            .unwrap_or_default();
        let cert_paths = webservers::certificate_paths(&vhosts);
        let certificates = tokio::task::spawn_blocking(move || tls::discover(&cert_paths))
            .await
            .unwrap_or_default();
        let scheduled = cron::discover(per_source)
            .await
            .into_iter()
            .filter(|t| !cron::is_ours(t))
            .collect();

        let findings = Findings {
            listeners: found_listeners.clone(),
            processes,
            units,
            containers,
            vhosts,
        };
        let classified = classify::classify(&findings);

        if started.elapsed() > self.budget {
            complete = false;
            warnings.push(format!(
                "scan took {:.1}s, over the {:?} budget",
                started.elapsed().as_secs_f32(),
                self.budget
            ));
        }

        let mut report = InventoryReport {
            scanned_at: now,
            duration_ms: started.elapsed().as_millis() as u64,
            complete,
            services: classified.services,
            listeners: found_listeners,
            certificates,
            scheduled,
            unknown: classified.unknown,
            warnings,
        };

        if let Some(v) = docker_version {
            for s in report
                .services
                .iter_mut()
                .filter(|s| s.key.starts_with("docker:"))
            {
                s.details
                    .entry("docker_version".into())
                    .or_insert_with(|| v.clone());
            }
        }

        debug!(
            services = report.services.len(),
            unknown = report.unknown.len(),
            ms = report.duration_ms,
            "inventory scan finished"
        );

        report
    }
}

/// Discovery runs niced with lowered IO priority so a scan on a busy box
/// costs the customer's services nothing noticeable.
fn lower_priority() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
        // ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13)
        libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
    }
}

/// Change events between two reports: services that appeared, went away,
/// or changed status. Plus every pre-existing failure the first scan sees,
/// timestamped and neutral, before ServerOS takes responsibility.
pub fn diff(previous: Option<&InventoryReport>, current: &InventoryReport) -> Vec<Event> {
    let mut events = Vec::new();
    let before: BTreeMap<&str, &DiscoveredService> = previous
        .map(|p| p.services.iter().map(|s| (s.key.as_str(), s)).collect())
        .unwrap_or_default();
    let after: BTreeMap<&str, &DiscoveredService> = current
        .services
        .iter()
        .map(|s| (s.key.as_str(), s))
        .collect();

    for (key, service) in &after {
        match before.get(key) {
            None if previous.is_some() => events.push(Event {
                kind: EventKind::ServiceDiscovered,
                severity: Severity::Info,
                summary: format!(
                    "new service detected: {}{}",
                    service.name,
                    ports_suffix(service)
                ),
                detail: Some(format!(
                    "run by {:?}, confidence {}%",
                    service.manager, service.confidence
                )),
                service: Some(service.key.clone()),
                data: BTreeMap::new(),
                suggested_action: Some(
                    "Review and adopt it from the machine's Services tab.".into(),
                ),
            }),
            None => {
                if service.status == daemon_protocol::ServiceStatus::Failed {
                    events.push(Event {
                        kind: EventKind::PreExisting,
                        severity: Severity::Warning,
                        summary: format!(
                            "{} was already failed when ServerOS first looked",
                            service.name
                        ),
                        detail: service.details.get("pre_existing_failure").cloned(),
                        service: Some(service.key.clone()),
                        data: BTreeMap::from([(
                            "first_seen".into(),
                            current.scanned_at.to_string(),
                        )]),
                        suggested_action: None,
                    });
                }
            }
            Some(old) if old.status != service.status => events.push(Event {
                kind: match service.status {
                    daemon_protocol::ServiceStatus::Failed => EventKind::ServiceCrashed,
                    daemon_protocol::ServiceStatus::Restarting => EventKind::RestartLoop,
                    _ => EventKind::ServiceDiscovered,
                },
                severity: match service.status {
                    daemon_protocol::ServiceStatus::Failed
                    | daemon_protocol::ServiceStatus::Restarting => Severity::Critical,
                    _ => Severity::Info,
                },
                summary: format!("{} is now {:?}", service.name, service.status).to_lowercase(),
                detail: None,
                service: Some(service.key.clone()),
                data: BTreeMap::new(),
                suggested_action: None,
            }),
            Some(_) => {}
        }
    }

    for (key, service) in &before {
        if !after.contains_key(key) {
            events.push(Event {
                kind: EventKind::ServiceGone,
                severity: Severity::Warning,
                summary: format!("{} is no longer running or listening", service.name),
                detail: None,
                service: Some(service.key.clone()),
                data: BTreeMap::new(),
                suggested_action: None,
            });
        }
    }

    for unknown in &current.unknown {
        let seen_before =
            previous.is_some_and(|p| p.unknown.iter().any(|u| u.port == unknown.port));

        if previous.is_some() && !seen_before {
            events.push(Event {
                kind: EventKind::ServiceDiscovered,
                severity: Severity::Info,
                summary: unknown.note.clone(),
                detail: None,
                service: None,
                data: BTreeMap::from([("port".into(), unknown.port.to_string())]),
                suggested_action: None,
            });
        }
    }

    events
}

fn ports_suffix(service: &DiscoveredService) -> String {
    match service.ports.first() {
        Some(port) => format!(" on :{port}"),
        None => String::new(),
    }
}

#[allow(dead_code)]
fn _keep(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_protocol::{ServiceKind, ServiceManager, ServiceStatus};

    fn service(key: &str, status: ServiceStatus) -> DiscoveredService {
        DiscoveredService {
            key: key.into(),
            name: key.split(':').next_back().unwrap().into(),
            kind: ServiceKind::Other,
            manager: ServiceManager::Systemd,
            status,
            version: None,
            ports: vec![8080],
            working_dir: None,
            user: None,
            exec: None,
            config_paths: vec![],
            data_dir: None,
            confidence: 80,
            details: BTreeMap::new(),
            capabilities: vec![],
            origin: Default::default(),
        }
    }

    fn report(services: Vec<DiscoveredService>) -> InventoryReport {
        InventoryReport {
            scanned_at: 1,
            duration_ms: 1,
            complete: true,
            services,
            listeners: vec![],
            certificates: vec![],
            scheduled: vec![],
            unknown: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn first_scan_reports_pre_existing_failures_only() {
        let events = diff(
            None,
            &report(vec![
                service("systemd:a", ServiceStatus::Running),
                service("systemd:b", ServiceStatus::Failed),
            ]),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::PreExisting);
        assert!(events[0].summary.contains("already failed"));
    }

    #[test]
    fn later_scans_report_new_gone_and_crashed() {
        let before = report(vec![
            service("systemd:a", ServiceStatus::Running),
            service("systemd:gone", ServiceStatus::Running),
        ]);
        let after = report(vec![
            service("systemd:a", ServiceStatus::Failed),
            service("systemd:new", ServiceStatus::Running),
        ]);

        let events = diff(Some(&before), &after);
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();

        assert!(kinds.contains(&EventKind::ServiceCrashed));
        assert!(kinds.contains(&EventKind::ServiceDiscovered));
        assert!(kinds.contains(&EventKind::ServiceGone));
        assert!(events
            .iter()
            .any(|e| e.summary == "new service detected: new on :8080"));
    }
}
