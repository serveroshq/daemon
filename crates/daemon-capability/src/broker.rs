use std::sync::{Arc, RwLock};

use daemon_audit::{Actor, AuditLog, Entry, Outcome};
use thiserror::Error;

use crate::ops::{MachineOp, Operation, ServiceOp};
use crate::policy::{self, Check, Created, Refusal};
use crate::roots::PermittedRoots;

#[derive(Debug, Clone)]
pub struct Request {
    pub actor: Actor,
    pub operation: Operation,
    pub confirmed: bool,
}

pub struct Grant {
    pub request: Request,
    audit: Arc<AuditLog>,
    started: std::time::Instant,
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl Grant {
    pub fn finish<E: std::fmt::Display>(self, result: &Result<(), E>, note: Option<&str>) {
        let duration = Some(self.started.elapsed());
        let (outcome, message) = match result {
            Ok(()) => (Outcome::Ok, note.map(str::to_string)),
            Err(e) => (
                Outcome::Failed,
                Some(match note {
                    Some(n) => format!("{e} ({n})"),
                    None => e.to_string(),
                }),
            ),
        };

        let _ = self.audit.record(Entry {
            actor: &self.request.actor,
            action: self.request.operation.verb(),
            target: &self.request.operation.target(),
            outcome,
            duration,
            note: message.as_deref(),
        });
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{explanation}")]
pub struct Denied {
    pub reason: Refusal,
    pub explanation: String,
}

#[derive(Debug, Default)]
pub struct BrokerState {
    pub roots: PermittedRoots,
    pub created: Created,
    pub adopted: Vec<String>,
    pub read_only: bool,
}

pub struct Broker {
    audit: Arc<AuditLog>,
    state: RwLock<BrokerState>,
}

impl Broker {
    pub fn new(audit: Arc<AuditLog>, state: BrokerState) -> Self {
        Self {
            audit,
            state: RwLock::new(state),
        }
    }

    pub fn set_read_only(&self, read_only: bool) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .read_only = read_only;
    }

    pub fn add_root(&self, root: std::path::PathBuf) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .roots
            .add(root);
    }

    pub fn record_created_service(&self, service: String) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .created
            .services
            .push(service);
    }

    pub fn set_adopted_services(&self, services: Vec<String>) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .adopted = services;
    }

    pub fn record_created_path(&self, path: std::path::PathBuf) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .created
            .paths
            .push(path);
    }

    pub fn record_created_user(&self, user: String) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .created
            .users
            .push(user);
    }

    pub fn authorize(&self, request: Request) -> Result<Grant, Denied> {
        let state = self.state.read().unwrap_or_else(|p| p.into_inner());

        if let Some(reason) = self.first_failing_check(&request, &state) {
            let explanation = policy::explain_refusal(&request.operation, &reason);

            let _ = self.audit.record(Entry {
                actor: &request.actor,
                action: request.operation.verb(),
                target: &request.operation.target(),
                outcome: Outcome::Refused,
                duration: None,
                note: Some(&explanation),
            });

            return Err(Denied {
                reason,
                explanation,
            });
        }

        drop(state);

        let _ = self.audit.record(Entry {
            actor: &request.actor,
            action: request.operation.verb(),
            target: &request.operation.target(),
            outcome: Outcome::Started,
            duration: None,
            note: None,
        });

        Ok(Grant {
            request,
            audit: Arc::clone(&self.audit),
            started: std::time::Instant::now(),
        })
    }

    fn first_failing_check(&self, request: &Request, state: &BrokerState) -> Option<Refusal> {
        let op = &request.operation;

        for check in policy::checks_for(op) {
            let failed = match check {
                Check::ReadOnlyMode => state.read_only,
                Check::Confirmation => !request.confirmed,
                Check::ForbiddenPath => op.path().is_some_and(|p| {
                    policy::is_forbidden_read(p) && !state.created.paths.iter().any(|c| c == p)
                }),
                Check::PermittedRoots => op.path().is_some_and(|p| !state.roots.permits(p)),
                Check::CreatedByUs => match op {
                    Operation::Service(
                        ServiceOp::Create { service } | ServiceOp::Update { service },
                    ) => !state.created.services.contains(service),
                    _ => false,
                },
                Check::CreatedOrAdopted => match op {
                    Operation::Service(
                        ServiceOp::Remove { service } | ServiceOp::Repair { service },
                    ) => {
                        !state.created.services.contains(service)
                            && !state.adopted.contains(service)
                    }
                    _ => false,
                },
                Check::ManagedUser => match op {
                    Operation::Machine(MachineOp::ManageSshKeys { user }) => {
                        !policy::manages_user(user, &state.created.users)
                    }
                    _ => false,
                },
            };

            if failed {
                return Some(match check {
                    Check::ReadOnlyMode => Refusal::ReadOnly,
                    Check::Confirmation => Refusal::NeedsConfirmation,
                    Check::ForbiddenPath => Refusal::ForbiddenPath,
                    Check::PermittedRoots => Refusal::OutsideRoots,
                    Check::CreatedByUs => Refusal::NotCreatedByUs,
                    Check::CreatedOrAdopted => Refusal::NotAdopted,
                    Check::ManagedUser => Refusal::UnmanagedUser,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ops::DataOp;

    fn broker(dir: &std::path::Path) -> Broker {
        let audit = Arc::new(AuditLog::open(&dir.join("actions.log")).unwrap());
        let mut state = BrokerState::default();
        state.roots.add(PathBuf::from("/srv/app"));
        state.created.services.push("serveros-app".into());

        Broker::new(audit, state)
    }

    fn request(op: Operation, confirmed: bool) -> Request {
        Request {
            actor: Actor::user("dylan@serveros.com"),
            operation: op,
            confirmed,
        }
    }

    fn log_lines(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("actions.log"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_file_read_inside_roots_is_granted_and_logged_twice() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());

        let grant = broker
            .authorize(request(
                Operation::Data(DataOp::ReadFile {
                    path: "/srv/app/.env".into(),
                }),
                false,
            ))
            .unwrap();
        grant.finish::<String>(&Ok(()), Some("412 bytes"));

        let lines = log_lines(dir.path());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("file.read") && lines[0].contains("started"));
        assert!(lines[1].contains("ok") && lines[1].contains("412 bytes"));
    }

    #[test]
    fn a_file_read_outside_roots_is_refused_and_logged() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());

        let denied = broker
            .authorize(request(
                Operation::Data(DataOp::ReadFile {
                    path: "/etc/nginx/nginx.conf".into(),
                }),
                false,
            ))
            .unwrap_err();

        assert_eq!(denied.reason, Refusal::OutsideRoots);
        assert!(log_lines(dir.path())[0].contains("refused"));
    }

    #[test]
    fn shadow_is_refused_even_inside_a_root() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.add_root(PathBuf::from("/etc"));

        let denied = broker
            .authorize(request(
                Operation::Data(DataOp::ReadFile {
                    path: "/etc/shadow".into(),
                }),
                true,
            ))
            .unwrap_err();

        assert_eq!(denied.reason, Refusal::ForbiddenPath);
    }

    #[test]
    fn keys_serveros_created_are_readable_by_serveros() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.add_root(PathBuf::from("/etc/letsencrypt"));
        broker.record_created_path(PathBuf::from(
            "/etc/letsencrypt/live/app.example/privkey.pem",
        ));

        assert!(broker
            .authorize(request(
                Operation::Data(DataOp::ReadFile {
                    path: "/etc/letsencrypt/live/app.example/privkey.pem".into()
                }),
                false
            ))
            .is_ok());
        assert!(broker
            .authorize(request(
                Operation::Data(DataOp::ReadFile {
                    path: "/etc/letsencrypt/live/other.example/privkey.pem".into()
                }),
                false
            ))
            .is_err());
    }

    #[test]
    fn restore_needs_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        let op = Operation::Data(DataOp::Restore {
            service: "pg".into(),
            snapshot: "s1".into(),
        });

        assert_eq!(
            broker
                .authorize(request(op.clone(), false))
                .unwrap_err()
                .reason,
            Refusal::NeedsConfirmation
        );
        assert!(broker.authorize(request(op, true)).is_ok());
    }

    #[test]
    fn read_only_mode_refuses_mutations_but_not_reads() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_read_only(true);

        assert_eq!(
            broker
                .authorize(request(
                    Operation::Service(ServiceOp::Restart {
                        service: "nginx".into()
                    }),
                    true
                ))
                .unwrap_err()
                .reason,
            Refusal::ReadOnly
        );
        assert!(broker
            .authorize(request(
                Operation::Service(ServiceOp::ReadLogs {
                    service: "nginx".into()
                }),
                false
            ))
            .is_ok());
        assert!(broker
            .authorize(request(Operation::Machine(MachineOp::ReadFacts), false))
            .is_ok());
    }

    fn remove(service: &str) -> Operation {
        Operation::Service(ServiceOp::Remove {
            service: service.into(),
        })
    }

    #[test]
    fn created_services_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());

        assert!(broker
            .authorize(request(remove("serveros-app"), true))
            .is_ok());
    }

    #[test]
    fn adopted_services_can_be_removed_once_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_adopted_services(vec!["docker:pterowings01".into()]);

        assert_eq!(
            broker
                .authorize(request(remove("docker:pterowings01"), false))
                .unwrap_err()
                .reason,
            Refusal::NeedsConfirmation
        );
        assert!(broker
            .authorize(request(remove("docker:pterowings01"), true))
            .is_ok());
    }

    #[test]
    fn discovered_services_cannot_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_adopted_services(vec!["docker:pterowings01".into()]);

        let denied = broker
            .authorize(request(remove("docker:somethingelse"), true))
            .unwrap_err();

        assert_eq!(denied.reason, Refusal::NotAdopted);
        assert!(denied.explanation.contains("adopt it first"));
    }

    #[test]
    fn adopted_services_still_cannot_be_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_adopted_services(vec!["docker:pterowings01".into()]);

        for op in [
            ServiceOp::Create {
                service: "docker:pterowings01".into(),
            },
            ServiceOp::Update {
                service: "docker:pterowings01".into(),
            },
        ] {
            assert_eq!(
                broker
                    .authorize(request(Operation::Service(op), true))
                    .unwrap_err()
                    .reason,
                Refusal::NotCreatedByUs
            );
        }
    }

    #[test]
    fn unadopting_takes_removal_away_again() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_adopted_services(vec!["docker:pterowings01".into()]);
        broker.set_adopted_services(Vec::new());

        assert_eq!(
            broker
                .authorize(request(remove("docker:pterowings01"), true))
                .unwrap_err()
                .reason,
            Refusal::NotAdopted
        );
    }

    #[test]
    fn read_only_mode_refuses_removing_adopted_services() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.set_adopted_services(vec!["docker:pterowings01".into()]);
        broker.set_read_only(true);

        assert_eq!(
            broker
                .authorize(request(remove("docker:pterowings01"), true))
                .unwrap_err()
                .reason,
            Refusal::ReadOnly
        );
    }

    #[test]
    fn ssh_keys_only_for_managed_users() {
        let dir = tempfile::tempdir().unwrap();
        let broker = broker(dir.path());
        broker.record_created_user("serveros".into());

        assert!(broker
            .authorize(request(
                Operation::Machine(MachineOp::ManageSshKeys {
                    user: "serveros".into()
                }),
                true
            ))
            .is_ok());
        assert_eq!(
            broker
                .authorize(request(
                    Operation::Machine(MachineOp::ManageSshKeys {
                        user: "root".into()
                    }),
                    true
                ))
                .unwrap_err()
                .reason,
            Refusal::UnmanagedUser
        );
    }
}
