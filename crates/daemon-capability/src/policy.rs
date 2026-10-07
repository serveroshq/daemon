use std::path::{Path, PathBuf};

use crate::ops::{DataOp, MachineOp, Operation, ServiceOp};

const FORBIDDEN_READS: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];

const KEY_DIRS: &[&str] = &[
    ".ssh",
    "private",
    "ssl/private",
    "letsencrypt/live",
    "letsencrypt/archive",
];

fn looks_like_private_key(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower = name.to_ascii_lowercase();

    lower == "id_rsa"
        || lower == "id_ed25519"
        || lower == "id_ecdsa"
        || lower == "id_dsa"
        || lower.ends_with(".key")
        || lower.ends_with(".pem") && lower.contains("priv")
        || lower == "privkey.pem"
}

pub fn is_forbidden_read(path: &Path) -> bool {
    let normalized = crate::roots::normalize(path);

    if FORBIDDEN_READS.iter().any(|f| normalized == Path::new(f)) {
        return true;
    }

    let in_key_dir = KEY_DIRS.iter().any(|dir| {
        let dir_path = Path::new(dir);
        normalized
            .components()
            .collect::<Vec<_>>()
            .windows(dir_path.components().count())
            .any(|w| {
                w.iter()
                    .map(|c| c.as_os_str())
                    .eq(dir_path.components().map(|c| c.as_os_str()))
            })
    });

    in_key_dir && looks_like_private_key(&normalized) || normalized.starts_with("/etc/shadow")
}

pub fn allowed_on_adopted(op: &ServiceOp) -> bool {
    !matches!(op, ServiceOp::Create { .. } | ServiceOp::Update { .. })
}

pub fn manages_user(user: &str, managed_users: &[String]) -> bool {
    managed_users.iter().any(|u| u == user)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub panel_host: String,
    pub storage_hosts: Vec<String>,
}

impl Egress {
    pub fn permits(&self, host: &str) -> bool {
        host == self.panel_host || self.storage_hosts.iter().any(|h| h == host)
    }
}

pub fn explain_refusal(op: &Operation, reason: &Refusal) -> String {
    match reason {
        Refusal::OutsideRoots => format!("{} is outside permitted roots", op.target()),
        Refusal::ForbiddenPath => format!("{} is never readable by ServerOS", op.target()),
        Refusal::NeedsConfirmation => {
            format!("{} needs an explicit, confirmed instruction", op.verb())
        }
        Refusal::ReadOnly => "machine is in read-only mode".into(),
        Refusal::NotCreatedByUs => format!("{} was not created by ServerOS", op.target()),
        Refusal::NotAdopted => format!(
            "{} was neither created nor adopted by ServerOS; adopt it first",
            op.target()
        ),
        Refusal::UnmanagedUser => format!("{} is not a ServerOS-managed user", op.target()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    OutsideRoots,
    ForbiddenPath,
    NeedsConfirmation,
    ReadOnly,
    NotCreatedByUs,
    NotAdopted,
    UnmanagedUser,
}

pub fn checks_for(op: &Operation) -> Vec<Check> {
    let mut checks = Vec::new();

    if op.mutates() {
        checks.push(Check::ReadOnlyMode);
    }

    if op.requires_confirmation() {
        checks.push(Check::Confirmation);
    }

    if op.path().is_some() {
        checks.push(Check::ForbiddenPath);
        checks.push(Check::PermittedRoots);
    }

    match op {
        Operation::Service(s) if !allowed_on_adopted(s) => checks.push(Check::CreatedByUs),
        Operation::Service(ServiceOp::Remove { .. }) => checks.push(Check::CreatedOrAdopted),
        Operation::Machine(MachineOp::ManageSshKeys { .. }) => checks.push(Check::ManagedUser),
        Operation::Data(DataOp::OpenTerminal { .. }) => checks.push(Check::ReadOnlyMode),
        _ => {}
    }

    checks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    ReadOnlyMode,
    Confirmation,
    ForbiddenPath,
    PermittedRoots,
    CreatedByUs,
    CreatedOrAdopted,
    ManagedUser,
}

#[derive(Debug, Clone, Default)]
pub struct Created {
    pub paths: Vec<PathBuf>,
    pub services: Vec<String>,
    pub users: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_reads_shadow_or_ssh_private_keys() {
        assert!(is_forbidden_read(Path::new("/etc/shadow")));
        assert!(is_forbidden_read(Path::new("/srv/app/../../etc/shadow")));
        assert!(is_forbidden_read(Path::new("/root/.ssh/id_ed25519")));
        assert!(is_forbidden_read(Path::new("/home/deploy/.ssh/id_rsa")));
        assert!(is_forbidden_read(Path::new("/etc/ssl/private/server.key")));
        assert!(is_forbidden_read(Path::new(
            "/etc/letsencrypt/live/example.com/privkey.pem"
        )));
    }

    #[test]
    fn public_keys_and_ordinary_files_are_not_forbidden() {
        assert!(!is_forbidden_read(Path::new("/root/.ssh/id_ed25519.pub")));
        assert!(!is_forbidden_read(Path::new("/root/.ssh/authorized_keys")));
        assert!(!is_forbidden_read(Path::new("/etc/nginx/nginx.conf")));
        assert!(!is_forbidden_read(Path::new(
            "/srv/app/storage/app.key.txt"
        )));
    }

    #[test]
    fn adopted_services_cannot_be_created_or_rewritten() {
        assert!(!allowed_on_adopted(&ServiceOp::Create {
            service: "nginx".into()
        }));
        assert!(!allowed_on_adopted(&ServiceOp::Update {
            service: "nginx".into()
        }));
        assert!(allowed_on_adopted(&ServiceOp::Remove {
            service: "nginx".into()
        }));
        assert!(allowed_on_adopted(&ServiceOp::Restart {
            service: "nginx".into()
        }));
        assert!(allowed_on_adopted(&ServiceOp::ReadLogs {
            service: "nginx".into()
        }));
    }

    #[test]
    fn egress_is_the_panel_and_configured_storage_only() {
        let egress = Egress {
            panel_host: "api.serveros.com".into(),
            storage_hosts: vec!["s3.eu-west-2.amazonaws.com".into()],
        };

        assert!(egress.permits("api.serveros.com"));
        assert!(egress.permits("s3.eu-west-2.amazonaws.com"));
        assert!(!egress.permits("evil.example"));
    }

    #[test]
    fn destructive_operations_demand_confirmation() {
        let restore = Operation::Data(DataOp::Restore {
            service: "pg".into(),
            snapshot: "s1".into(),
        });
        let reboot = Operation::Machine(MachineOp::Reboot);
        let restart = Operation::Service(ServiceOp::Restart {
            service: "pg".into(),
        });

        assert!(checks_for(&restore).contains(&Check::Confirmation));
        assert!(checks_for(&reboot).contains(&Check::Confirmation));
        assert!(!checks_for(&restart).contains(&Check::Confirmation));
    }

    #[test]
    fn removing_is_confirmed_and_limited_to_created_or_adopted_services() {
        let remove = Operation::Service(ServiceOp::Remove {
            service: "docker:abc123def456".into(),
        });
        let checks = checks_for(&remove);

        assert!(checks.contains(&Check::Confirmation));
        assert!(checks.contains(&Check::ReadOnlyMode));
        assert!(checks.contains(&Check::CreatedOrAdopted));
        assert!(!checks.contains(&Check::CreatedByUs));
    }

    #[test]
    fn running_a_command_is_confirmed_and_blocked_in_read_only_mode() {
        let exec = Operation::Service(ServiceOp::Exec {
            service: "docker:abc123def456".into(),
        });
        let checks = checks_for(&exec);

        assert!(checks.contains(&Check::Confirmation));
        assert!(checks.contains(&Check::ReadOnlyMode));
        assert!(!checks.contains(&Check::CreatedByUs));
    }
}
