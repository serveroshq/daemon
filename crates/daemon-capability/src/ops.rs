use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Machine(MachineOp),
    Service(ServiceOp),
    Deploy(DeployOp),
    Data(DataOp),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOp {
    ReadFacts,
    ReadMetrics,
    ListUnits,
    ListContainers,
    QueryPackageUpdates,
    ApplyPackageUpdates { security_only: bool },
    Reboot,
    ReadFirewall,
    WriteFirewall { rule: String },
    ManageSshKeys { user: String },
    ReadJournal { unit: Option<String> },
    ReadNamedLog { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceOp {
    Start { service: String },
    Stop { service: String },
    Restart { service: String },
    Reload { service: String },
    ReadLogs { service: String },
    ReadUsage { service: String },
    ReadConfig { service: String, path: PathBuf },
    Create { service: String },
    Update { service: String },
    Remove { service: String },
    Repair { service: String },
    Adopt { service: String },
    Unadopt { service: String },
    Exec { service: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployOp {
    FetchSource { service: String, workspace: PathBuf },
    Build { service: String, workspace: PathBuf },
    SwapContainers { service: String },
    WriteProxyConfig { service: String },
    ObtainCertificate { domains: Vec<String> },
    WriteEnvFile { service: String, path: PathBuf },
    Rollback { service: String },
    Release { service: String, path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOp {
    Snapshot { service: String },
    Restore { service: String, snapshot: String },
    UploadSnapshot { service: String },
    Browse { path: PathBuf },
    ReadFile { path: PathBuf },
    WriteFile { path: PathBuf },
    DeleteFile { path: PathBuf },
    Chmod { path: PathBuf },
    Chown { path: PathBuf },
    OpenTerminal { user: String },
}

impl Operation {
    pub fn verb(&self) -> &'static str {
        match self {
            Operation::Machine(m) => match m {
                MachineOp::ReadFacts => "machine.facts",
                MachineOp::ReadMetrics => "machine.metrics",
                MachineOp::ListUnits => "machine.units",
                MachineOp::ListContainers => "machine.containers",
                MachineOp::QueryPackageUpdates => "packages.query",
                MachineOp::ApplyPackageUpdates { .. } => "packages.apply",
                MachineOp::Reboot => "machine.reboot",
                MachineOp::ReadFirewall => "firewall.read",
                MachineOp::WriteFirewall { .. } => "firewall.write",
                MachineOp::ManageSshKeys { .. } => "ssh.keys",
                MachineOp::ReadJournal { .. } => "journal.read",
                MachineOp::ReadNamedLog { .. } => "log.read",
            },
            Operation::Service(s) => match s {
                ServiceOp::Start { .. } => "service.start",
                ServiceOp::Stop { .. } => "service.stop",
                ServiceOp::Restart { .. } => "service.restart",
                ServiceOp::Reload { .. } => "service.reload",
                ServiceOp::ReadLogs { .. } => "service.logs",
                ServiceOp::ReadUsage { .. } => "service.usage",
                ServiceOp::ReadConfig { .. } => "service.config",
                ServiceOp::Create { .. } => "service.create",
                ServiceOp::Update { .. } => "service.update",
                ServiceOp::Remove { .. } => "service.remove",
                ServiceOp::Repair { .. } => "service.repair",
                ServiceOp::Adopt { .. } => "service.adopt",
                ServiceOp::Unadopt { .. } => "service.unadopt",
                ServiceOp::Exec { .. } => "service.exec",
            },
            Operation::Deploy(d) => match d {
                DeployOp::FetchSource { .. } => "deploy.fetch",
                DeployOp::Build { .. } => "deploy.build",
                DeployOp::SwapContainers { .. } => "deploy.swap",
                DeployOp::WriteProxyConfig { .. } => "deploy.proxy",
                DeployOp::ObtainCertificate { .. } => "deploy.tls",
                DeployOp::WriteEnvFile { .. } => "deploy.env",
                DeployOp::Rollback { .. } => "deploy.rollback",
                DeployOp::Release { .. } => "deploy.release",
            },
            Operation::Data(d) => match d {
                DataOp::Snapshot { .. } => "backup.create",
                DataOp::Restore { .. } => "backup.restore",
                DataOp::UploadSnapshot { .. } => "backup.upload",
                DataOp::Browse { .. } => "file.browse",
                DataOp::ReadFile { .. } => "file.read",
                DataOp::WriteFile { .. } => "file.write",
                DataOp::DeleteFile { .. } => "file.delete",
                DataOp::Chmod { .. } => "file.chmod",
                DataOp::Chown { .. } => "file.chown",
                DataOp::OpenTerminal { .. } => "terminal.open",
            },
        }
    }

    pub fn target(&self) -> String {
        match self {
            Operation::Machine(m) => match m {
                MachineOp::ApplyPackageUpdates {
                    security_only: true,
                } => "security updates".into(),
                MachineOp::ApplyPackageUpdates {
                    security_only: false,
                } => "all updates".into(),
                MachineOp::WriteFirewall { rule } => rule.clone(),
                MachineOp::ManageSshKeys { user } => user.clone(),
                MachineOp::ReadJournal { unit } => unit.clone().unwrap_or_else(|| "system".into()),
                MachineOp::ReadNamedLog { path } => path.display().to_string(),
                _ => "machine".into(),
            },
            Operation::Service(s) => match s {
                ServiceOp::Start { service }
                | ServiceOp::Stop { service }
                | ServiceOp::Restart { service }
                | ServiceOp::Reload { service }
                | ServiceOp::ReadLogs { service }
                | ServiceOp::ReadUsage { service }
                | ServiceOp::Create { service }
                | ServiceOp::Update { service }
                | ServiceOp::Remove { service }
                | ServiceOp::Repair { service }
                | ServiceOp::Adopt { service }
                | ServiceOp::Unadopt { service }
                | ServiceOp::Exec { service } => service.clone(),
                ServiceOp::ReadConfig { service, path } => format!("{service} {}", path.display()),
            },
            Operation::Deploy(d) => match d {
                DeployOp::FetchSource { service, .. }
                | DeployOp::Build { service, .. }
                | DeployOp::SwapContainers { service }
                | DeployOp::WriteProxyConfig { service }
                | DeployOp::Rollback { service } => service.clone(),
                DeployOp::WriteEnvFile { service, path } | DeployOp::Release { service, path } => {
                    format!("{service} {}", path.display())
                }
                DeployOp::ObtainCertificate { domains } => domains.join(","),
            },
            Operation::Data(d) => match d {
                DataOp::Snapshot { service } | DataOp::UploadSnapshot { service } => {
                    service.clone()
                }
                DataOp::Restore { service, snapshot } => format!("{service} {snapshot}"),
                DataOp::Browse { path }
                | DataOp::ReadFile { path }
                | DataOp::WriteFile { path }
                | DataOp::DeleteFile { path }
                | DataOp::Chmod { path }
                | DataOp::Chown { path } => path.display().to_string(),
                DataOp::OpenTerminal { user } => user.clone(),
            },
        }
    }

    pub fn mutates(&self) -> bool {
        match self {
            Operation::Machine(m) => matches!(
                m,
                MachineOp::ApplyPackageUpdates { .. }
                    | MachineOp::Reboot
                    | MachineOp::WriteFirewall { .. }
                    | MachineOp::ManageSshKeys { .. }
            ),
            Operation::Service(s) => !matches!(
                s,
                ServiceOp::ReadLogs { .. }
                    | ServiceOp::ReadUsage { .. }
                    | ServiceOp::ReadConfig { .. }
            ),
            Operation::Deploy(_) => true,
            Operation::Data(d) => !matches!(d, DataOp::Browse { .. } | DataOp::ReadFile { .. }),
        }
    }

    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self,
            Operation::Machine(MachineOp::ApplyPackageUpdates { .. })
                | Operation::Machine(MachineOp::Reboot)
                | Operation::Data(DataOp::Restore { .. })
                | Operation::Service(ServiceOp::Remove { .. })
                | Operation::Service(ServiceOp::Repair { .. })
                | Operation::Service(ServiceOp::Exec { .. })
                | Operation::Data(DataOp::DeleteFile { .. })
        )
    }

    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            Operation::Machine(MachineOp::ReadNamedLog { path }) => Some(path),
            Operation::Service(ServiceOp::ReadConfig { path, .. }) => Some(path),
            Operation::Deploy(DeployOp::FetchSource { workspace, .. }) => Some(workspace),
            Operation::Deploy(DeployOp::Build { workspace, .. }) => Some(workspace),
            Operation::Deploy(DeployOp::WriteEnvFile { path, .. }) => Some(path),
            Operation::Deploy(DeployOp::Release { path, .. }) => Some(path),
            Operation::Data(DataOp::Browse { path })
            | Operation::Data(DataOp::ReadFile { path })
            | Operation::Data(DataOp::WriteFile { path })
            | Operation::Data(DataOp::DeleteFile { path })
            | Operation::Data(DataOp::Chmod { path })
            | Operation::Data(DataOp::Chown { path }) => Some(path),
            _ => None,
        }
    }
}
