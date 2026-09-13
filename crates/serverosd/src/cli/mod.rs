pub mod doctor;
pub mod enrol;
pub mod inventory;
pub mod status;
pub mod uninstall;
pub mod update;

/// Most commands need root: they touch /etc/serveros and the unit.
pub fn require_root(what: &str) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("{what} needs root. Re-run with sudo.");
    }

    Ok(())
}

pub fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}
