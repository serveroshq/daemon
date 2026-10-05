use daemon_core::buildinfo::parse_semver;
use daemon_core::config::UpdateConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default)]
    pub min_from: Option<String>,
    #[serde(default)]
    pub notes_url: Option<String>,
}

fn default_channel() -> String {
    "stable".into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub automatic: bool,
    pub channel: String,
    pub pinned_version: Option<String>,
    pub window: Option<(u8, u8, u8, u8)>,
    pub allow_major_automatically: bool,
}

impl From<&UpdateConfig> for Policy {
    fn from(cfg: &UpdateConfig) -> Self {
        Self {
            automatic: cfg.automatic,
            channel: cfg.channel.clone(),
            pinned_version: cfg.pinned_version.clone(),
            window: None,
            allow_major_automatically: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Install,
    NeedsApproval(String),
    Defer(String),
    Refuse(String),
}

pub fn decide(
    policy: &Policy,
    current: &str,
    candidate: &Candidate,
    explicit: bool,
    running_jobs: usize,
    local_minutes: u16,
) -> Decision {
    let Some(current_v) = parse_semver(current) else {
        return Decision::Refuse(format!(
            "current version {current:?} is not parseable; refusing to reason about updates"
        ));
    };
    let Some(candidate_v) = parse_semver(&candidate.version) else {
        return Decision::Refuse(format!(
            "offered version {:?} is not a version",
            candidate.version
        ));
    };

    if let Some(pin) = &policy.pinned_version {
        if parse_semver(pin) != Some(candidate_v) {
            return Decision::Refuse(format!(
                "this machine is pinned to {pin}; unpin it to update"
            ));
        }
    }

    if candidate_v == current_v {
        return Decision::Refuse(format!("{} is already installed", candidate.version));
    }

    if candidate_v < current_v && !explicit {
        return Decision::Refuse(format!(
            "{} is older than the installed {current}; downgrades need an explicit instruction",
            candidate.version
        ));
    }

    if let Some(min_from) = candidate.min_from.as_deref().and_then(parse_semver) {
        if current_v < min_from {
            return Decision::Refuse(format!(
                "{} upgrades from {} or newer; install an intermediate release first",
                candidate.version,
                candidate.min_from.clone().unwrap_or_default()
            ));
        }
    }

    if candidate.channel != policy.channel
        && !(policy.channel == "canary" && candidate.channel == "stable")
        && !explicit
    {
        return Decision::Refuse(format!(
            "{} is on the {} channel; this machine follows {}",
            candidate.version, candidate.channel, policy.channel
        ));
    }

    if !explicit && !policy.automatic {
        return Decision::NeedsApproval("automatic updates are off for this machine".into());
    }

    if !explicit && candidate_v.0 > current_v.0 && !policy.allow_major_automatically {
        return Decision::NeedsApproval(format!(
            "{} is a major version change from {current}; review the release notes and approve it",
            candidate.version
        ));
    }

    if running_jobs > 0 {
        return Decision::Defer(format!(
            "{running_jobs} job(s) still running; the update installs when they finish"
        ));
    }

    if let Some((from_h, from_m, to_h, to_m)) = policy.window {
        if !explicit
            && !in_window(
                local_minutes,
                from_h as u16 * 60 + from_m as u16,
                to_h as u16 * 60 + to_m as u16,
            )
        {
            return Decision::Defer(format!(
                "outside the maintenance window {from_h:02}:{from_m:02}-{to_h:02}:{to_m:02}"
            ));
        }
    }

    Decision::Install
}

fn in_window(now: u16, from: u16, to: u16) -> bool {
    if from <= to {
        (from..=to).contains(&now)
    } else {
        now >= from || now <= to
    }
}

pub fn parse_window(text: &str) -> Option<(u8, u8, u8, u8)> {
    let (a, b) = text.split_once('-')?;
    let (ah, am) = a.split_once(':')?;
    let (bh, bm) = b.split_once(':')?;
    let parts = (
        ah.parse().ok()?,
        am.parse().ok()?,
        bh.parse().ok()?,
        bm.parse().ok()?,
    );

    (parts.0 < 24 && parts.1 < 60 && parts.2 < 24 && parts.3 < 60).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(version: &str) -> Candidate {
        Candidate {
            version: version.into(),
            url: "https://x/y".into(),
            sha256: String::new(),
            signature: String::new(),
            channel: "stable".into(),
            min_from: None,
            notes_url: None,
        }
    }

    fn policy() -> Policy {
        Policy {
            automatic: true,
            channel: "stable".into(),
            pinned_version: None,
            window: None,
            allow_major_automatically: false,
        }
    }

    #[test]
    fn minor_updates_install_automatically() {
        assert_eq!(
            decide(&policy(), "1.2.0", &candidate("1.3.0"), false, 0, 600),
            Decision::Install
        );
    }

    #[test]
    fn major_jumps_wait_for_a_person_unless_explicit() {
        assert!(matches!(
            decide(&policy(), "1.9.0", &candidate("2.0.0"), false, 0, 600),
            Decision::NeedsApproval(_)
        ));
        assert_eq!(
            decide(&policy(), "1.9.0", &candidate("2.0.0"), true, 0, 600),
            Decision::Install
        );
    }

    #[test]
    fn automatic_off_means_offer_only() {
        let mut p = policy();
        p.automatic = false;

        assert!(matches!(
            decide(&p, "1.2.0", &candidate("1.3.0"), false, 0, 600),
            Decision::NeedsApproval(_)
        ));
        assert_eq!(
            decide(&p, "1.2.0", &candidate("1.3.0"), true, 0, 600),
            Decision::Install
        );
    }

    #[test]
    fn pins_and_min_from_beat_everything_including_explicit() {
        let mut p = policy();
        p.pinned_version = Some("1.2.0".into());
        assert!(matches!(
            decide(&p, "1.2.0", &candidate("1.3.0"), true, 0, 600),
            Decision::Refuse(_)
        ));

        let mut c = candidate("3.0.0");
        c.min_from = Some("2.0.0".into());
        assert!(
            matches!(decide(&policy(), "1.9.0", &c, true, 0, 600), Decision::Refuse(msg) if msg.contains("intermediate"))
        );
    }

    #[test]
    fn downgrades_and_wrong_channels_are_refused_unless_explicit() {
        assert!(matches!(
            decide(&policy(), "1.3.0", &candidate("1.2.0"), false, 0, 600),
            Decision::Refuse(_)
        ));
        assert_eq!(
            decide(&policy(), "1.3.0", &candidate("1.2.0"), true, 0, 600),
            Decision::Install
        );

        let mut c = candidate("1.4.0");
        c.channel = "canary".into();
        assert!(matches!(
            decide(&policy(), "1.3.0", &c, false, 0, 600),
            Decision::Refuse(_)
        ));

        let mut canary = policy();
        canary.channel = "canary".into();
        assert_eq!(
            decide(&canary, "1.3.0", &c, false, 0, 600),
            Decision::Install
        );
        assert_eq!(
            decide(&canary, "1.3.0", &candidate("1.4.0"), false, 0, 600),
            Decision::Install,
            "canary machines take stable too"
        );
    }

    #[test]
    fn jobs_and_windows_defer() {
        assert!(matches!(
            decide(&policy(), "1.2.0", &candidate("1.3.0"), false, 2, 600),
            Decision::Defer(_)
        ));

        let mut p = policy();
        p.window = parse_window("02:00-04:00");
        assert!(matches!(
            decide(&p, "1.2.0", &candidate("1.3.0"), false, 0, 12 * 60),
            Decision::Defer(_)
        ));
        assert_eq!(
            decide(&p, "1.2.0", &candidate("1.3.0"), false, 0, 3 * 60),
            Decision::Install
        );

        p.window = parse_window("23:00-01:00");
        assert_eq!(
            decide(&p, "1.2.0", &candidate("1.3.0"), false, 0, 0),
            Decision::Install
        );
        assert_eq!(parse_window("25:00-01:00"), None);
    }
}
