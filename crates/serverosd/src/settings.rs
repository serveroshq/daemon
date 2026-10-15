//! What the panel decides for this machine, applied to its config: at
//! enrolment, before the daemon first starts, and later through
//! `reconfigure`. Each setting that's there is applied, each one that
//! isn't is left alone, and a value the daemon can't use is skipped
//! rather than stopping the rest.

use daemon_core::ipmask::IpMasking;
use daemon_core::logskip::{LogSkip, SkipPattern};
use daemon_core::Config;
use daemon_protocol::{LogSkipPattern, LogSkipRules, MachineSettings};

/// What changed, as short notes for the audit log.
pub fn apply(config: &mut Config, settings: MachineSettings) -> Vec<String> {
    let mut changed = Vec::new();

    if let Some(on) = settings.discovery {
        config.discovery.enabled = on;
        changed.push(format!("discovery={on}"));
    }
    if let Some(on) = settings.logs {
        config.logs.enabled = on;
        changed.push(format!("logs={on}"));
    }
    if let Some(value) = settings.log_ip_masking.as_deref() {
        match parse_masking(value) {
            Some(masking) => {
                config.logs.mask_ips = masking;
                daemon_core::ipmask::set_mode(masking);
                changed.push(format!("log_ip_masking={}", masking_name(masking)));
            }
            None => changed.push(format!("unusable log_ip_masking: {value}")),
        }
    }
    if let Some(rules) = settings.log_skip {
        let skip = skip_from_wire(rules);
        let rejected = daemon_core::logskip::configure(&skip);
        changed.push(format!(
            "log_skip={} services, {} patterns",
            skip.services.len(),
            skip.patterns.len()
        ));
        if !rejected.is_empty() {
            changed.push(format!("unusable patterns: {}", rejected.join(" | ")));
        }
        config.logs.skip = skip;
    }
    if let Some(watch) = settings.security_watch {
        config.security.watch = watch;
        changed.push(format!("security_watch={watch}"));
    }
    if let Some(automatic) = settings.updates_automatic {
        config.updates.automatic = automatic;
        changed.push(format!("updates_automatic={automatic}"));
    }
    if let Some(channel) = settings.updates_channel {
        // Anything else would stop the config saving at all.
        if matches!(channel.as_str(), "stable" | "canary") {
            changed.push(format!("channel={channel}"));
            config.updates.channel = channel;
        } else {
            changed.push(format!("unusable channel: {channel}"));
        }
    }
    if let Some(pin) = settings.pinned_version {
        changed.push(format!(
            "pin={}",
            pin.clone().unwrap_or_else(|| "none".into())
        ));
        config.updates.pinned_version = pin;
    }

    changed
}

pub fn parse_masking(value: &str) -> Option<IpMasking> {
    match value {
        "off" => Some(IpMasking::Off),
        "partial" => Some(IpMasking::Partial),
        "hash" => Some(IpMasking::Hash),
        _ => None,
    }
}

pub fn masking_name(masking: IpMasking) -> &'static str {
    match masking {
        IpMasking::Off => "off",
        IpMasking::Partial => "partial",
        IpMasking::Hash => "hash",
    }
}

pub fn skip_to_wire(skip: &LogSkip) -> LogSkipRules {
    LogSkipRules {
        services: skip.services.clone(),
        patterns: skip
            .patterns
            .iter()
            .map(|p| LogSkipPattern {
                service: p.service.clone(),
                pattern: p.pattern.clone(),
            })
            .collect(),
    }
}

fn skip_from_wire(rules: LogSkipRules) -> LogSkip {
    LogSkip {
        services: rules.services,
        patterns: rules
            .patterns
            .into_iter()
            .map(|p| SkipPattern {
                service: p.service,
                pattern: p.pattern,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::new("panel.example", "m1")
    }

    #[test]
    fn missing_settings_change_nothing() {
        let mut c = config();
        let before = c.clone();

        assert!(apply(&mut c, MachineSettings::default()).is_empty());
        assert_eq!(c, before);
    }

    #[test]
    fn switches_turn_discovery_logs_and_updates_off() {
        let mut c = config();
        apply(
            &mut c,
            MachineSettings {
                discovery: Some(false),
                logs: Some(false),
                updates_automatic: Some(false),
                ..Default::default()
            },
        );

        assert!(!c.discovery.enabled);
        assert!(!c.logs.enabled);
        assert!(!c.updates.automatic);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn a_pin_can_be_set_and_cleared() {
        let mut c = config();
        let set: MachineSettings = serde_json::from_str(r#"{"pinned_version":"0.1.1"}"#).unwrap();
        apply(&mut c, set);
        assert_eq!(c.updates.pinned_version.as_deref(), Some("0.1.1"));

        let untouched: MachineSettings = serde_json::from_str("{}").unwrap();
        apply(&mut c, untouched);
        assert_eq!(c.updates.pinned_version.as_deref(), Some("0.1.1"));

        let clear: MachineSettings = serde_json::from_str(r#"{"pinned_version":null}"#).unwrap();
        apply(&mut c, clear);
        assert_eq!(c.updates.pinned_version, None);
    }

    #[test]
    fn an_unknown_channel_is_skipped_so_the_rest_still_saves() {
        let mut c = config();
        let notes = apply(
            &mut c,
            MachineSettings {
                updates_channel: Some("nightly".into()),
                logs: Some(false),
                ..Default::default()
            },
        );

        assert_eq!(c.updates.channel, "stable");
        assert!(!c.logs.enabled);
        assert!(c.validate().is_ok());
        assert!(notes.iter().any(|n| n.contains("unusable channel")));
    }
}
