use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("terminals are only available on Linux")]
    Unsupported,
    #[error("unknown user {0}")]
    UnknownUser(String),
    #[error("{0}")]
    Os(String),
}

pub struct Pty {
    pub master: OwnedFd,
    pub child_pid: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

pub fn lookup(user: &str) -> Option<(u32, u32, String, String)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;

    text.lines().find_map(|line| {
        let parts: Vec<&str> = line.split(':').collect();
        (parts.len() >= 7 && parts[0] == user).then(|| {
            (
                parts[2].parse().ok()?,
                parts[3].parse().ok()?,
                parts[5].to_string(),
                parts[6].to_string(),
            )
                .into()
        })?
    })
}

#[cfg(target_os = "linux")]
pub fn spawn(user: &str, size: Size) -> Result<Pty, PtyError> {
    use nix::pty::openpty;
    use nix::unistd::{fork, setgid, setsid, setuid, ForkResult, Gid, Uid};
    use std::ffi::CString;

    let (uid, gid, home, shell) = lookup(user).ok_or_else(|| PtyError::UnknownUser(user.into()))?;
    let shell = if shell.is_empty() || shell.ends_with("nologin") || shell.ends_with("false") {
        "/bin/bash".to_string()
    } else {
        shell
    };
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(Some(&winsize), None).map_err(|e| PtyError::Os(e.to_string()))?;

    let shell_c = CString::new(shell.clone()).map_err(|e| PtyError::Os(e.to_string()))?;
    let argv0 = CString::new(format!("-{}", shell.rsplit('/').next().unwrap_or("sh")))
        .map_err(|e| PtyError::Os(e.to_string()))?;
    let env: Vec<CString> = [
        format!("HOME={home}"),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
        format!("SHELL={shell}"),
        "TERM=xterm-256color".to_string(),
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "LANG=C.UTF-8".to_string(),
        "SERVEROS_TERMINAL=1".to_string(),
    ]
    .iter()
    .map(|s| CString::new(s.as_str()).unwrap())
    .collect();
    let env_ptrs: Vec<*const libc::c_char> = env
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let argv: [*const libc::c_char; 2] = [argv0.as_ptr(), std::ptr::null()];

    match unsafe { fork() }.map_err(|e| PtyError::Os(e.to_string()))? {
        ForkResult::Child => unsafe {
            let slave = pty.slave.as_raw_fd();
            let _ = setsid();
            libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            libc::close(pty.master.as_raw_fd());
            let _ = libc::chdir(CString::new(home).unwrap().as_ptr());
            if setgid(Gid::from_raw(gid)).is_err()
                || libc::initgroups(CString::new(user).unwrap().as_ptr(), gid) != 0
                || setuid(Uid::from_raw(uid)).is_err()
            {
                libc::_exit(126);
            }
            libc::execve(shell_c.as_ptr(), argv.as_ptr(), env_ptrs.as_ptr());
            libc::_exit(127);
        },
        ForkResult::Parent { child } => {
            drop(pty.slave);
            Ok(Pty {
                master: pty.master,
                child_pid: child.as_raw(),
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn(_user: &str, _size: Size) -> Result<Pty, PtyError> {
    Err(PtyError::Unsupported)
}

impl Pty {
    pub fn resize(&self, size: Size) {
        let winsize = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe {
            libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &winsize);
        }
    }

    pub fn terminate(&self) {
        unsafe {
            libc::kill(self.child_pid, libc::SIGHUP);
        }
    }

    pub fn async_master(&self) -> std::io::Result<tokio::io::unix::AsyncFd<OwnedFd>> {
        let dup = unsafe { libc::dup(self.master.as_raw_fd()) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(dup) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        unsafe {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        tokio::io::unix::AsyncFd::new(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_lookup_finds_root() {
        if std::path::Path::new("/etc/passwd").exists() {
            let (uid, _, home, _) = lookup("root").expect("root exists");
            assert_eq!(uid, 0);
            assert!(!home.is_empty());
        }
        assert!(lookup("definitely-not-a-user").is_none());
    }
}
