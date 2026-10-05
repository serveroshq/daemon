use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use daemon_protocol::{StreamFrame, StreamKind};
use tokio::io::Interest;
use tokio::sync::{mpsc, watch};
use tracing::info;
use uuid::Uuid;

use crate::pty::{self, Pty, PtyError, Size};
use crate::{decode, frame};

pub struct TerminalSession {
    pub id: Uuid,
    pub user: String,
    pub actor: String,
    pub opened_at: Instant,
    pub last_activity: Arc<Mutex<Instant>>,
    pub recording: bool,
    input: mpsc::Sender<Vec<u8>>,
    resize: mpsc::Sender<Size>,
    close: watch::Sender<bool>,
    pty: Arc<Pty>,
}

impl TerminalSession {
    pub fn duration(&self) -> Duration {
        self.opened_at.elapsed()
    }

    pub async fn input(&self, bytes: Vec<u8>) {
        *self.last_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        let _ = self.input.send(bytes).await;
    }

    pub async fn resize(&self, rows: u16, cols: u16) {
        let _ = self.resize.send(Size { rows, cols }).await;
    }

    pub fn close(&self) {
        let _ = self.close.send(true);
        self.pty.terminate();
    }
}

#[derive(Default)]
pub struct Sessions {
    open: Mutex<HashMap<Uuid, Arc<TerminalSession>>>,
    pub idle_timeout: Option<Duration>,
    pub recording: bool,
}

impl Sessions {
    pub fn new(idle_timeout: Duration, recording: bool) -> Self {
        Self {
            open: Mutex::default(),
            idle_timeout: Some(idle_timeout),
            recording,
        }
    }

    pub fn count(&self) -> usize {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn get(&self, id: Uuid) -> Option<Arc<TerminalSession>> {
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
    }

    pub fn open(
        &self,
        id: Uuid,
        user: &str,
        actor: &str,
        out: mpsc::Sender<StreamFrame>,
    ) -> Result<Arc<TerminalSession>, PtyError> {
        let pty = Arc::new(pty::spawn(user, Size { rows: 24, cols: 80 })?);
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(64);
        let (resize_tx, mut resize_rx) = mpsc::channel::<Size>(8);
        let (close_tx, mut close_rx) = watch::channel(false);
        let last_activity = Arc::new(Mutex::new(Instant::now()));

        let session = Arc::new(TerminalSession {
            id,
            user: user.into(),
            actor: actor.into(),
            opened_at: Instant::now(),
            last_activity: Arc::clone(&last_activity),
            recording: self.recording,
            input: input_tx,
            resize: resize_tx,
            close: close_tx,
            pty: Arc::clone(&pty),
        });
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, Arc::clone(&session));
        info!(session = %id, user, actor, "terminal opened");

        let master = pty
            .async_master()
            .map_err(|e| PtyError::Os(e.to_string()))?;
        let idle = self.idle_timeout;

        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            let mut idle_tick = tokio::time::interval(Duration::from_secs(15));

            loop {
                tokio::select! {
                    ready = master.readable() => {
                        let mut guard = match ready { Ok(g) => g, Err(_) => break };
                        match guard.try_io(|fd| {
                            let n = unsafe { libc::read(std::os::fd::AsRawFd::as_raw_fd(fd.get_ref()), buf.as_mut_ptr() as *mut _, buf.len()) };
                            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                        }) {
                            Ok(Ok(0)) | Ok(Err(_)) => break,
                            Ok(Ok(n)) => {
                                if out.send(frame(id, StreamKind::PtyOutput, &buf[..n], false)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_would_block) => continue,
                        }
                    }
                    Some(bytes) = input_rx.recv() => {
                        let _ = master.async_io(Interest::WRITABLE, |fd| {
                            let n = unsafe { libc::write(std::os::fd::AsRawFd::as_raw_fd(fd), bytes.as_ptr() as *const _, bytes.len()) };
                            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                        }).await;
                    }
                    Some(size) = resize_rx.recv() => pty.resize(size),
                    _ = close_rx.changed() => break,
                    _ = idle_tick.tick() => {
                        if let Some(limit) = idle {
                            let since = last_activity.lock().unwrap_or_else(|p| p.into_inner()).elapsed();
                            if since > limit {
                                let _ = out.send(frame(id, StreamKind::PtyOutput, b"\r\n[session closed after idle timeout]\r\n", false)).await;
                                break;
                            }
                        }
                    }
                }
            }

            pty.terminate();
            let _ = out.send(frame(id, StreamKind::PtyOutput, b"", true)).await;
        });

        Ok(session)
    }

    pub fn take(&self, id: Uuid) -> Option<Arc<TerminalSession>> {
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id)
    }

    pub async fn handle_frame(&self, frame: &StreamFrame) {
        let Some(session) = self.get(frame.session) else {
            return;
        };

        match frame.kind {
            StreamKind::PtyInput => session.input(decode(frame)).await,
            StreamKind::PtyResize => {
                let text = String::from_utf8_lossy(&decode(frame)).into_owned();
                if let Some((rows, cols)) = text
                    .split_once('x')
                    .and_then(|(r, c)| Some((r.parse().ok()?, c.parse().ok()?)))
                {
                    session.resize(rows, cols).await;
                }
            }
            _ => {}
        }

        if frame.eof {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_start_empty_and_unknown_ids_are_ignored() {
        let sessions = Sessions::new(Duration::from_secs(60), false);

        assert_eq!(sessions.count(), 0);
        assert!(sessions.get(Uuid::new_v4()).is_none());
        assert!(sessions.take(Uuid::new_v4()).is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn opening_off_linux_is_an_honest_error() {
        let sessions = Sessions::new(Duration::from_secs(60), false);
        let (tx, _rx) = mpsc::channel(4);

        assert!(matches!(
            sessions.open(Uuid::new_v4(), "root", "test", tx),
            Err(PtyError::Unsupported)
        ));
    }
}
