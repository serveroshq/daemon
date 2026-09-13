//! Who is connected right now, and how to reach them. Purely in-memory;
//! the panel is the durable record and asks `GET /machines` when it wants
//! the live view.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use daemon_protocol::{Kind, StreamFrame};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

/// A message the gateway wants delivered to a daemon. The connection task
/// sequences and frames it.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub kind: Kind,
    pub payload: Value,
    /// Commands carry the panel's job id so updates correlate.
    pub id: Option<Uuid>,
}

pub struct MachineHandle {
    pub uid: String,
    pub serial: String,
    pub major: u16,
    pub daemon_version: String,
    pub connected_at: i64,
    /// Unique per connection; a replaced handle must not be unregistered
    /// by the connection it replaced.
    pub generation: u64,
    pub tx: mpsc::Sender<Outgoing>,
    streams: Mutex<HashMap<Uuid, mpsc::Sender<StreamFrame>>>,
}

#[derive(Debug, Serialize)]
pub struct MachineSummary {
    pub uid: String,
    pub serial: String,
    pub major: u16,
    pub daemon_version: String,
    pub connected_at: i64,
    pub streams: usize,
}

#[derive(Default)]
pub struct Registry {
    machines: RwLock<HashMap<String, Arc<MachineHandle>>>,
    generations: AtomicU64,
}

impl Registry {
    pub fn next_generation(&self) -> u64 {
        self.generations.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn handle(
        &self,
        uid: String,
        serial: String,
        major: u16,
        daemon_version: String,
        tx: mpsc::Sender<Outgoing>,
    ) -> Arc<MachineHandle> {
        Arc::new(MachineHandle {
            uid,
            serial,
            major,
            daemon_version,
            connected_at: unix_now(),
            generation: self.next_generation(),
            tx,
            streams: Mutex::new(HashMap::new()),
        })
    }

    /// Register a connection. A machine that reconnects before its old
    /// socket died replaces it; the old handle's sender is dropped so its
    /// task ends.
    pub fn register(&self, handle: Arc<MachineHandle>) -> Option<Arc<MachineHandle>> {
        self.machines
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle.uid.clone(), handle)
    }

    /// Remove the connection only if it is still the current one.
    pub fn unregister(&self, uid: &str, generation: u64) -> bool {
        let mut machines = self.machines.write().unwrap_or_else(|e| e.into_inner());

        match machines.get(uid) {
            Some(current) if current.generation == generation => {
                machines.remove(uid);
                true
            }
            _ => false,
        }
    }

    pub fn get(&self, uid: &str) -> Option<Arc<MachineHandle>> {
        self.machines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(uid)
            .cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.machines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn list(&self) -> Vec<MachineSummary> {
        let mut all: Vec<MachineSummary> = self
            .machines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|m| MachineSummary {
                uid: m.uid.clone(),
                serial: m.serial.clone(),
                major: m.major,
                daemon_version: m.daemon_version.clone(),
                connected_at: m.connected_at,
                streams: m.stream_count(),
            })
            .collect();
        all.sort_by(|a, b| a.uid.cmp(&b.uid));

        all
    }
}

impl MachineHandle {
    pub fn attach_stream(&self, session: Uuid, tx: mpsc::Sender<StreamFrame>) {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session, tx);
    }

    pub fn detach_stream(&self, session: &Uuid) {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session);
    }

    /// Deliver a frame from the daemon to whichever browser holds the
    /// session. Returns false when nobody is attached (the frame is
    /// dropped: PTY output has no meaning without a viewer).
    pub fn route_stream(&self, frame: StreamFrame) -> bool {
        let sender = self
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&frame.session)
            .cloned();

        match sender {
            Some(tx) => tx.try_send(frame).is_ok(),
            None => false,
        }
    }

    pub fn stream_count(&self) -> usize {
        self.streams.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reconnect_replaces_the_old_handle_and_the_old_task_cannot_remove_it() {
        let registry = Registry::default();
        let (tx, _rx) = mpsc::channel(1);
        let first = registry.handle("m1".into(), "aa".into(), 1, "1.0.0".into(), tx.clone());
        let second = registry.handle("m1".into(), "aa".into(), 1, "1.0.1".into(), tx);

        assert!(registry.register(Arc::clone(&first)).is_none());
        assert!(registry.register(Arc::clone(&second)).is_some());
        assert!(!registry.unregister("m1", first.generation));
        assert_eq!(registry.get("m1").unwrap().daemon_version, "1.0.1");
        assert!(registry.unregister("m1", second.generation));
        assert!(registry.get("m1").is_none());
    }

    #[test]
    fn stream_frames_route_only_to_attached_sessions() {
        let registry = Registry::default();
        let (tx, _rx) = mpsc::channel(1);
        let handle = registry.handle("m1".into(), "aa".into(), 1, "1.0.0".into(), tx);
        let session = Uuid::new_v4();
        let (stream_tx, mut stream_rx) = mpsc::channel(4);

        let frame = StreamFrame {
            session,
            kind: daemon_protocol::StreamKind::PtyOutput,
            data_b64: "aGk=".into(),
            eof: false,
        };

        assert!(!handle.route_stream(frame.clone()));
        handle.attach_stream(session, stream_tx);
        assert!(handle.route_stream(frame.clone()));
        assert_eq!(stream_rx.try_recv().unwrap(), frame);
        handle.detach_stream(&session);
        assert!(!handle.route_stream(frame));
    }
}
