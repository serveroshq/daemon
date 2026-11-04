//! Exposed ports: a small TCP forwarder per port, listening on this
//! machine's network address and copying each connection to a service on
//! loopback or the Docker bridge.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use daemon_jobs::Failure;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::spec::{may_connect, Cidr, ExposePlan};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct Port {
    target: SocketAddrV4,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Port {
    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// The forwarders running for one network.
#[derive(Default)]
pub struct Forwarders {
    bind: Option<Ipv4Addr>,
    network: Option<Cidr>,
    ports: BTreeMap<u16, Port>,
}

impl Forwarders {
    pub fn ports(&self) -> Vec<(u16, SocketAddrV4)> {
        self.ports.iter().map(|(p, f)| (*p, f.target)).collect()
    }

    /// Makes the running set exactly `wanted`, on `bind`: forwarders that
    /// haven't changed keep running (and keep their connections), the rest
    /// are stopped before the new ones listen. Every new port is bound
    /// before any is started, so a port that's taken fails the lot.
    pub async fn replace(
        &mut self,
        bind: Ipv4Addr,
        network: Cidr,
        wanted: &[ExposePlan],
    ) -> Result<(), Failure> {
        if self.bind != Some(bind) || self.network != Some(network) {
            self.stop_all().await;
        }
        self.bind = Some(bind);
        self.network = Some(network);

        let stale: Vec<u16> = self
            .ports
            .iter()
            .filter(|(port, running)| {
                !wanted
                    .iter()
                    .any(|w| w.port == **port && w.target == running.target)
            })
            .map(|(port, _)| *port)
            .collect();
        for port in stale {
            if let Some(running) = self.ports.remove(&port) {
                running.stop().await;
            }
        }

        let mut bound = Vec::new();
        for w in wanted.iter().filter(|w| !self.ports.contains_key(&w.port)) {
            let addr = SocketAddrV4::new(bind, w.port);
            match TcpListener::bind(addr).await {
                Ok(listener) => bound.push((*w, listener)),
                Err(e) => {
                    return Err(Failure::new(
                        "expose",
                        format!("couldn't listen on {addr} for {}: {e}", w.target),
                    )
                    .with_next_step(
                        "Something else on this machine is using that port on the network address; free it or offer another port.",
                    ))
                }
            }
        }

        for (w, listener) in bound {
            let (stop, stopped) = watch::channel(false);
            let task = tokio::spawn(serve(listener, w.target, network, stopped));
            self.ports.insert(
                w.port,
                Port {
                    target: w.target,
                    stop,
                    task,
                },
            );
        }

        Ok(())
    }

    pub async fn stop_all(&mut self) {
        for (_, running) in std::mem::take(&mut self.ports) {
            running.stop().await;
        }
    }
}

async fn serve(
    listener: TcpListener,
    target: SocketAddrV4,
    network: Cidr,
    mut stopped: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            _ = stopped.changed() => return,
            accepted = listener.accept() => accepted,
        };
        let (inbound, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, %target, "network forwarder couldn't accept");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        if !may_connect(&network, peer.ip()) {
            debug!(%peer, %target, "refused a connection from outside the network");
            continue;
        }
        let mut stopped = stopped.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = stopped.changed() => {}
                _ = relay(inbound, peer, target) => {}
            }
        });
    }
}

async fn relay(mut inbound: TcpStream, peer: SocketAddr, target: SocketAddrV4) {
    let outbound = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await;
    let mut outbound = match outbound {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(error = %e, %peer, %target, "network forwarder couldn't reach its target");
            return;
        }
        Err(_) => {
            debug!(%peer, %target, "network forwarder timed out reaching its target");
            return;
        }
    };
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn echo() -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn round_trip(port: u16) -> std::io::Result<Vec<u8>> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
        s.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf))
            .await
            .map_err(|_| std::io::Error::other("timed out"))??;
        Ok(buf.to_vec())
    }

    #[tokio::test]
    async fn forwards_and_replaces_the_running_set() {
        let target = echo().await;
        let port = free_port();
        let network = Cidr::parse("10.88.3.0/24").unwrap();
        let mut forwarders = Forwarders::default();

        forwarders
            .replace(Ipv4Addr::LOCALHOST, network, &[ExposePlan { port, target }])
            .await
            .unwrap();
        assert_eq!(round_trip(port).await.unwrap(), b"ping");
        assert_eq!(forwarders.ports(), vec![(port, target)]);

        // The same list again leaves it running.
        forwarders
            .replace(Ipv4Addr::LOCALHOST, network, &[ExposePlan { port, target }])
            .await
            .unwrap();
        assert_eq!(round_trip(port).await.unwrap(), b"ping");

        // An empty list closes it.
        forwarders
            .replace(Ipv4Addr::LOCALHOST, network, &[])
            .await
            .unwrap();
        assert!(forwarders.ports().is_empty());
        assert!(round_trip(port).await.is_err());
    }

    #[tokio::test]
    async fn a_taken_port_fails_the_job() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let target = echo().await;
        let mut forwarders = Forwarders::default();

        let failure = forwarders
            .replace(
                Ipv4Addr::LOCALHOST,
                Cidr::parse("10.88.3.0/24").unwrap(),
                &[ExposePlan { port, target }],
            )
            .await
            .unwrap_err();
        assert_eq!(failure.phase, "expose");
        assert!(forwarders.ports().is_empty());
    }
}
