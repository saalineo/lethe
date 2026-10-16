//! Tor (arti) transport: onion service for the server, onion client for the peer.
//!
//! Everything runs on a private multi-thread tokio runtime owned by this
//! library; the host binary never sees it. The wire framing on top of the Tor
//! stream is the same 4-byte big-endian length prefix the TCP path uses.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataReader, DataStream, DataWriter, TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use safelog::DisplayRedacted;
use futures::{Stream, StreamExt};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{RunningOnionService, StreamRequest};
use tor_rtcompat::PreferredRuntime;
use zeroize::Zeroize;

use crate::{Link, BUF_SIZE};

/// Virtual port the onion service listens on / the client dials.
pub const ONION_PORT: u16 = 9000;
/// How long a server waits for its descriptor to become reachable.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a server waits for a peer (§8.5).
const PEER_TIMEOUT: Duration = Duration::from_secs(600);
/// Client connect attempts; fresh descriptors take time to propagate.
const CONNECT_ATTEMPTS: u32 = 8;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn rt() -> io::Result<&'static tokio::runtime::Runtime> {
    if let Some(r) = RT.get() {
        return Ok(r);
    }
    // arti's rustls needs a process-wide crypto provider; ignore "already set".
    let _ = rustls::crypto::ring::default_provider().install_default();
    let built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("lethe-tor")
        .build()?;
    Ok(RT.get_or_init(|| built))
}

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// State, cache and the (native) keystore live on the private tmpfs, never on
/// a real filesystem. arti 0.47's in-memory keystore was tried and does not let
/// the service publish (stays `Bootstrapping`, no intro points), so the key is
/// in tmpfs and not mlocked; the tmpfs is released with `umount2` at shutdown.
fn config(is_server: bool) -> io::Result<TorClientConfig> {
    // One directory per role so a server and client in one process never share a lock.
    let role = if is_server { "srv" } else { "cli" };
    let mut b = TorClientConfigBuilder::from_directories(
        format!("/tmp/sirfz/{role}/state"),
        format!("/tmp/sirfz/{role}/cache"),
    );
    // Single-user private tmpfs; avoids the fs-mistrust ownership walk, which
    // fails inside the user namespace (uid 0 mapped onto the real uid).
    b.storage().permissions().dangerously_trust_everyone();
    b.build().map_err(err)
}

type Rend = Pin<Box<dyn Stream<Item = StreamRequest> + Send>>;

struct Io {
    rd: AsyncMutex<DataReader>,
    wr: AsyncMutex<DataWriter>,
}

pub struct Node {
    client: Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
    svc: Mutex<Option<Arc<RunningOnionService>>>,
    rend: AsyncMutex<Option<Rend>>,
    addr: Option<String>,
    peer: Option<String>,
    io: OnceLock<Arc<Io>>,
    closed: AtomicBool,
    wake: Notify,
}

impl Node {
    /// Bootstraps Tor; for a server also launches the service and waits until
    /// its descriptor is reachable. Never blocks on a peer.
    pub fn start(is_server: bool, peer: Option<String>) -> io::Result<Arc<Node>> {
        let cfg = config(is_server)?;
        let rt = rt()?;
        rt.block_on(async move {
            let client = TorClient::builder()
                .config(cfg)
                .create_bootstrapped()
                .await
                .map_err(err)?;

            let mut node = Node {
                client: Mutex::new(Some(client.clone())),
                svc: Mutex::new(None),
                rend: AsyncMutex::new(None),
                addr: None,
                peer,
                io: OnceLock::new(),
                closed: AtomicBool::new(false),
                wake: Notify::new(),
            };

            if is_server {
                let svc_cfg = OnionServiceConfigBuilder::default()
                    .nickname("sirfz".parse().map_err(err)?) // local label only
                    .build()
                    .map_err(err)?;
                let (svc, rend_requests) = client
                    .launch_onion_service(svc_cfg)
                    .map_err(err)?
                    .ok_or_else(|| io::Error::other("onion service disabled"))?;

                let mut events = svc.status_events();
                let reachable = async {
                    while let Some(st) = events.next().await {
                        if std::env::var_os("LETHE_TOR_DEBUG").is_some() {
                            eprintln!("onion status: {:?} problem={:?}", st.state(), st.current_problem());
                        }
                        if st.state().is_fully_reachable() {
                            return true;
                        }
                    }
                    false
                };
                match tokio::time::timeout(PUBLISH_TIMEOUT, reachable).await {
                    Ok(true) => {}
                    _ => return Err(io::Error::other("onion service never became reachable")),
                }

                node.addr = svc.onion_address().map(|a| a.display_unredacted().to_string());
                if node.addr.is_none() {
                    return Err(io::Error::other("onion address unavailable"));
                }
                let streams: Rend = Box::pin(tor_hsservice::handle_rend_requests(rend_requests));
                *node.rend.get_mut() = Some(streams);
                *node.svc.lock().unwrap() = Some(svc);
            } else if node.peer.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client needs a peer .onion address",
                ));
            }
            Ok(Arc::new(node))
        })
    }

    pub fn address(&self) -> Option<&str> {
        self.addr.as_deref()
    }

    /// Blocks until the stream is up (server: first accepted request; client:
    /// connect finished, with backoff). Server timeouts drop the service.
    pub fn wait_peer(&self) -> io::Result<()> {
        if self.io.get().is_some() {
            return Ok(());
        }
        let stream = rt()?.block_on(async {
            tokio::select! {
                r = self.establish() => r,
                _ = self.wake.notified() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "stopped")),
            }
        })?;
        let (rd, wr) = stream.split();
        let io = Arc::new(Io { rd: AsyncMutex::new(rd), wr: AsyncMutex::new(wr) });
        let _ = self.io.set(io);
        Ok(())
    }

    async fn establish(&self) -> io::Result<DataStream> {
        let mut rend = self.rend.lock().await;
        if let Some(streams) = rend.as_mut() {
            let wait = async {
                loop {
                    let req = streams.next().await.ok_or_else(|| io::Error::other("closed"))?;
                    // Only BEGIN on our port; anything else is rejected.
                    match req.request() {
                        tor_proto::stream::IncomingStreamRequest::Begin(b)
                            if b.port() == ONION_PORT =>
                        {
                            let s = req
                                .accept(tor_cell::relaycell::msg::Connected::new_empty())
                                .await
                                .map_err(err)?;
                            return Ok::<_, io::Error>(s);
                        }
                        _ => {
                            let _ = req.shutdown_circuit();
                        }
                    }
                }
            };
            let res = tokio::time::timeout(PEER_TIMEOUT, wait).await;
            // Single-peer policy: no second connection is ever possible.
            *rend = None;
            if let Some(svc) = self.svc.lock().unwrap().take() {
                drop(svc);
            }
            return match res {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "no peer connected")),
            };
        }

        let client = self
            .client
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io::Error::other("stopped"))?;
        let peer = self.peer.as_deref().unwrap_or_default();
        let mut delay = Duration::from_secs(2);
        let mut last = io::Error::other("connect failed");
        for _ in 0..CONNECT_ATTEMPTS {
            match client.connect((peer, ONION_PORT)).await {
                Ok(s) => return Ok(s),
                Err(e) => last = err(e),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
        Err(last)
    }

    fn io(&self) -> io::Result<Arc<Io>> {
        self.io
            .get()
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "peer not connected"))
    }
}

impl Link for Node {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        let io = self.io()?;
        let mut framed = Vec::with_capacity(data.len() + 4);
        framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
        framed.extend_from_slice(data);
        let res = rt()?.block_on(async {
            let mut wr = io.wr.lock().await;
            wr.write_all(&framed).await?;
            wr.flush().await
        });
        framed.zeroize();
        res
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let io = self.io()?;
        rt()?.block_on(async {
            let mut rd = io.rd.lock().await;
            let read = async {
                let mut len = [0u8; 4];
                rd.read_exact(&mut len).await?;
                let len = u32::from_be_bytes(len) as usize;
                if len > BUF_SIZE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
                }
                let mut buf = vec![0u8; len];
                rd.read_exact(&mut buf).await?;
                Ok(buf)
            };
            tokio::select! {
                r = read => r,
                _ = self.wake.notified() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "stopped")),
            }
        })
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
        // Dropping the client and service tears the circuits down.
        self.svc.lock().unwrap().take();
        self.client.lock().unwrap().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live Tor round trip (needs network, takes minutes): `cargo test -- --ignored onion`.
    #[test]
    #[ignore]
    fn onion_round_trip() {
        let server = Node::start(true, None).expect("server start");
        let addr = server.address().expect("address").to_string();
        assert!(addr.ends_with(".onion"), "{addr}");

        let s2 = server.clone();
        let t = std::thread::spawn(move || {
            s2.wait_peer().expect("server wait");
            let got = s2.recv().expect("server recv");
            s2.send(&got).expect("server echo");
        });

        let client = Node::start(false, Some(addr)).expect("client start");
        client.wait_peer().expect("client connect");
        client.send(b"hello over tor").unwrap();
        assert_eq!(client.recv().unwrap(), b"hello over tor");
        t.join().unwrap();
        client.shutdown();
        server.shutdown();
    }
}
