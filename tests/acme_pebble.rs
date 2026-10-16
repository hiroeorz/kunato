//! End-to-end ACME tests against a local Pebble server.
//!
//! Pebble is Let's Encrypt's ACME test server. Start it with
//! `scripts/acme-pebble-test.sh`, which also points Pebble's TLS-ALPN-01
//! validation port at the test listener used below.
//!
//! The tests are `#[ignore]`d because they need Pebble and Docker.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::watch;

use kunato::acme::AcmeService;
use kunato::config;
use kunato::config::Acme;
use kunato::metrics::Metrics;
use kunato::proxy::server::Server;

const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
const DOMAIN: &str = "localhost";
const TLS_PORT: u16 = 15001;
const QUIC_PORT: u16 = 15002;
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .try_init();
}

fn trust_store(path: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).expect("open trust store") {
        roots
            .add(cert.expect("parse certificate"))
            .expect("add certificate");
    }
    assert!(!roots.is_empty(), "trust store is empty");
    roots
}

fn client_config(roots: RootCertStore, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn tls_handshake(
    addr: SocketAddr,
    roots: RootCertStore,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let connector = tokio_rustls::TlsConnector::from(client_config(roots, &[]));
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|err| err.to_string())?;
    let tls = connector
        .connect(ServerName::try_from(DOMAIN).expect("server name"), stream)
        .await
        .map_err(|err| err.to_string())?;
    let (_, connection) = tls.get_ref();
    Ok(connection
        .peer_certificates()
        .expect("peer certificates")
        .to_vec())
}

async fn wait_for_tls(addr: SocketAddr, roots: RootCertStore) -> Vec<CertificateDer<'static>> {
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    loop {
        match tls_handshake(addr, roots.clone()).await {
            Ok(certs) => return certs,
            Err(err) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("TLS handshake never succeeded: {err}");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn wait_for_renewed_tls(
    addr: SocketAddr,
    roots: RootCertStore,
    previous: &CertificateDer<'static>,
) -> Vec<CertificateDer<'static>> {
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    loop {
        if let Ok(certs) = tls_handshake(addr, roots.clone()).await
            && certs[0].as_ref() != previous.as_ref()
        {
            return certs;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("certificate was not renewed in time");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn quic_round_trip(addr: SocketAddr, roots: RootCertStore) {
    let client = client_config(roots, &[b"h3"]);
    let quic_tls =
        quinn::crypto::rustls::QuicClientConfig::try_from(client).expect("quic client tls");
    let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).expect("client endpoint");
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(addr, DOMAIN)
        .expect("connect")
        .await
        .expect("HTTP/3 handshake");
    assert!(conn.peer_identity().is_some(), "no peer identity");
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}

async fn wait_for_counter(counter: &AtomicU64, target: u64, label: &str) {
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    while counter.load(Ordering::Relaxed) < target {
        if tokio::time::Instant::now() >= deadline {
            panic!("{label} was not reached in time");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_file(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !path.is_file() {
        if tokio::time::Instant::now() >= deadline {
            panic!("{} was not written in time", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn pebble_roots() -> RootCertStore {
    let path = std::env::var("PEBBLE_ROOT_CERTS").expect("set PEBBLE_ROOT_CERTS");
    trust_store(Path::new(&path))
}

/// A full server lifecycle: config with an ACME block, automatic issuance over
/// TLS-ALPN-01, TLS and HTTP/3 serving with the issued certificate, and an
/// automatic renewal that rotates the served certificate without a restart.
#[tokio::test]
#[ignore]
async fn pebble_server_manages_certificates() {
    init_tracing();
    let roots = pebble_roots();
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_dir = dir.path().join("acme");

    let yaml = format!(
        "listen: 127.0.0.1:{TLS_PORT}\n\
         upstream: http://127.0.0.1:9\n\
         tls:\n\
         \x20 acme:\n\
         \x20   enabled: true\n\
         \x20   domains: [{DOMAIN}]\n\
         \x20   directory: {PEBBLE_DIRECTORY}\n\
         \x20   cache_dir: {}\n\
         http3:\n\
         \x20 enabled: true\n\
         \x20 listen: 127.0.0.1:{QUIC_PORT}\n",
        cache_dir.display()
    );
    let compiled = config::parse(&yaml).expect("valid config");
    let listen = compiled.listen;
    let settings = compiled
        .tls
        .as_ref()
        .and_then(|tls| tls.acme.clone())
        .expect("acme settings");
    let config = Arc::new(ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let service = AcmeService::start(&settings, metrics.clone(), shutdown_rx.clone())
        .await
        .expect("start ACME service");
    let server = Server::bind(listen, config, metrics.clone(), Some(&service))
        .await
        .expect("bind kunato");
    let addr = server.local_addr().expect("local address");
    let server_task = tokio::spawn(server.run(shutdown_rx.clone()));

    let first = wait_for_tls(addr, roots.clone()).await;
    assert_eq!(metrics.acme_issued.load(Ordering::Relaxed), 1);
    wait_for_file(&cache_dir.join("cert.pem")).await;
    quic_round_trip(SocketAddr::from(([127, 0, 0, 1], QUIC_PORT)), roots.clone()).await;

    let renewed = wait_for_renewed_tls(addr, roots, &first[0]).await;
    assert!(
        metrics.acme_issued.load(Ordering::Relaxed) >= 2,
        "renewal was not counted"
    );
    assert_ne!(first[0].as_ref(), renewed[0].as_ref());

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    let _ = service.into_driver().await;
}

/// A restart with the same cache directory deploys the cached certificate
/// before serving traffic, without registering a new account or placing a new
/// order.
#[tokio::test]
#[ignore]
async fn pebble_service_reuses_cache() {
    init_tracing();
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_dir = dir.path().join("acme");
    let settings = Acme {
        domains: vec![DOMAIN.to_owned()],
        contact: None,
        directory: PEBBLE_DIRECTORY.to_owned(),
        cache_dir: cache_dir.clone(),
    };

    // First run: bind a real server so Pebble can validate the challenge.
    let metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let service = AcmeService::start(&settings, metrics.clone(), shutdown_rx.clone())
        .await
        .expect("start ACME service");
    let yaml = format!(
        "listen: 127.0.0.1:{TLS_PORT}\n\
         upstream: http://127.0.0.1:9\n\
         tls:\n\
         \x20 acme:\n\
         \x20   enabled: true\n\
         \x20   domains: [{DOMAIN}]\n\
         \x20   directory: {PEBBLE_DIRECTORY}\n\
         \x20   cache_dir: {}\n",
        cache_dir.display()
    );
    let compiled = config::parse(&yaml).expect("valid config");
    let listen = compiled.listen;
    let config = Arc::new(ArcSwap::from_pointee(compiled));
    let server = Server::bind(listen, config, metrics.clone(), Some(&service))
        .await
        .expect("bind kunato");
    let server_task = tokio::spawn(server.run(shutdown_rx));
    wait_for_counter(&metrics.acme_issued, 1, "initial certificate").await;
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    let _ = service.into_driver().await;
    wait_for_file(&cache_dir.join("cert.pem")).await;
    wait_for_file(&cache_dir.join("account.key")).await;

    let restarted_metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let service = AcmeService::start(&settings, restarted_metrics.clone(), shutdown_rx)
        .await
        .expect("restart ACME service");
    assert_eq!(
        restarted_metrics.acme_cached.load(Ordering::Relaxed),
        1,
        "cached certificate must be deployed during startup"
    );
    assert_eq!(
        restarted_metrics.acme_issued.load(Ordering::Relaxed),
        0,
        "restart must not order a new certificate"
    );
    let _ = shutdown_tx.send(true);
    let _ = service.into_driver().await;
}
