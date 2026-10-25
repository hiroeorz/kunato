//! Minimal HTTP/3 probe used by the isolated security lab.
//!
//! It is built by `scripts/security-lab.sh prepare` and mounted into a lab
//! container; it is not part of the shipped proxy binary.

use std::error::Error;
use std::sync::Arc;

use bytes::Buf;
use http::{Method, Request, StatusCode};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::{Value, json};

struct Args {
    host: String,
    port: u16,
    cert: String,
    case: String,
    case_id: Option<String>,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args {
        host: "app.test".to_owned(),
        port: 8443,
        cert: "/lab/fixtures/tls/ca.pem".to_owned(),
        case: "normal".to_owned(),
        case_id: None,
    };
    let mut values = std::env::args().skip(1);
    while let Some(argument) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--host" => args.host = value,
            "--port" => args.port = value.parse()?,
            "--cert" => args.cert = value,
            "--case" => args.case = value,
            "--case-id" => args.case_id = Some(value),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(args)
}

fn client_config(cert: &str) -> Result<quinn::ClientConfig, Box<dyn Error>> {
    let certificate = CertificateDer::from_pem_file(cert)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(config)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

async fn connect(
    host: &str,
    port: u16,
    cert: &str,
) -> Result<(quinn::Endpoint, quinn::Connection), Box<dyn Error>> {
    let address = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or("no address for host")?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config(cert)?);
    let connection = endpoint.connect(address, host)?.await?;
    Ok((endpoint, connection))
}

async fn normal(
    host: &str,
    port: u16,
    cert: &str,
    case_id: &str,
) -> Result<StatusCode, Box<dyn Error>> {
    let (endpoint, connection) = connect(host, port, cert).await?;
    let (mut h3, mut send) = h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let task = tokio::spawn(async move {
        let _ = h3.wait_idle().await;
    });
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{host}/health"))
        .header("x-kunato-lab-case", case_id)
        .body(())?;
    let mut stream = send.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let status = response.status();
    while let Some(mut chunk) = stream.recv_data().await? {
        let _ = chunk.copy_to_bytes(chunk.remaining());
    }
    drop(send);
    drop(connection);
    drop(endpoint);
    task.abort();
    Ok(status)
}

async fn attack(host: &str, port: u16, cert: &str, case: &str) -> Result<(), Box<dyn Error>> {
    let (endpoint, connection) = connect(host, port, cert).await?;
    let (mut h3, mut send) = h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let task = tokio::spawn(async move {
        let _ = h3.wait_idle().await;
    });
    match case {
        "malformed" => {
            for _ in 0..32 {
                let (mut stream, _receive) = connection.open_bi().await?;
                stream.write_all(&[0x01, 0x08]).await?;
                stream.finish()?;
            }
        }
        "reset" => {
            for index in 0..50 {
                let request = Request::builder()
                    .method(Method::GET)
                    .uri(format!("https://{host}/health"))
                    .header("x-kunato-lab-case", format!("h3-reset-{index}"))
                    .body(())?;
                let mut stream = send.send_request(request).await?;
                stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            }
        }
        other => return Err(format!("unknown H3 attack case {other}").into()),
    }
    drop(send);
    drop(connection);
    drop(endpoint);
    task.abort();
    Ok(())
}

async fn run(args: Args) -> Value {
    let case = args.case.as_str();
    if case == "normal" {
        let case_id = args
            .case_id
            .clone()
            .unwrap_or_else(|| "h3-normal".to_owned());
        return match normal(&args.host, args.port, &args.cert, &case_id).await {
            Ok(status) => json!({
                "case": "normal",
                "case_id": case_id,
                "ok": status == StatusCode::OK,
                "status": status.as_u16(),
            }),
            Err(error) => {
                json!({"case": "normal", "case_id": case_id, "ok": false, "error": error.to_string()})
            }
        };
    }

    let attack_error = attack(&args.host, args.port, &args.cert, case)
        .await
        .err()
        .map(|error| error.to_string());
    let case_id = format!("h3-{case}-normal");
    match normal(&args.host, args.port, &args.cert, &case_id).await {
        Ok(status) => json!({
            "case": case,
            "normal": status == StatusCode::OK,
            "normal_status": status.as_u16(),
            "attack_error": attack_error,
        }),
        Err(error) => json!({
            "case": case,
            "normal": false,
            "normal_error": error.to_string(),
            "attack_error": attack_error,
        }),
    }
}

#[tokio::main]
async fn main() {
    let result = match parse_args() {
        Ok(args) => run(args).await,
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    };
    println!("{result}");
}
