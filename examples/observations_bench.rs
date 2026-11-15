//! Local development benchmark; no external hosts or production configuration.
use bytes::Bytes;
use http::{Request, Response};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use kunato::{
    admin::AdminServer,
    console::collector::HttpSource,
    metrics::Metrics,
    proxy::{BodyExt, Full, server::Server},
    snapshot::Snapshot,
};
use std::convert::Infallible;
use std::hint::black_box;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

fn measure(mut operation: impl FnMut(), iterations: u64) -> [f64; 3] {
    for _ in 0..1000 {
        operation();
    }
    let mut runs = Vec::new();
    for _ in 0..7 {
        let at = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        runs.push(at.elapsed().as_nanos() as f64 / iterations as f64);
    }
    runs.sort_by(f64::total_cmp);
    [runs[0], runs[3], runs[6]]
}

fn counters() {
    let metrics = Metrics::new();
    for (name, timings) in [
        (
            "request_increment",
            measure(
                || {
                    black_box(metrics.requests.fetch_add(1, Ordering::Relaxed));
                },
                5_000_000,
            ),
        ),
        (
            "request_rejection_reason_increments",
            measure(
                || {
                    black_box(metrics.requests.fetch_add(1, Ordering::Relaxed));
                    black_box(metrics.blocked.fetch_add(1, Ordering::Relaxed));
                    black_box(metrics.host_rejected.fetch_add(1, Ordering::Relaxed));
                },
                2_000_000,
            ),
        ),
        (
            "existing_metrics_render",
            measure(
                || {
                    black_box(metrics.render(black_box(42)));
                },
                20_000,
            ),
        ),
        (
            "illustrative_two_counter_sse",
            measure(
                || {
                    black_box(format!(
                        "event: counters\ndata: {{\"requests\":{},\"rejected\":{}}}\n\n",
                        metrics.requests.load(Ordering::Relaxed),
                        metrics.blocked.load(Ordering::Relaxed)
                    ));
                },
                200_000,
            ),
        ),
    ] {
        println!(
            "{name} {:.3} {:.3} {:.3}",
            timings[0], timings[1], timings[2]
        );
    }
    println!("metrics_payload_bytes {}", metrics.render(42).len());
    println!(
        "illustrative_sse_bytes {}",
        format!(
            "event: counters\ndata: {{\"requests\":{},\"rejected\":{}}}\n\n",
            metrics.requests.load(Ordering::Relaxed),
            metrics.blocked.load(Ordering::Relaxed)
        )
        .len()
    );
}

async fn case(
    enabled: bool,
    attack: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        while let Ok((socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(socket),
                        service_fn(|_: Request<Incoming>| async {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }),
                    )
                    .await;
            });
        }
    });
    let config = kunato::config::parse(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{origin}\nadmin: {{listen: 127.0.0.1:0}}\nprotection: {{enabled: false}}\ncategories:\n  - name: benchmark\n    action: BLOCK\n    rules:\n      - name: denied\n        match: {{path: '^/blocked'}}\n"
    ))?;
    let admin_spec = config.admin.clone();
    let config = Arc::new(Snapshot::new(config));
    let metrics = Arc::new(Metrics::with_observations(enabled));
    let server = Server::bind(config.load().listen, config.clone(), metrics.clone(), None).await?;
    let address = server.local_addr()?;
    let admin = AdminServer::bind(
        &admin_spec,
        config,
        metrics.clone(),
        server.protection(),
        server.maintenance(),
        server.admin_access(),
    )
    .await?;
    let source = HttpSource::new(admin.local_addr()?)?;
    let (stop, changed) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(server.run(changed.clone()));
    let admin_task = tokio::spawn(admin.run(changed));
    let export_ok = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let export_error = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ok = export_ok.clone();
    let error = export_error.clone();
    let polling = tokio::spawn(async move {
        let mut successes = 0;
        let mut busy = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if source.fetch().await.is_ok() {
                successes += 1;
                ok.fetch_add(1, Ordering::Relaxed);
            } else {
                busy += 1;
                error.fetch_add(1, Ordering::Relaxed);
            }
            tokio::task::yield_now().await;
            if successes + busy >= 4 {
                return (successes, busy);
            }
        }
    });
    let began = Instant::now();
    let deadline = began + Duration::from_secs(2);
    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(tokio::spawn(async move {
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let mut timings = Vec::new();
            let mut requests = 0_u64;
            while Instant::now() < deadline {
                let request = Request::builder()
                    .uri(format!(
                        "http://{address}/{}",
                        if attack { "blocked" } else { "ok" }
                    ))
                    .body(Full::new(Bytes::new()))
                    .expect("fixed benchmark URI");
                let start = Instant::now();
                let response = client
                    .request(request)
                    .await
                    .expect("local benchmark connection");
                assert_eq!(response.status().as_u16(), if attack { 403 } else { 200 });
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("local benchmark response");
                requests += 1;
                if timings.len() < 50_000 {
                    timings.push(start.elapsed().as_micros() as u64);
                }
            }
            (requests, timings)
        }));
    }
    let mut count = 0;
    let mut timings = Vec::new();
    for client in clients {
        let (requests, samples) = client.await?;
        count += requests;
        timings.extend(samples);
    }
    let elapsed = began.elapsed().as_secs_f64();
    timings.sort_unstable();
    polling.abort();
    let _ = stop.send(true);
    let _ = server_task.await;
    let _ = admin_task.await;
    upstream_task.abort();
    assert_eq!(metrics.requests.load(Ordering::Relaxed), count);
    let final_snapshot = if enabled {
        let snapshot = metrics.observations.snapshot(0)?;
        assert_eq!(snapshot.counters.requests, Some(count));
        assert_eq!(
            snapshot.counters.rejected_requests,
            Some(if attack { count } else { 0 })
        );
        Some(snapshot)
    } else {
        None
    };
    let quantile = |fraction: f64| timings[((timings.len() - 1) as f64 * fraction) as usize];
    Ok(
        serde_json::json!({"enabled":enabled,"attack":attack,"requests":count,"seconds":elapsed,"requests_per_second":count as f64 / elapsed,"p50_us":quantile(0.5),"p95_us":quantile(0.95),"p99_us":quantile(0.99),"clients":8,"poll_interval_seconds":1,"exports_ok":export_ok.load(Ordering::Relaxed),"exports_error":export_error.load(Ordering::Relaxed),"missed_minute_updates":final_snapshot.as_ref().map(|snapshot| snapshot.missed_updates)}),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|arg| arg == "--counters") {
        counters();
        return Ok(());
    }
    let mut cases = Vec::new();
    for repetition in 0..3 {
        for attack in [false, true] {
            for enabled in if repetition % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                cases.push(case(enabled, attack).await?);
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"method":"Three alternating paired trials per workload, two seconds per case, eight local HTTP/1 clients, security traffic hits a BLOCK rule; global protection disabled equally in both modes. Enabled source receives one-second export attempts. No SQLite or browser.","cases":cases})
    );
    Ok(())
}
