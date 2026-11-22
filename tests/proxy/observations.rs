use super::*;
use kunato::console::measurements::{AdditionalMeasurements, DimensionKind};
use kunato::console::model::RejectionReason;

fn additional(packet: &kunato::observations::StatisticsSnapshot) -> AdditionalMeasurements {
    let mut values = AdditionalMeasurements::measured();
    for bucket in &packet.buckets {
        values.merge(bucket.additional.as_ref().unwrap()).unwrap();
    }
    values
}

const RULES: &str = "categories:
  - name: observations
    action: LOG
    rules:
      - name: first
        match: { path: '^/' }
      - name: second
        match: { path: '^/' }
  - name: denial
    action: BLOCK
    rules:
      - name: denied
        match: { path: '^/blocked' }
  - name: trusted-normal
    action: ALLOW
    rules:
      - name: allow-normal
        match: { path: '^/normal$' }
";

#[tokio::test]
async fn http1_and_http2_account_actual_denials_without_log_emission() {
    let upstream = spawn_upstream(StatusCode::FORBIDDEN, "application denied").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\n{RULES}"
    ))
    .await;
    assert_eq!(
        send(running.addr, Method::GET, "/blocked", "").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_h2c_with_authority(running.addr, "localhost", "/normal")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let snapshot = running.metrics.observations.snapshot(0).unwrap();
    assert_eq!(snapshot.counters.requests, Some(2));
    assert_eq!(snapshot.counters.rejected_requests, Some(1));
    assert_eq!(snapshot.counters.log_requests, Some(2));
    assert_eq!(snapshot.counters.rule_matches, Some(6));
    let values = additional(&snapshot);
    assert_eq!(values.upstream_statuses.get(&403), Some(&1));
    assert_eq!(values.reason_latency[&RejectionReason::Rule].count, 1);
    assert_eq!(
        values
            .dimensions
            .iter()
            .filter(|value| value.kind == DimensionKind::Rule)
            .map(|value| value.counts.log_matches)
            .sum::<u64>(),
        4
    );
    assert_eq!(
        values
            .dimensions
            .iter()
            .filter(|value| value.kind == DimensionKind::Rule)
            .map(|value| value.counts.allow_matches)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        values
            .dimensions
            .iter()
            .filter(|value| value.kind == DimensionKind::Rule)
            .map(|value| value.counts.block_matches)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        snapshot.counters.rejection_reasons.as_ref().unwrap()[&RejectionReason::Rule],
        1
    );
    assert_eq!(
        snapshot.counters.rejection_classes.as_ref().unwrap()["other"],
        1
    );
    assert_eq!(
        snapshot
            .buckets
            .iter()
            .map(|bucket| bucket.outcomes.as_ref().unwrap().statuses[303])
            .sum::<u64>(),
        2
    );
    running.stop().await;
}

#[tokio::test]
async fn country_counts_follow_the_resolved_source() {
    let upstream = spawn_upstream(StatusCode::OK, "ok").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nclient_ip: {{ trusted_proxies: [127.0.0.1] }}\n"
    ))
    .await;
    for (source, path) in [("133.11.0.1", "/jp"), ("8.8.8.8", "/us")] {
        let (status, _) = send_h1_with_host(
            running.addr,
            Method::GET,
            path,
            "app.test",
            &[("x-forwarded-for", source)],
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let snapshot = running.metrics.observations.snapshot(0).unwrap();
    let values = additional(&snapshot);
    assert_eq!(values.countries["JP"].requests, 1);
    assert_eq!(values.countries["JP"].rejected, 0);
    assert_eq!(values.countries["US"].requests, 1);
    assert_eq!(values.countries["US"].rejected, 0);
    running.stop().await;
}

#[tokio::test]
async fn http3_uses_the_same_once_per_request_measurements() {
    let upstream = spawn_upstream(StatusCode::OK, "ok").await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(upstream, &cert, &key, RULES).await;
    assert_eq!(
        send_h3(
            running.addr,
            certificate.clone(),
            Method::GET,
            "/blocked",
            ""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_h3(running.addr, certificate, Method::GET, "/normal", "")
            .await
            .0,
        StatusCode::OK
    );
    let snapshot = running.metrics.observations.snapshot(0).unwrap();
    assert_eq!(snapshot.counters.requests, Some(2));
    assert_eq!(snapshot.counters.rejected_requests, Some(1));
    assert_eq!(snapshot.counters.log_requests, Some(2));
    assert_eq!(snapshot.counters.rule_matches, Some(6));
    let values = additional(&snapshot);
    assert_eq!(values.upstream_statuses.get(&200), Some(&1));
    assert_eq!(values.reason_latency[&RejectionReason::Rule].count, 1);
    assert!(values.state.unwrap().certificate_expires_at_ms.is_some());
    running.stop().await;
}

#[tokio::test]
async fn early_host_rejection_and_response_rule_replacement_have_distinct_reasons() {
    let upstream = spawn_upstream(StatusCode::OK, "ok").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nallowed_hosts: [localhost]\ncategories:
  - name: response
    phase: response
    action: BLOCK
    rules:
      - name: stop-response
        match: {{ status: 200 }}
"
    );
    let running = start_kunato(&yaml).await;
    assert_eq!(
        send(running.addr, Method::GET, "/", "").await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(
        send_h2c_with_authority(running.addr, "localhost", "/")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let packet = running.metrics.observations.snapshot(0).unwrap();
    assert_eq!(packet.counters.requests, Some(2));
    assert_eq!(packet.counters.rejected_requests, Some(2));
    assert_eq!(packet.counters.response_blocks, Some(1));
    let values = additional(&packet);
    assert_eq!(values.upstream_statuses.get(&200), Some(&1));
    assert!(!values.upstream_statuses.contains_key(&403));
    assert_eq!(values.reason_latency[&RejectionReason::Host].count, 1);
    assert_eq!(
        values.reason_latency[&RejectionReason::ResponseRule].count,
        1
    );
    assert!(values.dimensions.iter().any(|value| value.phase
        == kunato::console::model::Phase::Response
        && value.counts.block_matches == 1));
    let reasons = packet.counters.rejection_reasons.unwrap();
    assert_eq!(reasons[&RejectionReason::Host], 1);
    assert_eq!(reasons[&RejectionReason::ResponseRule], 1);
    running.stop().await;
}

#[tokio::test]
async fn loopback_export_collects_live_then_persists_and_reopens_real_waf_counts() {
    use kunato::console::collector::{Collector, CollectorConfig, HttpSource, run};
    use kunato::console::{ReadWindow, StorageConfig, Store, WriterConfig};
    let upstream = spawn_upstream(StatusCode::OK, "ok").await;
    let running = start_kunato_with_admin(&format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\nadmin: {{ listen: 127.0.0.1:0 }}\n{RULES}")).await;
    send(running.addr, Method::GET, "/blocked", "").await;
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let mut collector = Collector::start(
        storage.clone(),
        WriterConfig::default(),
        CollectorConfig::default(),
    )
    .await
    .unwrap();
    let mut live = collector.subscribe();
    let source = HttpSource::new(running.admin_addr).unwrap();
    let (stop, changed) = watch::channel(false);
    let task = tokio::spawn(async move {
        run(source, &mut collector, changed).await;
        collector
    });
    tokio::time::timeout(Duration::from_secs(2), live.changed())
        .await
        .unwrap()
        .unwrap();
    let packet = live.borrow_and_update().clone().unwrap();
    assert_eq!(packet.counters.requests, Some(1));
    assert_eq!(packet.counters.rejected_requests, Some(1));
    send(running.addr, Method::GET, "/normal", "").await;
    loop {
        tokio::time::timeout(Duration::from_secs(2), live.changed())
            .await
            .unwrap()
            .unwrap();
        if live.borrow_and_update().as_ref().unwrap().counters.requests == Some(2) {
            break;
        }
    }
    stop.send(true).unwrap();
    let collector = task.await.unwrap();
    assert!(collector.health().last_committed_at_ms.is_none());
    assert!(
        !collector
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap()
            .timed_out
    );
    let mut store = Store::open(storage).unwrap();
    let source = kunato::console::model::SourceIdentity {
        instance: "local-waf".into(),
        generation: packet.source.generation.clone(),
    };
    let rows = store
        .metrics(
            &source,
            ReadWindow {
                from_ms: packet.buckets[0].start_ms,
                until_ms: packet.observed_at_ms + 60_000,
                limit: 256,
            },
        )
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.counters.requests.unwrap())
            .sum::<u64>(),
        2
    );
    let history = store
        .history(&kunato::console::HistoryQuery {
            instance: "local-waf".into(),
            site: None,
            from_ms: packet.buckets[0].start_ms,
            until_ms: packet.observed_at_ms + 60_000,
            limit: 128,
            revision: None,
        })
        .unwrap();
    assert_eq!(history.pending_minutes, 0);
    assert_eq!(
        history
            .buckets
            .iter()
            .map(|bucket| bucket.reasons[&RejectionReason::Rule].sum)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        history
            .buckets
            .iter()
            .map(|bucket| bucket.counters[&kunato::console::history::CountMetric::Requests].sum)
            .sum::<u64>(),
        2
    );
    running.stop().await;
}
