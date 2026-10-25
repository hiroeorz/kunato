use crate::config::{Action, CompiledConfig, CompiledRule, Phase, ResponseSpec};
use crate::protection::RuleLimitCheck;
use crate::request_view::{RequestView, ResponseView};

#[derive(Debug)]
pub struct MatchRecord {
    pub category: String,
    pub rule: String,
    pub action: Action,
    pub phase: Phase,
}

#[derive(Debug)]
pub struct Blocked {
    pub category: String,
    pub rule: String,
    pub response: ResponseSpec,
    pub phase: Phase,
    pub rate_limited: bool,
}

#[derive(Debug, Default)]
pub struct EvalOutcome {
    pub blocked: Option<Blocked>,
    /// The ALLOW rule that stopped evaluation, if any. Callers need this to
    /// distinguish "no rule matched" from "a rule explicitly trusted the
    /// request" when a body could not be inspected completely.
    pub allowed: Option<MatchRecord>,
    pub logs: Vec<MatchRecord>,
}

/// How a phase is evaluated. The WebSocket variants only apply the payload
/// target of their phase to the inspected message.
#[derive(Clone, Copy)]
enum Mode {
    Request,
    WebsocketRequest,
    Response,
    WebsocketResponse,
}

fn matches(
    mode: Mode,
    rule: &CompiledRule,
    view: &RequestView<'_>,
    response: Option<&ResponseView<'_>>,
) -> bool {
    match mode {
        Mode::Request => rule.matcher.matches(view),
        Mode::WebsocketRequest => rule.matcher.matches_websocket(view),
        Mode::Response => match response {
            Some(response) => rule.matcher.matches_response(view, response),
            None => rule.matcher.matches(view),
        },
        Mode::WebsocketResponse => {
            response.is_some_and(|response| rule.matcher.matches_websocket_response(view, response))
        }
    }
}

pub fn evaluate(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    limits: Option<&dyn RuleLimitCheck>,
) -> EvalOutcome {
    evaluate_phase(config, Phase::Request, view, None, limits, Mode::Request)
}

/// Evaluate a post-upgrade WebSocket message. Request conditions still scope
/// the rules, but only the body target is matched against the message payload.
pub fn evaluate_websocket(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    limits: Option<&dyn RuleLimitCheck>,
) -> EvalOutcome {
    evaluate_phase(
        config,
        Phase::Request,
        view,
        None,
        limits,
        Mode::WebsocketRequest,
    )
}

pub fn evaluate_response(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    response: &ResponseView<'_>,
) -> EvalOutcome {
    evaluate_phase(
        config,
        Phase::Response,
        view,
        Some(response),
        None,
        Mode::Response,
    )
}

/// Evaluate a server-to-client WebSocket message. Response conditions scope the
/// handshake response and the tunnel's request, and only rules that match
/// `response_body` are applied to the message payload.
pub fn evaluate_websocket_response(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    response: &ResponseView<'_>,
) -> EvalOutcome {
    evaluate_phase(
        config,
        Phase::Response,
        view,
        Some(response),
        None,
        Mode::WebsocketResponse,
    )
}

fn evaluate_phase(
    config: &CompiledConfig,
    phase: Phase,
    view: &RequestView<'_>,
    response: Option<&ResponseView<'_>>,
    limits: Option<&dyn RuleLimitCheck>,
    mode: Mode,
) -> EvalOutcome {
    let mut outcome = EvalOutcome::default();

    for category in config
        .categories
        .iter()
        .filter(|category| category.phase == phase)
    {
        if let Some(threshold) = category.threshold {
            let mut score = 0u32;
            let mut last: Option<&CompiledRule> = None;
            for rule in &category.rules {
                let matched = matches(mode, rule, view, response);
                if matched {
                    score += 1;
                    last = Some(rule);
                }
            }

            let Some(last) = last.filter(|_| score >= threshold) else {
                continue;
            };

            match category.action {
                Some(Action::Block) => {
                    outcome.blocked = Some(Blocked {
                        category: category.name.clone(),
                        rule: last.name.clone(),
                        response: category.response.clone().unwrap_or_default(),
                        phase,
                        rate_limited: false,
                    });
                    return outcome;
                }
                Some(Action::Log) => outcome.logs.push(MatchRecord {
                    category: category.name.clone(),
                    rule: last.name.clone(),
                    action: Action::Log,
                    phase,
                }),
                _ => {}
            }
            continue;
        }

        for rule in &category.rules {
            let matched = matches(mode, rule, view, response);
            if !matched {
                continue;
            }

            if let Some(limit) = &rule.limit {
                let within = limits.is_some_and(|check| {
                    check.permit(&rule.limit_key, view.source_ip, limit, &config.protection)
                });
                if within {
                    continue;
                }
            }

            let Some(action) = rule.action.or(category.action) else {
                continue;
            };

            match action {
                Action::Allow => {
                    outcome.allowed = Some(MatchRecord {
                        category: category.name.clone(),
                        rule: rule.name.clone(),
                        action,
                        phase,
                    });
                    return outcome;
                }
                Action::Block => {
                    let response = rule
                        .response
                        .clone()
                        .or_else(|| category.response.clone())
                        .unwrap_or_default();
                    outcome.blocked = Some(Blocked {
                        category: category.name.clone(),
                        rule: rule.name.clone(),
                        response,
                        phase,
                        rate_limited: rule.limit.is_some(),
                    });
                    return outcome;
                }
                Action::Log => outcome.logs.push(MatchRecord {
                    category: category.name.clone(),
                    rule: rule.name.clone(),
                    action,
                    phase,
                }),
            }
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method, StatusCode, Uri};

    use super::*;
    use crate::config;
    use crate::request_view::{RequestView, ResponseView};

    fn evaluate_request(yaml: &str, path_and_query: &str) -> EvalOutcome {
        let config = config::parse(yaml).expect("valid test config");
        let method = Method::GET;
        let uri: Uri = path_and_query.parse().expect("valid URI");
        let headers = HeaderMap::new();
        let view = RequestView::new(
            &method,
            &uri,
            &headers,
            b"",
            "127.0.0.1".parse().expect("valid IP"),
        );
        evaluate(&config, &view, None)
    }

    const BASE: &str = "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n";

    #[test]
    fn no_match_is_pass_through() {
        let yaml = format!("{BASE}categories: []\n");
        let outcome = evaluate_request(&yaml, "/hello");
        assert!(outcome.blocked.is_none());
        assert!(outcome.logs.is_empty());
    }

    #[test]
    fn allow_query_marker_cannot_shadow_blocks_when_appended() {
        let yaml = format!(
            "{BASE}categories:
  - name: trusted-marker
    action: ALLOW
    rules:
      - name: marker
        match: {{ regex: '^q=tokenfree$', in: [query] }}
  - name: protected
    action: BLOCK
    rules:
      - name: no-secret
        match: {{ path: ^/secret }}
"
        );

        // The marker request itself is still trusted.
        assert!(
            evaluate_request(&yaml, "/secret?q=tokenfree")
                .blocked
                .is_none()
        );

        // Appending the marker to any other request keeps the BLOCK active.
        for appended in ["/secret?q=tokenfree&z=1", "/secret?a=zz&q=tokenfree"] {
            let outcome = evaluate_request(&yaml, appended);
            assert!(outcome.blocked.is_some(), "{appended} must be blocked");
        }
    }

    #[test]
    fn category_action_applies_to_rules() {
        let yaml = format!(
            "{BASE}categories:
  - name: sqli
    action: BLOCK
    rules:
      - name: union
        match: {{ path: / }} 
"
        );
        let outcome = evaluate_request(&yaml, "/?q=x");
        assert!(outcome.blocked.is_some());
    }

    #[test]
    fn rule_action_overrides_category() {
        let yaml = format!(
            "{BASE}categories:
  - name: scanners
    action: LOG
    rules:
      - name: sensitive
        action: BLOCK
        match: {{ path: /admin }}
"
        );
        let outcome = evaluate_request(&yaml, "/admin");
        assert!(outcome.blocked.is_some());
        assert!(outcome.logs.is_empty());
    }

    #[test]
    fn allow_short_circuits_later_categories() {
        let yaml = format!(
            "{BASE}categories:
  - name: trusted
    action: ALLOW
    rules:
      - name: local
        match: {{ source_ip: 127.0.0.1 }}
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
        );
        let outcome = evaluate_request(&yaml, "/anything");
        assert!(outcome.blocked.is_none());
        assert!(outcome.allowed.is_some());
    }

    #[test]
    fn log_continues_to_later_block() {
        let yaml = format!(
            "{BASE}categories:
  - name: logging
    action: LOG
    rules:
      - name: every-request
        match: {{ path: ^/ }}
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
        );
        let outcome = evaluate_request(&yaml, "/anything");
        assert_eq!(outcome.logs.len(), 1);
        assert!(outcome.blocked.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limit_is_transparent_until_exceeded() {
        use crate::protection::ProtectionState;

        let yaml = format!(
            "{BASE}categories:
  - name: brute-force
    action: BLOCK
    rules:
      - name: many-logins
        limit: {{ requests: 1, window: 60s }}
        match: {{ path: ^/login }}
"
        );
        let config = config::parse(&yaml).expect("valid test config");
        let state = ProtectionState::new();
        let method = Method::POST;
        let uri: Uri = "/login".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let view = RequestView::new(
            &method,
            &uri,
            &headers,
            b"",
            "127.0.0.1".parse().expect("valid IP"),
        );

        let outcome = evaluate(&config, &view, Some(&state));
        assert!(outcome.blocked.is_none());

        let outcome = evaluate(&config, &view, Some(&state));
        let blocked = outcome.blocked.expect("blocked");
        assert!(blocked.rate_limited);
    }

    #[test]
    fn threshold_category_blocks_only_after_enough_matches() {
        let yaml = format!(
            "{BASE}categories:
  - name: anomaly
    action: BLOCK
    threshold: 2
    rules:
      - name: weak-one
        match: {{ path: ^/x$ }}
      - name: weak-two
        match: {{ regex: beta }}
"
        );
        let outcome = evaluate_request(&yaml, "/x");
        assert!(outcome.blocked.is_none());

        let outcome = evaluate_request(&yaml, "/x?q=beta");
        let blocked = outcome.blocked.expect("blocked");
        assert_eq!(blocked.category, "anomaly");
        assert_eq!(blocked.rule, "weak-two");
        assert!(!blocked.rate_limited);
    }

    #[test]
    fn threshold_log_category_records_once_when_reached() {
        let yaml = format!(
            "{BASE}categories:
  - name: noisy-anomaly
    action: LOG
    threshold: 2
    rules:
      - name: weak-one
        match: {{ path: ^/x$ }}
      - name: weak-two
        match: {{ regex: beta }}
"
        );
        let outcome = evaluate_request(&yaml, "/x");
        assert!(outcome.logs.is_empty());

        let outcome = evaluate_request(&yaml, "/x?q=beta");
        assert_eq!(outcome.logs.len(), 1);
        assert_eq!(outcome.logs[0].rule, "weak-two");
        assert!(outcome.blocked.is_none());
    }

    #[test]
    fn default_block_response_is_403() {
        let yaml = format!(
            "{BASE}categories:
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
        );
        let outcome = evaluate_request(&yaml, "/");
        let blocked = outcome.blocked.expect("blocked");
        assert_eq!(blocked.response.status, 403);
    }

    fn evaluate_response_for(yaml: &str, status: StatusCode, body: &[u8]) -> EvalOutcome {
        let config = config::parse(yaml).expect("valid test config");
        let method = Method::GET;
        let uri: Uri = "/test".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let view = RequestView::new(
            &method,
            &uri,
            &headers,
            b"",
            "127.0.0.1".parse().expect("valid IP"),
        );
        let response = ResponseView::new(status, &headers, body, false);
        evaluate_response(&config, &view, &response)
    }

    fn evaluate_websocket_response_for(
        yaml: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> EvalOutcome {
        let config = config::parse(yaml).expect("valid test config");
        let method = Method::GET;
        let uri: Uri = "/ws".parse().expect("valid URI");
        let view = RequestView::new(
            &method,
            &uri,
            headers,
            b"",
            "127.0.0.1".parse().expect("valid IP"),
        );
        let response = ResponseView::new(StatusCode::SWITCHING_PROTOCOLS, headers, body, false);
        evaluate_websocket_response(&config, &view, &response)
    }

    #[test]
    fn request_phase_skips_response_categories() {
        let yaml = format!(
            "{BASE}categories:
  - name: response-leak
    phase: response
    action: BLOCK
    rules:
      - name: leak
        match: {{ regex: secret }}
"
        );
        let outcome = evaluate_request(&yaml, "/");
        assert!(outcome.blocked.is_none());
        assert!(outcome.logs.is_empty());
    }

    #[test]
    fn response_phase_blocks_and_ignores_request_categories() {
        let yaml = format!(
            "{BASE}categories:
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
  - name: response-leak
    phase: response
    action: BLOCK
    rules:
      - name: leak
        match: {{ regex: secret }}
"
        );
        let outcome = evaluate_response_for(&yaml, StatusCode::OK, b"the secret is out");
        let blocked = outcome.blocked.expect("blocked");
        assert_eq!(blocked.phase, config::Phase::Response);
        assert_eq!(blocked.rule, "leak");

        let outcome = evaluate_response_for(&yaml, StatusCode::OK, b"nothing to see");
        assert!(outcome.blocked.is_none());
    }

    #[test]
    fn response_log_continues_to_later_block() {
        let yaml = format!(
            "{BASE}categories:
  - name: noisy
    phase: response
    action: LOG
    rules:
      - name: every-response
        match: {{ status: 5xx }}
  - name: errors
    phase: response
    action: BLOCK
    rules:
      - name: server-error
        match: {{ status: 5xx }}
"
        );
        let outcome = evaluate_response_for(&yaml, StatusCode::SERVICE_UNAVAILABLE, b"oops");
        assert_eq!(outcome.logs.len(), 1);
        assert_eq!(outcome.logs[0].phase, config::Phase::Response);
        assert!(outcome.blocked.is_some());
    }

    #[test]
    fn response_allow_short_circuits_later_response_categories() {
        let yaml = format!(
            "{BASE}categories:
  - name: trusted-responses
    phase: response
    action: ALLOW
    rules:
      - name: ok
        match: {{ status: 200 }}
  - name: catch-all
    phase: response
    action: BLOCK
    rules:
      - name: everything
        match: {{ status: 2xx }}
"
        );
        let outcome = evaluate_response_for(&yaml, StatusCode::OK, b"fine");
        assert!(outcome.blocked.is_none());
        assert!(outcome.allowed.is_some());

        let outcome = evaluate_response_for(&yaml, StatusCode::CREATED, b"fine");
        assert!(outcome.blocked.is_some());
        assert!(outcome.allowed.is_none());
    }

    #[test]
    fn request_allow_does_not_stop_response_rules() {
        let yaml = format!(
            "{BASE}categories:
  - name: trusted
    action: ALLOW
    rules:
      - name: local
        match: {{ source_ip: 127.0.0.1 }}
  - name: response-leak
    phase: response
    action: BLOCK
    rules:
      - name: leak
        match: {{ regex: secret }}
"
        );
        let outcome = evaluate_request(&yaml, "/");
        assert!(outcome.blocked.is_none());
        assert!(outcome.allowed.is_some());

        let outcome = evaluate_response_for(&yaml, StatusCode::OK, b"secret");
        assert!(outcome.blocked.is_some());
        assert!(outcome.allowed.is_none());
    }

    #[test]
    fn websocket_response_blocks_a_matching_server_message() {
        let yaml = format!(
            "{BASE}categories:
  - name: response-leaks
    phase: response
    action: LOG
    rules:
      - name: private-key
        action: BLOCK
        match: {{ regex: 'BEGIN [A-Z ]*PRIVATE KEY', in: [response_body] }}
"
        );
        let headers = HeaderMap::new();
        let outcome =
            evaluate_websocket_response_for(&yaml, &headers, b"-----BEGIN RSA PRIVATE KEY-----");
        let blocked = outcome.blocked.expect("blocked");
        assert_eq!(blocked.phase, config::Phase::Response);
        assert_eq!(blocked.rule, "private-key");

        let outcome = evaluate_websocket_response_for(&yaml, &headers, b"hello from the origin");
        assert!(outcome.blocked.is_none());
    }

    #[test]
    fn websocket_response_skips_rules_without_a_body_condition() {
        let yaml = format!(
            "{BASE}categories:
  - name: hardening
    phase: response
    action: BLOCK
    rules:
      - name: frame-options-deny
        match: {{ response_headers: {{ X-Frame-Options: '^DENY$' }} }}
"
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", "DENY".parse().expect("header value"));

        let config = config::parse(&yaml).expect("valid config");
        let method = Method::GET;
        let uri: Uri = "/ws".parse().expect("valid URI");
        let view = RequestView::new(
            &method,
            &uri,
            &headers,
            b"",
            "127.0.0.1".parse().expect("valid IP"),
        );

        let response = ResponseView::new(StatusCode::OK, &headers, b"", false);
        assert!(
            evaluate_response(&config, &view, &response)
                .blocked
                .is_some()
        );

        let response = ResponseView::new(StatusCode::SWITCHING_PROTOCOLS, &headers, b"", false);
        assert!(
            evaluate_websocket_response(&config, &view, &response)
                .blocked
                .is_none()
        );
    }

    #[test]
    fn websocket_response_status_scopes_to_the_handshake() {
        let yaml = format!(
            "{BASE}categories:
  - name: ok-only
    phase: response
    action: BLOCK
    rules:
      - name: ok-body
        match: {{ status: 200, regex: secret }}
  - name: upgrade-only
    phase: response
    action: BLOCK
    rules:
      - name: upgrade-body
        match: {{ status: 101, regex: secret }}
"
        );
        let headers = HeaderMap::new();
        let outcome = evaluate_websocket_response_for(&yaml, &headers, b"secret");
        let blocked = outcome.blocked.expect("the 101 rule matches");
        assert_eq!(blocked.rule, "upgrade-body");
    }
}
