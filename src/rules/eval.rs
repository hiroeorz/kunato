use crate::config::{Action, CompiledConfig, Phase, ResponseSpec};
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
    pub logs: Vec<MatchRecord>,
}

pub fn evaluate(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    limits: Option<&dyn RuleLimitCheck>,
) -> EvalOutcome {
    evaluate_phase(config, Phase::Request, view, None, limits)
}

pub fn evaluate_response(
    config: &CompiledConfig,
    view: &RequestView<'_>,
    response: &ResponseView<'_>,
) -> EvalOutcome {
    evaluate_phase(config, Phase::Response, view, Some(response), None)
}

fn evaluate_phase(
    config: &CompiledConfig,
    phase: Phase,
    view: &RequestView<'_>,
    response: Option<&ResponseView<'_>>,
    limits: Option<&dyn RuleLimitCheck>,
) -> EvalOutcome {
    let mut outcome = EvalOutcome::default();

    for category in config
        .categories
        .iter()
        .filter(|category| category.phase == phase)
    {
        for rule in &category.rules {
            let matched = match response {
                Some(response) => rule.matcher.matches_response(view, response),
                None => rule.matcher.matches(view),
            };
            if !matched {
                continue;
            }

            if let Some(limit) = &rule.limit {
                let within = limits.is_some_and(|check| {
                    check.permit(rule.limit_key, view.source_ip, limit, &config.protection)
                });
                if within {
                    continue;
                }
            }

            let Some(action) = rule.action.or(category.action) else {
                continue;
            };

            match action {
                Action::Allow => return outcome,
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

        let outcome = evaluate_response_for(&yaml, StatusCode::CREATED, b"fine");
        assert!(outcome.blocked.is_some());
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

        let outcome = evaluate_response_for(&yaml, StatusCode::OK, b"secret");
        assert!(outcome.blocked.is_some());
    }
}
