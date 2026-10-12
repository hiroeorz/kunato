use crate::config::{Action, CompiledConfig, ResponseSpec};
use crate::request_view::RequestView;

#[derive(Debug)]
pub struct MatchRecord {
    pub category: String,
    pub rule: String,
    pub action: Action,
}

#[derive(Debug)]
pub struct Blocked {
    pub category: String,
    pub rule: String,
    pub response: ResponseSpec,
}

#[derive(Debug, Default)]
pub struct EvalOutcome {
    pub blocked: Option<Blocked>,
    pub logs: Vec<MatchRecord>,
}

pub fn evaluate(config: &CompiledConfig, view: &RequestView<'_>) -> EvalOutcome {
    let mut outcome = EvalOutcome::default();

    for category in &config.categories {
        for rule in &category.rules {
            if !rule.matcher.matches(view) {
                continue;
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
                    });
                    return outcome;
                }
                Action::Log => outcome.logs.push(MatchRecord {
                    category: category.name.clone(),
                    rule: rule.name.clone(),
                    action,
                }),
            }
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method, Uri};

    use super::*;
    use crate::config;
    use crate::request_view::RequestView;

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
        evaluate(&config, &view)
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
}
