use std::io;
use std::path::PathBuf;

/// Marker inside the compile issue raised when a rule names an `in` target this
/// build does not implement. `config` formats its message with this constant so
/// the check in [`Error::unsupported_construct`] cannot drift from the text.
pub(crate) const UNKNOWN_TARGET_ISSUE: &str = "unknown `in` target";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read configuration file `{path}`: {source}")]
    ConfigRead { path: PathBuf, source: io::Error },

    #[error("failed to parse configuration: {0}")]
    ConfigParse(#[from] serde_saphyr::Error),

    #[error("failed to parse rules file `{path}`: {source}")]
    RulesParse {
        path: PathBuf,
        source: Box<serde_saphyr::Error>,
    },

    #[error("invalid configuration:\n{}", format_issues(.0))]
    ConfigInvalid(Vec<String>),

    #[error("the downloaded rule set needs a newer Kunato build: {0}")]
    RulesNeedNewerBuild(String),

    #[error("{0}")]
    Message(String),

    #[error("failed to bind `{addr}`: {source}")]
    Bind { addr: String, source: io::Error },

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("logging setup failed: {0}")]
    Telemetry(String),

    #[error(transparent)]
    Io(#[from] io::Error),
}

fn format_issues(issues: &[String]) -> String {
    issues
        .iter()
        .map(|issue| format!("  - {issue}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Error {
    /// The construct this build does not implement, when the failure means a
    /// file uses a newer format than the running binary understands: an unknown
    /// field, enum variant, or match target, or a required field that is gone.
    /// Every other cause returns `None`.
    ///
    /// An older binary sees exactly this when the published rule set moves to a
    /// newer format, so callers use it to tell "upgrade Kunato" apart from
    /// transient or local failures.
    pub fn unsupported_construct(&self) -> Option<String> {
        // `from_str` wraps a deserialization error in a `WithSnippet` for
        // rustc-like rendering; the variant that carries the cause is inside.
        fn schema(error: &serde_saphyr::Error) -> bool {
            matches!(
                error.without_snippet(),
                serde_saphyr::Error::SerdeUnknownField { .. }
                    | serde_saphyr::Error::SerdeUnknownVariant { .. }
                    | serde_saphyr::Error::SerdeMissingField { .. }
            )
        }

        match self {
            Self::ConfigParse(error) if schema(error) => Some(error.without_snippet().to_string()),
            Self::RulesParse { source, .. } if schema(source) => {
                Some(source.without_snippet().to_string())
            }
            Self::ConfigInvalid(issues) => issues
                .iter()
                .find(|issue| issue.contains(UNKNOWN_TARGET_ISSUE))
                .cloned(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_rule_fields_need_a_newer_build() {
        let error = crate::config::parse_rules(
            "categories:
  - name: sample
    rules:
      - name: sample
        match: { regex: a, json_body: true }
",
        )
        .expect_err("unknown match field");
        assert!(error.unsupported_construct().is_some(), "{error}");
    }

    #[test]
    fn unknown_match_targets_need_a_newer_build() {
        let error = crate::config::parse_rules(
            "categories:
  - name: sample
    rules:
      - name: sample
        match: { regex: a, in: [json_body] }
",
        )
        .expect_err("unknown match target");
        assert!(error.unsupported_construct().is_some(), "{error}");
    }

    #[test]
    fn unknown_actions_need_a_newer_build() {
        let error = crate::config::parse_rules(
            "categories:\n  - name: sample\n    action: DROP\n    rules: []\n",
        )
        .expect_err("unknown action");
        assert!(error.unsupported_construct().is_some(), "{error}");
    }

    #[test]
    fn ordinary_failures_do_not_suggest_an_upgrade() {
        let cases = [
            "categories:\n  - name: sample\n    rules:\n      - name: sample\n        match: { regex: '(?', in: [query] }\n",
            "categories:\n  - name: sample\n    rules:\n      - name: sample\n        match: {}\n",
            "categories: [\n",
        ];
        for text in cases {
            let error = crate::config::parse_rules(text).expect_err("invalid rule set");
            assert!(error.unsupported_construct().is_none(), "{text}: {error}");
        }
    }
}
