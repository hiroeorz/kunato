use std::fmt::Write as _;

/// A user-facing attack class and the rule categories that belong to it.
///
/// Classification is category-based: the rule format has no per-rule attack
/// metadata, so one event has exactly the class of its category. CVE categories
/// are handled separately by [`AttackFilter::CvePrefix`] so `cve`,
/// `cve-2025`, and `cve-2026-04` can be selected without enumerating them.
#[derive(Debug)]
pub(crate) struct AttackClass {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub categories: &'static [&'static str],
}

const ATTACK_CLASSES: &[AttackClass] = &[
    AttackClass {
        name: "sql-injection",
        aliases: &["sqli"],
        categories: &["sql-injection"],
    },
    AttackClass {
        name: "nosql-injection",
        aliases: &["nosql"],
        categories: &["nosql-injection"],
    },
    AttackClass {
        name: "ldap-injection",
        aliases: &["ldap"],
        categories: &["ldap-injection"],
    },
    AttackClass {
        name: "xpath-injection",
        aliases: &["xpath"],
        categories: &["xpath-injection"],
    },
    AttackClass {
        name: "jdbc-injection",
        aliases: &["jdbc"],
        categories: &["jdbc-injection"],
    },
    AttackClass {
        name: "xss",
        aliases: &[],
        categories: &["xss"],
    },
    AttackClass {
        name: "css-injection",
        aliases: &["css"],
        categories: &["css-injection"],
    },
    AttackClass {
        name: "ssti",
        aliases: &[],
        categories: &["ssti"],
    },
    AttackClass {
        name: "command-injection",
        aliases: &["command", "rce"],
        categories: &["command-injection"],
    },
    AttackClass {
        name: "path-traversal",
        aliases: &["lfi", "traversal"],
        categories: &["path-traversal", "path-normalization"],
    },
    AttackClass {
        name: "remote-file-inclusion",
        aliases: &["rfi"],
        categories: &["remote-file-inclusion"],
    },
    AttackClass {
        name: "ssrf",
        aliases: &[],
        categories: &["ssrf"],
    },
    AttackClass {
        name: "xxe",
        aliases: &[],
        categories: &["xxe"],
    },
    AttackClass {
        name: "deserialization",
        aliases: &[],
        categories: &[
            "ruby-deserialization",
            "python-deserialization",
            "php-deserialization",
            "java-deserialization",
        ],
    },
    AttackClass {
        name: "prototype-pollution",
        aliases: &["prototype"],
        categories: &["prototype-pollution"],
    },
    AttackClass {
        name: "open-redirect",
        aliases: &["redirect"],
        categories: &["open-redirect"],
    },
    AttackClass {
        name: "parameter-pollution",
        aliases: &["hpp"],
        categories: &["parameter-pollution"],
    },
    AttackClass {
        name: "mass-assignment",
        aliases: &["mass"],
        categories: &["mass-assignment"],
    },
    AttackClass {
        name: "prompt-injection",
        aliases: &["prompt"],
        categories: &["prompt-injection"],
    },
    AttackClass {
        name: "cache-deception",
        aliases: &["cache"],
        categories: &["cache-deception"],
    },
    AttackClass {
        name: "config-injection",
        aliases: &["config"],
        categories: &["config-injection"],
    },
    AttackClass {
        name: "jwt",
        aliases: &[],
        categories: &["jwt"],
    },
    AttackClass {
        name: "malicious-upload",
        aliases: &["upload"],
        categories: &["malicious-upload"],
    },
    AttackClass {
        name: "protocol",
        aliases: &[],
        categories: &[
            "protocol-anomalies",
            "bad-methods",
            "nginx-capture-overflow",
            "webdav-and-digest",
        ],
    },
    AttackClass {
        name: "scanner",
        aliases: &["scanners"],
        categories: &["scanners-and-bots"],
    },
    AttackClass {
        name: "brute-force",
        aliases: &["bruteforce", "login-throttle"],
        categories: &["login-throttle"],
    },
    AttackClass {
        name: "discovery",
        aliases: &[],
        categories: &["api-discovery", "admin-interfaces"],
    },
    AttackClass {
        name: "exposure",
        aliases: &[],
        categories: &[
            "rails-debug-endpoints",
            "django-debug-endpoints",
            "nextjs-dev-endpoints",
            "laravel-debug-endpoints",
            "vite-dev-endpoints",
            "spring-actuator",
            "ai-service-management",
            "ci-cd-servers",
        ],
    },
    AttackClass {
        name: "info-disclosure",
        aliases: &["infodisclosure", "leaks"],
        categories: &[
            "sensitive-files",
            "response-leaks",
            "directory-index",
            "default-pages",
        ],
    },
    AttackClass {
        name: "bypass",
        aliases: &[],
        categories: &["framework-routing-bypass"],
    },
    AttackClass {
        name: "exploit",
        aliases: &[],
        categories: &["known-exploits"],
    },
];

fn is_cve(category: &str) -> bool {
    category
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cve-"))
}

pub(crate) fn classify(category: &str) -> Option<&'static AttackClass> {
    if is_cve(category) {
        return None;
    }
    ATTACK_CLASSES.iter().find(|class| {
        class
            .categories
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(category))
    })
}

/// The short name shown in table and JSON output.
pub(crate) fn attack_name(category: &str) -> &'static str {
    if is_cve(category) {
        return "cve";
    }
    classify(category).map_or("other", |class| class.name)
}

#[derive(Debug, Clone)]
pub(crate) enum AttackFilter {
    Class(&'static AttackClass),
    CvePrefix(String),
}

impl AttackFilter {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
        if normalized.is_empty() {
            return Err("attack type must not be empty".to_owned());
        }
        if normalized == "cve" {
            return Ok(Self::CvePrefix("cve-".to_owned()));
        }
        if let Some(rest) = normalized.strip_prefix("cve-") {
            let valid = match rest.split('-').collect::<Vec<_>>().as_slice() {
                [year] => year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()),
                [year, month] => {
                    year.len() == 4
                        && month.len() == 2
                        && year.bytes().all(|byte| byte.is_ascii_digit())
                        && month.bytes().all(|byte| byte.is_ascii_digit())
                }
                _ => false,
            };
            if !valid {
                return Err(format!(
                    "invalid CVE attack type `{value}`; use cve, cve-YYYY, or cve-YYYY-MM"
                ));
            }
            return Ok(Self::CvePrefix(format!("cve-{rest}")));
        }
        ATTACK_CLASSES
            .iter()
            .find(|class| {
                class.name.eq_ignore_ascii_case(&normalized)
                    || class
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(&normalized))
            })
            .map(Self::Class)
            .ok_or_else(|| {
                format!(
                    "unknown attack type `{value}`; run `kunato log --list-attacks` or use --category"
                )
            })
    }

    pub(crate) fn matches_category(&self, category: &str) -> bool {
        match self {
            Self::Class(class) => class
                .categories
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(category)),
            Self::CvePrefix(prefix) => {
                if !category
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                {
                    return false;
                }
                // `cve` is the generic prefix; a year or year-month prefix must
                // end at a category segment boundary.
                prefix == "cve-"
                    || category
                        .as_bytes()
                        .get(prefix.len())
                        .is_none_or(|byte| *byte == b'-')
            }
        }
    }
}

pub(crate) fn list() -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("Attack types (category-based):\n");
    for class in ATTACK_CLASSES {
        let _ = write!(out, "  {}: {}", class.name, class.categories.join(", "));
        if !class.aliases.is_empty() {
            let _ = write!(out, " (aliases: {})", class.aliases.join(", "));
        }
        out.push('\n');
    }
    out.push_str("  cve: cve-* (also cve-YYYY and cve-YYYY-MM)\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, Action};

    #[test]
    fn every_bundled_attack_category_is_classified() {
        let config = config::parse(include_str!("../../rules.example.yaml"))
            .expect("example configuration must parse");
        for category in &config.categories {
            if category.action == Some(Action::Allow) {
                continue;
            }
            assert_ne!(
                attack_name(&category.name),
                "other",
                "category `{}` needs an attack class",
                category.name
            );
        }
    }

    #[test]
    fn aliases_and_cve_ranges_match() {
        assert!(
            AttackFilter::parse("sqli")
                .expect("alias")
                .matches_category("sql-injection")
        );
        assert!(
            AttackFilter::parse("path-traversal")
                .expect("class")
                .matches_category("path-normalization")
        );
        assert!(
            AttackFilter::parse("cve-2025")
                .expect("year")
                .matches_category("cve-2025-signatures")
        );
        assert!(
            AttackFilter::parse("cve-2026")
                .expect("year")
                .matches_category("cve-2026-04-signatures")
        );
        assert!(
            AttackFilter::parse("cve")
                .expect("all")
                .matches_category("cve-2010-signatures")
        );
        assert!(
            !AttackFilter::parse("cve-2025")
                .expect("year")
                .matches_category("cve-20250-signatures")
        );
        assert!(
            !AttackFilter::parse("cve-2025")
                .expect("year")
                .matches_category("sql-injection")
        );
    }

    #[test]
    fn unknown_attack_type_is_rejected() {
        assert!(AttackFilter::parse("not-a-class").is_err());
        assert!(AttackFilter::parse("cve-25").is_err());
        assert!(AttackFilter::parse("cve-2025-1").is_err());
    }
}
