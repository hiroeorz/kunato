use std::env;

use tracing::Level;
use tracing::level_filters::LevelFilter;

const ENV: &str = "RUST_LOG";

#[derive(Debug, Clone)]
pub(crate) struct Filter {
    directives: Vec<Directive>,
}

#[derive(Debug, Clone)]
struct Directive {
    target: Option<String>,
    level: LevelFilter,
}

impl Filter {
    pub(crate) fn from_arg(level: Option<&str>) -> Result<Self, String> {
        match level {
            Some(level) => Self::parse(level),
            None => Ok(Self::from_env_value(env::var(ENV).ok())),
        }
    }

    fn from_env_value(value: Option<String>) -> Self {
        match value {
            Some(value) => Self::parse(&value).unwrap_or_else(|_| Self::info()),
            None => Self::info(),
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let mut directives = Vec::new();
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part
                .chars()
                .any(|character| matches!(character, '{' | '}' | '[' | ']'))
            {
                return Err(format!(
                    "unsupported filter directive `{part}`: span and field filters are not available"
                ));
            }
            if let Some((target, level)) = part.split_once('=') {
                let target = target.trim();
                if target.is_empty() {
                    return Err(format!("invalid filter directive `{part}`: empty target"));
                }
                let level = parse_level(level.trim())?;
                directives.push(Directive {
                    target: Some(target.to_owned()),
                    level,
                });
            } else if let Ok(level) = parse_level(part) {
                directives.push(Directive {
                    target: None,
                    level,
                });
            } else {
                directives.push(Directive {
                    target: Some(part.to_owned()),
                    level: LevelFilter::TRACE,
                });
            }
        }
        if directives.is_empty() {
            directives.push(Directive {
                target: None,
                level: LevelFilter::ERROR,
            });
        }
        Ok(Self { directives })
    }

    pub(crate) fn info() -> Self {
        Self {
            directives: vec![Directive {
                target: None,
                level: LevelFilter::INFO,
            }],
        }
    }

    pub(crate) fn enabled(&self, level: Level, target: &str) -> bool {
        let mut best: Option<(&Directive, usize)> = None;
        for directive in &self.directives {
            let Some(directive_target) = &directive.target else {
                if best.is_none_or(|(_, length)| length == 0) {
                    best = Some((directive, 0));
                }
                continue;
            };
            if !target.starts_with(directive_target) {
                continue;
            }
            if best.is_none_or(|(_, length)| directive_target.len() >= length) {
                best = Some((directive, directive_target.len()));
            }
        }
        let Some((directive, _)) = best else {
            return false;
        };
        directive
            .level
            .into_level()
            .is_some_and(|threshold| level <= threshold)
    }

    pub(crate) fn max_level(&self) -> LevelFilter {
        self.directives
            .iter()
            .map(|directive| directive.level)
            .max()
            .unwrap_or(LevelFilter::OFF)
    }
}

fn parse_level(value: &str) -> Result<LevelFilter, String> {
    match value.to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::OFF),
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        _ => Err(format!("invalid log level `{value}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_filter(value: &str) -> Filter {
        Filter::parse(value).expect("filter")
    }

    #[test]
    fn empty_filter_defaults_to_error() {
        let filter = parse_filter("");
        assert!(filter.enabled(Level::ERROR, "kunato"));
        assert!(!filter.enabled(Level::WARN, "kunato"));
    }

    #[test]
    fn global_level_applies_to_every_target() {
        let filter = parse_filter("info");
        assert!(filter.enabled(Level::INFO, "kunato::proxy"));
        assert!(filter.enabled(Level::ERROR, "hyper"));
        assert!(!filter.enabled(Level::DEBUG, "kunato::proxy"));
    }

    #[test]
    fn target_directives_use_the_longest_prefix() {
        let filter = parse_filter("kunato::proxy=debug,info");
        assert!(filter.enabled(Level::DEBUG, "kunato::proxy::server"));
        assert!(!filter.enabled(Level::TRACE, "kunato::proxy::server"));
        assert!(!filter.enabled(Level::DEBUG, "hyper"));
        assert!(filter.enabled(Level::INFO, "hyper"));

        let filter = parse_filter("kunato=debug,kunato::proxy=trace");
        assert!(filter.enabled(Level::TRACE, "kunato::proxy::server"));
        assert!(filter.enabled(Level::DEBUG, "kunato::rules"));
    }

    #[test]
    fn target_without_a_level_enables_trace() {
        let filter = parse_filter("kunato");
        assert!(filter.enabled(Level::TRACE, "kunato::proxy"));
        assert!(!filter.enabled(Level::ERROR, "hyper"));
    }

    #[test]
    fn off_disables_everything() {
        let filter = parse_filter("off");
        assert!(!filter.enabled(Level::ERROR, "kunato"));
        assert_eq!(filter.max_level(), LevelFilter::OFF);
    }

    #[test]
    fn max_level_tracks_the_most_verbose_directive() {
        assert_eq!(
            parse_filter("kunato::proxy=debug,info").max_level(),
            LevelFilter::DEBUG
        );
        assert_eq!(parse_filter("kunato=debug").max_level(), LevelFilter::DEBUG);
        assert_eq!(parse_filter("info").max_level(), LevelFilter::INFO);
    }

    #[test]
    fn invalid_explicit_levels_are_rejected() {
        assert_eq!(
            Filter::parse("bogus=level").unwrap_err(),
            "invalid log level `level`"
        );
        assert!(Filter::from_arg(Some("bogus=level")).is_err());
        let filter = Filter::from_arg(Some("debug")).expect("debug");
        assert!(filter.enabled(Level::DEBUG, "kunato"));
    }

    #[test]
    fn invalid_rust_log_falls_back_to_info() {
        let filter = Filter::from_env_value(Some("bogus=level".to_owned()));
        assert!(filter.enabled(Level::INFO, "kunato"));
        let filter = Filter::from_env_value(None);
        assert!(filter.enabled(Level::INFO, "kunato"));
        let filter = Filter::from_env_value(Some(String::new()));
        assert!(filter.enabled(Level::ERROR, "kunato"));
        assert!(!filter.enabled(Level::WARN, "kunato"));
    }

    #[test]
    fn span_and_field_directives_are_rejected() {
        assert!(Filter::parse("kunato[span]=debug").is_err());
        assert!(Filter::parse("kunato{field}=debug").is_err());
    }
}
