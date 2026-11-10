use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use http::{Uri, header::HOST};
use serde::Deserialize;

use super::{Runtime, token};
use crate::allowed_hosts::AllowedHosts;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum Action {
    #[default]
    #[serde(rename = "LOG")]
    Log,
    #[serde(rename = "BLOCK")]
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Template {
    Dotenv,
    GitConfig,
    WpConfig,
    SpringEnv,
}

impl Template {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dotenv => "dotenv",
            Self::GitConfig => "git-config",
            Self::WpConfig => "wp-config",
            Self::SpringEnv => "spring-env",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    Dotenv,
    GitConfig,
    WordpressBackup,
    SpringEnv,
}

impl Preset {
    fn paths(self) -> &'static [(&'static str, Template)] {
        match self {
            Self::Dotenv => &[("/.env", Template::Dotenv)],
            Self::GitConfig => &[("/.git/config", Template::GitConfig)],
            Self::WordpressBackup => &[
                ("/wp-config.php.bak", Template::WpConfig),
                ("/wp-config.php.old", Template::WpConfig),
            ],
            Self::SpringEnv => &[("/actuator/env", Template::SpringEnv)],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Issuance {
    pub per_minute: u32,
    pub burst: u32,
    pub per_source_per_minute: u32,
    pub per_source_burst: u32,
}

impl Default for Issuance {
    fn default() -> Self {
        Self {
            per_minute: 60,
            burst: 10,
            per_source_per_minute: 6,
            per_source_burst: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Verification {
    pub per_second: u32,
    pub burst: u32,
}

impl Default for Verification {
    fn default() -> Self {
        Self {
            per_second: 256,
            burst: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Observation {
    pub body: bool,
}

impl Default for Observation {
    fn default() -> Self {
        Self { body: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSpec {
    pub path: String,
    pub template: Template,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSpec {
    pub name: String,
    pub origin: String,
    pub sink: String,
    #[serde(default)]
    pub presets: Vec<Preset>,
    #[serde(default)]
    pub disabled_paths: Vec<String>,
    #[serde(default)]
    pub paths: Vec<PathSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    pub enabled: bool,
    #[serde(deserialize_with = "crate::config::de_duration")]
    pub token_ttl: Duration,
    pub on_reuse: Action,
    pub issuance: Issuance,
    pub verification: Verification,
    pub observation: Observation,
    pub sites: Vec<SiteSpec>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            enabled: false,
            token_ttl: Duration::from_secs(1800),
            on_reuse: Action::Log,
            issuance: Issuance::default(),
            verification: Verification::default(),
            observation: Observation::default(),
            sites: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Site {
    pub name: String,
    pub origin: String,
    pub authority: (String, Option<u16>),
    pub id: [u8; 16],
    pub sink: String,
    pub traps: BTreeMap<String, Template>,
}

impl Site {
    pub fn api_url(&self) -> String {
        format!("{}{}", self.origin, self.sink)
    }
}

#[derive(Debug)]
pub struct Policy {
    pub enabled: bool,
    pub token_ttl: Duration,
    pub on_reuse: Action,
    pub issuance: Issuance,
    pub verification: Verification,
    pub observation: Observation,
    pub sites: Vec<Site>,
    pub runtime: Arc<Runtime>,
}

impl Policy {
    pub fn compile(
        spec: &Spec,
        allowed: Option<&AllowedHosts>,
        protection: bool,
        issues: &mut Vec<String>,
    ) -> Self {
        let mut error = |reason: &str| issues.push(format!("decoys: {reason}"));
        if spec.enabled && (spec.sites.is_empty() || allowed.is_none()) {
            error("enabled decoys require sites and allowed_hosts");
        }
        if spec.sites.len() > 16 {
            error("at most 16 sites are allowed");
        }
        if !(60..=86400).contains(&spec.token_ttl.as_secs()) || spec.token_ttl.subsec_nanos() != 0 {
            error("token_ttl must be whole seconds in 1m..24h");
        }
        let i = spec.issuance;
        if !(1..=6000).contains(&i.per_minute)
            || !(1..=600).contains(&i.per_source_per_minute)
            || !(1..=100).contains(&i.burst)
            || !(1..=100).contains(&i.per_source_burst)
            || i.per_source_per_minute > i.per_minute
            || i.per_source_burst > i.burst
        {
            error(
                "invalid issuance rates or bursts (global 1..6000/min, source 1..600/min, bursts 1..100; source cannot exceed global)",
            );
        }
        if !(1..=4096).contains(&spec.verification.per_second)
            || !(1..=4096).contains(&spec.verification.burst)
        {
            error("verification rate and burst must be in 1..4096");
        }
        let mut sites = Vec::new();
        let mut names = BTreeSet::new();
        let mut origins = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for site in spec.sites.iter().take(16) {
            let Some(origin) = canonical_origin(&site.origin) else {
                error("invalid HTTPS origin");
                continue;
            };
            if !valid_name(&site.name) || !names.insert(site.name.clone()) {
                error("site names must be unique 1..64 ASCII name tokens");
            }
            if !origins.insert(origin.clone()) {
                error("duplicate site origin");
            }
            if spec.enabled
                && !allowed
                    .is_some_and(|a| a.matches(origin.strip_prefix("https://").unwrap_or("")))
            {
                error("site origin must be accepted by allowed_hosts");
            }
            let Some(authority) = origin
                .strip_prefix("https://")
                .and_then(crate::allowed_hosts::normalized_authority)
            else {
                error("invalid site authority");
                continue;
            };
            let id = token::site_id(&site.name, &origin);
            if !ids.insert(id) {
                error("site identity collision");
            }
            if !valid_path(&site.sink) {
                error("sink must be a canonical literal path of at most 512 bytes");
            }
            let mut traps = BTreeMap::new();
            let mut presets = Vec::new();
            for preset in site.presets.iter().take(32) {
                if presets.contains(preset) {
                    error("duplicate preset");
                }
                presets.push(*preset);
                for (path, template) in preset.paths() {
                    traps.insert((*path).to_owned(), *template);
                }
            }
            if site.presets.len() > 4 || site.paths.len() > 32 || site.disabled_paths.len() > 32 {
                error("too many preset or path entries");
            }
            let mut removed = BTreeSet::new();
            for path in site.disabled_paths.iter().take(32) {
                if !removed.insert(path) || traps.remove(path).is_none() {
                    error("disabled_paths must uniquely name preset paths");
                }
            }
            let mut local = BTreeSet::new();
            for path in site.paths.iter().take(32) {
                if !valid_path(&path.path)
                    || !local.insert(&path.path)
                    || removed.contains(&path.path)
                {
                    error("invalid, duplicate, or simultaneously disabled local path");
                }
                traps.insert(path.path.clone(), path.template);
            }
            if traps.is_empty() || traps.len() > 32 || traps.contains_key(&site.sink) {
                error("each site needs 1..32 traps disjoint from its sink");
            }
            let compiled = Site {
                name: site.name.clone(),
                origin,
                authority,
                id,
                sink: site.sink.clone(),
                traps,
            };
            for template in compiled.traps.values() {
                if super::render(
                    *template,
                    &compiled.api_url(),
                    &"0".repeat(token::TOKEN_BYTES),
                )
                .len()
                    > 4096
                {
                    error("rendered template exceeds 4096 bytes");
                }
            }
            sites.push(compiled);
        }
        if sites.iter().map(|s| s.traps.len()).sum::<usize>() > 128 {
            error("at most 128 traps are allowed across sites");
        }
        let runtime = Arc::new(Runtime::new(spec.issuance, spec.verification));
        if spec.enabled && protection && runtime.ensure_key().is_err() {
            error("cannot initialize token signing key");
        }
        Self {
            enabled: spec.enabled,
            token_ttl: spec.token_ttl,
            on_reuse: spec.on_reuse,
            issuance: spec.issuance,
            verification: spec.verification,
            observation: spec.observation,
            sites,
            runtime,
        }
    }

    pub fn site(&self, headers: &http::HeaderMap) -> Option<&Site> {
        let raw = headers.get(HOST)?.to_str().ok()?;
        let (host, port) = crate::allowed_hosts::normalized_authority(raw)?;
        self.sites
            .iter()
            .find(|s| s.authority.0 == host && s.authority.1.unwrap_or(443) == port.unwrap_or(443))
    }

    pub fn adopt_runtime(&mut self, prior: &Self, protection: bool) -> Result<(), &'static str> {
        if self.enabled && protection {
            prior.runtime.ensure_key()?;
        }
        self.runtime = Arc::clone(&prior.runtime);
        self.runtime.install(self.issuance, self.verification);
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 512
        && !path.contains("//")
        && path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'-' | b'.' | b'_' | b'~'))
        && !path.split('/').any(|s| s == "." || s == "..")
        && crate::decoding::normalize_path(path).is_none_or(|normal| normal == path)
}

fn canonical_origin(raw: &str) -> Option<String> {
    if raw.contains('#') || raw.len() > 512 {
        return None;
    }
    let uri: Uri = raw.parse().ok()?;
    if uri.scheme_str()? != "https"
        || uri
            .path_and_query()
            .is_some_and(|p| p.as_str() != "/" && !p.as_str().is_empty())
    {
        return None;
    }
    let (host, port) = crate::allowed_hosts::normalized_authority(uri.authority()?.as_str())?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Some(match port {
        Some(p) if p != 443 => format!("https://{host}:{p}"),
        _ => format!("https://{host}"),
    })
}
