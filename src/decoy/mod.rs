//! Bounded local deception and recognition of returned fictional credentials.

pub mod config;
pub mod metrics;
mod response;
mod runtime;
mod scan;
#[cfg(test)]
mod tests;
mod token;

pub(crate) use response::finalize;
pub use runtime::Runtime;
pub(crate) use runtime::{Bucket, QuotaPolicy};
pub(crate) use scan::{Observation, Reclaim, SCAN_BYTES};

use crate::{
    client_ip::ClientSource,
    config::{CompiledConfig, Protection},
    metrics::Metrics,
    protection::ProtectionState,
    proxy::{ProxyBody, server::InspectionGuard},
};
use config::{Action, Template};
use http::{Method, Response, StatusCode, request::Parts};
use metrics::bump;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct HeadChecked;

pub(crate) fn dispatch(
    parts: &mut Parts,
    config: &CompiledConfig,
    source: ClientSource,
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
    inspection: Option<InspectionGuard>,
) -> Option<Response<ProxyBody>> {
    if !config.decoys.enabled || !config.protection.enabled {
        return None;
    }
    parts.extensions.insert(HeadChecked);
    let policy = &config.decoys;
    let site = policy.site(&parts.headers)?;
    let forms = crate::request_view::path_forms(parts.uri.path());
    let mut route = None;
    let mut ambiguous = false;
    for form in &forms {
        let found = if form.as_ref() == site.sink {
            Some((site.sink.as_str(), None))
        } else {
            site.traps
                .get_key_value(form.as_ref())
                .map(|(path, template)| (path.as_str(), Some(*template)))
        };
        if let Some(found) = found {
            if route.is_some_and(|prior| prior != found) {
                ambiguous = true;
            }
            route = Some(found);
        }
    }
    drop(forms);
    let head = parts.method == Method::HEAD;
    let fallback = |status| {
        bump(&metrics.decoys.responses[2]);
        response::response(
            status,
            if status == StatusCode::SERVICE_UNAVAILABLE {
                "service unavailable\n"
            } else {
                "not found\n"
            }
            .to_owned(),
            false,
            head,
        )
    };
    let exempt = crate::protection::is_allowlisted(
        crate::protection::normalize_ip(source.client_ip),
        &config.protection.allowlist,
    );
    if exempt {
        return route.map(|_| fallback(StatusCode::NOT_FOUND));
    }
    if inspection.is_none() {
        bump(&metrics.decoys.incomplete[6]);
        return route.map(|_| {
            bump(&metrics.decoys.limited[4]);
            fallback(StatusCode::NOT_FOUND)
        });
    }
    let observation = Observation::new(
        policy,
        site,
        source,
        crate::protection::tracking_key(source.client_ip, &config.protection),
        Arc::clone(&metrics),
        Arc::clone(&protection),
        inspection,
    );
    let upgrade = parts.headers.contains_key("upgrade");
    let method = matches!(parts.method, Method::GET | Method::HEAD) && !upgrade;
    let sink = route.is_some_and(|(_, template)| template.is_none());
    let (credential, unavailable) = if sink && method && !ambiguous {
        observation.credential(parts)
    } else {
        (false, false)
    };
    observation.head(parts);
    parts.extensions.insert(observation);
    let (path, template) = route?;
    if ambiguous || !method {
        return Some(fallback(StatusCode::NOT_FOUND));
    }
    let result = if let Some(template) = template {
        let quota = policy.runtime.issue_quota();
        let limit = match quota {
            None => Some(0),
            Some(quota) => protection
                .decoy_issue(source.client_ip, &config.protection, quota)
                .err(),
        };
        if let Some(reason) = limit {
            bump(&metrics.decoys.limited[reason]);
            return Some(fallback(StatusCode::NOT_FOUND));
        }
        let token = if head {
            "0".repeat(token::TOKEN_BYTES)
        } else {
            match policy.runtime.mint(site.id, policy.token_ttl.as_secs()) {
                Ok(token) => token,
                Err(_) => {
                    bump(&metrics.decoys.errors);
                    if policy.runtime.log_quota(2) {
                        tracing::warn!(site=%site.name,"decoy nonce generation failed");
                    } else {
                        bump(&metrics.decoys.suppressed[2]);
                    }
                    return Some(fallback(StatusCode::SERVICE_UNAVAILABLE));
                }
            }
        };
        if !head {
            bump(&metrics.decoys.issued);
            if policy.runtime.log_quota(0) {
                tracing::info!(site=%site.name,template=template.name(),path,client=%source.client_ip,peer=%source.peer,token_id=%token::id(token.as_bytes()),lifetime_seconds=policy.token_ttl.as_secs(),"decoy credential issued");
            } else {
                bump(&metrics.decoys.suppressed[0]);
            }
        }
        bump(&metrics.decoys.responses[0]);
        response::response(
            StatusCode::OK,
            render(template, &site.api_url(), &token),
            template == Template::SpringEnv,
            head,
        )
    } else {
        if unavailable {
            bump(&metrics.decoys.limited[3]);
            return Some(fallback(StatusCode::SERVICE_UNAVAILABLE));
        }
        let blocked = credential && policy.on_reuse == Action::Block;
        if blocked {
            bump(&metrics.decoys.blocked);
        }
        bump(&metrics.decoys.responses[1]);
        response::response(
            if blocked {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            },
            "{\"error\":\"invalid credentials\"}\n".to_owned(),
            true,
            head,
        )
    };
    Some(result)
}

pub(crate) fn active(config: &CompiledConfig) -> bool {
    config.decoys.enabled && config.protection.enabled
}

pub(crate) fn exempt(source: std::net::IpAddr, protection: &Protection) -> bool {
    crate::protection::is_allowlisted(
        crate::protection::normalize_ip(source),
        &protection.allowlist,
    )
}

pub(crate) fn log_path(path: &str) -> std::borrow::Cow<'_, str> {
    if path.len() > 32768
        || path.contains("kdt1")
        || path.contains('%')
            && crate::decoding::percent_decode_forms(path)
                .iter()
                .any(|form| form.contains("kdt1"))
    {
        std::borrow::Cow::Borrowed("[redacted]")
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

pub(crate) fn render(template: Template, url: &str, token: &str) -> String {
    match template {
        Template::Dotenv => format!("APP_NAME=blog\nAPP_ENV=production\nINTERNAL_API_URL={url}\nINTERNAL_API_TOKEN={token}\n"),
        Template::GitConfig => format!("[remote \"origin\"]\n    url = https://git.example.invalid/blog.git\n[internal-api]\n    url = {url}\n    token = {token}\n"),
        Template::WpConfig => format!("<?php\ndefine('INTERNAL_API_URL', '{url}');\ndefine('INTERNAL_API_TOKEN', '{token}');\n"),
        Template::SpringEnv => serde_json::json!({"propertySources":[{"name":"systemEnvironment","properties":{"internal.api.url":{"value":url},"internal.api.token":{"value":token}}}]}).to_string(),
    }
}
