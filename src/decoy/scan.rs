use std::sync::{Arc, Mutex, PoisonError};

use http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use http::request::Parts;

use super::{
    config::{Policy, Site},
    metrics::bump,
    token::{self, Invalid, Parsed, TOKEN_BYTES},
};
use crate::{client_ip::ClientSource, metrics::Metrics, protection::ProtectionState};

pub(crate) const SCAN_BYTES: usize = 32768;
const MAX_CANDIDATES: usize = 16;
const BODY_BYTES: usize = 8192;

struct Cached {
    raw: [u8; TOKEN_BYTES],
    result: Option<u64>,
    unavailable: bool,
}

struct Evidence {
    id: String,
    age: u64,
    location: &'static str,
    credential: bool,
}

struct State {
    remaining: usize,
    candidates: Vec<Cached>,
    incomplete: u8,
    contexts: u8,
    evidence: Option<Evidence>,
    runtime: Arc<super::Runtime>,
    site: [u8; 16],
    name: String,
    source: ClientSource,
    source_key: std::net::IpAddr,
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
    block: bool,
    _inspection: Option<crate::proxy::server::InspectionGuard>,
}

impl State {
    fn incomplete(&mut self, reason: usize) {
        self.incomplete |= 1 << reason;
    }

    fn verify(&mut self, raw: &[u8]) -> (Option<u64>, bool) {
        if let Some(prior) = self
            .candidates
            .iter()
            .find(|prior| prior.raw.as_slice() == raw)
        {
            return (prior.result, prior.unavailable);
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            self.incomplete(1);
            return (None, false);
        }
        let mut cached = Cached {
            raw: [0; TOKEN_BYTES],
            result: None,
            unavailable: false,
        };
        if raw.len() != TOKEN_BYTES {
            return (None, false);
        }
        cached.raw.copy_from_slice(raw);
        let result = match Parsed::parse(raw) {
            Err(reason) => Err(reason),
            Ok(parsed) => {
                if !self.runtime.verification_quota() {
                    self.incomplete(4);
                    cached.unavailable = true;
                    self.candidates.push(cached);
                    return (None, true);
                }
                match self.runtime.key() {
                    Some(key) => key.verify(&parsed, self.site, self.runtime.elapsed()),
                    None => Err(Invalid::Mac),
                }
            }
        };
        match result {
            Ok(age) => cached.result = Some(age),
            Err(reason) => bump(
                &self.metrics.decoys.invalid[match reason {
                    Invalid::Syntax => 0,
                    Invalid::Mac => 1,
                    Invalid::Expired => 2,
                    Invalid::Scope => 3,
                }],
            ),
        }
        let result = cached.result;
        self.candidates.push(cached);
        (result, false)
    }

    fn evidence(&mut self, raw: &[u8], age: u64, location: &'static str, credential: bool) {
        self.contexts |= if credential { 1 } else { 2 };
        if self.evidence.is_none()
            || credential && self.evidence.as_ref().is_some_and(|e| !e.credential)
        {
            self.evidence = Some(Evidence {
                id: token::id(raw),
                age,
                location,
                credential,
            });
        }
    }

    fn raw(&mut self, bytes: &[u8], location: &'static str) {
        let count = bytes.len().min(self.remaining);
        if count < bytes.len() {
            self.incomplete(0);
        }
        self.remaining -= count;
        let bytes = &bytes[..count];
        let mut start = 0;
        while start + TOKEN_BYTES <= bytes.len() {
            let Some(index) = bytes[start..].windows(5).position(|s| s == b"kdt1.") else {
                break;
            };
            let index = start + index;
            if index + TOKEN_BYTES > bytes.len() {
                break;
            }
            let candidate = &bytes[index..index + TOKEN_BYTES];
            if let (Some(age), _) = self.verify(candidate) {
                self.evidence(candidate, age, location, false);
            }
            start = index + 5;
        }
    }

    fn text(&mut self, bytes: &[u8], location: &'static str) {
        let count = bytes.len().min(self.remaining);
        if count < bytes.len() {
            self.incomplete(0);
        }
        let bytes = &bytes[..count];
        self.raw(bytes, location);
        self.normalized(bytes, location);
        if count == 0 {
            return;
        }
        let mut prior = std::borrow::Cow::Borrowed(bytes);
        for _ in 0..2 {
            if self.remaining == 0 {
                self.incomplete(0);
                break;
            }
            let limit = prior.len().min(self.remaining);
            let Some(decoded) = percent_bytes(&prior[..limit]) else {
                break;
            };
            self.raw(&decoded, location);
            self.normalized(&decoded, location);
            prior = std::borrow::Cow::Owned(decoded);
        }
    }
    fn normalized(&mut self, bytes: &[u8], location: &'static str) {
        if location == "path"
            && self.remaining > 0
            && let Ok(path) = std::str::from_utf8(bytes)
            && let Some(normalized) = crate::decoding::normalize_path(path)
        {
            self.raw(normalized.as_bytes(), location);
        }
    }
}

fn percent_bytes(input: &[u8]) -> Option<Vec<u8>> {
    if !input.contains(&b'%') {
        return None;
    }
    let digit = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    let mut changed = false;
    while index < input.len() {
        if input[index] == b'%'
            && index + 2 < input.len()
            && let (Some(high), Some(low)) = (digit(input[index + 1]), digit(input[index + 2]))
        {
            decoded.push(high * 16 + low);
            index += 3;
            changed = true;
        } else {
            decoded.push(input[index]);
            index += 1;
        }
    }
    changed.then_some(decoded)
}

impl Drop for State {
    fn drop(&mut self) {
        for index in 0..7 {
            if self.incomplete & (1 << index) != 0 {
                bump(&self.metrics.decoys.incomplete[index]);
            }
        }
        for index in 0..2 {
            if self.contexts & (1 << index) != 0 {
                bump(&self.metrics.decoys.reuse[index]);
            }
        }
        let Some(evidence) = &self.evidence else {
            return;
        };
        if !self.runtime.log_quota(1) || !self.protection.decoy_reuse_log(self.source_key) {
            bump(&self.metrics.decoys.suppressed[1]);
            return;
        }
        tracing::info!(site=%self.name, token_id=%evidence.id, client=%self.source.client_ip,peer=%self.source.peer,
            age_seconds=evidence.age,context=if evidence.credential {"credential"} else {"occurrence"},
            location=evidence.location,action=if self.block && evidence.credential {"BLOCK"}else{"LOG"},
            incomplete=self.incomplete!=0,"decoy credential returned");
    }
}

#[derive(Clone)]
pub(crate) struct Observation(Arc<Mutex<State>>);

pub(crate) struct Reclaim(std::sync::Weak<Mutex<State>>);

impl Reclaim {
    pub(crate) fn release(&self) -> bool {
        let Some(observation) = self.0.upgrade() else {
            return false;
        };
        let (scratch, candidates) = {
            let mut state = observation.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(scratch) = state._inspection.take() else {
                return false;
            };
            state.incomplete(6);
            state.remaining = 0;
            (scratch, std::mem::take(&mut state.candidates))
        };
        drop(candidates);
        drop(scratch);
        true
    }
}

impl Observation {
    pub(crate) fn reclaimer(&self) -> Reclaim {
        Reclaim(Arc::downgrade(&self.0))
    }
    pub(crate) fn new(
        policy: &Policy,
        site: &Site,
        source: ClientSource,
        key: std::net::IpAddr,
        metrics: Arc<Metrics>,
        protection: Arc<ProtectionState>,
        inspection: Option<crate::proxy::server::InspectionGuard>,
    ) -> Self {
        Self(Arc::new(Mutex::new(State {
            remaining: SCAN_BYTES,
            candidates: Vec::with_capacity(MAX_CANDIDATES),
            incomplete: 0,
            contexts: 0,
            evidence: None,
            runtime: Arc::clone(&policy.runtime),
            site: site.id,
            name: site.name.clone(),
            source,
            source_key: key,
            metrics,
            protection,
            block: policy.on_reuse == super::config::Action::Block,
            _inspection: inspection,
        })))
    }

    pub(crate) fn credential(&self, parts: &Parts) -> (bool, bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let auth = parts
            .headers
            .get_all(AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        let keys = parts
            .headers
            .get_all("x-api-key")
            .iter()
            .collect::<Vec<_>>();
        if auth.len() > 1 || keys.len() > 1 || !auth.is_empty() && !keys.is_empty() {
            state.incomplete(5);
            return (false, false);
        }
        let (value, bearer) = match (auth.first(), keys.first()) {
            (Some(value), None) => (*value, true),
            (None, Some(value)) => (*value, false),
            _ => return (false, false),
        };
        if value.as_bytes().len() > 512 {
            state.incomplete(0);
            return (false, false);
        }
        let value = value.as_bytes();
        let first = value
            .iter()
            .position(|byte| !matches!(*byte, b' ' | b'\t'))
            .unwrap_or(value.len());
        let last = value
            .iter()
            .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
            .map_or(first, |index| index + 1);
        let value = &value[first..last];
        state.remaining = state.remaining.saturating_sub(value.len());
        let raw = if bearer {
            if value.len() < 7 || !value[..6].eq_ignore_ascii_case(b"Bearer") || value[6] != b' ' {
                return (false, false);
            }
            &value[7..]
        } else {
            value
        };
        if raw.len() != TOKEN_BYTES || Parsed::parse(raw).is_err() {
            return (false, false);
        }
        let (age, unavailable) = state.verify(raw);
        if let Some(age) = age {
            state.evidence(raw, age, "authentication", true);
        }
        (age.is_some(), unavailable)
    }

    pub(crate) fn head(&self, parts: &Parts) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let credential = state.contexts & 1 != 0;
        for name in ["authorization", "x-api-key"] {
            if credential {
                continue;
            }
            for value in parts.headers.get_all(name) {
                state.text(value.as_bytes(), "authentication");
                if name == "authorization"
                    && let Ok(value) = value.to_str()
                    && value.len() <= 1030
                    && value
                        .get(..6)
                        .is_some_and(|s| s.eq_ignore_ascii_case("Basic "))
                {
                    let encoded = &value[6..];
                    if encoded.len() <= 1024
                        && state.remaining >= encoded.len()
                        && let Some(decoded) = crate::acme::base64::decode_standard(encoded)
                    {
                        state.text(&decoded, "basic");
                    }
                }
            }
        }
        state.text(parts.uri.path().as_bytes(), "path");
        if let Some(query) = parts.uri.query() {
            state.text(query.as_bytes(), "query");
        }
        for value in parts.headers.get_all(COOKIE) {
            state.text(value.as_bytes(), "cookie");
        }
        for (name, value) in &parts.headers {
            if !matches!(name.as_str(), "authorization" | "x-api-key" | "cookie") {
                state.text(value.as_bytes(), "header");
            }
        }
    }

    pub(crate) fn body(
        &self,
        bytes: &[u8],
        headers: &http::HeaderMap,
        decoded_available: bool,
        truncated: bool,
    ) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !decoded_available {
            state.incomplete(3);
            return;
        }
        if bytes.len() > BODY_BYTES || truncated {
            state.incomplete(2);
        }
        let prefix = &bytes[..bytes.len().min(BODY_BYTES).min(state.remaining)];
        if prefix.len() < bytes.len().min(BODY_BYTES) {
            state.incomplete(0);
        }
        if crate::decoding::uninspectable_charset(headers, prefix).is_some() {
            state.incomplete(3);
            return;
        }
        if crate::upload::is_multipart(headers) {
            let content_type = headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let Ok(boundaries) = crate::decoding::multipart_boundaries(content_type) else {
                state.incomplete(3);
                return;
            };
            for boundary in boundaries {
                let Some(parts) = crate::decoding::multipart_parts(prefix, &boundary) else {
                    state.incomplete(2);
                    continue;
                };
                for part in parts {
                    state.text(part.headers, "body");
                    if !part.has_filename() {
                        state.text(part.value, "body");
                    }
                }
            }
            return;
        }
        state.text(prefix, "body");
        if state.remaining > 0
            && headers
                .get(CONTENT_TYPE)
                .and_then(|s| s.to_str().ok())
                .is_some_and(|s| {
                    s.split(';')
                        .next()
                        .is_some_and(|s| s == "application/json" || s.ends_with("+json"))
                })
        {
            if let Some(decoded) = crate::decoding::decode_body_format(prefix, headers) {
                state.text(&decoded[..decoded.len().min(BODY_BYTES)], "body");
            } else if prefix.contains(&b'\\') {
                state.incomplete(3);
            }
        }
    }
}
