//! Bounded GraphQL document analysis for the automatic complexity limit.
//!
//! The analyzer never trusts the request's declared content type: a JSON body
//! is parsed as JSON regardless of how it is labelled, so relabelling a query
//! as `text/plain` does not hide it. Fragment spreads are expanded when both
//! the depth and the field count are computed, because a document can carry
//! arbitrarily deep or wide structure behind a short top-level query.
//!
//! Anything that is not a valid GraphQL document is ignored here and left to
//! the application, which rejects it. Failed analysis and truncated bodies are
//! the exception: the caller refuses to forward a body it could not inspect.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

use http::header::{CONTENT_TYPE, HeaderMap};
use serde::Deserialize;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};

/// Upper bound for parsed selection nodes. This bounds analyzer memory
/// independently of the configured field limit.
const MAX_NODES: usize = 20_000;
/// Inline fragments do not add a selection level, but they do add parser
/// recursion. Cap them relative to the configured depth so a body full of
/// `...{` cannot overflow the worker stack.
const MAX_INLINE_NESTING: usize = 64;
/// How many documents may be carried by one request (a batch or repeated
/// `query` fields). More than this is rejected rather than silently ignored.
const MAX_CANDIDATES: usize = 256;
/// How many JSON-looking lines are tried in a flattened multipart body.
const MAX_MULTIPART_JSON_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: usize,
    pub max_fields: usize,
    pub block_introspection: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    Introspection,
    TooDeep { depth: usize },
    TooManyFields { fields: usize },
    TooComplex,
    Incomplete,
    Uninspectable,
    Cyclic,
    Ambiguous,
}

/// Inspects every GraphQL document carried by the request. Returns `None` when
/// the request is not GraphQL or stays within the configured limits.
pub fn inspect(
    uri_query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
    body_truncated: bool,
    limits: Limits,
) -> Option<Violation> {
    // A truncated body can hold a shallow document in the prefix and the
    // executed (deep) one after it, or a later duplicate of the same field.
    // Nothing short of inspecting the whole body can prove which document the
    // upstream will execute, so fail closed before parsing anything.
    if body_truncated {
        return Some(Violation::Incomplete);
    }
    let Some(candidates) = candidates(uri_query, headers, body) else {
        return Some(Violation::TooComplex);
    };
    if limits.block_introspection
        && candidates
            .iter()
            .any(|candidate| contains_introspection(candidate))
    {
        return Some(Violation::Introspection);
    }
    if candidates.is_empty() {
        // A multipart body is the one shape where forwarding an unextracted
        // document is dangerous: the parser supports several boundary
        // interpretations and part orders, so a body with no readable
        // `operations` document is refused instead of being passed through
        // uninspected.
        if media_type(headers).as_deref() == Some("multipart/form-data") {
            return Some(Violation::Uninspectable);
        }
        return None;
    }

    let mut analysed = false;
    for candidate in &candidates {
        match Document::parse(candidate, limits.max_depth) {
            Ok(document) => {
                analysed = true;
                if let Some(violation) = document.analyse(limits) {
                    return Some(violation);
                }
            }
            Err(ParseError::TooDeep { depth }) => return Some(Violation::TooDeep { depth }),
            Err(ParseError::TooComplex) => return Some(Violation::TooComplex),
            Err(ParseError::Ambiguous) => return Some(Violation::Ambiguous),
            Err(ParseError::Syntax) => {}
        }
    }

    if !analysed && media_type(headers).as_deref() == Some("multipart/form-data") {
        return Some(Violation::Uninspectable);
    }
    None
}

#[derive(Debug, Clone)]
enum Selection {
    Field { child: Option<Vec<Selection>> },
    Spread { name: String },
    Inline { child: Vec<Selection> },
}

#[derive(Debug, Default)]
struct Document {
    operations: Vec<Vec<Selection>>,
    fragments: HashMap<String, Vec<Selection>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Metrics {
    depth: usize,
    fields: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visit {
    Visiting,
    Done,
}

#[derive(Debug)]
enum ParseError {
    Syntax,
    TooDeep { depth: usize },
    TooComplex,
    Ambiguous,
}

impl Document {
    fn parse(source: &str, max_depth: usize) -> Result<Self, ParseError> {
        let mut parser = Parser {
            src: source.as_bytes(),
            pos: 0,
            max_depth,
            nodes: 0,
        };
        let mut document = Self::default();
        loop {
            parser.skip_ignored();
            if parser.at_end() {
                break;
            }
            if parser.peek_byte() == Some(b'{') {
                document.operations.push(parser.parse_operation()?);
                continue;
            }
            let Some(name) = parser.peek_name() else {
                return Err(ParseError::Syntax);
            };
            if name == "fragment" {
                parser.take_name();
                let (name, selections) = parser.parse_fragment()?;
                if document.fragments.insert(name, selections).is_some() {
                    return Err(ParseError::Ambiguous);
                }
            } else {
                document.operations.push(parser.parse_operation()?);
            }
        }
        if document.operations.is_empty() {
            return Err(ParseError::Syntax);
        }
        Ok(document)
    }

    fn analyse(&self, limits: Limits) -> Option<Violation> {
        if self
            .operations
            .iter()
            .any(|operation| self.has_undefined_spread(operation))
        {
            return Some(Violation::Ambiguous);
        }
        let reachable = self.reachable_fragments();
        let mut states: HashMap<&str, Visit> = HashMap::new();
        let mut metrics: HashMap<&str, Metrics> = HashMap::new();

        for &name in &reachable {
            if states.get(name).copied() == Some(Visit::Done) {
                continue;
            }
            if self
                .fragments
                .get(name)
                .is_some_and(|selections| self.has_undefined_spread(selections))
            {
                return Some(Violation::Ambiguous);
            }
            let mut stack: Vec<(&str, bool)> = vec![(name, false)];
            while let Some((current, exiting)) = stack.pop() {
                if exiting {
                    let selections = self.fragments.get(current)?;
                    let metric = evaluate(selections, &metrics, limits)?;
                    metrics.insert(current, metric);
                    states.insert(current, Visit::Done);
                    continue;
                }
                match states.get(current).copied() {
                    Some(Visit::Done) => continue,
                    Some(Visit::Visiting) => return Some(Violation::Cyclic),
                    None => {}
                }
                states.insert(current, Visit::Visiting);
                stack.push((current, true));
                let selections = self.fragments.get(current)?;
                for spread in spreads(selections) {
                    match states.get(spread).copied() {
                        Some(Visit::Visiting) => return Some(Violation::Cyclic),
                        Some(Visit::Done) => {}
                        None => {
                            if self.fragments.contains_key(spread) {
                                stack.push((spread, false));
                            }
                        }
                    }
                }
            }
        }

        for operation in &self.operations {
            let metric = evaluate(operation, &metrics, limits)?;
            if metric.depth > limits.max_depth {
                return Some(Violation::TooDeep {
                    depth: metric.depth,
                });
            }
            if metric.fields > limits.max_fields {
                return Some(Violation::TooManyFields {
                    fields: metric.fields,
                });
            }
        }
        None
    }

    fn reachable_fragments(&self) -> Vec<&str> {
        let mut seen = HashSet::new();
        let mut pending: Vec<&str> = Vec::new();
        for operation in &self.operations {
            pending.extend(spreads(operation));
        }
        let mut reachable = Vec::new();
        while let Some(name) = pending.pop() {
            if !seen.insert(name) {
                continue;
            }
            if let Some(selections) = self.fragments.get(name) {
                reachable.push(name);
                pending.extend(spreads(selections));
            }
        }
        reachable
    }

    fn has_undefined_spread(&self, selections: &[Selection]) -> bool {
        selections.iter().any(|selection| match selection {
            Selection::Spread { name } => !self.fragments.contains_key(name.as_str()),
            Selection::Field { child: Some(child) } => self.has_undefined_spread(child),
            Selection::Inline { child } => self.has_undefined_spread(child),
            Selection::Field { child: None } => false,
        })
    }
}

fn spreads(selections: &[Selection]) -> Vec<&str> {
    let mut names = Vec::new();
    for selection in selections {
        match selection {
            Selection::Spread { name } => names.push(name.as_str()),
            Selection::Field { child: Some(child) } => names.extend(spreads(child)),
            Selection::Inline { child } => names.extend(spreads(child)),
            Selection::Field { child: None } => {}
        }
    }
    names
}

/// Computes the expanded depth and field count of one selection set. Fragment
/// metrics are memoized by the caller, so shared fragments are evaluated once.
fn evaluate(
    selections: &[Selection],
    fragments: &HashMap<&str, Metrics>,
    limits: Limits,
) -> Option<Metrics> {
    let mut metric = Metrics::default();
    for selection in selections {
        match selection {
            Selection::Field { child } => {
                metric.fields = metric.fields.saturating_add(1);
                if let Some(child) = child {
                    let child = evaluate(child, fragments, limits)?;
                    metric.depth = metric.depth.max(child.depth.saturating_add(1));
                    metric.fields = metric.fields.saturating_add(child.fields);
                } else {
                    metric.depth = metric.depth.max(1);
                }
            }
            Selection::Spread { name } => {
                let fragment = fragments.get(name.as_str())?;
                metric.depth = metric.depth.max(fragment.depth);
                metric.fields = metric.fields.saturating_add(fragment.fields);
            }
            Selection::Inline { child } => {
                let child = evaluate(child, fragments, limits)?;
                metric.depth = metric.depth.max(child.depth);
                metric.fields = metric.fields.saturating_add(child.fields);
            }
        }
        if metric.depth > limits.max_depth || metric.fields > limits.max_fields {
            return Some(metric);
        }
    }
    Some(metric)
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    max_depth: usize,
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek_byte(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.src
            .get(self.pos..)
            .is_some_and(|rest| rest.starts_with(prefix))
    }

    fn skip_ignored(&mut self) {
        loop {
            // graphql-js and the GraphQL lexer treat U+FEFF as an ignored
            // token between any two tokens, not only at the start of the
            // document. Skipping it everywhere keeps the analyzer aligned.
            if self.starts_with(&[0xEF, 0xBB, 0xBF]) {
                self.pos += 3;
                continue;
            }
            match self.peek_byte() {
                Some(b' ' | b'\t' | b'\n' | b'\r' | b',') => self.pos += 1,
                Some(b'#') => {
                    while let Some(byte) = self.peek_byte() {
                        self.pos += 1;
                        if byte == b'\n' || byte == b'\r' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn peek_name(&self) -> Option<&'a str> {
        let start = self.pos;
        let first = *self.src.get(start)?;
        if !is_name_start(first) {
            return None;
        }
        let mut end = start + 1;
        while end < self.src.len() && is_name_continue(self.src[end]) {
            end += 1;
        }
        std::str::from_utf8(&self.src[start..end]).ok()
    }

    fn take_name(&mut self) -> Option<&'a str> {
        let name = self.peek_name()?;
        self.pos += name.len();
        Some(name)
    }

    fn expect_name(&mut self, expected: &str) -> Result<(), ParseError> {
        self.skip_ignored();
        match self.take_name() {
            Some(name) if name == expected => Ok(()),
            _ => Err(ParseError::Syntax),
        }
    }

    fn eat_punct(&mut self, punct: u8) -> bool {
        self.skip_ignored();
        if self.peek_byte() == Some(punct) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, punct: u8) -> Result<(), ParseError> {
        if self.eat_punct(punct) {
            Ok(())
        } else {
            Err(ParseError::Syntax)
        }
    }

    fn bump_node(&mut self) -> Result<(), ParseError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(ParseError::TooComplex);
        }
        Ok(())
    }

    fn parse_operation(&mut self) -> Result<Vec<Selection>, ParseError> {
        self.skip_ignored();
        if self.peek_byte() == Some(b'{') {
            return self.parse_selection_set(1, 1);
        }
        let keyword = self.take_name().ok_or(ParseError::Syntax)?;
        if !matches!(keyword, "query" | "mutation" | "subscription") {
            return Err(ParseError::Syntax);
        }
        self.skip_ignored();
        if self.peek_name().is_some() {
            self.take_name();
        }
        self.skip_ignored();
        if self.peek_byte() == Some(b'(') {
            self.pos += 1;
            self.skip_paren_body()?;
        }
        self.skip_directives()?;
        self.parse_selection_set(1, 1)
    }

    fn parse_fragment(&mut self) -> Result<(String, Vec<Selection>), ParseError> {
        self.skip_ignored();
        let name = self.take_name().ok_or(ParseError::Syntax)?.to_owned();
        self.expect_name("on")?;
        self.skip_ignored();
        self.take_name().ok_or(ParseError::Syntax)?;
        self.skip_directives()?;
        let selections = self.parse_selection_set(1, 1)?;
        Ok((name, selections))
    }

    fn parse_selection_set(
        &mut self,
        depth: usize,
        nesting: usize,
    ) -> Result<Vec<Selection>, ParseError> {
        if depth > self.max_depth {
            return Err(ParseError::TooDeep { depth });
        }
        if nesting > self.max_depth.saturating_add(MAX_INLINE_NESTING) {
            return Err(ParseError::TooComplex);
        }
        self.expect_punct(b'{')?;
        let mut selections = Vec::new();
        loop {
            self.skip_ignored();
            if self.eat_punct(b'}') {
                return Ok(selections);
            }
            if self.at_end() {
                return Err(ParseError::Syntax);
            }
            selections.push(self.parse_selection(depth, nesting)?);
        }
    }

    fn parse_selection(&mut self, depth: usize, nesting: usize) -> Result<Selection, ParseError> {
        self.bump_node()?;
        self.skip_ignored();
        if self.eat_punct(b'.') {
            self.expect_punct(b'.')?;
            self.expect_punct(b'.')?;
            self.skip_ignored();
            if self.peek_name() == Some("on") {
                self.take_name();
                self.skip_ignored();
                self.take_name().ok_or(ParseError::Syntax)?;
                self.skip_directives()?;
                return Ok(Selection::Inline {
                    child: self.parse_selection_set(depth, nesting + 1)?,
                });
            }
            if self.peek_byte() == Some(b'@') {
                self.skip_directives()?;
                return Ok(Selection::Inline {
                    child: self.parse_selection_set(depth, nesting + 1)?,
                });
            }
            if self.peek_byte() == Some(b'{') {
                return Ok(Selection::Inline {
                    child: self.parse_selection_set(depth, nesting + 1)?,
                });
            }
            let name = self.take_name().ok_or(ParseError::Syntax)?.to_owned();
            self.skip_directives()?;
            return Ok(Selection::Spread { name });
        }

        self.take_name().ok_or(ParseError::Syntax)?;
        self.skip_ignored();
        if self.eat_punct(b':') {
            self.skip_ignored();
            self.take_name().ok_or(ParseError::Syntax)?;
        }
        self.skip_arguments()?;
        self.skip_directives()?;
        self.skip_ignored();
        let child = if self.peek_byte() == Some(b'{') {
            Some(self.parse_selection_set(depth + 1, nesting + 1)?)
        } else {
            None
        };
        Ok(Selection::Field { child })
    }

    fn skip_arguments(&mut self) -> Result<(), ParseError> {
        self.skip_ignored();
        if self.eat_punct(b'(') {
            self.skip_paren_body()?;
        }
        Ok(())
    }

    fn skip_directives(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_ignored();
            if !self.eat_punct(b'@') {
                return Ok(());
            }
            self.skip_ignored();
            self.take_name().ok_or(ParseError::Syntax)?;
            self.skip_arguments()?;
        }
    }

    fn skip_paren_body(&mut self) -> Result<(), ParseError> {
        let mut depth = 1usize;
        loop {
            self.skip_ignored();
            let byte = self.peek_byte().ok_or(ParseError::Syntax)?;
            match byte {
                b'"' => self.skip_string()?,
                b'(' => {
                    self.pos += 1;
                    depth += 1;
                }
                b')' => {
                    self.pos += 1;
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.pos += 1,
            }
        }
    }

    fn skip_string(&mut self) -> Result<(), ParseError> {
        if self.starts_with(b"\"\"\"") {
            self.pos += 3;
            loop {
                if self.starts_with(b"\\\"\"\"") {
                    self.pos += 4;
                    continue;
                }
                if self.starts_with(b"\"\"\"") {
                    self.pos += 3;
                    return Ok(());
                }
                if self.at_end() {
                    return Err(ParseError::Syntax);
                }
                self.pos += 1;
            }
        }
        self.pos += 1;
        loop {
            let byte = self.peek_byte().ok_or(ParseError::Syntax)?;
            self.pos += 1;
            match byte {
                b'\\' => {
                    if self.at_end() {
                        return Err(ParseError::Syntax);
                    }
                    self.pos += 1;
                }
                b'"' => return Ok(()),
                b'\n' | b'\r' => return Err(ParseError::Syntax),
                _ => {}
            }
        }
    }
}

fn is_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_name_continue(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

fn contains_introspection(text: &str) -> bool {
    for marker in ["__schema", "__type"] {
        for (index, _) in text.match_indices(marker) {
            let after = text[index + marker.len()..].chars().next();
            if !after.is_some_and(|character| character == '_' || character.is_ascii_alphanumeric())
            {
                return true;
            }
        }
    }
    false
}

fn media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media = value.split(';').next()?.trim().to_ascii_lowercase();
    (!media.is_empty()).then_some(media)
}

fn candidates(uri_query: Option<&str>, headers: &HeaderMap, body: &[u8]) -> Option<Vec<String>> {
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let mut candidates = Vec::new();
    if let Some(query) = uri_query {
        collect_form_queries(query, &mut candidates);
    }
    if body.is_empty() {
        return Some(deduplicate(candidates));
    }

    let media = media_type(headers);
    if media.as_deref() == Some("application/graphql")
        && let Ok(text) = std::str::from_utf8(body)
    {
        push_candidate(&mut candidates, text);
    }
    collect_json_body_queries(body, &mut candidates);
    if let Ok(text) = std::str::from_utf8(body) {
        collect_form_queries(text, &mut candidates);
    }
    if media.as_deref() == Some("multipart/form-data") {
        collect_multipart_queries(body, headers, &mut candidates);
    }
    if candidates.is_empty()
        && let Ok(text) = std::str::from_utf8(body)
    {
        // The endpoint is already known to be GraphQL, so fall back to the raw
        // body as a document candidate. This keeps a valid query visible when
        // the client lies about its content type; the parser rejects anything
        // that is not a document.
        push_candidate(&mut candidates, text);
    }
    let candidates = deduplicate(candidates);
    if candidates.len() > MAX_CANDIDATES {
        return None;
    }
    Some(candidates)
}

fn collect_multipart_queries(body: &[u8], headers: &HeaderMap, candidates: &mut Vec<String>) {
    for form in crate::decoding::decode_body_formats(body, headers) {
        let Ok(text) = std::str::from_utf8(&form) else {
            continue;
        };
        let mut offset = 0;
        let mut attempts = 0;
        for line in text.split_inclusive('\n') {
            let start = offset;
            offset += line.len();
            let trimmed = line.trim_start();
            if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
                continue;
            }
            if attempts >= MAX_MULTIPART_JSON_ATTEMPTS {
                break;
            }
            attempts += 1;
            collect_json_text_queries(&text[start..], candidates);
        }
    }
}

/// Extracts `query` values from a JSON GraphQL request without materializing
/// the whole document tree. Non-query members (notably `variables`) are skipped
/// through `IgnoredAny`, so a one-megabyte body does not turn into a one-
/// megabyte `serde_json::Value` graph. Both members of a duplicate `query` key
/// are collected, so a disagreement between first-wins and last-wins parsers
/// cannot hide a document.
/// A `query` member of a GraphQL request object. Non-string values are
/// consumed without building a value tree; a request with duplicate `query`
/// keys still contributes every string value, regardless of whether the
/// upstream parser keeps the first or the last.
enum QueryValue {
    Text(String),
    Other,
}

impl<'de> Deserialize<'de> for QueryValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct QueryValueVisitor;

        impl<'de> Visitor<'de> for QueryValueVisitor {
            type Value = QueryValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a GraphQL query string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Text(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Text(value))
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                QueryValue::deserialize(deserializer)
            }

            fn visit_bytes<E>(self, _: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(QueryValue::Other)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(QueryValue::Other)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(QueryValue::Other)
            }
        }

        deserializer.deserialize_any(QueryValueVisitor)
    }
}

#[derive(Debug, Default)]
struct QueryDocuments {
    queries: Vec<String>,
}

impl<'de> Deserialize<'de> for QueryDocuments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DocumentsVisitor;

        impl<'de> Visitor<'de> for DocumentsVisitor {
            type Value = QueryDocuments;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a GraphQL request object or batch array")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut documents = QueryDocuments::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "query" {
                        if let QueryValue::Text(query) = map.next_value::<QueryValue>()? {
                            documents.queries.push(query);
                        }
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(documents)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut documents = QueryDocuments::default();
                while let Some(element) = seq.next_element::<QueryDocuments>()? {
                    documents.queries.extend(element.queries);
                }
                Ok(documents)
            }
        }

        deserializer.deserialize_any(DocumentsVisitor)
    }
}

fn collect_json_body_queries(body: &[u8], candidates: &mut Vec<String>) {
    if let Ok(documents) = serde_json::from_slice::<QueryDocuments>(body) {
        for query in documents.queries {
            push_candidate(candidates, &query);
        }
    }
}

fn collect_json_text_queries(text: &str, candidates: &mut Vec<String>) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    if let Ok(documents) = QueryDocuments::deserialize(&mut deserializer) {
        for query in documents.queries {
            push_candidate(candidates, &query);
        }
    }
}

fn collect_form_queries(input: &str, candidates: &mut Vec<String>) {
    for pair in input.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if decode_component(name) == "query" {
            push_candidate(candidates, &decode_component(value));
        }
    }
}

fn decode_component(value: &str) -> String {
    let replaced: Cow<'_, str> = if value.contains('+') {
        Cow::Owned(value.replace('+', " "))
    } else {
        Cow::Borrowed(value)
    };
    crate::decoding::percent_decode(&replaced).into_owned()
}

fn push_candidate(candidates: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && candidates.len() <= MAX_CANDIDATES {
        candidates.push(value.to_owned());
    }
}

fn deduplicate(mut candidates: Vec<String>) -> Vec<String> {
    candidates.sort();
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn inspect_with(
        uri_query: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
        body_truncated: bool,
    ) -> Option<Violation> {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).expect("header"),
            );
        }
        inspect(
            uri_query,
            &headers,
            body,
            body_truncated,
            Limits {
                max_depth: 20,
                max_fields: 1000,
                block_introspection: false,
            },
        )
    }

    fn nested(depth: usize) -> String {
        let mut query = String::new();
        for _ in 0..depth {
            query.push_str("{ a ");
        }
        query.push_str(&"}".repeat(depth));
        query
    }

    fn json_body(query: &str) -> Vec<u8> {
        format!(
            "{{\"query\":{}}}",
            serde_json::to_string(query).expect("encode")
        )
        .into_bytes()
    }

    #[test]
    fn accepts_a_query_at_the_depth_limit() {
        assert_eq!(
            inspect_with(
                None,
                Some("application/json"),
                &json_body(&nested(20)),
                false
            ),
            None
        );
    }

    #[test]
    fn rejects_a_query_over_the_depth_limit() {
        let violation = inspect_with(
            None,
            Some("application/json"),
            &json_body(&nested(21)),
            false,
        );
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn expands_fragment_depth() {
        let mut query = String::from("query { ...F0 }");
        for level in 0..21 {
            query.push_str(&format!(
                " fragment F{level} on Query {{ a {{ ...F{} }} }}",
                level + 1
            ));
        }
        query.push_str(" fragment F21 on Query { a }");
        let violation = inspect_with(None, None, query.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn rejects_fragment_cycles() {
        let query =
            "query { ...A } fragment A on Query { a { ...B } } fragment B on Query { b { ...A } }";
        assert_eq!(
            inspect_with(None, None, query.as_bytes(), false),
            Some(Violation::Cyclic)
        );
    }

    #[test]
    fn rejects_undefined_fragment_spreads() {
        let query = "query A { ...Missing } query B { b }";
        assert_eq!(
            inspect_with(None, None, query.as_bytes(), false),
            Some(Violation::Ambiguous)
        );

        // The same document with an over-limit operation must still be
        // rejected rather than silently passing because of the missing
        // fragment.
        let query = format!(
            "query A {{ ...Missing }} query B {{ {} }}",
            nested(21).trim_start_matches('{').trim_end_matches('}')
        );
        assert!(
            matches!(
                inspect_with(None, None, query.as_bytes(), false),
                Some(Violation::Ambiguous | Violation::TooDeep { .. })
            ),
            "an undefined fragment must not hide a deep operation"
        );
    }

    #[test]
    fn rejects_duplicate_fragment_definitions() {
        let query = "query { ...A } fragment A on Query { a } fragment A on Query { b }";
        assert_eq!(
            inspect_with(None, None, query.as_bytes(), false),
            Some(Violation::Ambiguous)
        );
    }

    #[test]
    fn rejects_alias_floods() {
        let mut query = String::from("query {");
        for index in 0..1001 {
            query.push_str(&format!(" a{index}: field"));
        }
        query.push('}');
        let violation = inspect_with(None, None, query.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooManyFields { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn ignores_braces_in_strings_and_comments() {
        let query = "query { a(arg: \"{{{{\") { b } } # }}} \n }";
        assert_eq!(inspect_with(None, None, query.as_bytes(), false), None);
    }

    #[test]
    fn ignores_braces_in_block_strings() {
        let query = "query { a(arg: \"\"\" } } } \"\"\") { b } }";
        assert_eq!(inspect_with(None, None, query.as_bytes(), false), None);
    }

    #[test]
    fn accepts_a_shallow_fragment_document() {
        let query =
            "query Q($id: ID!) { node(id: $id) { ...Fields } } fragment Fields on Node { id name }";
        assert_eq!(inspect_with(None, None, query.as_bytes(), false), None);
    }

    #[test]
    fn detects_a_query_in_a_get_parameter() {
        let deep = nested(21);
        let encoded: String = url_encode(&deep);
        let violation = inspect_with(Some(&format!("query={encoded}")), None, b"", false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn detects_a_query_in_a_form_body() {
        let encoded = url_encode(&nested(21));
        let body = format!("query={encoded}&variables=%7B%7D");
        let violation = inspect_with(
            None,
            Some("application/x-www-form-urlencoded"),
            body.as_bytes(),
            false,
        );
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn detects_a_query_in_a_json_batch() {
        let body = format!(
            "[{{\"query\":\"{{ a }}\"}},{{\"query\":{}}}]",
            serde_json::to_string(&nested(21)).expect("encode")
        );
        let violation = inspect_with(None, Some("application/json"), body.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn ignores_the_content_type_when_parsing_json() {
        let violation = inspect_with(None, Some("text/plain"), &json_body(&nested(21)), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn ignores_a_utf8_bom_before_json() {
        let mut body = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(&json_body(&nested(21)));
        let violation = inspect_with(None, Some("application/json"), &body, false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn inspects_every_duplicate_query_key() {
        let body = format!(
            "{{\"query\":\"{{ a }}\",\"query\":{}}}",
            serde_json::to_string(&nested(21)).expect("encode")
        );
        let violation = inspect_with(None, Some("application/json"), body.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );

        // A non-string first value must not stop the collector before the
        // string value a last-wins parser would execute.
        let body = format!(
            "{{\"query\":123,\"query\":{}}}",
            serde_json::to_string(&nested(21)).expect("encode")
        );
        let violation = inspect_with(None, Some("application/json"), body.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn caps_inline_fragment_recursion() {
        // Inline fragments do not add a selection level, so they need a
        // separate parser recursion bound; this shape used to overflow the
        // stack before the node budget was reached.
        let mut query = String::from("{");
        for _ in 0..2_000 {
            query.push_str("...{");
        }
        query.push_str(&"}".repeat(2_001));
        assert_eq!(
            inspect_with(None, None, query.as_bytes(), false),
            Some(Violation::TooComplex)
        );
    }

    #[test]
    fn skips_a_bom_between_tokens() {
        let query = format!("query\u{feff}{}", nested(21));
        let violation = inspect_with(None, None, query.as_bytes(), false);
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn blocks_introspection_when_configured() {
        let headers = HeaderMap::new();
        let limits = Limits {
            max_depth: 20,
            max_fields: 1000,
            block_introspection: true,
        };
        assert_eq!(
            inspect(
                None,
                &headers,
                br#"{"query":"{__schema{types{name}}}"}"#,
                false,
                limits
            ),
            Some(Violation::Introspection)
        );
        assert_eq!(
            inspect(
                None,
                &headers,
                br#"{"query":"{__typename}"}"#,
                false,
                limits
            ),
            None
        );
    }

    #[test]
    fn detects_a_bare_application_graphql_body() {
        let violation = inspect_with(
            None,
            Some("application/graphql"),
            nested(21).as_bytes(),
            false,
        );
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn detects_multipart_operations() {
        let body = format!(
            "--X\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{}\r\n--X\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{{}}\r\n--X--\r\n",
            String::from_utf8(json_body(&nested(21))).expect("json")
        );
        let violation = inspect_with(
            None,
            Some("multipart/form-data; boundary=X"),
            body.as_bytes(),
            false,
        );
        assert!(
            matches!(violation, Some(Violation::TooDeep { .. })),
            "{violation:?}"
        );
    }

    #[test]
    fn rejects_multipart_bodies_without_an_operations_document() {
        let body = "--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nPNG\r\n--X--\r\n";
        assert_eq!(
            inspect_with(
                None,
                Some("multipart/form-data; boundary=X"),
                body.as_bytes(),
                false
            ),
            Some(Violation::Uninspectable)
        );
    }

    #[test]
    fn rejects_multipart_bodies_with_too_many_boundaries() {
        let body = format!(
            "--E\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{}\r\n--E--\r\n",
            String::from_utf8(json_body(&nested(21))).expect("json")
        );
        let content_type =
            "multipart/form-data; boundary=a; boundary=b; boundary=c; boundary=d; boundary=E";
        assert_eq!(
            inspect_with(None, Some(content_type), body.as_bytes(), false),
            Some(Violation::Uninspectable)
        );
    }

    #[test]
    fn rejects_an_incomplete_body() {
        let body = b"{\"query\":\"{ a ";
        assert_eq!(
            inspect_with(None, Some("application/json"), body, true),
            Some(Violation::Incomplete)
        );
        assert_eq!(
            inspect_with(None, Some("application/json"), body, false),
            None
        );

        // A complete shallow document in the prefix does not make a truncated
        // body safe: a second, deeper operation may follow in the stream.
        assert_eq!(
            inspect_with(
                Some("operationName=Deep"),
                Some("application/graphql"),
                b"query Shallow { a }",
                true
            ),
            Some(Violation::Incomplete)
        );
    }

    #[test]
    fn ignores_non_graphql_queries() {
        let body = b"{\"query\":\"select * from users\"}";
        assert_eq!(
            inspect_with(None, Some("application/json"), body, false),
            None
        );
    }

    #[test]
    fn bounds_parser_memory() {
        let mut query = String::from("query {");
        for index in 0..=MAX_NODES {
            query.push_str(&format!(" a{index}"));
        }
        query.push('}');
        assert_eq!(
            inspect_with(None, None, query.as_bytes(), false),
            Some(Violation::TooComplex)
        );
    }

    #[test]
    fn rejects_oversized_batches() {
        let batch = |count: usize| {
            let items = (0..count)
                .map(|index| format!("{{\"query\":\"{{ a{index} }}\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        };
        assert_eq!(
            inspect_with(
                None,
                Some("application/json"),
                batch(MAX_CANDIDATES).as_bytes(),
                false
            ),
            None
        );
        assert_eq!(
            inspect_with(
                None,
                Some("application/json"),
                batch(MAX_CANDIDATES + 1).as_bytes(),
                false
            ),
            Some(Violation::TooComplex)
        );
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x0BAD_F00D_DEAD_BEEFu64;
        for _ in 0..2_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = (state % 96) as usize;
            let mut body = Vec::with_capacity(length);
            for _ in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                body.push((state >> 33) as u8);
            }
            let _ = inspect_with(None, Some("application/json"), &body, false);
            let _ = inspect_with(None, Some("application/graphql"), &body, true);
            let _ = inspect(
                Some("query=%7B"),
                &HeaderMap::new(),
                &body,
                true,
                Limits {
                    max_depth: 5,
                    max_fields: 10,
                    block_introspection: false,
                },
            );
        }
    }

    fn url_encode(value: &str) -> String {
        let mut encoded = String::new();
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                b' ' => encoded.push_str("%20"),
                _ => encoded.push_str(&format!("%{byte:02X}")),
            }
        }
        encoded
    }
}
