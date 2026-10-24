//! In-tree YAML parser and serde deserializer for configuration and rule files.
//!
//! The parser builds a small [`value::Value`] tree and [`de`] implements
//! [`serde::Deserializer`] for it. The supported YAML subset is documented in
//! `docs/development.md`: block and flow collections, plain/quoted/block
//! scalars, and comments. Anchors, aliases, merge keys, explicit tags,
//! directives, and multiple documents are rejected.

mod de;
mod error;
mod parser;
mod value;

pub(crate) use error::Error;

use serde::de::DeserializeOwned;

/// Parse one YAML document and deserialize it into `T`.
///
/// The whole document is parsed before deserialization so every scalar keeps
/// its source spelling and style, which untagged enums and string fields rely
/// on. Schema errors are annotated with the current key or mapping location and
/// a cropped source line.
pub(crate) fn from_str<T>(input: &str) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    error::reset_location();
    let result = parser::parse(input).and_then(T::deserialize);
    error::reset_location();
    result.map_err(|mut error| {
        error.attach_source(input);
        error
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigSpec, RulesFileSpec};

    #[test]
    fn parses_the_real_configuration() {
        let spec: ConfigSpec =
            from_str(include_str!("../../rules.example.yaml")).expect("rules.example.yaml");
        assert!(!spec.categories.is_empty());
        assert!(
            spec.categories
                .iter()
                .any(|category| !category.rules.is_empty())
        );
    }

    #[test]
    fn parses_the_published_rule_set() {
        let spec: RulesFileSpec =
            from_str(include_str!("../../dist/rules.yaml")).expect("dist/rules.yaml");
        assert!(!spec.categories.is_empty());
    }

    #[test]
    fn classifies_unknown_fields_for_rule_updates() {
        let error = from_str::<RulesFileSpec>(
            "categories:\n  - name: sample\n    rules:\n      - name: sample\n        match: { regex: a, json_body: true }\n",
        )
        .expect_err("unknown field");
        assert!(error.is_unsupported_construct(), "{error}");
        assert!(error.summary().contains("json_body"), "{error}");
        assert!(error.to_string().contains("json_body"), "{error}");
    }

    #[test]
    fn classifies_unknown_variants_and_missing_fields() {
        let error = from_str::<RulesFileSpec>(
            "categories:\n  - name: sample\n    action: DROP\n    rules: []\n",
        )
        .expect_err("unknown variant");
        assert!(error.is_unsupported_construct(), "{error}");
        assert!(error.summary().contains("DROP"), "{error}");

        let error = from_str::<RulesFileSpec>(
            "categories:\n  - name: sample\n    rules:\n      - match: { regex: a }\n",
        )
        .expect_err("missing field");
        assert!(error.is_unsupported_construct(), "{error}");
        assert!(error.summary().contains("name"), "{error}");
    }

    #[test]
    fn ordinary_parse_failures_are_not_format_errors() {
        let error = from_str::<RulesFileSpec>("categories: [\n").expect_err("syntax");
        assert!(!error.is_unsupported_construct(), "{error}");
        let rendered = error.to_string();
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains('^'), "{rendered}");
    }

    #[test]
    fn parses_into_untyped_json_values() {
        let value: serde_json::Value = from_str(
            "name: sample\nenabled: true\nport: 8080\nratio: 0.5\nitems: [a, '404', null]\n",
        )
        .expect("json value");
        assert_eq!(value["name"], "sample");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["port"], 8080);
        assert_eq!(value["ratio"], 0.5);
        assert_eq!(value["items"][1], "404");
        assert!(value["items"][2].is_null());
    }

    #[test]
    fn parses_block_folded_and_multiline_plain_scalars() {
        let value: serde_json::Value = from_str(
            "literal: |\n  line one\n  line two\nfolded: >\n  line one\n  line two\nplain: a\n  b\n",
        )
        .expect("scalars");
        assert_eq!(value["literal"], "line one\nline two\n");
        assert_eq!(value["folded"], "line one line two\n");
        assert_eq!(value["plain"], "a b");
    }

    #[test]
    fn rejects_unsupported_constructs_and_empty_input() {
        for document in [
            "a: &x 1\nb: *x\n",
            "a: !!str 1\n",
            "a: 1\n---\nb: 2\n",
            "",
            "# only a comment\n",
        ] {
            assert!(
                from_str::<serde_json::Value>(document).is_err(),
                "{document}"
            );
        }
    }

    #[test]
    fn schema_errors_point_at_the_offending_key() {
        let error = from_str::<ConfigSpec>(
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nunknown: true\n",
        )
        .expect_err("unknown field");
        let rendered = error.to_string();
        assert!(rendered.contains("unknown field `unknown`"), "{rendered}");
        assert!(rendered.contains("line 3"), "{rendered}");
        assert!(rendered.contains('^'), "{rendered}");
    }

    #[test]
    fn mutated_documents_never_panic() {
        let seed = include_str!("../../rules.example.yaml").as_bytes();
        let mut state = 0x9e37_79b9u32;
        for _ in 0..512 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let start = (state as usize) % seed.len();
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let length = ((state >> 8) as usize % 256).max(1);
            let end = (start + length).min(seed.len());
            let mut mutated = seed.to_vec();
            match state % 3 {
                0 => mutated.truncate(start),
                1 => {
                    mutated.drain(start..end);
                }
                _ => {
                    let mut replacement = vec![b'['];
                    replacement.extend_from_slice(&seed[start..end]);
                    mutated.splice(start..end, replacement);
                }
            }
            if let Ok(text) = String::from_utf8(mutated) {
                let _ = from_str::<serde_json::Value>(&text);
            }
        }
    }
}
