//! In-tree YAML subset parser.
//!
//! The parser covers the constructs Kunato configuration and rule files use:
//! block and flow collections, plain/quoted/block scalars, comments, and a
//! single document. Anchors, aliases, merge keys, explicit tags, and directives
//! are rejected. Flow collections and quoted scalars must be on one line.

use crate::yaml::error::Error;
use crate::yaml::value::{MapBuilder, Scalar, Value};

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1_000_000;
/// Bound the line table. A 16 MiB document of very short lines would otherwise
/// allocate tens of millions of line entries before the node limit applies.
const MAX_LINES: usize = 1_000_000;

pub(crate) fn parse(input: &str) -> Result<Value, Error> {
    Parser::new(input)?.parse_document()
}

struct Line<'a> {
    number: usize,
    indent: usize,
    content: &'a str,
}

struct Parser<'a> {
    lines: Vec<Line<'a>>,
    index: usize,
    depth: usize,
    nodes: usize,
}

struct MappingEntry<'a> {
    key: Value,
    rest: &'a str,
    rest_column: usize,
}

struct FlowCursor<'a> {
    text: &'a str,
    pos: usize,
    line: usize,
    base_column: usize,
}

impl<'a> FlowCursor<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.pos += ch.len_utf8();
        }
    }

    fn skip_spaces(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn column(&self) -> usize {
        self.base_column + self.text[..self.pos].chars().count()
    }
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, Error> {
        let input = input.strip_prefix('\u{feff}').unwrap_or(input);
        let mut lines = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let number = index + 1;
            let mut indent = 0;
            for (offset, ch) in raw.char_indices() {
                match ch {
                    ' ' => indent += 1,
                    '\t' => {
                        return Err(Error::syntax(
                            "tab characters are not allowed for indentation",
                            number,
                            offset,
                        ));
                    }
                    _ => break,
                }
            }
            if lines.len() >= MAX_LINES {
                return Err(Error::syntax("document has too many lines", number, indent));
            }
            lines.push(Line {
                number,
                indent,
                content: &raw[indent..],
            });
        }
        Ok(Self {
            lines,
            index: 0,
            depth: 0,
            nodes: 0,
        })
    }

    fn parse_document(mut self) -> Result<Value, Error> {
        self.skip_ignorable();
        let Some(line) = self.lines.get(self.index) else {
            return Err(Error::syntax("unexpected end of input", 1, 0));
        };
        if line.content.starts_with('%') {
            return Err(Error::syntax(
                "YAML directives are not supported",
                line.number,
                line.indent,
            ));
        }
        if is_document_marker(line.content, "---") {
            self.index += 1;
            self.skip_ignorable();
        } else if document_marker_prefix(line.content) {
            return Err(Error::syntax(
                "document markers with content are not supported",
                line.number,
                line.indent,
            ));
        }
        self.skip_ignorable();
        let Some(line) = self.lines.get(self.index) else {
            return Err(Error::syntax("unexpected end of input", 1, 0));
        };
        if line.content.starts_with('%') {
            return Err(Error::syntax(
                "YAML directives are not supported",
                line.number,
                line.indent,
            ));
        }
        if is_document_marker(line.content, "---") {
            return Err(Error::syntax(
                "multiple YAML documents are not supported",
                line.number,
                line.indent,
            ));
        }
        if is_document_marker(line.content, "...") {
            return Err(Error::syntax(
                "document has no content",
                line.number,
                line.indent,
            ));
        }
        let indent = line.indent;
        let value = self.parse_block_node(indent)?;
        self.skip_ignorable();
        if let Some(line) = self.lines.get(self.index) {
            if is_document_marker(line.content, "...") {
                self.index += 1;
                self.skip_ignorable();
            }
            if let Some(line) = self.lines.get(self.index) {
                if is_document_marker(line.content, "---") || line.content.starts_with('%') {
                    return Err(Error::syntax(
                        "multiple YAML documents are not supported",
                        line.number,
                        line.indent,
                    ));
                }
                return Err(Error::syntax(
                    "unexpected content after the document",
                    line.number,
                    line.indent,
                ));
            }
        }
        Ok(value)
    }

    fn skip_ignorable(&mut self) {
        while let Some(line) = self.lines.get(self.index) {
            if line.content.trim().is_empty() || line.content.starts_with('#') {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn count_node(&mut self, line: usize, column: usize) -> Result<(), Error> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::syntax("document has too many nodes", line, column));
        }
        Ok(())
    }

    fn parse_block_node(&mut self, indent: usize) -> Result<Value, Error> {
        self.skip_ignorable();
        let Some(line) = self.lines.get(self.index) else {
            return Err(Error::syntax("unexpected end of input", 1, 0));
        };
        if line.indent != indent {
            return Err(Error::syntax(
                "unexpected indentation",
                line.number,
                line.indent,
            ));
        }
        let (number, column, content) = (line.number, line.indent, line.content);
        if is_sequence_entry(content) {
            return self.parse_block_seq(indent);
        }
        if split_mapping_entry(content, number, column)?.is_some() {
            return self.parse_block_map(indent, None);
        }
        self.index += 1;
        if content.starts_with('?') {
            return Err(Error::syntax(
                "explicit mapping keys are not supported",
                number,
                column,
            ));
        }
        self.parse_inline_or_scalar(content, indent, column, number)
    }

    fn parse_block_seq(&mut self, indent: usize) -> Result<Value, Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            let line = self.lines.get(self.index);
            return Err(Error::syntax(
                "document is nested too deeply",
                line.map_or(1, |line| line.number),
                line.map_or(0, |line| line.indent),
            ));
        }
        let Some(line) = self.lines.get(self.index) else {
            self.depth -= 1;
            return Err(Error::syntax("unexpected end of input", 1, 0));
        };
        let start_line = line.number;
        let start_column = line.indent;
        let result = self.parse_seq_items(indent, start_line, start_column, None);
        self.depth -= 1;
        result
    }

    fn parse_seq_items(
        &mut self,
        indent: usize,
        start_line: usize,
        start_column: usize,
        first: Option<(&'a str, usize, usize)>,
    ) -> Result<Value, Error> {
        let mut items = Vec::new();
        if let Some((text, line, column)) = first {
            items.push(self.parse_seq_item(text, indent, line, column)?);
        }
        loop {
            self.skip_ignorable();
            let Some(line) = self.lines.get(self.index) else {
                break;
            };
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(Error::syntax(
                    "unexpected indentation",
                    line.number,
                    line.indent,
                ));
            }
            if !is_sequence_entry(line.content) {
                break;
            }
            let (number, content) = (line.number, line.content);
            let rest_start = if content == "-" { 1 } else { 2 };
            let rest = &content[rest_start..];
            let rest_column = line.indent + rest_start;
            self.index += 1;
            items.push(self.parse_seq_item(rest, indent, number, rest_column)?);
        }
        self.count_node(start_line, start_column)?;
        Ok(Value::Seq {
            items,
            line: start_line,
            column: start_column,
        })
    }

    fn parse_seq_item(
        &mut self,
        rest: &'a str,
        seq_indent: usize,
        line: usize,
        column: usize,
    ) -> Result<Value, Error> {
        let trimmed = rest.trim_start_matches([' ', '\t']);
        let column = column + rest[..rest.len() - trimmed.len()].chars().count();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return self.parse_nested_or_null(seq_indent, line, column, false);
        }
        if is_sequence_entry(trimmed) {
            let rest_start = if trimmed == "-" { 1 } else { 2 };
            let inner = &trimmed[rest_start..];
            let inner_column = column + rest_start;
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                self.depth -= 1;
                return Err(Error::syntax("document is nested too deeply", line, column));
            }
            let result =
                self.parse_seq_items(column, line, column, Some((inner, line, inner_column)));
            self.depth -= 1;
            return result;
        }
        if let Some(entry) = split_mapping_entry(trimmed, line, column)? {
            self.count_node(line, column)?;
            let value = self.parse_value_after_indicator(
                entry.rest,
                column,
                entry.rest_column,
                line,
                true,
            )?;
            return self.parse_block_map(column, Some((entry.key, value, line, column)));
        }
        self.parse_inline_or_scalar(trimmed, seq_indent, column, line)
    }

    fn parse_block_map(
        &mut self,
        indent: usize,
        first: Option<(Value, Value, usize, usize)>,
    ) -> Result<Value, Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            let line = self.lines.get(self.index);
            return Err(Error::syntax(
                "document is nested too deeply",
                line.map_or(1, |line| line.number),
                line.map_or(0, |line| line.indent),
            ));
        }
        let result = self.parse_map_entries(indent, first);
        self.depth -= 1;
        result
    }

    fn parse_map_entries(
        &mut self,
        indent: usize,
        first: Option<(Value, Value, usize, usize)>,
    ) -> Result<Value, Error> {
        let (start_line, start_column) = match &first {
            Some((_, _, line, column)) => (*line, *column),
            None => {
                let Some(line) = self.lines.get(self.index) else {
                    return Err(Error::syntax("unexpected end of input", 1, 0));
                };
                (line.number, line.indent)
            }
        };
        let mut builder = MapBuilder::new(start_line, start_column);
        if let Some((key, value, line, column)) = first {
            builder.insert(key, value, line, column)?;
        }
        loop {
            self.skip_ignorable();
            let Some(line) = self.lines.get(self.index) else {
                break;
            };
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(Error::syntax(
                    "unexpected indentation",
                    line.number,
                    line.indent,
                ));
            }
            let (number, line_indent, content) = (line.number, line.indent, line.content);
            let Some(entry) = split_mapping_entry(content, number, line_indent)? else {
                break;
            };
            self.index += 1;
            self.count_node(number, line_indent)?;
            let value = self.parse_value_after_indicator(
                entry.rest,
                indent,
                entry.rest_column,
                number,
                true,
            )?;
            builder.insert(entry.key, value, number, line_indent)?;
        }
        self.count_node(start_line, start_column)?;
        Ok(builder.finish())
    }

    fn parse_value_after_indicator(
        &mut self,
        rest: &'a str,
        parent_indent: usize,
        column: usize,
        line: usize,
        allow_indentless_seq: bool,
    ) -> Result<Value, Error> {
        let trimmed = rest.trim_start_matches([' ', '\t']);
        let column = column + rest[..rest.len() - trimmed.len()].chars().count();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return self.parse_nested_or_null(parent_indent, line, column, allow_indentless_seq);
        }
        self.parse_inline_or_scalar(trimmed, parent_indent, column, line)
    }

    fn parse_nested_or_null(
        &mut self,
        parent_indent: usize,
        line: usize,
        column: usize,
        allow_indentless_seq: bool,
    ) -> Result<Value, Error> {
        self.skip_ignorable();
        if let Some(next) = self.lines.get(self.index) {
            if next.indent > parent_indent {
                return self.parse_block_node(next.indent);
            }
            if allow_indentless_seq
                && next.indent == parent_indent
                && is_sequence_entry(next.content)
            {
                return self.parse_block_seq(parent_indent);
            }
        }
        self.count_node(line, column)?;
        Ok(Value::Scalar(Scalar {
            text: String::new(),
            plain: true,
            line,
            column,
        }))
    }

    fn parse_inline_or_scalar(
        &mut self,
        text: &'a str,
        parent_indent: usize,
        column: usize,
        line: usize,
    ) -> Result<Value, Error> {
        match text.chars().next() {
            Some('&') => Err(Error::syntax(
                "YAML anchors are not supported",
                line,
                column,
            )),
            Some('*') => Err(Error::syntax(
                "YAML aliases are not supported",
                line,
                column,
            )),
            Some('!') => Err(Error::syntax(
                "explicit YAML tags are not supported",
                line,
                column,
            )),
            Some('%') => Err(Error::syntax(
                "YAML directives are not supported",
                line,
                column,
            )),
            Some('@') | Some('`') => Err(Error::syntax(
                "reserved YAML indicator is not supported",
                line,
                column,
            )),
            Some('?') => Err(Error::syntax(
                "explicit mapping keys are not supported",
                line,
                column,
            )),
            Some('|') | Some('>') => self.parse_block_scalar(text, parent_indent, line, column),
            Some('[') | Some('{') => self.parse_flow_text(text, line, column),
            Some('\'') | Some('"') => {
                let (value, consumed) = parse_quoted_text(text, line, column)?;
                self.ensure_trailing(&text[consumed..], line, column + consumed)?;
                self.count_node(line, column)?;
                Ok(Value::Scalar(Scalar {
                    text: value,
                    plain: false,
                    line,
                    column,
                }))
            }
            None => self.null_scalar(line, column),
            Some(_) => {
                let plain = strip_comment(text).trim_end();
                if plain.is_empty() {
                    return self.null_scalar(line, column);
                }
                if plain.contains(": ") {
                    return Err(Error::syntax(
                        "mapping values are not allowed in a plain scalar",
                        line,
                        column,
                    ));
                }
                self.parse_plain_with_continuation(plain, parent_indent, line, column)
            }
        }
    }

    fn parse_plain_with_continuation(
        &mut self,
        first: &str,
        parent_indent: usize,
        line: usize,
        column: usize,
    ) -> Result<Value, Error> {
        let mut text = first.to_owned();
        loop {
            let mut look = self.index;
            let mut blanks = 0;
            while let Some(next) = self.lines.get(look) {
                if next.content.trim().is_empty() {
                    blanks += 1;
                    look += 1;
                } else if next.content.starts_with('#') {
                    look += 1;
                } else {
                    break;
                }
            }
            let Some(next) = self.lines.get(look) else {
                break;
            };
            if next.indent <= parent_indent {
                break;
            }
            if is_sequence_entry(next.content) {
                return Err(Error::syntax(
                    "unexpected indentation after a plain scalar",
                    next.number,
                    next.indent,
                ));
            }
            if split_mapping_entry(next.content, next.number, next.indent)?.is_some() {
                return Err(Error::syntax(
                    "unexpected indentation after a plain scalar",
                    next.number,
                    next.indent,
                ));
            }
            if blanks > 0 {
                for _ in 0..blanks {
                    text.push('\n');
                }
            } else {
                text.push(' ');
            }
            text.push_str(strip_comment(next.content).trim_end());
            self.index = look + 1;
        }
        self.count_node(line, column)?;
        Ok(Value::Scalar(Scalar {
            text,
            plain: true,
            line,
            column,
        }))
    }

    fn null_scalar(&mut self, line: usize, column: usize) -> Result<Value, Error> {
        self.count_node(line, column)?;
        Ok(Value::Scalar(Scalar {
            text: String::new(),
            plain: true,
            line,
            column,
        }))
    }

    fn ensure_trailing(&self, rest: &str, line: usize, column: usize) -> Result<(), Error> {
        let trimmed = rest.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            Ok(())
        } else {
            Err(Error::syntax(
                "unexpected content after value",
                line,
                column,
            ))
        }
    }

    fn parse_flow_text(
        &mut self,
        text: &'a str,
        line: usize,
        column: usize,
    ) -> Result<Value, Error> {
        let mut cursor = FlowCursor {
            text,
            pos: 0,
            line,
            base_column: column,
        };
        let value = self.parse_flow_value(&mut cursor, 0)?;
        cursor.skip_spaces();
        if cursor.pos < cursor.text.len() && !cursor.rest().starts_with('#') {
            return Err(Error::syntax(
                "unexpected content after flow value",
                line,
                cursor.column(),
            ));
        }
        Ok(value)
    }

    fn parse_flow_value(
        &mut self,
        cursor: &mut FlowCursor<'a>,
        depth: usize,
    ) -> Result<Value, Error> {
        cursor.skip_spaces();
        let Some(ch) = cursor.peek() else {
            return Err(Error::syntax(
                "unterminated flow collection",
                cursor.line,
                cursor.column(),
            ));
        };
        match ch {
            '[' => self.parse_flow_seq(cursor, depth),
            '{' => self.parse_flow_map(cursor, depth),
            '\'' | '"' => {
                let column = cursor.column();
                let (text, consumed) = parse_quoted_text(cursor.rest(), cursor.line, column)?;
                cursor.pos += consumed;
                self.count_node(cursor.line, column)?;
                Ok(Value::Scalar(Scalar {
                    text,
                    plain: false,
                    line: cursor.line,
                    column,
                }))
            }
            '&' => Err(Error::syntax(
                "YAML anchors are not supported",
                cursor.line,
                cursor.column(),
            )),
            '*' => Err(Error::syntax(
                "YAML aliases are not supported",
                cursor.line,
                cursor.column(),
            )),
            '!' => Err(Error::syntax(
                "explicit YAML tags are not supported",
                cursor.line,
                cursor.column(),
            )),
            ',' | ']' | '}' => Err(Error::syntax(
                "unexpected flow indicator",
                cursor.line,
                cursor.column(),
            )),
            _ => {
                let column = cursor.column();
                let text = scan_flow_plain(cursor);
                if text.is_empty() {
                    return Err(Error::syntax("expected a flow value", cursor.line, column));
                }
                self.count_node(cursor.line, column)?;
                Ok(Value::Scalar(Scalar {
                    text,
                    plain: true,
                    line: cursor.line,
                    column,
                }))
            }
        }
    }

    fn parse_flow_seq(
        &mut self,
        cursor: &mut FlowCursor<'a>,
        depth: usize,
    ) -> Result<Value, Error> {
        if self.depth + depth >= MAX_DEPTH {
            return Err(Error::syntax(
                "document is nested too deeply",
                cursor.line,
                cursor.column(),
            ));
        }
        let line = cursor.line;
        let column = cursor.column();
        cursor.bump();
        let mut items = Vec::new();
        loop {
            cursor.skip_spaces();
            if cursor.peek() == Some(']') {
                cursor.bump();
                break;
            }
            if !items.is_empty() {
                if cursor.peek() != Some(',') {
                    return Err(Error::syntax(
                        "expected `,` or `]` in flow sequence",
                        cursor.line,
                        cursor.column(),
                    ));
                }
                cursor.bump();
                cursor.skip_spaces();
                if cursor.peek() == Some(']') {
                    cursor.bump();
                    break;
                }
            }
            items.push(self.parse_flow_value(cursor, depth + 1)?);
        }
        self.count_node(line, column)?;
        Ok(Value::Seq {
            items,
            line,
            column,
        })
    }

    fn parse_flow_map(
        &mut self,
        cursor: &mut FlowCursor<'a>,
        depth: usize,
    ) -> Result<Value, Error> {
        if self.depth + depth >= MAX_DEPTH {
            return Err(Error::syntax(
                "document is nested too deeply",
                cursor.line,
                cursor.column(),
            ));
        }
        let line = cursor.line;
        let column = cursor.column();
        cursor.bump();
        let mut builder = MapBuilder::new(line, column);
        let mut first = true;
        loop {
            cursor.skip_spaces();
            if cursor.peek() == Some('}') {
                cursor.bump();
                break;
            }
            if !first {
                if cursor.peek() != Some(',') {
                    return Err(Error::syntax(
                        "expected `,` or `}` in flow mapping",
                        cursor.line,
                        cursor.column(),
                    ));
                }
                cursor.bump();
                cursor.skip_spaces();
                if cursor.peek() == Some('}') {
                    cursor.bump();
                    break;
                }
            }
            first = false;
            let (key, key_line, key_column) = self.parse_flow_key(cursor, depth + 1)?;
            cursor.skip_spaces();
            let value = if cursor.peek() == Some(':') {
                cursor.bump();
                self.parse_flow_value(cursor, depth + 1)?
            } else {
                self.null_scalar(key_line, key_column)?
            };
            builder.insert(key, value, key_line, key_column)?;
        }
        self.count_node(line, column)?;
        Ok(builder.finish())
    }

    fn parse_flow_key(
        &mut self,
        cursor: &mut FlowCursor<'a>,
        depth: usize,
    ) -> Result<(Value, usize, usize), Error> {
        cursor.skip_spaces();
        let line = cursor.line;
        let column = cursor.column();
        match cursor.peek() {
            Some('\'') | Some('"') => {
                let (text, consumed) = parse_quoted_text(cursor.rest(), line, column)?;
                cursor.pos += consumed;
                self.count_node(line, column)?;
                Ok((
                    Value::Scalar(Scalar {
                        text,
                        plain: false,
                        line,
                        column,
                    }),
                    line,
                    column,
                ))
            }
            Some('[') | Some('{') => {
                let value = self.parse_flow_value(cursor, depth)?;
                Ok((value, line, column))
            }
            Some('&') => Err(Error::syntax(
                "YAML anchors are not supported",
                line,
                column,
            )),
            Some('*') => Err(Error::syntax(
                "YAML aliases are not supported",
                line,
                column,
            )),
            Some('!') => Err(Error::syntax(
                "explicit YAML tags are not supported",
                line,
                column,
            )),
            Some(',') | Some('}') => {
                Err(Error::syntax("expected a flow mapping key", line, column))
            }
            Some(_) => {
                let text = scan_flow_plain(cursor);
                if text.is_empty() {
                    return Err(Error::syntax("expected a flow mapping key", line, column));
                }
                self.count_node(line, column)?;
                Ok((
                    Value::Scalar(Scalar {
                        text,
                        plain: true,
                        line,
                        column,
                    }),
                    line,
                    column,
                ))
            }
            None => Err(Error::syntax("unterminated flow mapping", line, column)),
        }
    }

    fn parse_block_scalar(
        &mut self,
        text: &'a str,
        parent_indent: usize,
        line: usize,
        column: usize,
    ) -> Result<Value, Error> {
        let mut chars = text.chars();
        let Some(indicator) = chars.next() else {
            return Err(Error::syntax("empty block scalar", line, column));
        };
        if indicator != '|' && indicator != '>' {
            return Err(Error::syntax("invalid block scalar", line, column));
        }
        let rest = &text[indicator.len_utf8()..];
        let mut chomp = Chomp::Clip;
        let mut explicit_indent = None;
        let mut header_end = rest.len();
        for (offset, ch) in rest.char_indices() {
            match ch {
                ' ' | '\t' | '#' => {
                    header_end = offset;
                    break;
                }
                '+' | '-' => {
                    if chomp != Chomp::Clip {
                        return Err(Error::syntax(
                            "duplicate block scalar chomping indicator",
                            line,
                            column,
                        ));
                    }
                    chomp = if ch == '+' { Chomp::Keep } else { Chomp::Strip };
                }
                '1'..='9' => {
                    if explicit_indent.is_some() {
                        return Err(Error::syntax(
                            "duplicate block scalar indentation indicator",
                            line,
                            column,
                        ));
                    }
                    explicit_indent = Some(ch as usize - '0' as usize);
                }
                _ => {
                    return Err(Error::syntax("invalid block scalar header", line, column));
                }
            }
        }
        let trailing = &rest[header_end..];
        let trailing_trimmed = trailing.trim_start_matches([' ', '\t']);
        if !trailing_trimmed.is_empty() && !trailing_trimmed.starts_with('#') {
            return Err(Error::syntax(
                "unexpected content after block scalar header",
                line,
                column,
            ));
        }
        let content_indent = match explicit_indent {
            Some(digits) => Some(parent_indent + digits),
            None => {
                let mut look = self.index;
                loop {
                    let Some(next) = self.lines.get(look) else {
                        break None;
                    };
                    if next.content.trim().is_empty() {
                        look += 1;
                        continue;
                    }
                    if next.indent > parent_indent {
                        break Some(next.indent);
                    }
                    break None;
                }
            }
        };
        let Some(content_indent) = content_indent else {
            self.count_node(line, column)?;
            return Ok(Value::Scalar(Scalar {
                text: String::new(),
                plain: false,
                line,
                column,
            }));
        };

        let mut content = Vec::new();
        while let Some(next) = self.lines.get(self.index) {
            if next.content.trim().is_empty() {
                content.push(String::new());
                self.index += 1;
                continue;
            }
            if next.indent < content_indent {
                break;
            }
            let extra = next.indent - content_indent;
            let mut text = String::with_capacity(extra + next.content.len());
            for _ in 0..extra {
                text.push(' ');
            }
            text.push_str(next.content);
            content.push(text);
            self.index += 1;
        }

        let text = if indicator == '|' {
            literal_scalar(&content, chomp)
        } else {
            folded_scalar(&content, chomp)
        };
        self.count_node(line, column)?;
        Ok(Value::Scalar(Scalar {
            text,
            plain: false,
            line,
            column,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chomp {
    Clip,
    Strip,
    Keep,
}

fn is_sequence_entry(content: &str) -> bool {
    content == "-" || content.starts_with("- ") || content.starts_with("-\t")
}

fn is_document_marker(text: &str, marker: &str) -> bool {
    strip_comment(text).trim_end() == marker
}

fn document_marker_prefix(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("---") else {
        return false;
    };
    rest.is_empty() || rest.starts_with([' ', '\t', '#'])
}

fn strip_comment(text: &str) -> &str {
    for (offset, ch) in text.char_indices() {
        if ch == '#'
            && (offset == 0 || text[..offset].ends_with(' ') || text[..offset].ends_with('\t'))
        {
            return &text[..offset];
        }
    }
    text
}

fn split_mapping_entry<'a>(
    text: &'a str,
    line: usize,
    base_column: usize,
) -> Result<Option<MappingEntry<'a>>, Error> {
    let Some(first) = text.chars().next() else {
        return Ok(None);
    };
    if first == '[' || first == '{' {
        return Ok(None);
    }
    if first == '&' {
        return Err(Error::syntax(
            "YAML anchors are not supported",
            line,
            base_column,
        ));
    }
    if first == '*' {
        return Err(Error::syntax(
            "YAML aliases are not supported",
            line,
            base_column,
        ));
    }
    if first == '!' {
        return Err(Error::syntax(
            "explicit YAML tags are not supported",
            line,
            base_column,
        ));
    }
    if first == '?' {
        return Err(Error::syntax(
            "explicit mapping keys are not supported",
            line,
            base_column,
        ));
    }
    if first == '\'' || first == '"' {
        let (key_text, consumed) = parse_quoted_text(text, line, base_column)?;
        let after_quote = &text[consumed..];
        let trimmed = after_quote.trim_start_matches([' ', '\t']);
        let colon_offset = consumed + (after_quote.len() - trimmed.len());
        if !trimmed.starts_with(':') {
            return Ok(None);
        }
        let after_colon = &trimmed[1..];
        if !after_colon.is_empty() && !after_colon.starts_with([' ', '\t']) {
            return Ok(None);
        }
        let rest = after_colon.trim_start_matches([' ', '\t']);
        let rest_column = base_column
            + text[..colon_offset + 1].chars().count()
            + (after_colon.len() - rest.len());
        return Ok(Some(MappingEntry {
            key: Value::Scalar(Scalar {
                text: key_text,
                plain: false,
                line,
                column: base_column,
            }),
            rest,
            rest_column,
        }));
    }

    let mut colon = None;
    for (offset, ch) in text.char_indices() {
        if ch == '#'
            && (offset == 0 || text[..offset].ends_with(' ') || text[..offset].ends_with('\t'))
        {
            return Ok(None);
        }
        if ch == ':' {
            let next = text[offset + 1..].chars().next();
            if next.is_none() || matches!(next, Some(' ' | '\t')) {
                colon = Some(offset);
                break;
            }
        }
    }
    let Some(colon) = colon else {
        return Ok(None);
    };
    let key_text = text[..colon].trim_end();
    if key_text.is_empty() {
        return Ok(None);
    }
    let after_colon = &text[colon + 1..];
    let rest = after_colon.trim_start_matches([' ', '\t']);
    let rest_column =
        base_column + text[..colon + 1].chars().count() + (after_colon.len() - rest.len());
    Ok(Some(MappingEntry {
        key: Value::Scalar(Scalar {
            text: key_text.to_owned(),
            plain: true,
            line,
            column: base_column,
        }),
        rest,
        rest_column,
    }))
}

fn parse_quoted_text(
    text: &str,
    line: usize,
    base_column: usize,
) -> Result<(String, usize), Error> {
    let quote = text
        .chars()
        .next()
        .ok_or_else(|| Error::syntax("expected a quoted scalar", line, base_column))?;
    if quote != '\'' && quote != '"' {
        return Err(Error::syntax("expected a quoted scalar", line, base_column));
    }
    let mut out = String::new();
    let mut iter = text.char_indices().skip(1).peekable();
    while let Some((offset, ch)) = iter.next() {
        if quote == '\'' {
            if ch == '\'' {
                if iter.peek().is_some_and(|(_, ch)| *ch == '\'') {
                    iter.next();
                    out.push('\'');
                } else {
                    return Ok((out, offset + 1));
                }
            } else {
                out.push(ch);
            }
            continue;
        }
        match ch {
            '"' => return Ok((out, offset + 1)),
            '\\' => {
                let Some((escape_offset, escape)) = iter.next() else {
                    return Err(Error::syntax(
                        "unterminated escape sequence",
                        line,
                        base_column + text[..offset].chars().count(),
                    ));
                };
                match escape {
                    '0' => out.push('\0'),
                    'a' => out.push('\u{7}'),
                    'b' => out.push('\u{8}'),
                    't' => out.push('\t'),
                    'n' => out.push('\n'),
                    'v' => out.push('\u{b}'),
                    'f' => out.push('\u{c}'),
                    'r' => out.push('\r'),
                    'e' => out.push('\u{1b}'),
                    ' ' => out.push(' '),
                    '"' => out.push('"'),
                    '/' => out.push('/'),
                    '\\' => out.push('\\'),
                    'N' => out.push('\u{85}'),
                    '_' => out.push('\u{a0}'),
                    'L' => out.push('\u{2028}'),
                    'P' => out.push('\u{2029}'),
                    'x' | 'u' | 'U' => {
                        let digits = match escape {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let mut value = 0u32;
                        for _ in 0..digits {
                            let Some((_, digit)) = iter.next() else {
                                return Err(Error::syntax(
                                    "unterminated Unicode escape",
                                    line,
                                    base_column + text[..escape_offset].chars().count(),
                                ));
                            };
                            let Some(digit) = digit.to_digit(16) else {
                                return Err(Error::syntax(
                                    "invalid Unicode escape",
                                    line,
                                    base_column + text[..escape_offset].chars().count(),
                                ));
                            };
                            value = value * 16 + digit;
                        }
                        let Some(ch) = char::from_u32(value) else {
                            return Err(Error::syntax(
                                "invalid Unicode code point",
                                line,
                                base_column + text[..escape_offset].chars().count(),
                            ));
                        };
                        out.push(ch);
                    }
                    other => {
                        return Err(Error::syntax(
                            format!("invalid escape sequence `\\{other}`"),
                            line,
                            base_column + text[..escape_offset].chars().count(),
                        ));
                    }
                }
            }
            _ => out.push(ch),
        }
    }
    Err(Error::syntax(
        "unterminated quoted scalar",
        line,
        base_column,
    ))
}

fn scan_flow_plain(cursor: &mut FlowCursor<'_>) -> String {
    let start = cursor.pos;
    let mut end = cursor.pos;
    for (offset, ch) in cursor.rest().char_indices() {
        let absolute = cursor.pos + offset;
        match ch {
            ',' | ']' | '}' => break,
            ':' => {
                let next = cursor.text[absolute + 1..].chars().next();
                if next.is_none() || matches!(next, Some(' ' | '\t' | ',' | ']' | '}')) {
                    break;
                }
                end = absolute + ch.len_utf8();
            }
            '#' => {
                if absolute == start
                    || cursor.text[..absolute].ends_with(' ')
                    || cursor.text[..absolute].ends_with('\t')
                {
                    break;
                }
                end = absolute + ch.len_utf8();
            }
            _ => end = absolute + ch.len_utf8(),
        }
    }
    let text = cursor.text[start..end].trim().to_owned();
    cursor.pos = end;
    text
}

fn literal_scalar(lines: &[String], chomp: Chomp) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut text = lines.join("\n");
    match chomp {
        Chomp::Strip => {
            while text.ends_with('\n') {
                text.pop();
            }
        }
        Chomp::Clip => {
            while text.ends_with('\n') {
                text.pop();
            }
            if !text.is_empty() {
                text.push('\n');
            }
        }
        Chomp::Keep => text.push('\n'),
    }
    text
}

fn folded_scalar(lines: &[String], chomp: Chomp) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut text = String::new();
    let mut pending_blank = 0;
    let mut first = true;
    let mut previous_more_indented = false;
    for line in lines {
        if line.is_empty() {
            pending_blank += 1;
            continue;
        }
        let more_indented = line.starts_with(' ');
        if !first {
            if pending_blank > 0 {
                for _ in 0..pending_blank {
                    text.push('\n');
                }
            } else if more_indented || previous_more_indented {
                text.push('\n');
            } else {
                text.push(' ');
            }
        } else {
            for _ in 0..pending_blank {
                text.push('\n');
            }
        }
        text.push_str(line);
        pending_blank = 0;
        previous_more_indented = more_indented;
        first = false;
    }
    match chomp {
        Chomp::Strip => {
            while text.ends_with('\n') {
                text.pop();
            }
        }
        Chomp::Clip => {
            while text.ends_with('\n') {
                text.pop();
            }
            if !text.is_empty() {
                text.push('\n');
            }
        }
        Chomp::Keep => {
            for _ in 0..pending_blank + 1 {
                text.push('\n');
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(document: &str) -> serde_json::Value {
        crate::yaml::from_str(document).expect("valid YAML")
    }

    fn error(document: &str) -> String {
        crate::yaml::from_str::<serde_json::Value>(document)
            .expect_err("invalid YAML")
            .to_string()
    }

    #[test]
    fn parses_block_fold_and_compact_collections() {
        let value = json(
            "categories:\n  - name: sample\n    rules:\n      - name: r\n        match: { path: /x, in: [query, body] }\n",
        );
        assert_eq!(value["categories"][0]["rules"][0]["match"]["in"][1], "body");

        let value = json("a:\n  - - x\n    - why\n  - z\n");
        assert_eq!(value["a"][0][1], "why");
        assert_eq!(value["a"][1], "z");

        let value = json("a:\n- x\n- why\n");
        assert_eq!(value["a"][1], "why");
    }

    #[test]
    fn parses_flow_collections_and_quoted_scalars() {
        let value = json("a: {b: [1, 2.5, true, null, 'x,y'], c: \"d\"}\n");
        assert_eq!(value["a"]["b"][0], 1);
        assert_eq!(value["a"]["b"][1], 2.5);
        assert_eq!(value["a"]["b"][2], true);
        assert!(value["a"]["b"][3].is_null());
        assert_eq!(value["a"]["b"][4], "x,y");

        let value = json("a: \"line\\nbreak\\t\\\"q\\\" \\u0041\"\nb: 'it''s'\n");
        assert_eq!(value["a"], "line\nbreak\t\"q\" A");
        assert_eq!(value["b"], "it's");
    }

    #[test]
    fn parses_block_scalars_and_multiline_plain_scalars() {
        let value = json(
            "literal: |\n  one\n  two\nfolded: >\n  one\n  two\nstrip: |-\n  one\nkeep: |+\n  one\n\nplain: a\n  b\n",
        );
        assert_eq!(value["literal"], "one\ntwo\n");
        assert_eq!(value["folded"], "one two\n");
        assert_eq!(value["strip"], "one");
        assert_eq!(value["keep"], "one\n\n");
        assert_eq!(value["plain"], "a b");
    }

    #[test]
    fn handles_bom_crlf_and_comments() {
        let value = json("\u{feff}a: 1 # inline\r\n# full line\r\nb: 2\r\n");
        assert_eq!(value["a"], 1);
        assert_eq!(value["b"], 2);
    }

    #[test]
    fn rejects_unsupported_constructs() {
        for (document, expected) in [
            ("a: &x 1\nb: *x\n", "anchors are not supported"),
            ("a: !!str 1\n", "tags are not supported"),
            ("a: 1\n---\nb: 2\n", "multiple YAML documents"),
            ("<<: {a: 1}\n", "merge keys are not supported"),
            ("%YAML 1.2\n---\na: 1\n", "directives are not supported"),
            ("a:\n\tb: 1\n", "tab characters"),
            ("? a\n: b\n", "explicit mapping keys"),
            ("a: 1\na: 2\n", "duplicate mapping key"),
        ] {
            let message = error(document);
            assert!(
                message.contains(expected),
                "{document:?}: {message} (expected {expected})"
            );
        }
    }

    #[test]
    fn rejects_deep_nesting_and_empty_input() {
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(error(&deep).contains("nested too deeply"));
        assert!(error("").contains("unexpected end of input"));
        assert!(error("# only a comment\n").contains("unexpected end of input"));
    }

    #[test]
    fn parses_root_scalars_and_flow_values() {
        assert_eq!(json("404\n"), 404);
        assert_eq!(json("'404'\n"), "404");
        assert_eq!(json("[a, {b: c}]\n")[1]["b"], "c");
    }

    #[test]
    fn parses_empty_and_trailing_flow_and_comments() {
        let value =
            json("a: []\nb: {}\nc: [1,]\nd: {x: 1,}\ne: [1, 2] # comment\nf: \"x\" # comment\n");
        assert!(value["a"].as_array().unwrap().is_empty());
        assert!(value["b"].as_object().unwrap().is_empty());
        assert_eq!(value["c"][0], 1);
        assert_eq!(value["d"]["x"], 1);
        assert_eq!(value["e"][1], 2);
        assert_eq!(value["f"], "x");
    }

    #[test]
    fn parses_document_markers_and_explicit_block_indent() {
        let value = json("---\na: |2\n  x\n...\n");
        assert_eq!(value["a"], "x\n");
        let value = json("--- # start\na: 1\n... # end\n");
        assert_eq!(value["a"], 1);
        assert_eq!(json("---: x\n")["---"], "x");
        assert!(error("--- a: 1\n").contains("document markers with content"));
        assert!(error("---\n---\na: 1\n").contains("multiple YAML documents"));
    }

    #[test]
    fn rejects_mapping_values_inside_plain_scalars() {
        assert!(error("a: b: c\n").contains("mapping values are not allowed"));
    }
}
