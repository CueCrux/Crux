// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;

use crate::ConnectionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    pub(crate) fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

pub(crate) fn parse(input: &str) -> Result<JsonValue, ConnectionError> {
    let mut parser = Parser {
        input: input.as_bytes(),
        position: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.position != parser.input.len() {
        return Err(ConnectionError::new("JSON contains trailing data"));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<JsonValue, ConnectionError> {
        if depth > 64 {
            return Err(ConnectionError::new("JSON nesting exceeds the supported limit"));
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => {
                self.literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'0'..=b'9') => self.number().map(JsonValue::Number),
            _ => Err(ConnectionError::new("JSON contains an invalid value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, ConnectionError> {
        self.take_byte(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.take_byte(b':')?;
            let value = self.value(depth)?;
            if values.insert(key, value).is_some() {
                return Err(ConnectionError::new("JSON object contains a duplicate field"));
            }
            self.whitespace();
            if self.consume(b'}') {
                break;
            }
            self.take_byte(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, ConnectionError> {
        self.take_byte(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            if self.consume(b']') {
                break;
            }
            self.take_byte(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn string(&mut self) -> Result<String, ConnectionError> {
        self.take_byte(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| ConnectionError::new("JSON string is not terminated"))?;
            match byte {
                b'"' => return Ok(output),
                b'\\' => self.escape(&mut output)?,
                0..=0x1f => return Err(ConnectionError::new("JSON string contains a control byte")),
                0x20..=0x7f => output.push(char::from(byte)),
                _ => {
                    self.position = self.position.saturating_sub(1);
                    let remaining = std::str::from_utf8(&self.input[self.position..])
                        .map_err(|_| ConnectionError::new("JSON string is not valid UTF-8"))?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or_else(|| ConnectionError::new("JSON string is not valid UTF-8"))?;
                    self.position += character.len_utf8();
                    output.push(character);
                }
            }
        }
    }

    fn escape(&mut self, output: &mut String) -> Result<(), ConnectionError> {
        let escaped = self
            .next()
            .ok_or_else(|| ConnectionError::new("JSON escape is not terminated"))?;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    self.take_byte(b'\\')?;
                    self.take_byte(b'u')?;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ConnectionError::new("JSON contains an invalid surrogate pair"));
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ConnectionError::new("JSON contains an unpaired surrogate"));
                } else {
                    u32::from(first)
                };
                let character = char::from_u32(scalar)
                    .ok_or_else(|| ConnectionError::new("JSON contains an invalid Unicode scalar"))?;
                output.push(character);
            }
            _ => return Err(ConnectionError::new("JSON contains an invalid escape")),
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, ConnectionError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| ConnectionError::new("JSON Unicode escape is truncated"))?;
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(ConnectionError::new("JSON Unicode escape is invalid")),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<u64, ConnectionError> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        let raw = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| ConnectionError::new("JSON number is invalid"))?;
        if raw.len() > 1 && raw.starts_with('0') {
            return Err(ConnectionError::new("JSON number has a leading zero"));
        }
        raw.parse::<u64>()
            .map_err(|_| ConnectionError::new("JSON integer is outside the supported range"))
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ConnectionError> {
        let end = self.position.saturating_add(literal.len());
        if self.input.get(self.position..end) != Some(literal) {
            return Err(ConnectionError::new("JSON literal is invalid"));
        }
        self.position = end;
        Ok(())
    }

    fn take_byte(&mut self, expected: u8) -> Result<(), ConnectionError> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(ConnectionError::new("JSON punctuation is invalid"))
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
}

pub(crate) fn push_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(value));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::{parse, push_string, JsonValue};

    #[test]
    fn parses_and_serializes_escaped_unicode() {
        let parsed = parse(r#"{"value":"Crux \ud83d\udc51\n"}"#).unwrap();
        let value = parsed.as_object().unwrap().get("value").unwrap().as_str().unwrap();
        assert_eq!(value, "Crux 👑\n");
        let mut encoded = String::new();
        push_string(&mut encoded, value);
        assert_eq!(parse(&encoded).unwrap(), JsonValue::String(value.to_string()));
    }

    #[test]
    fn rejects_duplicates_trailing_data_and_bad_surrogates() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse("null false").is_err());
        assert!(parse(r#""\ud800""#).is_err());
    }
}
