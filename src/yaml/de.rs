use serde::de::{
    self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor,
};

use crate::yaml::error::{self, Error, ErrorKind};
use crate::yaml::value::{Int, Scalar, Value, parse_bool_text, parse_float_text, parse_int_text};

fn unexpected_scalar(scalar: &Scalar) -> Unexpected<'_> {
    if scalar.is_null() {
        return Unexpected::Unit;
    }
    if scalar.plain {
        if let Ok(value) = parse_bool_text(&scalar.text) {
            return Unexpected::Bool(value);
        }
        if let Ok(value) = parse_int_text(&scalar.text) {
            return match value {
                Int::I(value) if value >= 0 => u64::try_from(value)
                    .map(Unexpected::Unsigned)
                    .unwrap_or(Unexpected::Str(&scalar.text)),
                Int::I(value) => i64::try_from(value)
                    .map(Unexpected::Signed)
                    .unwrap_or(Unexpected::Str(&scalar.text)),
                Int::U(value) => u64::try_from(value)
                    .map(Unexpected::Unsigned)
                    .unwrap_or(Unexpected::Str(&scalar.text)),
            };
        }
        if let Ok(value) = parse_float_text(&scalar.text) {
            return Unexpected::Float(value);
        }
    }
    Unexpected::Str(&scalar.text)
}

fn invalid_type(value: &Value, expected: &dyn de::Expected) -> Error {
    match value {
        Value::Scalar(scalar) => de::Error::invalid_type(unexpected_scalar(scalar), expected),
        Value::Seq { .. } => de::Error::invalid_type(Unexpected::Seq, expected),
        Value::Map { .. } => de::Error::invalid_type(Unexpected::Map, expected),
    }
}

impl<'de> de::Deserializer<'de> for Value {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) => {
                error::set_location(scalar.line, scalar.column);
                if scalar.is_null() {
                    return visitor.visit_unit();
                }
                if scalar.plain {
                    if let Ok(value) = parse_bool_text(&scalar.text) {
                        return visitor.visit_bool(value);
                    }
                    if let Ok(value) = parse_int_text(&scalar.text) {
                        return match value {
                            Int::I(value) if value >= 0 => match u64::try_from(value) {
                                Ok(value) => visitor.visit_u64(value),
                                Err(_) => visitor.visit_i128(value),
                            },
                            Int::I(value) => match i64::try_from(value) {
                                Ok(value) => visitor.visit_i64(value),
                                Err(_) => visitor.visit_i128(value),
                            },
                            Int::U(value) => match u64::try_from(value) {
                                Ok(value) => visitor.visit_u64(value),
                                Err(_) => visitor.visit_u128(value),
                            },
                        };
                    }
                    if let Ok(value) = parse_float_text(&scalar.text) {
                        if !value.is_finite() {
                            return Err(Error::new(
                                ErrorKind::Message,
                                format!(
                                    "non-finite float `{}` rejected by reject_non_finite_typeless_float",
                                    scalar.text
                                ),
                                scalar.line,
                                scalar.column,
                            ));
                        }
                        return visitor.visit_f64(value);
                    }
                }
                visitor.visit_string(scalar.text)
            }
            Value::Seq {
                items,
                line,
                column,
            } => error::with_location(line, column, || {
                visitor.visit_seq(Seq {
                    iter: items.into_iter(),
                })
            }),
            Value::Map {
                entries,
                line,
                column,
            } => error::with_location(line, column, || {
                visitor.visit_map(Map {
                    iter: entries.into_iter(),
                    value: None,
                    map_location: (line, column),
                })
            }),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) => {
                error::set_location(scalar.line, scalar.column);
                parse_bool_text(&scalar.text)
                    .map_err(|_| {
                        Error::new(
                            ErrorKind::Message,
                            "invalid boolean",
                            scalar.line,
                            scalar.column,
                        )
                    })
                    .and_then(|value| visitor.visit_bool(value))
            }
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        deserialize_integer(self, visitor)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_f64(visitor)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) => {
                error::set_location(scalar.line, scalar.column);
                parse_float_text(&scalar.text)
                    .map_err(|_| {
                        Error::new(
                            ErrorKind::Message,
                            "invalid floating point",
                            scalar.line,
                            scalar.column,
                        )
                    })
                    .and_then(|value| visitor.visit_f64(value))
            }
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) if !scalar.is_null() => {
                error::set_location(scalar.line, scalar.column);
                let mut chars = scalar.text.chars();
                match (chars.next(), chars.next()) {
                    (Some(ch), None) => visitor.visit_char(ch),
                    _ => Err(de::Error::custom("expected a single character")),
                }
            }
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) if !scalar.is_null() => {
                error::set_location(scalar.line, scalar.column);
                visitor.visit_string(scalar.text)
            }
            Value::Scalar(scalar) => Err(Error::new(
                ErrorKind::Message,
                "cannot deserialize null into string; use Option<String>",
                scalar.line,
                scalar.column,
            )),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) if !scalar.is_null() => {
                error::set_location(scalar.line, scalar.column);
                visitor.visit_byte_buf(scalar.text.into_bytes())
            }
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match &self {
            Value::Scalar(scalar) if scalar.is_null() => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match &self {
            Value::Scalar(scalar) if scalar.is_null() => visitor.visit_unit(),
            _ => Err(invalid_type(&self, &visitor)),
        }
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Seq {
                items,
                line,
                column,
            } => error::with_location(line, column, || {
                visitor.visit_seq(Seq {
                    iter: items.into_iter(),
                })
            }),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Map {
                entries,
                line,
                column,
            } => error::with_location(line, column, || {
                visitor.visit_map(Map {
                    iter: entries.into_iter(),
                    value: None,
                    map_location: (line, column),
                })
            }),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self {
            Value::Scalar(scalar) if !scalar.is_null() => {
                error::with_location(scalar.line, scalar.column, || {
                    visitor.visit_enum(Enum {
                        variant: scalar.text,
                        value: None,
                    })
                })
            }
            Value::Map {
                mut entries,
                line,
                column,
            } if entries.len() == 1 => {
                let Some((key, value)) = entries.pop() else {
                    return Err(Error::new(
                        ErrorKind::Message,
                        "expected a single enum variant",
                        line,
                        column,
                    ));
                };
                match key {
                    Value::Scalar(scalar) => {
                        error::with_location(scalar.line, scalar.column, || {
                            visitor.visit_enum(Enum {
                                variant: scalar.text,
                                value: Some(value),
                            })
                        })
                    }
                    _ => Err(Error::new(
                        ErrorKind::Message,
                        "expected an enum variant name",
                        line,
                        column,
                    )),
                }
            }
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        drop(self);
        visitor.visit_unit()
    }
}

fn deserialize_integer<'de, V>(value: Value, visitor: V) -> Result<V::Value, Error>
where
    V: Visitor<'de>,
{
    match value {
        Value::Scalar(scalar) => {
            error::set_location(scalar.line, scalar.column);
            let value = parse_int_text(&scalar.text).map_err(|_| {
                Error::new(
                    ErrorKind::Message,
                    "invalid integer",
                    scalar.line,
                    scalar.column,
                )
            })?;
            match value {
                Int::I(value) if value >= 0 => match u64::try_from(value) {
                    Ok(value) => visitor.visit_u64(value),
                    Err(_) => visitor.visit_i128(value),
                },
                Int::I(value) => match i64::try_from(value) {
                    Ok(value) => visitor.visit_i64(value),
                    Err(_) => visitor.visit_i128(value),
                },
                Int::U(value) => match u64::try_from(value) {
                    Ok(value) => visitor.visit_u64(value),
                    Err(_) => visitor.visit_u128(value),
                },
            }
        }
        other => Err(invalid_type(&other, &visitor)),
    }
}

struct Seq {
    iter: std::vec::IntoIter<Value>,
}

impl<'de> SeqAccess<'de> for Seq {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some(value) => {
                let (line, column) = value.location();
                error::set_location(line, column);
                seed.deserialize(value).map(Some)
            }
            None => Ok(None),
        }
    }
}

struct Map {
    iter: std::vec::IntoIter<(Value, Value)>,
    value: Option<Value>,
    map_location: (usize, usize),
}

impl<'de> MapAccess<'de> for Map {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Error>
    where
        K: DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some((key, value)) => {
                let (line, column) = key.location();
                error::set_location(line, column);
                self.value = Some(value);
                seed.deserialize(key).map(Some)
            }
            None => {
                let (line, column) = self.map_location;
                error::set_location(line, column);
                Ok(None)
            }
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Error>
    where
        V: DeserializeSeed<'de>,
    {
        let Some(value) = self.value.take() else {
            return Err(Error::new(
                ErrorKind::Message,
                "mapping value requested before key",
                0,
                0,
            ));
        };
        let (line, column) = value.location();
        error::set_location(line, column);
        seed.deserialize(value)
    }
}

struct Enum {
    variant: String,
    value: Option<Value>,
}

impl<'de> EnumAccess<'de> for Enum {
    type Error = Error;
    type Variant = Variant;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Error>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = seed.deserialize(Value::Scalar(Scalar {
            text: self.variant,
            plain: true,
            line: 0,
            column: 0,
        }))?;
        Ok((variant, Variant { value: self.value }))
    }
}

struct Variant {
    value: Option<Value>,
}

impl<'de> VariantAccess<'de> for Variant {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        match self.value {
            None => Ok(()),
            Some(Value::Scalar(scalar)) if scalar.is_null() => Ok(()),
            Some(_) => Err(de::Error::custom("expected a unit enum variant")),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Error>
    where
        T: DeserializeSeed<'de>,
    {
        let Some(value) = self.value else {
            return Err(de::Error::custom("expected a newtype enum variant value"));
        };
        seed.deserialize(value)
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(Value::Seq {
                items,
                line,
                column,
            }) => error::with_location(line, column, || {
                visitor.visit_seq(Seq {
                    iter: items.into_iter(),
                })
            }),
            _ => Err(de::Error::custom("expected a tuple enum variant")),
        }
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(Value::Map {
                entries,
                line,
                column,
            }) => error::with_location(line, column, || {
                visitor.visit_map(Map {
                    iter: entries.into_iter(),
                    value: None,
                    map_location: (line, column),
                })
            }),
            _ => Err(de::Error::custom("expected a struct enum variant")),
        }
    }
}
