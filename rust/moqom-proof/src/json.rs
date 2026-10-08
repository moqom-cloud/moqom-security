// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::collections::HashSet;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// `json` as one JSON object of type `T`, refusing anything two parsers could
/// read differently: an array where the object belongs (which `serde` would
/// read field by field), or an object anywhere inside that names a member
/// twice. `serde_json` already refuses invalid UTF-8 and unpaired surrogate
/// escapes.
pub(crate) fn object<T: for<'de> Deserialize<'de>>(json: &[u8]) -> Option<T> {
    if json.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }
    serde_json::from_slice::<UniqueMembers>(json).ok()?;
    serde_json::from_slice(json).ok()
}

/// For an optional member: absent is `None`, and `null` is refused rather
/// than read as absent.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// JSON in which no object, at any depth, names a member twice. Names are
/// compared after unescaping, so `jti` and `j\u0074i` are the same.
struct UniqueMembers;

impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueMembers)
    }
}

impl<'de> Visitor<'de> for UniqueMembers {
    type Value = Self;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with no duplicate member names")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_unit<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<Self>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate member"));
            }
            map.next_value::<Self>()?;
        }
        Ok(self)
    }
}
