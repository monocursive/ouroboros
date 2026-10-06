//! Shared operator retention settings; neither consumer performs automatic deletion.
use serde::{Deserialize, Deserializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Days(pub u32);

impl<'de> Deserialize<'de> for Days {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text.strip_suffix('d').unwrap_or("");
        let days = digits
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=36_500).contains(n));
        if !digits.bytes().all(|b| b.is_ascii_digit()) || days.is_none() {
            return Err(serde::de::Error::custom("retention must be 1d..36500d"));
        }
        Ok(Self(days.expect("validated days")))
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRetention {
    pub retain: Option<Days>,
    pub capture_retain: Option<Days>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub retain_days: u32,
    pub capture_retain_days: u32,
}

impl LedgerRetention {
    pub fn resolve(
        &self,
        history: Option<u32>,
        captures: Option<u32>,
    ) -> Result<RetentionPolicy, &'static str> {
        let retain_days = history.or(self.retain.map(|v| v.0)).unwrap_or(90);
        let capture_retain_days = captures
            .or(self.capture_retain.map(|v| v.0))
            .unwrap_or(retain_days);
        if !(1..=36_500).contains(&retain_days) || !(1..=36_500).contains(&capture_retain_days) {
            return Err("retention requires 1..36500 days");
        }
        if capture_retain_days > retain_days {
            return Err("capture retention cannot exceed history retention");
        }
        Ok(RetentionPolicy {
            retain_days,
            capture_retain_days,
        })
    }
}
