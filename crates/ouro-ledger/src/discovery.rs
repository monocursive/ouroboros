//! Input bounds shared by launch metadata and run discovery.
use crate::protocol::{LedgerError, Result, RunFilter};

pub const MAX_CATALOG_RUNS: usize = 16_384;
pub const MAX_CATALOG_LIMIT: u32 = 100;
pub const MAX_POSITION_BYTES: usize = 4096;

pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

pub fn validate_tags(tags: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    if tags.len() > 16
        || tags
            .iter()
            .any(|tag| tag.len() > 64 || !valid_name(tag) || !seen.insert(tag))
    {
        return Err(LedgerError(
            "tags require at most sixteen unique names of 1..64 ASCII identifier bytes".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_filter(filter: &RunFilter) -> Result<()> {
    validate_tags(&filter.tags)?;
    if filter.launch.as_deref().is_some_and(|v| !valid_name(v)) {
        return Err(LedgerError(
            "launch filter needs a bounded profile name".into(),
        ));
    }
    if filter
        .since
        .as_deref()
        .is_some_and(|v| !crate::reader::utc_second(v))
        || filter
            .until
            .as_deref()
            .is_some_and(|v| !crate::reader::utc_second(v))
        || matches!((&filter.since, &filter.until), (Some(a), Some(b)) if a >= b)
    {
        return Err(LedgerError(
            "run times need a valid increasing whole-second UTC interval".into(),
        ));
    }
    if filter.outcome.as_deref().is_some_and(|v| {
        ![
            "pending",
            "refused",
            "exited",
            "signaled",
            "exec_error",
            "unknown",
        ]
        .contains(&v)
    }) {
        return Err(LedgerError("unsupported recorded outcome filter".into()));
    }
    Ok(())
}
