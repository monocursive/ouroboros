//! Whole-snapshot paging. The catalog and a comparison recompute their whole
//! result for every page; the caller's position says where the previous page
//! ended and binds the snapshot it was cut from, so no page is spliced onto a
//! changed result.
//!
//! What binds a snapshot is each result's own: the catalog fingerprints every
//! matching run summary, because a summary changes without a new record when
//! GC prunes a run; a comparison binds both runs' chain heads, because its
//! counts are a function of the two canonical histories alone; discovery
//! pages the catalog one run at a time and binds the catalog's snapshot.
//! Verification and GC plans page by run id instead, and bind no snapshot:
//! every page is a fresh look at the runs after the last one.

use serde::de::DeserializeOwned;

use crate::protocol::{LedgerError, Result};

/// The caller's position, refused with `oversized` when it exceeds `bound`
/// bytes and before it is parsed.
pub(crate) fn position<T: DeserializeOwned>(
    after: Option<&str>,
    bound: usize,
    oversized: &str,
) -> Result<Option<T>> {
    after
        .map(|value| {
            if value.len() > bound {
                return Err(LedgerError::refused(oversized));
            }
            Ok(serde_json::from_str(value)?)
        })
        .transpose()
}

/// One page of encoded items, under a count and a byte bound.
pub(crate) struct Page {
    limit: usize,
    max_bytes: usize,
    taken: usize,
    bytes: usize,
    full: bool,
}

impl Page {
    pub(crate) fn new(limit: usize, max_bytes: usize) -> Self {
        Self {
            limit,
            max_bytes,
            taken: 0,
            bytes: 0,
            full: false,
        }
    }

    /// Whether an item of `size` encoded bytes joins the page. An item no
    /// page could hold is refused with `oversized` wherever it is offered;
    /// once one item does not fit, no later item joins.
    pub(crate) fn offer(&mut self, size: usize, oversized: &str) -> Result<bool> {
        if size > self.max_bytes {
            return Err(LedgerError::refused(oversized));
        }
        self.full |= self.taken >= self.limit || self.bytes + size > self.max_bytes;
        if self.full {
            return Ok(false);
        }
        self.taken += 1;
        self.bytes += size;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_stops_at_its_count_or_bytes_and_refuses_what_no_page_holds() {
        let mut page = Page::new(2, 10);
        assert!(page.offer(4, "too big").unwrap());
        assert!(!page.offer(7, "too big").unwrap());
        // A later item that would fit still waits for the next page.
        assert!(!page.offer(1, "too big").unwrap());
        assert_eq!(page.offer(11, "too big").unwrap_err().message(), "too big");
        let mut page = Page::new(1, 10);
        assert!(page.offer(10, "too big").unwrap());
        assert!(!page.offer(0, "too big").unwrap());
    }

    #[test]
    fn a_position_is_bounded_before_it_is_parsed() {
        assert_eq!(
            position::<u32>(Some("12345"), 4, "position exceeds bound")
                .unwrap_err()
                .message(),
            "position exceeds bound"
        );
        assert_eq!(position::<u32>(Some("1234"), 4, "").unwrap(), Some(1234));
        assert_eq!(position::<u32>(None, 4, "").unwrap(), None);
        assert!(position::<u32>(Some("[]"), 4, "").is_err());
    }
}
