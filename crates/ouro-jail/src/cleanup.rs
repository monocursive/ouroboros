//! Vendor-state cleanup status.
//!
//! Implements the part of jail-v1 §12 this slice can honestly report. J1 loads
//! no launch profile and stages no credential, so no vendor state is ever
//! created and the only true status is `not_needed`. Anchored deletion,
//! resumable cleanup and the `pending`/`complete` transitions arrive with the
//! launch profiles in J3.

use crate::records::StateCleanup;

/// The cleanup status for an attempt that staged nothing.
///
/// Returned as a function rather than a constant so that the J3 slice replaces
/// one call site with a real traversal instead of a literal in every receipt
/// builder.
#[must_use]
pub fn not_needed() -> StateCleanup {
    StateCleanup::NotNeeded
}

/// Whether this build can remove vendor state at all.
///
/// False here: claiming otherwise would let a receipt say `complete` for a
/// deletion that never ran.
#[must_use]
pub fn vendor_state_removal_implemented() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_slice_stages_nothing_and_says_so() {
        assert_eq!(not_needed(), StateCleanup::NotNeeded);
        assert!(!vendor_state_removal_implemented());
    }
}
