//! The lifecycle vocabulary of a receipt's `lifetime` group (§9.3, §13.2).
//!
//! The platform seam and the records carry these values as text. Code that
//! decides on them reads them here: one spelling of each value, and one
//! parse of a lifetime group into the facts a decision needs.

use crate::records::Lifetime;

/// `lifetime.integrity`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Integrity {
    /// No boundary exists yet.
    Pending,
    /// The boundary's identity holds.
    Verified,
    /// A membership escape, a replaced identity or a failed verification
    /// was detected.
    Lost,
}

impl Integrity {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Integrity::Pending => "pending",
            Integrity::Verified => "verified",
            Integrity::Lost => "lost",
        }
    }

    /// Whether `text` spells this value.
    #[must_use]
    pub fn is(self, text: &str) -> bool {
        text == self.as_str()
    }
}

/// `lifetime.boundary` while no boundary has been created (§13.2): the
/// refusal tuple's value, and the only boundary value a lifecycle decision
/// tells apart from the rest.
pub const BOUNDARY_PENDING: &str = "pending";

/// What a lifetime group says about the end of the attempt's tree, parsed
/// once from its text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeEnd {
    /// `integrity` is `lost`: nothing about the tree can be trusted.
    pub integrity_lost: bool,
    /// `boundary` is `pending`: no boundary, so no tree, ever existed.
    pub no_boundary: bool,
    /// `tree_empty` is true: the tree's end was verified.
    pub verified_empty: bool,
}

impl TreeEnd {
    /// The facts of `lifetime`.
    #[must_use]
    pub fn of(lifetime: &Lifetime) -> TreeEnd {
        TreeEnd::from_text(&lifetime.integrity, &lifetime.boundary, lifetime.tree_empty)
    }

    /// The facts of a lifetime group's `integrity`, `boundary` and
    /// `tree_empty`, however they were read.
    #[must_use]
    pub fn from_text(integrity: &str, boundary: &str, tree_empty: Option<bool>) -> TreeEnd {
        TreeEnd {
            integrity_lost: Integrity::Lost.is(integrity),
            no_boundary: boundary == BOUNDARY_PENDING,
            verified_empty: tree_empty == Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_integrity_is_its_own_spelling_and_nothing_else() {
        let all = [Integrity::Pending, Integrity::Verified, Integrity::Lost];
        for value in all {
            for other in all {
                assert_eq!(
                    value.is(other.as_str()),
                    value == other,
                    "{value:?} {other:?}"
                );
            }
            for text in ["", "Lost", "lost ", "unknown"] {
                assert!(!value.is(text), "{value:?} {text:?}");
            }
        }
    }

    #[test]
    fn the_tree_end_facts_read_only_their_exact_spellings() {
        assert_eq!(
            TreeEnd::from_text("lost", "pending", Some(true)),
            TreeEnd {
                integrity_lost: true,
                no_boundary: true,
                verified_empty: true,
            }
        );
        assert_eq!(
            TreeEnd::from_text("", "pid_namespace", None),
            TreeEnd {
                integrity_lost: false,
                no_boundary: false,
                verified_empty: false,
            }
        );
        assert!(!TreeEnd::from_text("verified", "", Some(false)).verified_empty);
        assert_eq!(
            TreeEnd::of(&Lifetime::pending()),
            TreeEnd::from_text("pending", "pending", None)
        );
    }
}
