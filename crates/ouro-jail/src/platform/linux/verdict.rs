//! What the facts at the end of a run justify (§9.3, §13.2).

use std::time::SystemTime;

use crate::lifecycle::{Integrity, VerificationScope};
use crate::platform::TreeObservation;

use super::tracer::TracerSummary;

/// Whether an observer's account permits a claim that the tree died.
///
/// A tracee it had to kill on the way out, or a direct child whose exit status
/// now has no route to this process, means the tree's end was not observed.
/// §9.3: that is `tree_empty = null` and `tree_unknown`, never a claim of
/// emptiness. With no observer there is nothing here to object.
pub(super) fn observer_verdict(summary: Option<&TracerSummary>) -> bool {
    match summary {
        Some(summary) => {
            summary.loss.abandoned_tracees == 0
                && summary.unreaped_children.is_empty()
                && !summary.thread_panicked
        }
        None => true,
    }
}

/// What is known about the tree when its budget is spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeInputs {
    /// The namespace init still has an entry in `/proc`.
    pub init_alive: bool,
    /// The backend's exit was seen.
    pub backend_reaped: bool,
    /// The observer said it was done, or there was no observer.
    pub tracer_finished: bool,
    /// The loop saw the tree end on its own rather than running out of time.
    pub natural_end: bool,
    /// Tracees the observer had to kill on the way out.
    pub abandoned_tracees: u64,
    /// Direct children whose exit status no longer has a route here.
    pub unreaped_children: usize,
    /// Stops another filter asked for — a child's own `SECCOMP_RET_TRACE`
    /// with its own trace data, on a call outside the closed set. Surfaced
    /// for the receipt (audit 3 A5); never a verdict input,
    /// because the stop was continued and nothing was lost.
    pub requested_by_other_filters: u64,
    /// The observer's thread panicked, so its counters mean nothing.
    pub observer_panicked: bool,
}

/// The tree observation those facts justify (§9.3, §13.2).
///
/// `tree_empty = Some(true)` needs every one of them to say the tree ended and
/// that the ending was seen. Anything unknown — an init still there, a backend
/// whose exit was never collected, an observer that gave up on a tracee or
/// lost a child's status — is `None` and `pending`, which the supervisor turns
/// into `tree_unknown`. There is no input combination that produces `false`:
/// this code either watched the tree end or does not know.
#[must_use]
pub fn verdict(inputs: &TreeInputs) -> TreeObservation {
    let verified = inputs.natural_end
        && !inputs.init_alive
        && inputs.backend_reaped
        && inputs.tracer_finished
        && inputs.abandoned_tracees == 0
        && inputs.unreaped_children == 0
        && !inputs.observer_panicked;
    if verified {
        TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: VerificationScope::AttemptTree,
            integrity: Integrity::Verified,
        }
    } else {
        TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: VerificationScope::AttemptTree,
            integrity: Integrity::Pending,
        }
    }
}

// The verdict of a teardown whose target never ran
/// What a teardown after an abort or a failed release established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortInputs {
    /// The backend, this supervisor's child, is dead and reaped.
    pub backend_reaped: bool,
    /// The outside watcher is dead and reaped.
    pub watcher_reaped: bool,
    /// The namespace init's pidfd reports its death.
    pub init_dead: bool,
    /// The execution cgroup, if any, was observed unpopulated with its
    /// identity intact (true when there is no cgroup).
    pub cgroup_empty: bool,
    /// Tracees the observer had to kill on the way out.
    pub abandoned_tracees: u64,
    /// The observer's thread panicked.
    pub observer_panicked: bool,
    /// This process's children the observer left unreaped when it stopped.
    pub unreaped_children: Vec<libc::pid_t>,
    /// Stops another filter asked for, continued unobserved. Surfaced for the
    /// receipt (audit 3 A5); never a verdict input, because
    /// the stop was continued and nothing was lost.
    pub requested_by_other_filters: u64,
    /// The backend's pid.
    pub backend_pid: libc::pid_t,
    /// The watcher's pid.
    pub watcher_pid: libc::pid_t,
}

/// Whether a teardown whose target never ran verified the tree's death.
///
/// The settlement facts without the target: the init's death (which the PID
/// namespace makes the death of every member), the backend and the watcher
/// reaped, the leaf empty, and an observer account with nothing abandoned.
/// The observer's "unreaped children" are forgiven only when they are exactly
/// the backend and the watcher and this thread reaped them afterwards; any
/// other child is a process this verdict knows nothing about.
#[must_use]
pub fn abort_verdict(inputs: &AbortInputs) -> bool {
    let children_accounted = inputs.unreaped_children.iter().all(|pid| {
        (*pid == inputs.backend_pid && inputs.backend_reaped)
            || (*pid == inputs.watcher_pid && inputs.watcher_reaped)
    });
    inputs.backend_reaped
        && inputs.watcher_reaped
        && inputs.init_dead
        && inputs.cgroup_empty
        && inputs.abandoned_tracees == 0
        && !inputs.observer_panicked
        && children_accounted
}

/// What is known about a `none` tree when verification ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoneTreeInputs {
    /// A membership escape, identity replacement or failed verification was
    /// detected at any point of the attempt.
    pub integrity_lost: bool,
    /// The loop saw the boundary empty on its own, not at a spent budget.
    pub natural_end: bool,
    /// The target's final status was collected (it is not a live process and
    /// not an unreaped zombie).
    pub target_reaped: bool,
    /// The leaf still names the pinned inode and reads unpopulated.
    pub leaf_verified_empty: bool,
    /// The observer's account objects to nothing (or there was no observer).
    pub observer_clean: bool,
}

/// The tree observation those facts justify (§9.3, §13.2).
///
/// A detected loss wins over everything: `lost`, and neither a tree result
/// nor a time. Otherwise `tree_empty = true` needs every fact; anything short
/// of that is unknown (`pending`), never `false`.
#[must_use]
pub fn none_verdict(inputs: &NoneTreeInputs) -> TreeObservation {
    if inputs.integrity_lost {
        return TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: VerificationScope::RegisteredBoundary,
            integrity: Integrity::Lost,
        };
    }
    if inputs.natural_end
        && inputs.target_reaped
        && inputs.leaf_verified_empty
        && inputs.observer_clean
    {
        return TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: VerificationScope::RegisteredBoundary,
            integrity: Integrity::Verified,
        };
    }
    TreeObservation {
        tree_empty: None,
        verified_at: None,
        verification_scope: VerificationScope::RegisteredBoundary,
        integrity: Integrity::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tracee_the_observer_had_to_kill_means_the_tree_is_unverified() {
        // Nothing to object to when no observer ran.
        assert!(observer_verdict(None));
        assert!(observer_verdict(Some(&TracerSummary::default())));

        let mut abandoned = TracerSummary::default();
        abandoned.loss.abandoned_tracees = 1;
        assert!(
            !observer_verdict(Some(&abandoned)),
            "a tracee killed on the way out is not an observed death"
        );

        let unreaped = TracerSummary {
            unreaped_children: vec![4242],
            ..TracerSummary::default()
        };
        assert!(
            !observer_verdict(Some(&unreaped)),
            "a child whose exit status has no route left is not an observed death"
        );

        let panicked = TracerSummary {
            thread_panicked: true,
            ..TracerSummary::default()
        };
        assert!(
            !observer_verdict(Some(&panicked)),
            "a panicked observer's counters cannot verify anything"
        );
    }

    #[test]
    fn a_tree_is_only_empty_when_every_fact_says_its_end_was_seen() {
        let seen = TreeInputs {
            init_alive: false,
            backend_reaped: true,
            tracer_finished: true,
            natural_end: true,
            abandoned_tracees: 0,
            unreaped_children: 0,
            requested_by_other_filters: 0,
            observer_panicked: false,
        };
        let verified = verdict(&seen);
        assert_eq!(verified.tree_empty, Some(true));
        assert_eq!(verified.integrity, Integrity::Verified);
        assert!(verified.verified_at.is_some());

        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops are carried
        // for the receipt, and because each was continued they are not loss:
        // they never unverify the tree.
        let guessed = TreeInputs {
            requested_by_other_filters: 15,
            ..seen
        };
        assert_eq!(guessed.requested_by_other_filters, 15);
        assert_eq!(
            verdict(&guessed).tree_empty,
            Some(true),
            "a continued wrong-guess stop is not an unobserved death"
        );

        // Each fact on its own is enough to withhold the claim, and none of
        // them turns it into a claim that the tree is NOT empty: unknown is
        // unknown.
        let doubts = [
            (
                "the init is still there",
                TreeInputs {
                    init_alive: true,
                    ..seen
                },
            ),
            (
                "the backend was never reaped",
                TreeInputs {
                    backend_reaped: false,
                    ..seen
                },
            ),
            (
                "the observer did not finish",
                TreeInputs {
                    tracer_finished: false,
                    ..seen
                },
            ),
            (
                "the budget ran out",
                TreeInputs {
                    natural_end: false,
                    ..seen
                },
            ),
            (
                "a tracee had to be killed",
                TreeInputs {
                    abandoned_tracees: 1,
                    ..seen
                },
            ),
            (
                "a child's status was lost",
                TreeInputs {
                    unreaped_children: 1,
                    ..seen
                },
            ),
            (
                "the observer panicked",
                TreeInputs {
                    observer_panicked: true,
                    ..seen
                },
            ),
        ];
        for (why, inputs) in doubts {
            let observation = verdict(&inputs);
            assert_eq!(observation.tree_empty, None, "{why}");
            assert_eq!(observation.verified_at, None, "{why}");
            assert_ne!(observation.integrity, Integrity::Verified, "{why}");
            assert_eq!(
                observation.verification_scope,
                VerificationScope::AttemptTree,
                "{why}"
            );
        }
    }

    #[test]
    fn an_abort_is_verified_only_by_every_settlement_fact() {
        use super::{AbortInputs, abort_verdict};
        let good = AbortInputs {
            backend_reaped: true,
            watcher_reaped: true,
            init_dead: true,
            cgroup_empty: true,
            abandoned_tracees: 0,
            observer_panicked: false,
            unreaped_children: vec![10, 11],
            requested_by_other_filters: 0,
            backend_pid: 10,
            watcher_pid: 11,
        };
        assert!(abort_verdict(&good));
        assert!(abort_verdict(&AbortInputs {
            unreaped_children: Vec::new(),
            ..good.clone()
        }));
        // Security 2026-09-27 (audit 3 A5): wrong-guess trace stops ride in the
        // inputs for the receipt and never unverify the abort, because each
        // was continued and nothing was lost.
        let guessed = AbortInputs {
            requested_by_other_filters: 10,
            ..good.clone()
        };
        assert_eq!(guessed.requested_by_other_filters, 10);
        assert!(
            abort_verdict(&guessed),
            "a continued wrong-guess stop is not an unobserved death"
        );
        for broken in [
            AbortInputs {
                backend_reaped: false,
                ..good.clone()
            },
            AbortInputs {
                watcher_reaped: false,
                ..good.clone()
            },
            AbortInputs {
                init_dead: false,
                ..good.clone()
            },
            AbortInputs {
                cgroup_empty: false,
                ..good.clone()
            },
            AbortInputs {
                abandoned_tracees: 1,
                ..good.clone()
            },
            AbortInputs {
                observer_panicked: true,
                ..good.clone()
            },
            AbortInputs {
                unreaped_children: vec![10, 11, 12],
                ..good.clone()
            },
        ] {
            assert!(!abort_verdict(&broken), "{broken:?}");
        }
    }

    fn clean() -> NoneTreeInputs {
        NoneTreeInputs {
            integrity_lost: false,
            natural_end: true,
            target_reaped: true,
            leaf_verified_empty: true,
            observer_clean: true,
        }
    }

    #[test]
    fn a_clean_none_tree_is_empty_only_in_the_registered_scope() {
        let observed = none_verdict(&clean());
        assert_eq!(observed.tree_empty, Some(true));
        assert!(observed.verified_at.is_some());
        assert_eq!(observed.integrity, Integrity::Verified);
        assert_eq!(
            observed.verification_scope,
            VerificationScope::RegisteredBoundary
        );
    }

    #[test]
    fn a_detected_loss_wins_over_every_other_fact() {
        let observed = none_verdict(&NoneTreeInputs {
            integrity_lost: true,
            ..clean()
        });
        assert_eq!(observed.tree_empty, None);
        assert_eq!(observed.verified_at, None);
        assert_eq!(observed.integrity, Integrity::Lost);
        assert_eq!(
            observed.verification_scope,
            VerificationScope::RegisteredBoundary
        );
    }

    #[test]
    fn any_missing_fact_is_unknown_never_false() {
        for (why, inputs) in [
            (
                "the budget ran out",
                NoneTreeInputs {
                    natural_end: false,
                    ..clean()
                },
            ),
            (
                "the target was not reaped",
                NoneTreeInputs {
                    target_reaped: false,
                    ..clean()
                },
            ),
            (
                "the leaf was not seen empty",
                NoneTreeInputs {
                    leaf_verified_empty: false,
                    ..clean()
                },
            ),
            (
                "the observer objected",
                NoneTreeInputs {
                    observer_clean: false,
                    ..clean()
                },
            ),
        ] {
            let observed = none_verdict(&inputs);
            assert_eq!(observed.tree_empty, None, "{why}");
            assert_eq!(observed.verified_at, None, "{why}");
            assert_eq!(observed.integrity, Integrity::Pending, "{why}");
        }
    }
}
