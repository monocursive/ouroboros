//! Which children of this process, besides its tracees, the tracer
//! answers for (J5-T), and so when it is done.

use libc::pid_t;

use super::Session;
use super::seams::ProcView;
use crate::platform::linux::tracer::{proc, sys};

/// J5-T: the children of this process, besides its tracees, whose end the
/// tracer answers for.
///
/// It ends on this account, never on `waitpid(-1)` returning `ECHILD`. A
/// process can start with children it never made — a shell's process
/// substitution forked before it `exec`ed the supervisor, a background job,
/// a library's helper — and those are no part of the attempt: waiting for
/// them held the tracer open until its deadline and then reported them as
/// unreaped. While the tracer runs it still reaps any of them that exits
/// (`waitpid(-1)` cannot leave them out) and delivers the status as
/// [`TracerEvent::UntracedChildExit`], so nothing is lost; one alive when it
/// finishes is left to its owner. A child it gains after attaching is the
/// opposite case — an orphan of the traced tree adopted by a subreaper
/// supervisor — and is owed like the backend (`Session::adopted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owed {
    /// Nothing: the launcher is itself a child of this process.
    Nothing,
    /// The child the launcher descends through — bubblewrap — with its
    /// birth, until its exit has been reaped and delivered.
    Backend {
        pid: pid_t,
        birth: Option<u64>,
        reaped: bool,
    },
    /// The launcher's ancestry could not be read, so which child is the
    /// backend is unknown: every child is waited for, as before J5-T.
    Every,
}

impl Owed {
    /// What this process, `own`, owes for `launcher`: read from the
    /// kernel's parent links while the launcher is seized and blocked, so
    /// the chain above it cannot change under the walk.
    pub(super) fn toward(own: pid_t, launcher: pid_t, procfs: &dyn ProcView) -> Owed {
        match proc::child_toward(own, launcher, |pid| procfs.ppid(pid)) {
            Some(child) if child == launcher => Owed::Nothing,
            Some(child) => Owed::Backend {
                pid: child,
                birth: procfs.start_ticks(child),
                reaped: false,
            },
            None => Owed::Every,
        }
    }
}

impl Session {
    /// J5-T: every tracee has been reaped and the backend's exit delivered
    /// ([`Owed`]). Any other child of this process may live on.
    pub(super) fn accounted_for(&self) -> bool {
        self.tasks.is_empty()
            && match self.owed {
                Owed::Nothing => true,
                Owed::Backend { pid, birth, reaped } => reaped || !self.still_there(pid, birth),
                Owed::Every => false,
            }
            && self.adopted().is_empty()
    }

    /// J5-T: this process's children that are not tracees and that it did
    /// not have, under the same birth, when the tracer attached — orphans of
    /// the traced tree a subreaper supervisor adopted, zombie or alive. They
    /// are the attempt's, so the tracer reaps them before it finishes (L01.7).
    pub(super) fn adopted(&self) -> Vec<pid_t> {
        self.procfs
            .children(sys::getpid())
            .into_iter()
            .filter(|pid| !self.tasks.contains(*pid))
            .filter(|pid| {
                !self.beside.iter().any(|(known, birth)| {
                    known == pid && self.procfs.start_ticks(*pid) == Some(*birth)
                })
            })
            .collect()
    }

    /// Whether `pid` still names the process born at `birth`, zombie
    /// included. Without a birth, whether anything has the number.
    pub(super) fn still_there(&self, pid: pid_t, birth: Option<u64>) -> bool {
        match (self.procfs.start_ticks(pid), birth) {
            (Some(now), Some(born)) => now == born,
            (now, None) => now.is_some(),
            (None, Some(_)) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::*;
    use crate::platform::linux::tracer::TracerConfig;

    /// J5-T, through the `/proc` seam: what the tracer owes follows the
    /// parent links from the launcher up to this process. Nothing when the
    /// launcher is its own child; the child it descends through, with that
    /// child's birth, when it is deeper; every child when the chain cannot
    /// be read to this process.
    #[test]
    fn j5t_what_is_owed_follows_the_launchers_parents() {
        const OWN: pid_t = 5_000_100;
        const BACKEND: pid_t = 5_000_101;
        const NAMESPACE_INIT: pid_t = 5_000_102;
        const LAUNCHER: pid_t = 5_000_103;
        let proc = FakeProc::default().task(BACKEND, BACKEND, 1500);
        let parents = |links: &[(pid_t, pid_t)]| {
            proc.edit(|script| script.parents = links.iter().copied().collect());
        };
        parents(&[(LAUNCHER, OWN)]);
        assert_eq!(Owed::toward(OWN, LAUNCHER, &proc), Owed::Nothing);
        parents(&[
            (LAUNCHER, NAMESPACE_INIT),
            (NAMESPACE_INIT, BACKEND),
            (BACKEND, OWN),
        ]);
        assert_eq!(
            Owed::toward(OWN, LAUNCHER, &proc),
            Owed::Backend {
                pid: BACKEND,
                birth: Some(1500),
                reaped: false,
            }
        );
        parents(&[(LAUNCHER, NAMESPACE_INIT), (BACKEND, OWN)]);
        assert_eq!(
            Owed::toward(OWN, LAUNCHER, &proc),
            Owed::Every,
            "a link that cannot be read"
        );
        parents(&[(LAUNCHER, 1)]);
        assert_eq!(
            Owed::toward(OWN, LAUNCHER, &proc),
            Owed::Every,
            "reparented to init: not below this process"
        );
    }

    /// J5-T (review of the fix, M5): the backend is owed only while its
    /// number still names the process born at the recorded time. A reused
    /// number — same pid, another birth — is not the backend: the tracer
    /// neither waits for it nor lists it as unreaped. The same pid and
    /// birth is, zombie included, until its exit is reaped. The kernel
    /// will not reuse a live pid on demand, so the birth is scripted.
    #[test]
    fn j5t_the_backend_is_owed_only_under_its_own_birth() {
        const BACKEND: pid_t = RECYCLED;
        let proc = FakeProc::default();
        let (mut session, rx) = new_session(TracerConfig::default(), proc.clone(), 64);
        session.owed = Owed::Backend {
            pid: BACKEND,
            birth: Some(1000),
            reaped: false,
        };
        let now_named = |birth: Option<u64>| {
            proc.edit(|script| {
                match birth {
                    Some(ticks) => script.tasks.insert(BACKEND, (BACKEND, ticks)),
                    None => script.tasks.remove(&BACKEND),
                };
            });
        };

        now_named(Some(1000));
        assert!(session.tasks.is_empty());
        assert!(
            !session.accounted_for(),
            "the backend, born at 1000, is alive or a zombie: wait for its exit"
        );
        now_named(Some(2000));
        assert!(
            session.accounted_for(),
            "the number now names a process born at 2000: the backend is gone"
        );
        now_named(None);
        assert!(session.accounted_for(), "nothing has the number");

        // Without a recorded birth any holder of the number is kept.
        session.owed = Owed::Backend {
            pid: BACKEND,
            birth: None,
            reaped: false,
        };
        now_named(Some(2000));
        assert!(!session.accounted_for());
        // A reaped backend is done whatever holds its number now.
        session.owed = Owed::Backend {
            pid: BACKEND,
            birth: Some(1000),
            reaped: true,
        };
        now_named(Some(1000));
        assert!(session.accounted_for());

        // The same rule decides what `finish` reports as unreaped.
        let unreaped = |birth_now: u64| {
            let (mut session, _rx) = new_session(TracerConfig::default(), proc.clone(), 64);
            session.owed = Owed::Backend {
                pid: BACKEND,
                birth: Some(1000),
                reaped: false,
            };
            now_named(Some(birth_now));
            let handles = stopped(&session);
            session.finish(&handles).unreaped_children
        };
        assert_eq!(unreaped(1000), vec![BACKEND], "its own birth: unreaped");
        assert_eq!(
            unreaped(2000),
            Vec::<pid_t>::new(),
            "another birth: not the backend, not loss"
        );
        drop(rx);
    }

    /// J5-T w3: the children a session was attached beside are recognised
    /// by pid and birth; anything else that is not a tracee was gained since
    /// and is owed — awaited, and listed unreaped if the tracer stops first.
    /// A pid the kernel reused after a bystander ended is gained, not beside.
    /// Scripted: the kernel will not reuse a pid, or hand an unprivileged
    /// test a live orphan, on demand.
    #[test]
    fn j5t_a_child_gained_after_the_attach_is_owed_and_a_bystander_is_not() {
        const BYSTANDER: pid_t = RECYCLED;
        const ORPHAN: pid_t = WORKER;
        let proc = FakeProc::default();
        // This process's children, each with its birth.
        let set = |children: &[(pid_t, u64)]| {
            proc.edit(|script| {
                script.tasks = children
                    .iter()
                    .map(|(pid, birth)| (*pid, (*pid, *birth)))
                    .collect();
                script.children = children.iter().map(|(pid, _)| *pid).collect();
            });
        };
        set(&[(BYSTANDER, 1000)]);
        let session = || {
            let (mut session, _) = new_session(TracerConfig::default(), proc.clone(), 64);
            session.owed = Owed::Nothing;
            session.beside = vec![(BYSTANDER, 1000)];
            session
        };

        let s = session();
        assert!(s.adopted().is_empty());
        assert!(s.accounted_for(), "only the bystander: done");
        set(&[(BYSTANDER, 1000), (ORPHAN, 1500)]);
        assert_eq!(s.adopted(), vec![ORPHAN]);
        assert!(!s.accounted_for(), "an orphan gained since: wait for it");
        set(&[(BYSTANDER, 2000)]);
        assert_eq!(
            s.adopted(),
            vec![BYSTANDER],
            "the bystander's number under another birth is a new child"
        );
        assert!(!s.accounted_for());

        set(&[(BYSTANDER, 1000), (ORPHAN, 1500)]);
        let s = session();
        let h = stopped(&s);
        assert_eq!(
            s.finish(&h).unreaped_children,
            vec![ORPHAN],
            "stopped first: the orphan is unreaped, the bystander is not"
        );
    }
}
