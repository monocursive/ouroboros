//! The crate's one rule for a poisoned lock.
//!
//! A `Mutex` is poisoned when a thread panicked while holding it. The locks
//! taken through these helpers guard plain facts (counters, flags, a slot, a
//! table entry) that every critical section changes in a few assignments, so
//! a panic cannot leave them half-written. The guard is recovered and the
//! work goes on: one panicking thread must not turn into a stuck proxy, a
//! result that is never accounted, or a credential that can no longer be
//! revoked.
//!
//! The exceptions guard a stream a panic can leave in the middle of an
//! exchange, which recovering would read or write past: the shared trace
//! writer ([`crate::trace::SharedTrace`], a record cut in half) and the
//! unix-peer mediator's `sock_diag` socket (a request without its reply).
//! Their callers never recover them: a poisoned trace lock is a write that
//! did not happen, accounted as lost evidence, and a poisoned `sock_diag`
//! lock refuses the connect it was asked about.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError, WaitTimeoutResult};
use std::time::Duration;

/// Locks `mutex`, recovering it if a panic poisoned it.
pub(crate) fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Waits on `condvar` with `guard`, recovering the lock if a panic poisoned
/// it meanwhile.
pub(crate) fn wait<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condvar.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

/// [`wait`], for at most `timeout`.
pub(crate) fn wait_timeout<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
    condvar
        .wait_timeout(guard, timeout)
        .unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_is_recovered_with_its_value() {
        let shared = Arc::new((Mutex::new(1), Condvar::new()));
        let held = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let mut value = held.0.lock().unwrap();
            *value = 2;
            panic!("poison the lock (test)");
        })
        .join();
        assert!(shared.0.is_poisoned());
        *lock(&shared.0) += 1;
        assert_eq!(*lock(&shared.0), 3);
        let (guard, waited) = wait_timeout(&shared.1, lock(&shared.0), Duration::ZERO);
        assert!(waited.timed_out());
        assert_eq!(*guard, 3);
    }
}
