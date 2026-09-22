//! Host-side name resolution for the proxy (§10 step 2).
//!
//! The proxy resolves each name exactly once per request, through this trait,
//! and connects only to an address from that one answer set. Resolution never
//! happens inside the sandbox.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Instant;

/// Why resolution produced no answer set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResolveError {
    /// The deadline passed first.
    Timeout,
    /// The name does not resolve, or the resolver failed.
    Failed,
    /// Too many resolutions are already outstanding.
    Overloaded,
}

/// A resolver. Implementations must return by `deadline`; the proxy relies on
/// it to keep its DNS budget.
pub trait Resolver {
    /// Resolves an ASCII, normalized, non-numeric host name.
    ///
    /// # Errors
    /// [`ResolveError`].
    fn resolve(&self, host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ResolveError>;
}

/// The host's system resolver (`getaddrinfo` through std), bounded by the
/// deadline.
///
/// `getaddrinfo` cannot be cancelled, so each lookup runs on a worker thread
/// and the caller stops waiting at the deadline. At most `max_in_flight`
/// workers exist at once; beyond that a lookup refuses immediately instead of
/// leaking another thread. A late worker finishes on its own and is counted
/// until it does.
pub struct SystemResolver {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: usize,
}

impl SystemResolver {
    /// A resolver with at most `max_in_flight` concurrent lookups.
    #[must_use]
    pub fn new(max_in_flight: usize) -> Self {
        SystemResolver {
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight,
        }
    }

    /// Lookups currently running, including abandoned late ones.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        SystemResolver::new(16)
    }
}

struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        // Numeric strings never reach a resolver (the network rules parse
        // them first); refusing here keeps std from parsing one itself. A
        // name that already ends in a dot is not a normalized name.
        if host.parse::<IpAddr>().is_ok()
            || host.is_empty()
            || !host.is_ascii()
            || host.ends_with('.')
        {
            return Err(ResolveError::Failed);
        }
        let mut current = self.in_flight.load(Ordering::SeqCst);
        loop {
            if current >= self.max_in_flight {
                return Err(ResolveError::Overloaded);
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let guard = InFlight(Arc::clone(&self.in_flight));
        let (sender, receiver) = mpsc::sync_channel(1);
        // An absolute name: the rule permitted exactly this DNS name, so the
        // host's search domains must not turn it into another one.
        let name = format!("{host}.");
        let spawned = thread::Builder::new()
            .name("ouro-proxy-resolve".to_owned())
            // `getaddrinfo` and its NSS modules use generous stack.
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _guard = guard;
                let answers: Result<Vec<IpAddr>, ()> = (name.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|address| address.ip()).collect())
                    .map_err(|_| ());
                let _ = sender.send(answers);
            });
        if spawned.is_err() {
            return Err(ResolveError::Overloaded);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(Ok(answers)) => Ok(answers),
            Ok(Err(())) => Err(ResolveError::Failed),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ResolveError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ResolveError::Failed),
        }
    }
}

/// One scripted answer of the [`FixtureResolver`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FixtureAnswer {
    /// Return these addresses.
    Addresses(Vec<IpAddr>),
    /// Fail.
    Fail,
    /// Block until the deadline, then time out.
    Hang,
}

#[derive(Default)]
struct FixtureState {
    scripts: HashMap<String, VecDeque<FixtureAnswer>>,
    calls: HashMap<String, usize>,
}

/// A controlled resolver for tests: each name has a script of answers, used
/// in order; the last one repeats. Unknown names fail. Every call is counted,
/// so a test can prove there was no second resolution.
#[derive(Default)]
pub struct FixtureResolver {
    state: Mutex<FixtureState>,
    wake: Condvar,
}

impl FixtureResolver {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        FixtureResolver::default()
    }

    /// Scripts the answers for `host`.
    pub fn script(&self, host: &str, answers: Vec<FixtureAnswer>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.scripts.insert(host.to_owned(), answers.into());
    }

    /// How many times `host` was resolved.
    #[must_use]
    pub fn calls(&self, host: &str) -> usize {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.calls.get(host).copied().unwrap_or(0)
    }
}

impl Resolver for FixtureResolver {
    fn resolve(&self, host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state.calls.entry(host.to_owned()).or_default() += 1;
        let answer = match state.scripts.get_mut(host) {
            None => return Err(ResolveError::Failed),
            Some(script) if script.len() > 1 => script.pop_front(),
            Some(script) => script.front().cloned(),
        };
        match answer {
            Some(FixtureAnswer::Addresses(addresses)) => Ok(addresses),
            Some(FixtureAnswer::Fail) | None => Err(ResolveError::Failed),
            Some(FixtureAnswer::Hang) => {
                // Nothing ever notifies `wake`: this waits out the deadline
                // on the condition variable, not on a sleep.
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ResolveError::Timeout);
                    }
                    state = self
                        .wake
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }
}
