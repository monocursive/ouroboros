//! Host-side name resolution for the proxy (§10 step 2).
//!
//! The proxy resolves each name exactly once per request, through this trait,
//! and connects only to an address from that one answer set. Resolution never
//! happens inside the sandbox.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// Why resolution produced no answer set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResolveError {
    /// The deadline passed first.
    Timeout,
    /// The name does not resolve, or the resolver failed.
    Failed,
    /// Too many resolutions are already outstanding.
    Overloaded,
    /// Not a normalized host name (numeric, empty, non-ASCII or already
    /// absolute): the proxy never asks for one, and a resolver never guesses.
    Invalid,
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

/// The lookup a [`SystemResolver`] runs on its worker thread. It receives the
/// absolute name (see [`absolute_name`]).
pub type Lookup = dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync;

/// The name a [`SystemResolver`] looks up: the normalized name with a
/// trailing dot. The rule permitted exactly this DNS name, so the host's
/// search domains must never turn it into another one.
#[must_use]
pub fn absolute_name(host: &str) -> String {
    format!("{host}.")
}

/// The host's system resolver (`getaddrinfo` through std), bounded by the
/// deadline.
///
/// `getaddrinfo` cannot be cancelled, so each lookup runs on a worker thread
/// and the caller stops waiting at the deadline. At most `max_in_flight`
/// workers exist at once; a further lookup *waits* for a slot until its
/// deadline instead of being refused (issue draft 04: a client that opens
/// many connections at once — `uv` asking for one host 48 times in a
/// second — must not see allowlisted hosts refused for capacity). Only a
/// queue past `4 * max_in_flight` waiters refuses with
/// [`ResolveError::Overloaded`], as a bound on supervisor memory. A late
/// worker finishes on its own and is counted until it does.
///
/// Successful answers are cached per name for [`CACHE_TTL`], so a burst of
/// connections to one host costs one lookup.
pub struct SystemResolver {
    state: Arc<Shared>,
    max_in_flight: usize,
    lookup: Arc<Lookup>,
}

/// How long one answer set serves later lookups of the same name.
const CACHE_TTL: Duration = Duration::from_secs(30);
/// Names kept in the answer cache; a full cache clears itself, which is
/// bounded and predictable.
const CACHE_MAX: usize = 512;

struct Shared {
    in_flight: Mutex<usize>,
    free: Condvar,
    waiting: AtomicUsize,
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

fn system_lookup(name: &str) -> io::Result<Vec<IpAddr>> {
    (name, 0u16)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
}

impl SystemResolver {
    /// A resolver with at most `max_in_flight` concurrent lookups; further
    /// lookups queue behind them until their deadline.
    #[must_use]
    pub fn new(max_in_flight: usize) -> Self {
        SystemResolver::with_lookup(max_in_flight, Arc::new(system_lookup))
    }

    /// The same bounded resolver over another lookup function; the tests
    /// use it to hold a lookup past its deadline.
    #[must_use]
    pub fn with_lookup(max_in_flight: usize, lookup: Arc<Lookup>) -> Self {
        SystemResolver {
            state: Arc::new(Shared {
                in_flight: Mutex::new(0),
                free: Condvar::new(),
                waiting: AtomicUsize::new(0),
                cache: Mutex::new(HashMap::new()),
            }),
            max_in_flight,
            lookup,
        }
    }

    /// Lookups currently running, including abandoned late ones.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        *self.state.in_flight.lock().unwrap_or_else(poison)
    }
}

fn poison<T>(error: PoisonError<T>) -> T {
    error.into_inner()
}

/// Serves one fresh cached answer set, if there is one.
fn cached(
    cache: &Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
    name: &str,
) -> Option<Vec<IpAddr>> {
    let cache = cache.lock().unwrap_or_else(poison);
    let (at, answers) = cache.get(name)?;
    (at.elapsed() < CACHE_TTL).then(|| answers.clone())
}

/// Stores one answer set, keeping the cache bounded.
fn store(
    cache: &Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
    name: String,
    answers: Vec<IpAddr>,
) {
    let mut cache = cache.lock().unwrap_or_else(poison);
    if cache.len() >= CACHE_MAX {
        cache.clear();
    }
    cache.insert(name, (Instant::now(), answers));
}

impl Default for SystemResolver {
    fn default() -> Self {
        SystemResolver::new(16)
    }
}

/// Releases one in-flight slot and wakes the next waiter.
struct InFlight(Arc<Shared>);

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut in_flight = self.0.in_flight.lock().unwrap_or_else(poison);
        *in_flight = in_flight.saturating_sub(1);
        self.0.free.notify_one();
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        // Numeric strings never reach a resolver (the network rules parse
        // them first); refusing here keeps the lookup from parsing one
        // itself. A name that already ends in a dot is not a normalized name.
        if host.parse::<IpAddr>().is_ok()
            || host.is_empty()
            || !host.is_ascii()
            || host.ends_with('.')
        {
            return Err(ResolveError::Invalid);
        }
        let name = absolute_name(host);
        if let Some(answers) = cached(&self.state.cache, &name) {
            return Ok(answers);
        }
        if self.max_in_flight == 0 {
            return Err(ResolveError::Overloaded);
        }
        // Queue for a slot, bounded by the deadline and a waiter bound.
        let waiters = self.state.waiting.fetch_add(1, Ordering::SeqCst) + 1;
        let queued = if waiters > self.max_in_flight.saturating_mul(4) {
            Err(ResolveError::Overloaded)
        } else {
            let mut in_flight = self.state.in_flight.lock().unwrap_or_else(poison);
            loop {
                if Instant::now() >= deadline {
                    break Err(ResolveError::Timeout);
                }
                if *in_flight < self.max_in_flight {
                    *in_flight += 1;
                    break Ok(());
                }
                let (guard, wait) = self
                    .state
                    .free
                    .wait_timeout(
                        in_flight,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .unwrap_or_else(poison);
                in_flight = guard;
                if wait.timed_out() {
                    continue;
                }
            }
        };
        self.state.waiting.fetch_sub(1, Ordering::SeqCst);
        queued?;
        let state = Arc::clone(&self.state);
        let guard = InFlight(Arc::clone(&self.state));
        let (sender, receiver) = mpsc::sync_channel(1);
        let lookup = Arc::clone(&self.lookup);
        let lookup_name = name.clone();
        let spawned = thread::Builder::new()
            .name("ouro-proxy-resolve".to_owned())
            // `getaddrinfo` and its NSS modules use generous stack.
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _guard = guard;
                let answers = lookup(&lookup_name).map_err(|_| ());
                // A late worker still serves the cache: a caller that timed
                // out and retried finds the answer without a new lookup.
                if let Ok(answers) = &answers {
                    store(&state.cache, lookup_name, answers.clone());
                }
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
