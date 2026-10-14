//! The outside proxy of the `agent` profile (jail-v1 §10, jail-v2 §6), as a
//! library: HTTP CONNECT and plain HTTP from the bridge's HTTP port, SOCKS5
//! CONNECT from its SOCKS port, under one policy.
//!
//! It runs in the supervisor, outside the sandbox and the execution cgroup, on
//! std threads with blocking I/O and explicit deadlines; there is no async
//! runtime. The caller binds the Unix listener at `<attempt>/proxy/proxy.sock`
//! and hands it over with the attempt's [`Rules`] and, when credentials are
//! vaulted, the attempt's vault ([`start_with_vault`]).
//!
//! For every connection the proxy:
//!
//! 1. with a vault, reads the sealed bridge's origin preamble and claims the
//!    process that initiated the connection (`vault::origin`);
//! 2. reads one request within the header deadline and byte budget, an HTTP
//!    request head ([`http`]) or a SOCKS5 CONNECT, and parses one
//!    unambiguous destination;
//! 3. checks the host rule (plain HTTP needs a grant that names its port);
//! 4. resolves a name once, through [`Resolver`], within the DNS deadline;
//! 5. refuses forbidden or mixed answer sets ([`Rules::check_answers`]) and
//!    connects only to an approved numeric address, never resolving again;
//! 6. for a tunnel to a name, answers it, then reads the client's first
//!    flight (bounded) and refuses it unless its TLS SNI or HTTP `Host`
//!    names the same destination, all before connecting;
//! 7. relays: a tunnel's bytes both ways; for plain HTTP, in a tunnel or
//!    not, exactly the framed request with hop-by-hop headers and proxy
//!    credentials removed and vault placeholders substituted where their
//!    credential declares, then the response as a stream. With a vault, a
//!    TLS tunnel goes through the vault's TLS lane instead: one request,
//!    terminated, checked and re-originated with certificate validation.
//!
//! One request per client connection: bytes after the first request are
//! read, counted in [`ProxyResult::discarded_bytes`] and dropped, and the
//! connection closes after its response. Deadlines are per phase: the header
//! deadline runs from accept, the resolve and connect deadlines from the start
//! of their phase.
//!
//! Each accepted connection yields exactly one [`ProxyResult`] through the
//! [`ProxySink`] (immediately on denial or connect failure, at close for a
//! relayed request), unless it closed before sending a byte, in which case
//! there was no request. Results carry the destination, safe reason codes,
//! the connected address, byte counters and duration, never a path, query,
//! header, token or body. The proxy writes no log.

mod conn;
mod event;
pub mod http;
pub(crate) mod origin;
mod relay;
mod resolve;
mod server;
mod socks;
pub(crate) mod sys;
mod tls;
mod types;

pub use event::proxy_event;
pub use resolve::{
    FixtureAnswer, FixtureResolver, Lookup, ResolveError, Resolver, SystemResolver, absolute_name,
};
pub use server::{ProxyHandle, start, start_with_vault};
pub use sys::{nofile_limits, open_descriptor_count, raise_nofile_soft_to_hard};
pub use types::{
    Budgets, EndReason, FD_HEADROOM, FDS_PER_CONNECTION, MAX_DEADLINE, ProxyConfig, ProxyDecision,
    ProxyResult, ProxySink, ProxySummary, Reason, RequestKind, Transport, Verification,
};
