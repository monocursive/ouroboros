//! The proxy's vocabulary: its budgets and configuration, and the facts
//! of one request it reports (reasons, decisions, verifications, results).

use std::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Duration;

use super::Resolver;
use crate::network::{Destination, Rules};

/// Resource budgets per attempt (§10). These are budgets, not grants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budgets {
    /// Active connections; excess connections are refused with `overload`.
    pub max_connections: usize,
    /// Bytes of one request head (request line, headers, final CRLF).
    pub max_header_bytes: usize,
    /// From accept to a complete request head.
    pub header_deadline: Duration,
    /// For one resolution, from its start.
    pub resolve_deadline: Duration,
    /// For connecting upstream, over every approved address, from its start.
    pub connect_deadline: Duration,
    /// Total relay buffer bytes. Each relay direction of an admitted
    /// connection owns `relay_buffer_bytes / (2 * max_connections)`, and at
    /// most `max_connections` connections are admitted, so the total holds
    /// by construction.
    pub relay_buffer_bytes: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets::DEFAULT
    }
}

impl Budgets {
    /// §10: 128 active connections, 32 KiB request headers, 10-second
    /// DNS/connect/header deadline, 1 MiB total relay buffers.
    pub const DEFAULT: Budgets = Budgets {
        max_connections: 128,
        max_header_bytes: 32 * 1024,
        header_deadline: Duration::from_secs(10),
        resolve_deadline: Duration::from_secs(10),
        connect_deadline: Duration::from_secs(10),
        relay_buffer_bytes: 1024 * 1024,
    };

    /// The buffer one relay direction owns.
    #[must_use]
    pub fn relay_chunk(&self) -> usize {
        self.relay_buffer_bytes
            .checked_div(self.max_connections.saturating_mul(2))
            .unwrap_or(0)
    }

    /// The descriptors the budget needs: [`FDS_PER_CONNECTION`] per
    /// connection plus [`FD_HEADROOM`].
    #[must_use]
    pub fn descriptors_needed(&self) -> usize {
        self.max_connections
            .saturating_mul(FDS_PER_CONNECTION)
            .saturating_add(FD_HEADROOM)
    }
}

/// The longest deadline a budget may carry; beyond it `Instant` arithmetic
/// is not guaranteed and no request needs that long.
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);

/// Descriptors one admitted connection holds at most: the client's socket
/// and the destination's. Both relay directions and the stop registry share
/// them; nothing is duplicated.
pub const FDS_PER_CONNECTION: usize = 2;

/// Descriptors reserved beyond the connections: the listener and its wake
/// pair, connections being refused for overload, resolver lookups, and the
/// rest of the supervisor.
pub const FD_HEADROOM: usize = 64;

/// Everything the proxy needs.
pub struct ProxyConfig {
    /// Bound by the caller at `<attempt>/proxy/proxy.sock`.
    pub listener: UnixListener,
    /// Allow-host rules and explicit address grants.
    pub rules: Rules,
    /// Resource budgets.
    pub budgets: Budgets,
    /// The host resolver; the jail never resolves inside the sandbox.
    pub resolver: Arc<dyn Resolver + Send + Sync>,
}

/// What kind of request a result describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestKind {
    /// A CONNECT tunnel.
    Connect,
    /// A plain-HTTP absolute-form request.
    Http,
    /// Nothing parseable arrived.
    Unknown,
}

impl RequestKind {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::Connect => "connect",
            RequestKind::Http => "http",
            RequestKind::Unknown => "unknown",
        }
    }
}

/// The proxy's policy decision, independent of connect success (§13.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyDecision {
    /// The destination passed every check.
    Allow,
    /// The request was refused.
    Deny,
}

/// A safe reason code. Never contains request data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// Credential path was not granted.
    CredentialPathDenied,
    /// A vault placeholder appeared outside the placement its credential
    /// declares (another header, the request line, an unknown credential).
    CredentialPlacementDenied,
    /// The connection's initiating process is not one the credential is
    /// bound to.
    CredentialProcessDenied,
    /// The connection's initiating process could not be established: the
    /// bridge's preamble was late or invalid, the process could not be
    /// pinned, or no authority was published within the rendezvous.
    CredentialProcessUnverified,
    /// The credential source is missing, revoked or changed.
    CredentialRevoked,
    /// The credential is expired or awaiting a safe refresh.
    CredentialUnavailable,
    /// The first flight names a different destination.
    OriginMismatch,
    /// The first flight cannot establish a supported routing name.
    OriginUnverified,
    /// The bounded first-flight deadline expired.
    OriginTimeout,
    /// Allowed, connected and relayed until close.
    Relayed,
    /// Allowed, but no approved address accepted the connection.
    ConnectFailed,
    /// Allowed, but connecting exceeded the deadline.
    ConnectTimeout,
    /// Allowed and connected, but the upstream failed the TLS handshake
    /// (certificate validation included) or answered outside the protocol.
    UpstreamProtocol,
    /// No host rule permits the destination.
    HostNotAllowed,
    /// A host rule permits the destination, but only as TLS: every rule that
    /// does omitted its port, and the request is plaintext HTTP, either an
    /// absolute-form request or a tunnel whose first flight is HTTP
    /// (network-rules.md §Normalization).
    PlaintextNotGranted,
    /// Every answer is forbidden or unusable.
    ForbiddenAddress,
    /// Allowed and forbidden answers were mixed.
    MixedAnswers,
    /// The resolver returned no address.
    ResolveEmpty,
    /// The resolver failed.
    ResolveFailed,
    /// Resolution exceeded the deadline.
    ResolveTimeout,
    /// The resolver refused: too many lookups outstanding.
    ResolverOverloaded,
    /// The request head is malformed.
    MalformedRequest,
    /// The body framing is ambiguous (duplicate or conflicting lengths).
    AmbiguousFraming,
    /// The absolute-URI authority and Host disagree.
    HostMismatch,
    /// Not a CONNECT or `http://` absolute-form request.
    UnsupportedRequest,
    /// The request head exceeded the byte budget.
    HeaderTooLarge,
    /// The request head did not complete within the deadline.
    HeaderTimeout,
    /// The client closed or failed before completing the head.
    ClientClosed,
    /// The connection budget was exhausted.
    Overload,
    /// The proxy ran out of a process resource (descriptors, threads, or
    /// the budget of pinned connection initiators).
    ResourceExhausted,
    /// The proxy is stopping.
    Stopping,
    /// The handler failed unexpectedly; the request was not relayed.
    InternalError,
}

impl Reason {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::CredentialPathDenied => "credential_path_denied",
            Reason::CredentialPlacementDenied => "credential_placement_denied",
            Reason::CredentialProcessDenied => "credential_process_denied",
            Reason::CredentialProcessUnverified => "credential_process_unverified",
            Reason::CredentialRevoked => "credential_revoked",
            Reason::CredentialUnavailable => "credential_unavailable",
            Reason::OriginMismatch => "origin_mismatch",
            Reason::OriginUnverified => "origin_unverified",
            Reason::OriginTimeout => "origin_timeout",
            Reason::Relayed => "relayed",
            Reason::ConnectFailed => "connect_failed",
            Reason::ConnectTimeout => "connect_timeout",
            Reason::UpstreamProtocol => "upstream_protocol",
            Reason::HostNotAllowed => "host_not_allowed",
            Reason::PlaintextNotGranted => "plaintext_not_granted",
            Reason::ForbiddenAddress => "forbidden_address",
            Reason::MixedAnswers => "mixed_answers",
            Reason::ResolveEmpty => "resolve_empty",
            Reason::ResolveFailed => "resolve_failed",
            Reason::ResolveTimeout => "resolve_timeout",
            Reason::ResolverOverloaded => "resolver_overloaded",
            Reason::MalformedRequest => "malformed_request",
            Reason::AmbiguousFraming => "ambiguous_framing",
            Reason::HostMismatch => "host_mismatch",
            Reason::UnsupportedRequest => "unsupported_request",
            Reason::HeaderTooLarge => "header_too_large",
            Reason::HeaderTimeout => "header_timeout",
            Reason::ClientClosed => "client_closed",
            Reason::Overload => "overload",
            Reason::ResourceExhausted => "resource_exhausted",
            Reason::Stopping => "stopping",
            Reason::InternalError => "internal_error",
        }
    }

    /// The HTTP status a refusal for this reason answers with.
    pub(super) fn status(self) -> (u16, &'static str) {
        match self {
            Reason::CredentialPathDenied
            | Reason::CredentialPlacementDenied
            | Reason::CredentialProcessDenied
            | Reason::CredentialProcessUnverified
            | Reason::CredentialRevoked
            | Reason::CredentialUnavailable
            | Reason::OriginMismatch
            | Reason::OriginUnverified
            | Reason::OriginTimeout
            | Reason::HostNotAllowed
            | Reason::PlaintextNotGranted
            | Reason::ForbiddenAddress
            | Reason::MixedAnswers => (403, "Forbidden"),
            Reason::ResolveEmpty
            | Reason::ResolveFailed
            | Reason::ConnectFailed
            | Reason::UpstreamProtocol => (502, "Bad Gateway"),
            Reason::ResolveTimeout | Reason::ConnectTimeout => (504, "Gateway Timeout"),
            Reason::HeaderTooLarge => (431, "Request Header Fields Too Large"),
            Reason::HeaderTimeout => (408, "Request Timeout"),
            Reason::Overload
            | Reason::ResourceExhausted
            | Reason::ResolverOverloaded
            | Reason::Stopping => (503, "Service Unavailable"),
            Reason::InternalError => (500, "Internal Server Error"),
            Reason::MalformedRequest
            | Reason::AmbiguousFraming
            | Reason::HostMismatch
            | Reason::UnsupportedRequest
            | Reason::ClientClosed
            | Reason::Relayed => (400, "Bad Request"),
        }
    }
}

/// How an allowed, connected, relayed request ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndReason {
    /// A live credential lease was revoked or its initiating process changed.
    CredentialRevoked,
    /// The upstream closed its side first.
    UpstreamClosed,
    /// The client closed its side first.
    ClientClosed,
    /// Reading from or writing to the upstream failed.
    UpstreamError,
    /// Reading from or writing to the client failed.
    ClientError,
    /// The client's request body framing was invalid; forwarding stopped at
    /// the first invalid byte.
    ClientFraming,
    /// The proxy was stopped.
    Stopped,
    /// The proxy's own lifetime for the connection ran out (the TLS lane's
    /// client deadline).
    Deadline,
    /// The relay failed inside the proxy (a worker panicked); the byte
    /// counts may be short.
    InternalError,
}

impl EndReason {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EndReason::CredentialRevoked => "credential_revoked",
            EndReason::UpstreamClosed => "upstream_closed",
            EndReason::ClientClosed => "client_closed",
            EndReason::UpstreamError => "upstream_error",
            EndReason::ClientError => "client_error",
            EndReason::ClientFraming => "client_framing",
            EndReason::Stopped => "stopped",
            EndReason::Deadline => "deadline",
            EndReason::InternalError => "internal_error",
        }
    }
}

/// The client protocol a connection speaks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// An HTTP proxy request: CONNECT or absolute-form plain HTTP.
    Http,
    /// A SOCKS5 CONNECT (RFC 1928).
    Socks5,
}

impl Transport {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Socks5 => "socks5",
        }
    }
}

/// How a result's origin was verified (jail-v2 §3.1: network evidence names
/// the actual verification, never an unqualified application origin).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verification {
    /// The plain-HTTP request's `Host`.
    HttpHost,
    /// The TLS ClientHello's SNI, a routing name only.
    TlsSni,
    /// The `Host` of the request decrypted by the vault's TLS lane.
    MitmHttpHost,
    /// An explicit IP grant: an address and port, not a name.
    ExplicitIp,
}

impl Verification {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verification::HttpHost => "http_host",
            Verification::TlsSni => "tls_sni",
            Verification::MitmHttpHost => "mitm_http_host",
            Verification::ExplicitIp => "explicit_ip",
        }
    }
}

/// One proxy result: the facts of one request, never its content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProxyResult {
    /// Unique within this proxy, starting at 1, in accept order.
    pub request_id: u64,
    /// First-flight verification, never an assertion about encrypted HTTP.
    pub origin: Option<String>,
    /// How `origin` was verified.
    pub origin_verification: Option<Verification>,
    /// Client protocol.
    pub transport: Transport,
    /// CONNECT, plain HTTP, or unknown.
    pub kind: RequestKind,
    /// The normalized destination, when one was parsed.
    pub destination: Option<Destination>,
    /// Allow or deny.
    pub decision: ProxyDecision,
    /// Why.
    pub reason: Reason,
    /// The numeric address actually connected, whether or not anything was
    /// relayed afterwards.
    pub connected: Option<SocketAddr>,
    /// The OS error of a failed connect, when there was one.
    pub connect_errno: Option<i32>,
    /// Bytes relayed from the destination to the client.
    pub bytes_in: u64,
    /// Bytes relayed from the client to the destination (for plain HTTP
    /// including the rewritten request head).
    pub bytes_out: u64,
    /// Client bytes after the first request (a second, pipelined request,
    /// for example), read and not forwarded: one request per connection.
    pub discarded_bytes: u64,
    /// From accept to the result.
    pub duration: Duration,
    /// How a relayed request ended; `None` when nothing was relayed.
    pub end: Option<EndReason>,
}

/// Receives results. Called from connection threads; must not block for
/// long, because a blocked sink holds that connection's slot.
pub trait ProxySink: Send + Sync {
    /// One result.
    fn emit(&self, result: ProxyResult);
}

/// What [`ProxyHandle::stop`] established. It covers accepted connections
/// only: connections still in the kernel's backlog when stop began are
/// closed without being accepted, so they have no result and no count.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ProxySummary {
    /// Connections accepted, including the ones refused for overload.
    pub accepted: u64,
    /// Results delivered to the sink.
    pub results_emitted: u64,
    /// Accepted connections whose result was not delivered because the drain
    /// budget ran out first. Coverage must reflect these.
    pub results_missing: u64,
    /// Connections that closed before sending a byte: no request, no result.
    pub without_request: u64,
    /// The accept loop exited and dropped the listener within the budget.
    pub listener_closed: bool,
}

impl ProxySummary {
    /// Whether every accepted connection settled: its result was delivered
    /// or it sent no request. When false, `proxy.net` coverage has a gap
    /// (§10, §11.4: "An interrupted drain can leave that result missing;
    /// coverage must reflect it").
    #[must_use]
    pub fn complete(&self) -> bool {
        self.results_missing == 0
    }
}
