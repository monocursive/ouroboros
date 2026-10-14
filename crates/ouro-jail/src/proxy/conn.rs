//! One connection, from its request to its result: the policy checks in
//! order, the upstream connect and the relay.

use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::server::{Closer, Shared, denial};
use super::{
    EndReason, ProxyDecision, ProxyResult, Reason, RequestKind, ResolveError, Transport,
    Verification, http, origin, relay, socks, tls,
};
use crate::network::{AnswerDenial, Destination, Host};

impl Transport {
    /// Tells the client, in its protocol, that its tunnel is open.
    fn establish(self, client: &UnixStream) -> Result<(), Reason> {
        match self {
            Transport::Http => origin::established(client),
            Transport::Socks5 => socks::reply(client, socks::Reply::Succeeded),
        }
    }

    /// Refuses the client in its protocol: an HTTP error response naming
    /// `reason`, or the SOCKS reply `reply`. Best effort: the client may
    /// already be gone.
    fn refuse(self, client: &UnixStream, reason: Reason, reply: socks::Reply, budget: Duration) {
        match self {
            Transport::Http => respond(client, reason, budget),
            Transport::Socks5 => {
                let _ = socks::reply(client, reply);
            }
        }
    }
}

/// Guarantees exactly one result (or one "no request" count) per connection,
/// including when the handler panics, and releases the connection's
/// admission just before it settles, so a caller that saw the result can
/// rely on the slot being free.
struct ResultSlot<'a> {
    shared: &'a Shared,
    /// The process that initiated the connection, as the bridge's preamble
    /// and the mediator established it.
    initiator: crate::vault::origin::Initiator,
    id: u64,
    accepted_at: Instant,
    kind: RequestKind,
    destination: Option<Destination>,
    origin_verification: Option<Verification>,
    transport: Transport,
    admitted: bool,
    done: bool,
    /// Whether the client may already have received bytes, so no error
    /// response can follow.
    replied: bool,
}

impl ResultSlot<'_> {
    fn release(&mut self) {
        if self.admitted {
            self.admitted = false;
            self.shared.release();
        }
    }

    fn emit(&mut self, result: ProxyResult) {
        if !self.done {
            self.done = true;
            self.release();
            self.shared.emit(result);
        }
    }

    fn deny(&mut self, reason: Reason) {
        let mut result = denial(
            self.id,
            self.destination.clone(),
            self.kind,
            reason,
            self.accepted_at,
        );
        result.transport = self.transport;
        self.emit(result);
    }

    /// An allowed request's result.
    fn allowed(&self, reason: Reason, connected: Option<SocketAddr>) -> ProxyResult {
        ProxyResult {
            request_id: self.id,
            origin: self
                .origin_verification
                .as_ref()
                .and(self.destination.as_ref())
                .map(|d| d.host.to_string()),
            origin_verification: self.origin_verification,
            transport: self.transport,
            kind: self.kind,
            destination: self.destination.clone(),
            decision: ProxyDecision::Allow,
            reason,
            connected,
            connect_errno: None,
            bytes_in: 0,
            bytes_out: 0,
            discarded_bytes: 0,
            duration: self.accepted_at.elapsed(),
            end: None,
        }
    }

    fn no_request(&mut self) {
        if !self.done {
            self.done = true;
            self.release();
            self.shared.no_request();
        }
    }
}

impl Drop for ResultSlot<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.deny(Reason::InternalError);
        }
        self.release();
    }
}

fn respond(client: &UnixStream, reason: Reason, budget: Duration) {
    let _ = client.set_write_timeout(Some(budget.max(Duration::from_millis(1))));
    let _ = (&*client).write_all(&http::error_response(reason));
    let _ = client.shutdown(Shutdown::Both);
}

pub(super) fn handle_connection(
    shared: &Shared,
    client: &Arc<UnixStream>,
    id: u64,
    accepted_at: Instant,
) {
    let mut slot = ResultSlot {
        shared,
        initiator: crate::vault::origin::Initiator::default(),
        id,
        accepted_at,
        kind: RequestKind::Unknown,
        destination: None,
        origin_verification: None,
        transport: Transport::Http,
        admitted: true,
        done: false,
        replied: false,
    };
    // A panic anywhere below (a resolver bug, say) still settles the
    // connection once, answers the client if nothing was sent yet, and
    // closes its sockets.
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        serve(shared, &mut slot, client, accepted_at)
    }));
    let refusal = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(reason)) => Some(reason),
        Err(_) => Some(Reason::InternalError),
    };
    if let Some(reason) = refusal {
        slot.deny(reason);
        if !slot.replied {
            slot.transport.refuse(
                client,
                reason,
                socks::Reply::NotAllowed,
                shared.budgets.header_deadline,
            );
        }
    }
    drop(slot);
    shared.close_connection(id);
    let _ = client.shutdown(Shutdown::Both);
}

/// Serves one request. `Err` is a denial the caller reports and answers;
/// `Ok` means the result was already emitted (or there was no request).
fn serve(
    shared: &Shared,
    slot: &mut ResultSlot<'_>,
    client: &Arc<UnixStream>,
    accepted_at: Instant,
) -> Result<(), Reason> {
    let budgets = shared.budgets;
    if let Some(vault) = &shared.vault {
        slot.initiator = match vault.origins.receive(client) {
            Ok(Some(initiator)) => initiator,
            Ok(None) => {
                slot.no_request();
                return Ok(());
            }
            // Stop shuts the socket down under a reader, too.
            Err(_) if shared.is_stopping() => return Err(Reason::Stopping),
            Err(reason) => return Err(reason),
        };
    }
    let Some(transport) = socks::detect(client, accepted_at + budgets.header_deadline)? else {
        slot.no_request();
        return Ok(());
    };
    slot.transport = transport;
    let (head, request) = if transport == Transport::Socks5 {
        let destination = match socks::request(client, accepted_at + budgets.header_deadline) {
            Ok(destination) => destination,
            Err(e) => {
                slot.replied = true;
                return Err(e);
            }
        };
        (
            http::Head::empty(),
            http::Request {
                destination,
                framing: http::Framing::Tunnel,
                forward_head: Vec::new(),
            },
        )
    } else {
        let head = match http::read_head(
            client,
            budgets.max_header_bytes,
            accepted_at + budgets.header_deadline,
        ) {
            Ok(head) => head,
            Err(http::HeadError::NoBytes) => {
                slot.no_request();
                return Ok(());
            }
            Err(http::HeadError::Reject(reason)) => {
                return Err(if shared.is_stopping() {
                    Reason::Stopping
                } else {
                    reason
                });
            }
        };
        let request = http::parse_request(head.head())?;
        (head, request)
    };
    slot.kind = request.kind();
    slot.destination = Some(request.destination.clone());
    if shared.is_stopping() {
        return Err(Reason::Stopping);
    }
    // Step 1: the host rule.
    if !shared.rules.permits_destination(&request.destination) {
        return Err(Reason::HostNotAllowed);
    }
    // Audit 2026-10-08 L21: plaintext HTTP requires a grant that named its
    // port explicitly (network-rules.md §Normalization). The omitted-port
    // expansion to 443 is the TLS shape — a plain request riding it has no
    // explicit rule that permits it — while an explicit `host:PORT` grant
    // serves whatever scheme its operator named the port for. The host rule
    // did permit the destination, so the refusal says which part did not.
    if request.kind() == RequestKind::Http
        && !shared
            .rules
            .permits_destination_explicit(&request.destination)
    {
        return Err(Reason::PlaintextNotGranted);
    }
    // Step 2: resolve on the host, once.
    let answers = match &request.destination.host {
        Host::Ip(address) => vec![*address],
        Host::Name(name) => {
            let deadline = Instant::now() + budgets.resolve_deadline;
            match shared.resolver.resolve(name, deadline) {
                Ok(answers) => answers,
                Err(ResolveError::Timeout) => return Err(Reason::ResolveTimeout),
                Err(ResolveError::Overloaded) => return Err(Reason::ResolverOverloaded),
                Err(ResolveError::Failed | ResolveError::Invalid) => {
                    return Err(Reason::ResolveFailed);
                }
            }
        }
    };
    // Steps 3 and 4: every answer passes, or none is used.
    let approved = shared
        .rules
        .check_answers(request.destination.port, &answers)
        .map_err(|denial| match denial {
            AnswerDenial::Empty => Reason::ResolveEmpty,
            AnswerDenial::Forbidden => Reason::ForbiddenAddress,
            AnswerDenial::Mixed => Reason::MixedAnswers,
        })?;
    if shared.is_stopping() {
        return Err(Reason::Stopping);
    }
    connect_and_relay(shared, slot, client, &request, &approved, &head)
}

/// Whether a connect error is this process running out of a resource
/// rather than anything the destination did.
fn local_exhaustion(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

fn connect_upstream(
    approved: &[IpAddr],
    port: u16,
    deadline: Instant,
) -> Result<(TcpStream, SocketAddr), (Reason, Option<i32>)> {
    let mut last: (Reason, Option<i32>) = (Reason::ConnectFailed, None);
    for &address in approved {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((Reason::ConnectTimeout, None));
        }
        let target = SocketAddr::new(address, port);
        match TcpStream::connect_timeout(&target, remaining) {
            Ok(stream) => return Ok((stream, target)),
            Err(error) if local_exhaustion(&error) => {
                return Err((Reason::ResourceExhausted, error.raw_os_error()));
            }
            Err(error) => {
                let reason = if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) {
                    Reason::ConnectTimeout
                } else {
                    Reason::ConnectFailed
                };
                last = (reason, error.raw_os_error());
            }
        }
    }
    Err(last)
}

fn connect_and_relay(
    shared: &Shared,
    slot: &mut ResultSlot<'_>,
    client: &Arc<UnixStream>,
    request: &http::Request,
    approved: &[IpAddr],
    head: &http::Head,
) -> Result<(), Reason> {
    let budgets = shared.budgets;
    let reply_budget = budgets.header_deadline;
    let mut flight = if request.framing == http::Framing::Tunnel {
        if matches!(request.destination.host, Host::Name(_)) {
            slot.transport.establish(client)?;
            slot.replied = true;
        }
        Some(origin::inspect(
            client,
            head.leftover(),
            &request.destination,
        )?)
    } else {
        None
    };
    // A tunnel whose first flight is HTTP carries plaintext HTTP, which the
    // TLS shape of an omitted-port grant does not admit any more than an
    // absolute-form request (above). A tunnel to an address is not inspected
    // (`explicit_ip`), so this holds for named destinations only.
    if flight.as_ref().is_some_and(|flight| flight.http.is_some())
        && !shared
            .rules
            .permits_destination_explicit(&request.destination)
    {
        return Err(Reason::PlaintextNotGranted);
    }
    let mut forwarded = request.clone();
    let mut lease = crate::vault::lifecycle::Lease::default();
    if let Some(vault) = &shared.vault {
        if forwarded.framing != http::Framing::Tunnel {
            lease.extend(vault.inject_bound("http", &mut forwarded, &slot.initiator)?);
        }
        if let Some(inner) = flight.as_mut().and_then(|f| f.http.as_mut()) {
            lease.extend(vault.inject_bound("http", inner, &slot.initiator)?);
        }
    }
    let request = &forwarded;
    slot.origin_verification = Some(
        flight
            .as_ref()
            .map_or(Verification::HttpHost, |f| f.mechanism),
    );
    let deadline = Instant::now() + budgets.connect_deadline;
    let (upstream, connected) = match connect_upstream(approved, request.destination.port, deadline)
    {
        Ok(pair) => pair,
        Err((reason, errno)) => {
            // Allowed by policy; the connection itself was not made.
            let mut result = slot.allowed(reason, None);
            result.connect_errno = errno;
            slot.emit(result);
            if !slot.replied {
                slot.transport.refuse(
                    client,
                    reason,
                    socks::Reply::ConnectionRefused,
                    reply_budget,
                );
            }
            slot.replied = true;
            return Ok(());
        }
    };
    let upstream = Arc::new(upstream);
    if !shared.register(slot.id, Closer::Tcp(Arc::clone(&upstream))) {
        // Stop began while connecting: the connection was made, nothing
        // was relayed.
        let _ = upstream.shutdown(Shutdown::Both);
        let mut result = slot.allowed(Reason::Stopping, Some(connected));
        result.end = Some(EndReason::Stopped);
        slot.emit(result);
        if !slot.replied {
            slot.transport.refuse(
                client,
                Reason::Stopping,
                socks::Reply::GeneralFailure,
                reply_budget,
            );
        }
        slot.replied = true;
        return Ok(());
    }
    let _ = upstream.set_nodelay(true);
    let chunk = budgets.relay_chunk();
    if request.framing == http::Framing::Tunnel && !slot.replied {
        slot.transport.establish(client)?;
        slot.replied = true;
    }
    // Whether the client has heard anything yet: a tunnel has its
    // establishment reply, a plain request nothing. A relay that cannot
    // start writes to neither side, so that request can still be refused.
    let answered = slot.replied;
    // From here the client may receive relayed bytes; an error response can
    // no longer follow.
    slot.replied = true;
    if let Some(vault) = &shared.vault
        && let Some(flight) = &flight
        && flight.http.is_none()
    {
        let result = tls::relay(
            vault,
            client,
            &upstream,
            &request.destination,
            &flight.bytes,
            chunk,
            &slot.initiator,
        );
        let mut event = match result {
            Ok(outcome) => {
                slot.origin_verification = Some(Verification::MitmHttpHost);
                let mut event = slot.allowed(Reason::Relayed, Some(connected));
                event.bytes_in = outcome.bytes_in;
                event.bytes_out = outcome.bytes_out;
                event.discarded_bytes = outcome.discarded;
                event.end = Some(outcome.end);
                event
            }
            Err(failure) => {
                let mut event = denial(
                    slot.id,
                    slot.destination.clone(),
                    slot.kind,
                    failure.reason,
                    slot.accepted_at,
                );
                event.connected = Some(connected);
                event.bytes_in = failure.progress.bytes_in;
                event.bytes_out = failure.progress.bytes_out;
                event.discarded_bytes = failure.progress.discarded;
                if event.bytes_in != 0 || event.bytes_out != 0 {
                    event.end = Some(failure.progress.end);
                }
                event.transport = slot.transport;
                event
            }
        };
        if shared.is_stopping() {
            event.end = Some(EndReason::Stopped);
        }
        slot.emit(event);
        return Ok(());
    }
    let watch =
        crate::vault::lifecycle::Watch::start(Arc::new(lease), client.clone(), upstream.clone())?;
    let relayed = match request.framing {
        http::Framing::Tunnel => {
            let flight = flight.as_ref().expect("tunnel inspected before connecting");
            if let Some(inner) = &flight.http {
                relay::http(
                    client,
                    &upstream,
                    &inner.forward_head,
                    inner.framing,
                    &flight.bytes,
                    chunk,
                )
            } else {
                relay::tunnel(client, &upstream, &flight.bytes, chunk)
            }
        }
        framing => relay::http(
            client,
            &upstream,
            &request.forward_head,
            framing,
            head.leftover(),
            chunk,
        ),
    };
    if shared.vault.is_some() {
        use zeroize::Zeroize as _;
        forwarded.forward_head.zeroize();
        if let Some(inner) = flight.as_mut().and_then(|f| f.http.as_mut()) {
            inner.forward_head.zeroize();
        }
    }
    let Ok(outcome) = relayed else {
        // The relay could not start; nothing was written to either side.
        let _ = upstream.shutdown(Shutdown::Both);
        // A tunnel already answered with its establishment reply; a plain
        // request has heard nothing yet and still gets its refusal.
        if !answered {
            slot.transport.refuse(
                client,
                Reason::ResourceExhausted,
                socks::Reply::GeneralFailure,
                reply_budget,
            );
        }
        slot.emit(slot.allowed(Reason::ResourceExhausted, Some(connected)));
        return Ok(());
    };
    let end = if watch.revoked() {
        EndReason::CredentialRevoked
    } else if shared.is_stopping() {
        EndReason::Stopped
    } else {
        outcome.end
    };
    let mut result = slot.allowed(Reason::Relayed, Some(connected));
    result.bytes_in = outcome.bytes_in;
    result.bytes_out = outcome.bytes_out;
    result.discarded_bytes = outcome.discarded;
    result.end = Some(end);
    slot.emit(result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn connect_deadline_is_shared_across_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("address").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let approved = [
            "127.0.0.1".parse().expect("ip"),
            "127.0.0.1".parse().expect("ip"),
        ];
        // A deadline already spent: no attempt is made at all.
        let spent = Instant::now();
        let error = connect_upstream(&approved, port, spent).expect_err("no time left");
        assert_eq!(error, (Reason::ConnectTimeout, None));
        assert!(listener.accept().is_err(), "nothing connected");
        // With time left the first answer is used.
        let (stream, target) =
            connect_upstream(&approved, port, Instant::now() + Duration::from_secs(10))
                .expect("connects");
        assert_eq!(target.port(), port);
        drop(stream);
    }

    #[test]
    fn local_exhaustion_is_not_blamed_on_the_destination() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(local_exhaustion(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!local_exhaustion(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
    }
}
