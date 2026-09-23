//! Network rules v1 (`ouro.jail.network/1`): jail-v1 §6.3 and §10 and
//! `docs/specs/jail-v1/network-rules.md`.
//!
//! One implementation normalizes hosts for policy comparison, for the proxy's
//! request parsing and for resolver answers (§6.3: "Network and path
//! normalization must use the same implementation in comparison and
//! launch"):
//!
//! - names go through UTS 46 revision 35 ToASCII over Unicode 17.0.0 with the
//!   flags `network-rules.md` fixes ([`idna`]), from tables generated from the
//!   pinned Unicode files; there is no approximation and no fallback;
//! - a host that ends in a number is IPv4 in four strict decimal octets or
//!   refused, before and after IDNA mapping;
//! - IPv6 is parsed as an address, `::ffff:0:0/96` normalizes to IPv4 and the
//!   deprecated compatible forms refuse;
//! - addresses are classified by the checked-in forbidden-address table plus
//!   the configured translation prefixes, and only an explicit numeric grant
//!   for the exact address and port overrides a default denial.

use std::fmt;
use std::net::IpAddr;

mod address;
pub mod idna;
mod unicode;

pub use address::{
    AddressClass, AddressError, NETWORK_ADDRESSES_JSON, Prefix, is_numeric_looking, normalize,
    parse_ipv4_strict, parse_ipv6,
};
pub use idna::IdnaError;

/// The ruleset identifier the snapshot records for proxy policies.
pub const RULESET: &str = "ouro.jail.network/1";

/// The Unicode version of the IDNA tables.
pub const IDNA_UNICODE_VERSION: &str = unicode::UNICODE_VERSION;

/// The UTS 46 revision of the IDNA mapping table.
pub const IDNA_UTS46_REVISION: u32 = unicode::UTS46_REVISION;

/// SHA-256 of the `IdnaMappingTable.txt` the tables were generated from.
pub const IDNA_TABLE_SHA256: &str = unicode::IDNA_TABLE_SHA256;

/// UAX #15 NFC over the same Unicode 17.0.0 tables UTS 46 processing uses.
/// Public so the conformance suite can check it against
/// `NormalizationTest.txt`.
#[must_use]
pub fn nfc(input: &str) -> String {
    unicode::nfc(input)
}

/// Requested network mode (§6.3, §10).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum NetworkMode {
    /// No network at all: `tool` and `build`.
    None,
    /// Mediated by the outside proxy: `agent`.
    Proxy,
    /// The host network, unfiltered: `none`.
    Host,
}

impl NetworkMode {
    /// The wire spelling used by the snapshot and the receipt.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::None => "none",
            NetworkMode::Proxy => "proxy",
            NetworkMode::Host => "host",
        }
    }

    /// Orders modes by the authority they carry, lowest first.
    ///
    /// Narrowing may only move down this order (§6.3: "Change proxy network to
    /// none, or shrink its allowed host set | Allow").
    #[must_use]
    pub fn authority_rank(self) -> u8 {
        match self {
            NetworkMode::None => 0,
            NetworkMode::Proxy => 1,
            NetworkMode::Host => 2,
        }
    }
}

/// Why a host, rule or authority cannot be used. Every variant refuses; none
/// is mapped to something comparable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostRuleError {
    /// UTS 46 processing recorded an error.
    Idna(IdnaError),
    /// The host ends in a number but is not four strict decimal octets.
    AmbiguousNumeric,
    /// A deprecated IPv4-compatible IPv6 form.
    DeprecatedCompatible,
    /// The rule or authority is malformed for the stated reason.
    Malformed(&'static str),
}

impl fmt::Display for HostRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostRuleError::Idna(error) => write!(
                f,
                "the host fails UTS 46 revision 35 processing: {}",
                error.as_str()
            ),
            HostRuleError::AmbiguousNumeric => f.write_str(
                "the host ends in a number but is not four decimal octets without leading zeros",
            ),
            HostRuleError::DeprecatedCompatible => {
                f.write_str("the host is a deprecated IPv4-compatible IPv6 address")
            }
            HostRuleError::Malformed(reason) => write!(f, "malformed host: {reason}"),
        }
    }
}

/// A normalized host: a lowercase ASCII DNS name or a normalized address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Host {
    /// ToASCII output, lowercase, without a terminal dot.
    Name(String),
    /// An address after mapped-IPv6 normalization.
    Ip(IpAddr),
}

impl fmt::Display for Host {
    /// The URI host spelling: IPv6 in brackets, RFC 5952 form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(name) => f.write_str(name),
            Host::Ip(IpAddr::V4(v4)) => write!(f, "{v4}"),
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
        }
    }
}

/// A normalized destination: host and explicit port.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Destination {
    /// The host.
    pub host: Host,
    /// The port, 1–65535.
    pub port: u16,
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

fn reject_syntax(raw: &str) -> Result<(), HostRuleError> {
    for c in raw.chars() {
        match c {
            '@' => return Err(HostRuleError::Malformed("userinfo is not allowed")),
            '%' => {
                return Err(HostRuleError::Malformed(
                    "percent escapes and zone identifiers are not allowed",
                ));
            }
            '/' | '\\' | '?' | '#' => {
                return Err(HostRuleError::Malformed(
                    "a path, query or fragment is not allowed",
                ));
            }
            c if c.is_control() || c == ' ' => {
                return Err(HostRuleError::Malformed(
                    "control characters and whitespace are not allowed",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parses a port: decimal digits only, no leading zero, 1–65535.
///
/// # Errors
/// [`HostRuleError::Malformed`].
pub fn parse_port(raw: &str) -> Result<u16, HostRuleError> {
    const BAD: HostRuleError = HostRuleError::Malformed("the port is not a decimal 1-65535");
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    if raw.starts_with('0') {
        return Err(BAD);
    }
    match raw.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(BAD),
    }
}

fn ipv6_literal(raw: &str) -> Result<IpAddr, HostRuleError> {
    let v6 = parse_ipv6(raw).map_err(HostRuleError::Malformed)?;
    normalize(IpAddr::V6(v6)).map_err(|_| HostRuleError::DeprecatedCompatible)
}

/// Normalizes one host that is not a bracketed or colon-bearing IPv6 literal
/// and carries no port: UTS 46 ToASCII (removing at most one terminal dot
/// after mapping), then the numeric rule on the ASCII result.
///
/// # Errors
/// Returns [`HostRuleError`]; nothing is passed on half-normalized.
pub fn normalize_host(raw: &str) -> Result<Host, HostRuleError> {
    if raw.is_empty() {
        return Err(HostRuleError::Malformed("the host is empty"));
    }
    reject_syntax(raw)?;
    if raw.contains(['[', ']', ':']) {
        return Err(HostRuleError::Malformed(
            "brackets and colons belong only to an IPv6 literal",
        ));
    }
    if raw.contains('*') {
        return Err(HostRuleError::Malformed(
            "a wildcard is only valid as the whole leading label of a rule",
        ));
    }
    let ascii = idna::to_ascii(raw, true).map_err(HostRuleError::Idna)?;
    // `network-rules.md`: "If IDNA mapping produces a numeric address, apply
    // the numeric parsing rules again; it must not take a hostname-only path."
    if is_numeric_looking(&ascii) {
        return parse_ipv4_strict(&ascii)
            .map(|v4| Host::Ip(IpAddr::V4(v4)))
            .ok_or(HostRuleError::AmbiguousNumeric);
    }
    Ok(Host::Name(ascii))
}

/// Parses a request authority (`host[:port]`, IPv6 in brackets) into a
/// normalized destination. `default_port` applies only when no port is
/// written; `None` makes the port mandatory (CONNECT).
///
/// # Errors
/// Returns [`HostRuleError`] for userinfo, escapes, zone identifiers,
/// wildcards, an empty or invalid port, an unbracketed IPv6 address, or any
/// host normalization failure.
pub fn parse_authority(raw: &str, default_port: Option<u16>) -> Result<Destination, HostRuleError> {
    if raw.is_empty() {
        return Err(HostRuleError::Malformed("the authority is empty"));
    }
    reject_syntax(raw)?;
    let missing_port = HostRuleError::Malformed("the authority has no port");
    if let Some(rest) = raw.strip_prefix('[') {
        let (literal, after) = rest.split_once(']').ok_or(HostRuleError::Malformed(
            "an IPv6 literal has no closing bracket",
        ))?;
        let host = Host::Ip(ipv6_literal(literal)?);
        let port = match after.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None if after.is_empty() => default_port.ok_or(missing_port)?,
            None => {
                return Err(HostRuleError::Malformed(
                    "unexpected characters after an IPv6 literal",
                ));
            }
        };
        return Ok(Destination { host, port });
    }
    match raw.matches(':').count() {
        0 => Ok(Destination {
            host: normalize_host(raw)?,
            port: default_port.ok_or(missing_port)?,
        }),
        1 => {
            let (host, port) = raw.split_once(':').unwrap_or((raw, ""));
            Ok(Destination {
                host: normalize_host(host)?,
                port: parse_port(port)?,
            })
        }
        _ => Err(HostRuleError::Malformed(
            "an IPv6 address in an authority needs brackets",
        )),
    }
}

/// A host pattern: DNS labels in written order, or one address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum HostPattern {
    /// Exactly these labels.
    Exact(Vec<String>),
    /// One or more labels beneath these labels; never the apex.
    Wildcard(Vec<String>),
    /// Exactly this normalized address. Also the explicit address grant that
    /// can override a default denial for this address and port.
    Address(IpAddr),
}

/// One canonical allow rule: a host pattern and an explicit port.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct HostRule {
    /// The host pattern.
    pub pattern: HostPattern,
    /// The explicit destination port.
    pub port: u16,
}

fn labels_of(name: &str) -> Vec<String> {
    name.split('.').map(str::to_owned).collect()
}

impl HostRule {
    /// Parses one `HOST[:PORT]` rule (`[IPV6][:PORT]`, or a bare IPv6 address
    /// without a port).
    ///
    /// An omitted port expands to exactly two rules, port 80 and port 443
    /// (§10). The result is sorted so that a rule set has one canonical order.
    ///
    /// # Errors
    /// Returns [`HostRuleError`] for any rule `ouro.jail.network/1` cannot
    /// normalize, including the unspecified address, which is no destination.
    pub fn parse(raw: &str) -> Result<Vec<HostRule>, HostRuleError> {
        if raw.is_empty() {
            return Err(HostRuleError::Malformed("the rule is empty"));
        }
        reject_syntax(raw)?;
        let (pattern, port) = if let Some(rest) = raw.strip_prefix('[') {
            let (literal, after) = rest.split_once(']').ok_or(HostRuleError::Malformed(
                "an IPv6 literal has no closing bracket",
            ))?;
            let port = match after.strip_prefix(':') {
                Some(port) => Some(parse_port(port)?),
                None if after.is_empty() => None,
                None => {
                    return Err(HostRuleError::Malformed(
                        "unexpected characters after an IPv6 literal",
                    ));
                }
            };
            (HostPattern::Address(ipv6_literal(literal)?), port)
        } else if raw.matches(':').count() >= 2 {
            // `network-rules.md`: "IPv6 ports require brackets". An unbracketed
            // literal therefore carries no port.
            (HostPattern::Address(ipv6_literal(raw)?), None)
        } else {
            let (host, port) = match raw.split_once(':') {
                Some((host, port)) => (host, Some(parse_port(port)?)),
                None => (raw, None),
            };
            let pattern = if let Some(rest) = host.strip_prefix("*.") {
                match normalize_host(rest)? {
                    Host::Name(name) => HostPattern::Wildcard(labels_of(&name)),
                    Host::Ip(_) => {
                        return Err(HostRuleError::Malformed(
                            "a wildcard covers names beneath a domain, not addresses",
                        ));
                    }
                }
            } else {
                match normalize_host(host)? {
                    Host::Name(name) => HostPattern::Exact(labels_of(&name)),
                    Host::Ip(address) => HostPattern::Address(address),
                }
            };
            (pattern, port)
        };
        if let HostPattern::Address(address) = pattern
            && address.is_unspecified()
        {
            return Err(HostRuleError::Malformed(
                "the unspecified address is not a destination",
            ));
        }
        Ok(match port {
            Some(port) => vec![HostRule { pattern, port }],
            None => {
                let mut rules = vec![
                    HostRule {
                        pattern: pattern.clone(),
                        port: 80,
                    },
                    HostRule { pattern, port: 443 },
                ];
                rules.sort();
                rules
            }
        })
    }

    /// The canonical `host:port` spelling recorded in the snapshot: lowercase
    /// ASCII names, `*.` for a wildcard, IPv4 dotted quad, IPv6 RFC 5952 form
    /// in brackets, and always an explicit decimal port.
    #[must_use]
    pub fn canonical(&self) -> String {
        match &self.pattern {
            HostPattern::Exact(labels) => format!("{}:{}", labels.join("."), self.port),
            HostPattern::Wildcard(labels) => format!("*.{}:{}", labels.join("."), self.port),
            HostPattern::Address(address) => {
                format!("{}:{}", Host::Ip(*address), self.port)
            }
        }
    }

    /// Whether this rule authorizes everything `other` authorizes.
    ///
    /// A wildcard covers strictly deeper names and deeper wildcards, never the
    /// apex and never a different domain that merely shares a string suffix
    /// (§6.3: "A host wildcard is a set of DNS labels, not an arbitrary string
    /// suffix"). An address rule covers only the same address; no name rule
    /// covers an address and no address rule covers a name.
    #[must_use]
    pub fn covers(&self, other: &HostRule) -> bool {
        if self.port != other.port {
            return false;
        }
        match (&self.pattern, &other.pattern) {
            (HostPattern::Exact(mine), HostPattern::Exact(theirs)) => mine == theirs,
            (HostPattern::Wildcard(mine), HostPattern::Exact(theirs)) => {
                theirs.len() > mine.len() && theirs.ends_with(mine.as_slice())
            }
            (HostPattern::Wildcard(mine), HostPattern::Wildcard(theirs)) => {
                theirs.len() >= mine.len() && theirs.ends_with(mine.as_slice())
            }
            (HostPattern::Address(mine), HostPattern::Address(theirs)) => mine == theirs,
            _ => false,
        }
    }

    /// Whether this rule permits a request to `destination`.
    #[must_use]
    pub fn permits(&self, destination: &Destination) -> bool {
        if self.port != destination.port {
            return false;
        }
        match (&self.pattern, &destination.host) {
            (HostPattern::Exact(labels), Host::Name(name)) => {
                labels.len() == name.split('.').count()
                    && labels.iter().map(String::as_str).eq(name.split('.'))
            }
            (HostPattern::Wildcard(labels), Host::Name(name)) => {
                let theirs: Vec<&str> = name.split('.').collect();
                theirs.len() > labels.len()
                    && theirs
                        .iter()
                        .rev()
                        .zip(labels.iter().rev())
                        .all(|(a, b)| *a == b.as_str())
            }
            (HostPattern::Address(mine), Host::Ip(theirs)) => mine == theirs,
            _ => false,
        }
    }
}

/// Why an answer set cannot be used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnswerDenial {
    /// The resolver returned no address.
    Empty,
    /// Every answer is forbidden or unusable.
    Forbidden,
    /// Some answers pass and some do not: the whole set refuses.
    Mixed,
}

/// The effective network rules of one proxy policy: canonical allow rules
/// (numeric ones double as explicit address grants) and the configured
/// translation prefixes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rules {
    allow: Vec<HostRule>,
    translation: Vec<Prefix>,
}

impl Rules {
    /// Builds rules from parsed allow rules and the snapshot's
    /// `network.translation_prefixes`.
    ///
    /// # Errors
    /// Returns [`HostRuleError::Malformed`] when a translation prefix is not
    /// an IPv6 CIDR.
    pub fn new(
        allow: Vec<HostRule>,
        translation_prefixes: &[String],
    ) -> Result<Rules, HostRuleError> {
        let mut translation = Vec::with_capacity(translation_prefixes.len());
        for entry in translation_prefixes {
            match Prefix::parse(entry).map_err(HostRuleError::Malformed)? {
                prefix @ Prefix::V6(..) => translation.push(prefix),
                Prefix::V4(..) => {
                    return Err(HostRuleError::Malformed(
                        "a translation prefix is not an IPv6 prefix",
                    ));
                }
            }
        }
        Ok(Rules { allow, translation })
    }

    /// Builds rules from the snapshot's `network.allow` strings.
    ///
    /// # Errors
    /// Returns [`HostRuleError`] for any entry that does not parse.
    pub fn from_strings(
        allow: &[String],
        translation_prefixes: &[String],
    ) -> Result<Rules, HostRuleError> {
        let mut rules = Vec::new();
        for entry in allow {
            rules.extend(HostRule::parse(entry)?);
        }
        Rules::new(rules, translation_prefixes)
    }

    /// The allow rules.
    #[must_use]
    pub fn allow(&self) -> &[HostRule] {
        &self.allow
    }

    /// §10 step 1: whether a host rule permits the destination.
    #[must_use]
    pub fn permits_destination(&self, destination: &Destination) -> bool {
        self.allow.iter().any(|rule| rule.permits(destination))
    }

    /// Whether an explicit numeric grant exists for this exact normalized
    /// address and port. It grants no prefix.
    #[must_use]
    pub fn grants_address(&self, address: IpAddr, port: u16) -> bool {
        self.allow.iter().any(|rule| {
            rule.port == port
                && matches!(rule.pattern, HostPattern::Address(granted) if granted == address)
        })
    }

    /// Normalizes and classifies one address by default policy (no grants).
    ///
    /// # Errors
    /// [`AddressError::DeprecatedCompatible`].
    pub fn classify(&self, address: IpAddr) -> Result<(IpAddr, AddressClass), AddressError> {
        let normalized = normalize(address)?;
        Ok((normalized, address::classify(normalized, &self.translation)))
    }

    /// Whether `address` may be connected to for `port`: normalized, then
    /// public by default or explicitly granted.
    #[must_use]
    pub fn address_permitted(&self, address: IpAddr, port: u16) -> Option<IpAddr> {
        let (normalized, class) = self.classify(address).ok()?;
        match class {
            AddressClass::Public => Some(normalized),
            AddressClass::Forbidden => self.grants_address(normalized, port).then_some(normalized),
        }
    }

    /// §10 steps 3 and 4: checks every answer; a mixed set refuses. Returns the
    /// approved normalized addresses in answer order, without duplicates.
    ///
    /// # Errors
    /// [`AnswerDenial`].
    pub fn check_answers(
        &self,
        port: u16,
        answers: &[IpAddr],
    ) -> Result<Vec<IpAddr>, AnswerDenial> {
        if answers.is_empty() {
            return Err(AnswerDenial::Empty);
        }
        let mut approved: Vec<IpAddr> = Vec::with_capacity(answers.len());
        let mut failed = 0usize;
        for &answer in answers {
            match self.address_permitted(answer, port) {
                Some(address) => {
                    if !approved.contains(&address) {
                        approved.push(address);
                    }
                }
                None => failed += 1,
            }
        }
        match (failed, approved.is_empty()) {
            (0, _) => Ok(approved),
            (_, true) => Err(AnswerDenial::Forbidden),
            (_, false) => Err(AnswerDenial::Mixed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(raw: &str) -> HostRule {
        let mut rules = HostRule::parse(raw).expect("parses");
        assert_eq!(rules.len(), 1, "expected one rule for {raw}");
        rules.remove(0)
    }

    #[test]
    fn an_omitted_port_expands_to_eighty_and_four_four_three() {
        let rules = HostRule::parse("example.com").expect("parses");
        let canonical: Vec<String> = rules.iter().map(HostRule::canonical).collect();
        assert_eq!(canonical, vec!["example.com:80", "example.com:443"]);
    }

    #[test]
    fn a_wildcard_is_labels_not_a_string_suffix() {
        let base = rule("*.example.com:443");
        assert!(base.covers(&rule("a.example.com:443")));
        assert!(base.covers(&rule("a.b.example.com:443")));
        assert!(!base.covers(&rule("example.com:443")), "apex is excluded");
        assert!(
            !base.covers(&rule("notexample.com:443")),
            "a shared string suffix is not a shared label set"
        );
        assert!(!base.covers(&rule("a.example.com:80")), "ports differ");
    }

    #[test]
    fn an_exact_rule_never_covers_a_wildcard() {
        assert!(!rule("example.com:443").covers(&rule("*.example.com:443")));
        assert!(rule("*.example.com:443").covers(&rule("*.a.example.com:443")));
    }

    #[test]
    fn idna_and_numeric_rules_normalize() {
        assert_eq!(
            rule("BÜCHER.example.:443").canonical(),
            "xn--bcher-kva.example:443"
        );
        assert_eq!(rule("127.0.0.1:8080").canonical(), "127.0.0.1:8080");
        assert_eq!(
            rule("[::FFFF:127.0.0.1]:8080").canonical(),
            "127.0.0.1:8080"
        );
        assert_eq!(rule("[2001:DB8::1]:443").canonical(), "[2001:db8::1]:443");
        let bare: Vec<String> = HostRule::parse("2001:db8::1")
            .expect("parses")
            .iter()
            .map(HostRule::canonical)
            .collect();
        assert_eq!(bare, vec!["[2001:db8::1]:80", "[2001:db8::1]:443"]);
    }

    #[test]
    fn unmappable_and_malformed_hosts_refuse() {
        assert!(matches!(
            HostRule::parse("127.1:443"),
            Err(HostRuleError::AmbiguousNumeric)
        ));
        assert!(matches!(
            HostRule::parse("[::127.0.0.1]:443"),
            Err(HostRuleError::DeprecatedCompatible)
        ));
        for bad in [
            "user@example.com",
            "example..com",
            "a.*.example.com",
            "example.com:0",
            "example.com:0443",
            "example.com:+443",
            "*.127.0.0.1:443",
            "[fe80::1%lo0]:443",
            "0.0.0.0:80",
            "[::]:80",
            "exa mple.com",
            "ex%41mple.com",
        ] {
            assert!(HostRule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn one_terminal_dot_is_removed_and_two_refuse() {
        assert_eq!(rule("Example.COM.:443").canonical(), "example.com:443");
        assert!(HostRule::parse("example.com..:443").is_err());
    }
}
