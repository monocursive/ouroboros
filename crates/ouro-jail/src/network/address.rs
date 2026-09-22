//! Numeric parsing and the frozen forbidden-address table of
//! `ouro.jail.network/1` (`network-rules.md`, `network-addresses.json`).
//!
//! The table is the checked-in JSON itself, embedded at build time from its
//! documentation path, so the classification can never drift from the file
//! the contract validator checks. The JSON also names the mapped/compatible
//! IPv6 semantics; they must be exactly the ones implemented here, or the
//! table is treated as unusable and every address is forbidden.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use serde::Deserialize;

/// The checked-in address data, byte for byte.
pub const NETWORK_ADDRESSES_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/specs/jail-v1/network-addresses.json"
));

/// Parses IPv4 only as four decimal octets 0–255 without leading zeros
/// (except the single digit `0`). Every legacy spelling is `None`.
#[must_use]
pub fn parse_ipv4_strict(text: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

/// Whether an ASCII host "ends in a number": its last label is all decimal
/// digits or a `0x` hexadecimal spelling. Such a host is a numeric attempt:
/// it is either a strict IPv4 address or refused, never a DNS name.
#[must_use]
pub fn is_numeric_looking(ascii: &str) -> bool {
    let last = ascii.rsplit('.').next().unwrap_or(ascii);
    if last.is_empty() {
        return false;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    match last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
        Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// Parses an IPv6 literal (no brackets). Zone identifiers and anything other
/// than hexadecimal digits, colons and a trailing dotted IPv4 refuse.
///
/// # Errors
/// A static reason.
pub fn parse_ipv6(text: &str) -> Result<Ipv6Addr, &'static str> {
    if text.contains('%') {
        return Err("an IPv6 zone identifier names a link, not a destination");
    }
    if !text
        .bytes()
        .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        return Err("an IPv6 literal has a character outside hex digits, `:` and `.`");
    }
    text.parse::<Ipv6Addr>()
        .map_err(|_| "the IPv6 literal does not parse")
}

/// Why an address cannot be used at all (as opposed to being forbidden).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressError {
    /// A deprecated IPv4-compatible `::/96` form other than `::` and `::1`.
    DeprecatedCompatible,
}

/// Applies the ruleset's normalization: `::ffff:0:0/96` becomes the embedded
/// IPv4 address; deprecated compatible forms refuse; `::` and `::1` stay (the
/// table denies them).
///
/// # Errors
/// [`AddressError::DeprecatedCompatible`].
pub fn normalize(address: IpAddr) -> Result<IpAddr, AddressError> {
    match address {
        IpAddr::V4(_) => Ok(address),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return Ok(IpAddr::V4(v4));
            }
            let bits = u128::from(v6);
            if bits >> 32 == 0 && bits > 1 {
                return Err(AddressError::DeprecatedCompatible);
            }
            Ok(address)
        }
    }
}

/// An address prefix with its host bits cleared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prefix {
    /// IPv4.
    V4(u32, u8),
    /// IPv6.
    V6(u128, u8),
}

fn mask32(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(length.min(32)))
    }
}

fn mask128(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(length.min(128)))
    }
}

impl Prefix {
    /// Parses `address/length`, clearing host bits.
    ///
    /// # Errors
    /// A static reason.
    pub fn parse(text: &str) -> Result<Prefix, &'static str> {
        let (address, length) = text.split_once('/').ok_or("a prefix has no `/length`")?;
        if length.is_empty()
            || length.len() > 3
            || !length.bytes().all(|b| b.is_ascii_digit())
            || (length.len() > 1 && length.starts_with('0'))
        {
            return Err("a prefix length is not a canonical decimal integer");
        }
        let length: u8 = length
            .parse()
            .map_err(|_| "a prefix length is out of range")?;
        if address.contains(':') {
            if length > 128 {
                return Err("an IPv6 prefix length exceeds 128");
            }
            let bits = u128::from(parse_ipv6(address)?);
            Ok(Prefix::V6(bits & mask128(length), length))
        } else {
            if length > 32 {
                return Err("an IPv4 prefix length exceeds 32");
            }
            let bits = u32::from(parse_ipv4_strict(address).ok_or("an IPv4 prefix is malformed")?);
            Ok(Prefix::V4(bits & mask32(length), length))
        }
    }

    /// Whether `address` lies in this prefix. No family conversion happens
    /// here: callers normalize first.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (*self, address) {
            (Prefix::V4(network, length), IpAddr::V4(v4)) => {
                u32::from(v4) & mask32(length) == network
            }
            (Prefix::V6(network, length), IpAddr::V6(v6)) => {
                u128::from(v6) & mask128(length) == network
            }
            _ => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableFile {
    ruleset: String,
    #[allow(dead_code)]
    retrieved_at: String,
    #[allow(dead_code)]
    registries: Vec<serde_json::Value>,
    ipv4_deny: Vec<String>,
    ipv6_deny: Vec<String>,
    ipv6_default_public: String,
    mapped_ipv6: String,
    compatible_ipv6: String,
}

/// The parsed forbidden-address table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddressTable {
    /// Denied prefixes, both families.
    pub deny: Vec<Prefix>,
    /// IPv6 outside this prefix is denied by default.
    pub ipv6_public: Prefix,
}

fn load() -> Result<AddressTable, &'static str> {
    let file: TableFile =
        serde_json::from_str(NETWORK_ADDRESSES_JSON).map_err(|_| "the table is not valid JSON")?;
    if file.ruleset != crate::network::RULESET {
        return Err("the table names a different ruleset");
    }
    if file.mapped_ipv6 != "normalize_to_ipv4_before_classification"
        || file.compatible_ipv6 != "reject_except_unspecified_and_loopback"
    {
        return Err("the table names IPv6 semantics this implementation does not implement");
    }
    let mut deny = Vec::new();
    for entry in &file.ipv4_deny {
        let prefix = Prefix::parse(entry)?;
        if !matches!(prefix, Prefix::V4(..)) {
            return Err("an ipv4_deny entry is not IPv4");
        }
        deny.push(prefix);
    }
    for entry in &file.ipv6_deny {
        let prefix = Prefix::parse(entry)?;
        if !matches!(prefix, Prefix::V6(..)) {
            return Err("an ipv6_deny entry is not IPv6");
        }
        deny.push(prefix);
    }
    let ipv6_public = Prefix::parse(&file.ipv6_default_public)?;
    if !matches!(ipv6_public, Prefix::V6(..)) {
        return Err("ipv6_default_public is not IPv6");
    }
    Ok(AddressTable { deny, ipv6_public })
}

/// The embedded table, parsed once.
///
/// # Errors
/// A static reason when the embedded data is unusable. Callers treat that as
/// "every address is forbidden".
pub fn table() -> Result<&'static AddressTable, &'static str> {
    static TABLE: OnceLock<Result<AddressTable, &'static str>> = OnceLock::new();
    TABLE.get_or_init(load).as_ref().map_err(|error| *error)
}

/// Default classification of a normalized address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressClass {
    /// Not in any denied prefix.
    Public,
    /// Denied by default: the table, IPv6 outside 2000::/3, or a configured
    /// translation prefix.
    Forbidden,
}

/// Classifies an already-normalized address against the table and the
/// configured translation prefixes. An unusable table forbids everything.
#[must_use]
pub fn classify(address: IpAddr, translation: &[Prefix]) -> AddressClass {
    let Ok(table) = table() else {
        return AddressClass::Forbidden;
    };
    let denied = table.deny.iter().any(|prefix| prefix.contains(address))
        || translation.iter().any(|prefix| prefix.contains(address))
        || (address.is_ipv6() && !table.ipv6_public.contains(address));
    if denied {
        AddressClass::Forbidden
    } else {
        AddressClass::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_loads() {
        let table = table().expect("the checked-in table is usable");
        assert_eq!(table.deny.len(), 18 + 14);
    }

    #[test]
    fn strict_ipv4_refuses_every_legacy_spelling() {
        assert_eq!(parse_ipv4_strict("127.0.0.1"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(parse_ipv4_strict("0.0.0.0"), Some(Ipv4Addr::UNSPECIFIED));
        for bad in [
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "017700000001",
            "1.2.3.4.5",
            "1.2.3.256",
            "1.2.3.",
            "+1.2.3.4",
            "1.2.3.04",
            "1..3.4",
            "",
        ] {
            assert_eq!(parse_ipv4_strict(bad), None, "{bad}");
        }
    }

    #[test]
    fn numeric_looking_names_are_the_ones_ending_in_a_number() {
        assert!(is_numeric_looking("127.1"));
        assert!(is_numeric_looking("0x7f"));
        assert!(is_numeric_looking("example.0x"));
        assert!(is_numeric_looking("a.b.123"));
        assert!(!is_numeric_looking("0x7f.example"));
        assert!(!is_numeric_looking("1e100.net"));
        assert!(!is_numeric_looking("example.com"));
    }

    #[test]
    fn prefixes_clear_host_bits_and_match_their_family_only() {
        let prefix = Prefix::parse("10.1.2.3/8").expect("parses");
        assert_eq!(prefix, Prefix::V4(0x0a00_0000, 8));
        assert!(prefix.contains(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))));
        assert!(!prefix.contains("::ffff:10.0.0.1".parse().expect("parses")));
        assert!(Prefix::parse("10.0.0.0/33").is_err());
        assert!(Prefix::parse("10.0.0.0/08").is_err());
        assert!(Prefix::parse("::/129").is_err());
    }
}
