//! N03 (rules part): network rules v1 against every frozen case.
//!
//! - `fixtures/network-cases.json`: default classification, normalization and
//!   refusal of each frozen address case;
//! - `network-rules.md`: the IDNA examples, repeated dots, invalid joiners and
//!   malformed A-labels, mapped/compatible IPv6, configured NAT64 prefixes,
//!   explicit numeric exceptions, nondefault ports, mixed answers and
//!   wildcard/apex matching;
//! - the Unicode 17.0.0 `IdnaTestV2.txt` conformance file, every line, for
//!   ToASCII with the flags `network-rules.md` fixes (all checks on);
//! - ambiguous numeric spellings in requests.
//!
//! Rebinding, Host/absolute-URI disagreement and the single-resolution rule
//! need the running proxy and are in `portable_proxy.rs` (`n03_*`).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_jail::network::{
    AddressClass, AnswerDenial, Destination, Host, HostRule, HostRuleError, IDNA_TABLE_SHA256,
    IDNA_UNICODE_VERSION, IDNA_UTS46_REVISION, IdnaError, NETWORK_ADDRESSES_JSON, Rules, idna, nfc,
    normalize_host, parse_authority, parse_ipv6,
};
use sha2::{Digest, Sha256};

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1")
}

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("data")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a valid test address")
}

fn rules(allow: &[&str], translation: &[&str]) -> Rules {
    let allow: Vec<String> = allow.iter().map(|rule| (*rule).to_owned()).collect();
    let translation: Vec<String> = translation.iter().map(|p| (*p).to_owned()).collect();
    Rules::from_strings(&allow, &translation).expect("the test rules parse")
}

/// A frozen case's verdict under the ruleset: `reject` when the input is not
/// a usable address, else the default classification after normalization.
fn verdict(rules: &Rules, input: &str) -> (String, Option<String>) {
    let parsed = if input.contains(':') {
        parse_authority(&format!("[{input}]"), Some(1)).map(|destination| destination.host)
    } else {
        normalize_host(input)
    };
    let address = match parsed {
        Ok(Host::Ip(address)) => address,
        Ok(Host::Name(_)) | Err(_) => return ("reject".to_owned(), None),
    };
    match rules.classify(address) {
        Err(_) => ("reject".to_owned(), None),
        Ok((normalized, AddressClass::Public)) => {
            ("public".to_owned(), Some(normalized.to_string()))
        }
        Ok((normalized, AddressClass::Forbidden)) => {
            ("deny".to_owned(), Some(normalized.to_string()))
        }
    }
}

#[test]
fn n03_every_frozen_address_case_matches_network_cases_json() {
    let text = std::fs::read_to_string(specs_dir().join("fixtures/network-cases.json"))
        .expect("the frozen cases are readable");
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(cases.len(), 26, "the frozen corpus has 26 cases");
    let rules = rules(&[], &[]);
    for case in &cases {
        let input = case["input"].as_str().expect("an input");
        let expected = case["result"].as_str().expect("a result");
        let (result, normalized) = verdict(&rules, input);
        assert_eq!(result, expected, "case {input}");
        if let Some(want) = case.get("normalized").and_then(|value| value.as_str()) {
            assert_eq!(
                normalized.as_deref(),
                Some(want),
                "normalization of {input}"
            );
        }
    }
}

#[test]
fn n03_the_embedded_address_table_is_the_checked_in_file() {
    let on_disk = std::fs::read_to_string(specs_dir().join("network-addresses.json"))
        .expect("the table is readable");
    assert_eq!(NETWORK_ADDRESSES_JSON, on_disk);
}

#[test]
fn n03_every_forbidden_prefix_is_denied_at_both_ends_and_bounded() {
    let table: serde_json::Value =
        serde_json::from_str(NETWORK_ADDRESSES_JSON).expect("valid JSON");
    let rules = rules(&[], &[]);
    let deny = |address: IpAddr| -> bool {
        matches!(rules.classify(address), Ok((_, AddressClass::Forbidden)))
    };
    for entry in table["ipv4_deny"].as_array().expect("a list") {
        let (network, length) = entry
            .as_str()
            .expect("a CIDR")
            .split_once('/')
            .expect("CIDR");
        let base = u32::from(network.parse::<std::net::Ipv4Addr>().expect("IPv4"));
        let length: u32 = length.parse().expect("a length");
        let last = base | (u32::MAX.checked_shr(length).unwrap_or(0));
        assert!(deny(IpAddr::V4(base.into())), "{entry} first");
        assert!(deny(IpAddr::V4(last.into())), "{entry} last");
    }
    for entry in table["ipv6_deny"].as_array().expect("a list") {
        let (network, length) = entry
            .as_str()
            .expect("a CIDR")
            .split_once('/')
            .expect("CIDR");
        let base = u128::from(network.parse::<std::net::Ipv6Addr>().expect("IPv6"));
        let length: u32 = length.parse().expect("a length");
        let last = base | (u128::MAX.checked_shr(length).unwrap_or(0));
        for address in [base, last] {
            let address = IpAddr::V6(address.into());
            // `::ffff:0:0/96` normalizes to IPv4 first and is then classified
            // there; `::/96` holds compatible forms that refuse outright.
            match rules.classify(address) {
                Ok((_, AddressClass::Forbidden)) | Err(_) => {}
                Ok((normalized, AddressClass::Public)) => {
                    panic!("{entry}: {address} classified public as {normalized}")
                }
            }
        }
    }
    // Neighbours just outside prefixes stay public: the table is not a
    // blanket denial.
    for public in [
        "11.0.0.0",
        "9.255.255.255",
        "172.32.0.0",
        "100.128.0.0",
        "8.8.8.8",
    ] {
        assert!(!deny(ip(public)), "{public}");
    }
    for public in [
        "2001:4860:4860::8888",
        "2001:200::1",
        "2a00::1",
        "2620:4f:7fff::1",
    ] {
        assert!(!deny(ip(public)), "{public}");
    }
    // IPv6 outside 2000::/3 is denied by default.
    for outside in ["4000::1", "1000::1", "e000::1"] {
        assert!(deny(ip(outside)), "{outside}");
    }
}

#[test]
fn n03_mapped_ipv6_normalizes_before_classification_and_grants() {
    let rules = rules(&["127.0.0.1:8080"], &[]);
    assert_eq!(
        rules.classify(ip("::ffff:127.0.0.1")).expect("usable"),
        (ip("127.0.0.1"), AddressClass::Forbidden)
    );
    assert_eq!(
        rules.classify(ip("::ffff:8.8.8.8")).expect("usable"),
        (ip("8.8.8.8"), AddressClass::Public)
    );
    // A grant written in mapped form is the IPv4 grant.
    assert_eq!(
        HostRule::parse("[::ffff:127.0.0.1]:8080")
            .expect("parses")
            .first()
            .map(HostRule::canonical),
        Some("127.0.0.1:8080".to_owned())
    );
    // A mapped resolver answer meets the IPv4 grant after normalization.
    assert_eq!(
        rules.check_answers(8080, &[ip("::ffff:127.0.0.1")]),
        Ok(vec![ip("127.0.0.1")])
    );
    // A mapped answer never slips past the IPv4 table.
    let none = self::rules(&[], &[]);
    assert_eq!(
        none.check_answers(443, &[ip("::ffff:169.254.169.254")]),
        Err(AnswerDenial::Forbidden)
    );
}

#[test]
fn n03_deprecated_compatible_ipv6_refuses_everywhere() {
    let rules = rules(&[], &[]);
    assert!(rules.classify(ip("::127.0.0.1")).is_err());
    assert!(rules.classify(ip("::8.8.8.8")).is_err());
    assert!(matches!(
        HostRule::parse("[::127.0.0.1]:443"),
        Err(HostRuleError::DeprecatedCompatible)
    ));
    assert!(matches!(
        parse_authority("[::127.0.0.1]:443", None),
        Err(HostRuleError::DeprecatedCompatible)
    ));
    assert_eq!(
        rules.check_answers(443, &[ip("::7f00:1")]),
        Err(AnswerDenial::Forbidden)
    );
    // The ordinary unspecified and loopback addresses are denied, not refused.
    assert_eq!(
        rules.classify(ip("::")).expect("usable").1,
        AddressClass::Forbidden
    );
    assert_eq!(
        rules.classify(ip("::1")).expect("usable").1,
        AddressClass::Forbidden
    );
}

#[test]
fn n03_known_and_configured_translation_prefixes_deny_whole_ranges() {
    let rules = rules(&[], &["2600:1f00:64::/96"]);
    // Known ranges: an encoded public IPv4 is still denied.
    for address in [
        "64:ff9b::808:808",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::808:808",
    ] {
        assert_eq!(
            rules.classify(ip(address)).expect("usable").1,
            AddressClass::Forbidden,
            "{address}"
        );
    }
    // A configured network-specific prefix is denied whole ...
    for address in ["2600:1f00:64::a9fe:a9fe", "2600:1f00:64::808:808"] {
        assert_eq!(
            rules.classify(ip(address)).expect("usable").1,
            AddressClass::Forbidden,
            "{address}"
        );
    }
    // ... and nothing beyond it.
    assert_eq!(
        rules
            .classify(ip("2600:1f00:65::808:808"))
            .expect("usable")
            .1,
        AddressClass::Public
    );
    let unconfigured = self::rules(&[], &[]);
    assert_eq!(
        unconfigured
            .classify(ip("2600:1f00:64::a9fe:a9fe"))
            .expect("usable")
            .1,
        AddressClass::Public,
        "without the host manifest the prefix is not known"
    );
    assert!(Rules::from_strings(&[], &["10.0.0.0/8".to_owned()]).is_err());
    assert!(Rules::from_strings(&[], &["64:ff9b::/129".to_owned()]).is_err());
}

#[test]
fn n03_explicit_numeric_exceptions_are_exact_address_and_port() {
    let rules = rules(&["127.0.0.1:8080", "[::1]:8443", "fixture.test:8080"], &[]);
    assert_eq!(
        rules.check_answers(8080, &[ip("127.0.0.1")]),
        Ok(vec![ip("127.0.0.1")])
    );
    assert_eq!(rules.check_answers(8443, &[ip("::1")]), Ok(vec![ip("::1")]));
    // Another port, a neighbour address, another family: no grant.
    assert_eq!(
        rules.check_answers(8081, &[ip("127.0.0.1")]),
        Err(AnswerDenial::Forbidden)
    );
    assert_eq!(
        rules.check_answers(8080, &[ip("127.0.0.2")]),
        Err(AnswerDenial::Forbidden)
    );
    assert_eq!(
        rules.check_answers(8080, &[ip("::1")]),
        Err(AnswerDenial::Forbidden)
    );
    // A hostname rule alone never authorizes a private answer.
    let names_only = self::rules(&["fixture.test:8080"], &[]);
    assert_eq!(
        names_only.check_answers(8080, &[ip("127.0.0.1")]),
        Err(AnswerDenial::Forbidden)
    );
    // The unspecified address cannot be granted, and a grant is no prefix.
    assert!(HostRule::parse("0.0.0.0:8080").is_err());
    assert!(HostRule::parse("127.0.0.0/8").is_err());
    // Malformed representations cannot be granted.
    for bad in [
        "127.1:8080",
        "0x7f000001:8080",
        "[fe80::1%lo0]:8080",
        "[::127.0.0.1]:8080",
    ] {
        assert!(HostRule::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn n03_mixed_answer_sets_refuse_whole() {
    let rules = rules(&["127.0.0.1:443"], &[]);
    assert_eq!(
        rules.check_answers(443, &[ip("8.8.8.8"), ip("10.0.0.1")]),
        Err(AnswerDenial::Mixed)
    );
    assert_eq!(
        rules.check_answers(443, &[ip("10.0.0.1"), ip("8.8.8.8")]),
        Err(AnswerDenial::Mixed)
    );
    assert_eq!(
        rules.check_answers(443, &[ip("8.8.8.8"), ip("::127.0.0.1")]),
        Err(AnswerDenial::Mixed),
        "an unusable answer mixes as a failure"
    );
    assert_eq!(
        rules.check_answers(443, &[ip("8.8.8.8"), ip("127.0.0.1"), ip("8.8.8.8")]),
        Ok(vec![ip("8.8.8.8"), ip("127.0.0.1")]),
        "granted and public answers pass together, deduplicated in order"
    );
    assert_eq!(rules.check_answers(443, &[]), Err(AnswerDenial::Empty));
    assert_eq!(
        rules.check_answers(443, &[ip("10.0.0.1"), ip("192.168.0.1")]),
        Err(AnswerDenial::Forbidden)
    );
}

fn permits(rules: &Rules, authority: &str) -> bool {
    let destination: Destination = parse_authority(authority, None).expect("the authority parses");
    rules.permits_destination(&destination)
}

#[test]
fn n03_wildcards_match_labels_beneath_never_the_apex() {
    let rules = rules(&["*.example.com:443", "*.BÜCHER.example:443"], &[]);
    assert!(permits(&rules, "a.example.com:443"));
    assert!(permits(&rules, "A.B.Example.COM.:443"));
    assert!(!permits(&rules, "example.com:443"), "the apex is excluded");
    assert!(!permits(&rules, "badexample.com:443"));
    assert!(!permits(&rules, "a.example.com.evil:443"));
    assert!(!permits(&rules, "a.example.com:80"), "the rule's port only");
    assert!(permits(&rules, "www.xn--bcher-kva.example:443"));
    assert!(permits(&rules, "WWW.Bücher.example:443"));
    assert!(!permits(&rules, "xn--bcher-kva.example:443"));
    for bad in [
        "*.com.*:443",
        "a.*.example.com:443",
        "*example.com:443",
        "**.example.com:443",
    ] {
        assert!(HostRule::parse(bad).is_err(), "{bad}");
    }
    assert!(
        parse_authority("*.example.com:443", None).is_err(),
        "no wildcard in a request"
    );
}

#[test]
fn n03_idna_names_narrow_like_their_a_labels() {
    // Policy comparison and the proxy use this one normalization, so a
    // U-label narrowing a wildcard is compared by its A-label (§6.3).
    let base = &HostRule::parse("*.example.com:443").expect("parses")[0];
    let narrowed = &HostRule::parse("BÜCHER.Example.COM:443").expect("parses")[0];
    assert_eq!(narrowed.canonical(), "xn--bcher-kva.example.com:443");
    assert!(base.covers(narrowed));
    let other = &HostRule::parse("bücher.example.net:443").expect("parses")[0];
    assert!(!base.covers(other));
    // An address rule is covered only by the same address rule.
    let address = &HostRule::parse("[::ffff:127.0.0.1]:443").expect("parses")[0];
    assert!(!base.covers(address));
    assert!(HostRule::parse("127.0.0.1:443").expect("parses")[0].covers(address));
}

#[test]
fn n03_omitted_ports_mean_80_and_443_and_nondefault_ports_are_exact() {
    let rules = rules(&["example.com", "api.example.com:8443"], &[]);
    assert!(permits(&rules, "example.com:80"));
    assert!(permits(&rules, "example.com:443"));
    assert!(!permits(&rules, "example.com:8443"));
    assert!(permits(&rules, "api.example.com:8443"));
    assert!(!permits(&rules, "api.example.com:443"));
    for bad in [
        "example.com:0",
        "example.com:65536",
        "example.com:0443",
        "example.com:",
    ] {
        assert!(HostRule::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn n03_network_rules_md_idna_examples() {
    let canonical = |raw: &str| -> Result<String, HostRuleError> {
        HostRule::parse(&format!("{raw}:443"))
            .map(|rules| rules.first().map(HostRule::canonical).unwrap_or_default())
    };
    assert_eq!(
        canonical("BÜCHER.example.").as_deref(),
        Ok("xn--bcher-kva.example:443")
    );
    assert_eq!(canonical("faß.de").as_deref(), Ok("xn--fa-hia.de:443"));
    // Invalid joiners (ContextJ).
    assert!(matches!(
        canonical("a\u{200d}b.example"),
        Err(HostRuleError::Idna(_))
    ));
    assert!(matches!(
        canonical("a\u{200c}b.example"),
        Err(HostRuleError::Idna(_))
    ));
    // A joiner after a virama is valid.
    assert!(canonical("\u{915}\u{94d}\u{200d}\u{937}.example").is_ok());
    // Malformed A-labels (with a well-formed control first).
    assert_eq!(
        canonical("xn--ls8h.example").as_deref(),
        Ok("xn--ls8h.example:443")
    );
    for bad in [
        "xn--.example",
        "xn--a.example",
        // RFC 3492 §6.2: a delimiter with nothing before it is not a
        // separator, so `-` is decoded as a digit and fails.
        "xn---ls8h.example",
        "xn--ab-.example",
        "xn--zz-9999999999.example",
    ] {
        assert!(
            matches!(canonical(bad), Err(HostRuleError::Idna(_))),
            "{bad}"
        );
    }
    // Repeated dots: interior, and more than one terminal dot.
    for bad in ["a..example", ".example", "example..", "example.\u{3002}"] {
        assert!(canonical(bad).is_err(), "{bad}");
    }
    // One terminal dot, including an ideographic one, is removed.
    assert_eq!(canonical("example\u{3002}").as_deref(), Ok("example:443"));
    // Controls, percent escapes and zone identifiers refuse.
    for bad in [
        "exa\u{7f}mple",
        "exa\u{85}mple",
        "ex%61mple",
        "fe80::1%25eth0",
    ] {
        assert!(canonical(bad).is_err(), "{bad:?}");
    }
    // DNS lengths.
    let label63 = "a".repeat(63);
    assert!(canonical(&format!("{label63}.example")).is_ok());
    assert!(canonical(&format!("{}.example", "a".repeat(64))).is_err());
    let long = [label63.as_str(); 4].join(".");
    assert!(canonical(&long).is_err(), "255 characters");
}

#[test]
fn n03_idna_output_that_is_numeric_takes_the_numeric_path() {
    // Full-width digits and dots map to an IPv4 literal ...
    assert_eq!(
        normalize_host("\u{ff11}\u{ff12}\u{ff17}\u{ff0e}0\u{ff0e}0\u{ff0e}1"),
        Ok(Host::Ip(ip("127.0.0.1")))
    );
    // ... and an ambiguous one refuses rather than becoming a name.
    assert_eq!(
        normalize_host("\u{ff11}\u{ff12}\u{ff17}\u{ff0e}1"),
        Err(HostRuleError::AmbiguousNumeric)
    );
}

#[test]
fn n03_ambiguous_ipv4_spellings_never_become_names() {
    for bad in [
        "127.1:80",
        "0x7f.1:80",
        "0x7f000001:80",
        "017700000001:80",
        "0177.0.0.1:80",
        "2130706433:80",
        "127.0.0.01:80",
        "1.2.3.4.5:80",
        "256.0.0.1:80",
        "example.123:80",
        "example.0x1f:80",
    ] {
        assert!(
            matches!(
                parse_authority(bad, None),
                Err(HostRuleError::AmbiguousNumeric)
            ),
            "{bad}"
        );
    }
    assert_eq!(
        parse_authority("127.0.0.1.:80", None).map(|d| d.host),
        Ok(Host::Ip(ip("127.0.0.1"))),
        "one terminal dot on an IPv4 literal"
    );
    assert!(parse_authority("0x7f.example:80", None).is_ok(), "a name");
}

/// Each syntax refusal names its own reason, before IDNA would have refused
/// the same input for a less useful one.
#[test]
fn n03_syntax_refusals_name_their_reason() {
    let malformed = |raw: &str| match normalize_host(raw) {
        Err(HostRuleError::Malformed(reason)) => reason,
        other => panic!("{raw:?}: {other:?}"),
    };
    assert_eq!(malformed("user@example.com"), "userinfo is not allowed");
    assert_eq!(
        malformed("ex%61mple.com"),
        "percent escapes and zone identifiers are not allowed"
    );
    assert_eq!(
        malformed("exa\u{1}mple.com"),
        "control characters and whitespace are not allowed"
    );
    assert_eq!(
        malformed("exa mple.com"),
        "control characters and whitespace are not allowed"
    );
    assert_eq!(
        parse_ipv6("fe80::1%eth0"),
        Err("an IPv6 zone identifier names a link, not a destination")
    );
}

// ---------------------------------------------------------------------------
// Bounded IDNA work: the reviewer's R01, R10 and R19 shapes.
// ---------------------------------------------------------------------------

/// One label of `n` distinct valid CJK ideographs (3 UTF-8 bytes each).
fn costly_label(n: u32) -> String {
    (0..n)
        .map(|i| char::from_u32(0x4E00 + i).expect("a CJK ideograph"))
        .collect()
}

/// Runs `normalize_host` `rounds` times; returns the error and the time.
fn timed(host: &str, rounds: u32) -> (HostRuleError, Duration) {
    let started = Instant::now();
    let mut last = None;
    for _ in 0..rounds {
        last = Some(normalize_host(host).expect_err("the host refuses"));
    }
    (last.expect("at least one round"), started.elapsed())
}

/// A long label used to be punycode-encoded (quadratic) before
/// VerifyDnsLength refused it: 67 ms per host on macOS, 131 ms on the
/// reference host, in release builds (seconds in debug). It now refuses at
/// the mapping bound: the error names the early step, and twenty rounds stay
/// under a second in any build, where the old code needed at least 1.3 s.
#[test]
fn n03_a_long_label_refuses_before_any_quadratic_work() {
    let host = format!("{}.example", costly_label(10_000));
    let (error, elapsed) = timed(&host, 20);
    assert_eq!(error, HostRuleError::Idna(IdnaError::NameLength));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    // Squared katakana (U+3300..U+3357) map to two to five code points.
    let squares: String = (0..10_000u32)
        .map(|i| char::from_u32(0x3300 + (i % 0x58)).expect("a square"))
        .collect();
    let (error, elapsed) = timed(&format!("{}{squares}", costly_label(3_000)), 20);
    assert_eq!(error, HostRuleError::Idna(IdnaError::NameLength));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    // Just inside the mapping bound, the label bound refuses before encoding.
    let (error, elapsed) = timed(&format!("{}.example", costly_label(1_000)), 20);
    assert_eq!(error, HostRuleError::Idna(IdnaError::LabelLength));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

/// U+FDFA maps to eighteen code points: 10,800 of them used to expand to
/// 194,400 code points (and their NFC copies) per request. The mapping step
/// now stops at its bound.
#[test]
fn n03_mapping_expansion_is_bounded() {
    let host: String = std::iter::repeat_n('\u{fdfa}', 10_800).collect();
    let (error, elapsed) = timed(&host, 20);
    assert_eq!(error, HostRuleError::Idna(IdnaError::NameLength));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

/// A long A-label used to be decoded with a quadratic insert; decoding now
/// stops after 63 code points, and a very long one refuses at the mapping
/// bound before decoding starts.
#[test]
fn n03_a_long_a_label_refuses_before_quadratic_decoding() {
    let (error, elapsed) = timed(&format!("xn--{}", "a".repeat(30_000)), 20);
    assert_eq!(error, HostRuleError::Idna(IdnaError::NameLength));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    let (error, _) = timed(&format!("xn--{}", "a".repeat(1_000)), 1);
    assert_eq!(error, HostRuleError::Idna(IdnaError::LabelLength));
}

/// The early refusals lose no valid name: the longest valid labels and names
/// still pass, and one more refuses.
#[test]
fn n03_the_bounds_keep_every_valid_length() {
    let label63 = "a".repeat(63);
    let name253 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(61));
    assert_eq!(name253.len(), 253);
    assert_eq!(normalize_host(&name253), Ok(Host::Name(name253.clone())));
    assert_eq!(
        normalize_host(&format!("{name253}.")),
        Ok(Host::Name(name253.clone())),
        "one terminal dot is removed"
    );
    assert!(normalize_host(&format!("{name253}a")).is_err());
    // A maximal U-label: 63 output bytes from a non-ASCII label.
    let unicode = format!("{}\u{fc}", "a".repeat(55));
    let ascii = idna::to_ascii(&unicode, true).expect("a valid U-label");
    assert!(ascii.len() <= 63, "{ascii}");
    // Uppercase and full-width forms map (and shrink under NFC) inside the
    // bound: 253 full-width letters and dots are 253 code points.
    let wide: String = name253
        .chars()
        .map(|c| if c == '.' { '\u{ff0e}' } else { '\u{ff41}' })
        .collect();
    assert_eq!(normalize_host(&wide), Ok(Host::Name(name253)));
}

#[test]
fn n03_request_authorities_refuse_userinfo_escapes_zones_and_unbracketed_ipv6() {
    for bad in [
        "user@example.com:443",
        "user:pw@example.com:443",
        "ex%61mple.com:443",
        "[fe80::1%25eth0]:443",
        "[fe80::1%eth0]:443",
        "::1:443",
        "[::1]443",
        "[::1",
        "example.com",
        "example.com:",
        "example.com:443/path",
        "example.com:443?q",
        "exa mple.com:443",
    ] {
        assert!(parse_authority(bad, None).is_err(), "{bad}");
    }
    assert_eq!(
        parse_authority("[2001:DB8::1]:443", None)
            .map(|destination| destination.to_string())
            .as_deref(),
        Ok("[2001:db8::1]:443")
    );
}

#[test]
fn n03_canonical_ipv6_rules_use_rfc_5952() {
    let canonical = |raw: &str| {
        HostRule::parse(raw)
            .expect("parses")
            .first()
            .map(HostRule::canonical)
            .unwrap_or_default()
    };
    assert_eq!(
        canonical("[2001:0DB8:0:0:1:0:0:1]:443"),
        "[2001:db8::1:0:0:1]:443"
    );
    assert_eq!(
        canonical("[2001:db8:0:1:1:1:1:1]:443"),
        "[2001:db8:0:1:1:1:1:1]:443"
    );
    assert_eq!(canonical("[2001:db8::0:1]:443"), "[2001:db8::1]:443");
}

// ---------------------------------------------------------------------------
// UTS 46 conformance: IdnaTestV2.txt (Unicode 17.0.0)
// ---------------------------------------------------------------------------

const IDNA_TEST_SHA256: &str = "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf";

/// Unescapes `\uXXXX` and `\x{X...}`; `None` when an escape is not a scalar
/// value (a lone surrogate cannot be a Rust string).
fn unescape(field: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let code = match chars.next() {
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                u32::from_str_radix(&hex, 16).ok()?
            }
            Some('x') => {
                if chars.next() != Some('{') {
                    return None;
                }
                let hex: String = chars.by_ref().take_while(|&c| c != '}').collect();
                u32::from_str_radix(&hex, 16).ok()?
            }
            _ => return None,
        };
        out.push(char::from_u32(code)?);
    }
    Some(out)
}

fn field(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw == "\"\"" {
        return Some(String::new());
    }
    unescape(raw)
}

#[test]
fn n03_uts46_conformance_file_toascii_nontransitional_all_flags() {
    assert_eq!(IDNA_UNICODE_VERSION, "17.0.0");
    assert_eq!(IDNA_UTS46_REVISION, 35);
    assert_eq!(
        IDNA_TABLE_SHA256,
        "87f05505dc026fdb2bff16132bdc68a8014675836882a9a2b1844540ad3be382"
    );
    let bytes = std::fs::read(data_dir().join("unicode-17.0.0/IdnaTestV2.txt"))
        .expect("the conformance file is checked in");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        IDNA_TEST_SHA256,
        "the pinned Unicode 17.0.0 IdnaTestV2.txt"
    );
    let text = String::from_utf8(bytes).expect("UTF-8");
    assert!(text.contains("# Version: 17.0.0"));
    let (mut checked, mut errors_expected, mut skipped) = (0usize, 0usize, 0usize);
    let mut failures = Vec::new();
    for line in text.lines() {
        let data = line.split('#').next().unwrap_or_default();
        if data.trim().is_empty() {
            continue;
        }
        let columns: Vec<&str> = data.split(';').collect();
        assert_eq!(columns.len(), 7, "seven columns: {line}");
        let Some(source) = field(columns[0]) else {
            // Only a lone surrogate is unrepresentable as a Rust string; the
            // proxy refuses non-UTF-8 bytes before IDNA. Such a line must
            // expect an error, so skipping it cannot hide an acceptance.
            assert!(
                columns[0].to_ascii_lowercase().contains("\\ud"),
                "only surrogate escapes are unrepresentable: {line}"
            );
            assert!(
                columns[4].contains("A3"),
                "a surrogate line expects A3: {line}"
            );
            skipped += 1;
            continue;
        };
        let to_unicode = match columns[1].trim() {
            "" => Some(source.clone()),
            other => field(other),
        };
        let to_unicode_status = columns[2].trim();
        let to_ascii_n = match columns[3].trim() {
            "" => to_unicode.clone(),
            other => field(other),
        };
        let status = match columns[4].trim() {
            "" => to_unicode_status,
            other => other,
        };
        let expect_error = !(status.is_empty() || status == "[]");
        let actual = idna::to_ascii(&source, false);
        checked += 1;
        if expect_error {
            errors_expected += 1;
            if let Ok(output) = &actual {
                failures.push(format!("{source:?}: expected {status}, got Ok({output:?})"));
            }
        } else {
            match (&actual, &to_ascii_n) {
                (Ok(output), Some(expected)) if output == expected => {}
                _ => failures.push(format!(
                    "{source:?}: expected Ok({to_ascii_n:?}), got {actual:?}"
                )),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} conformance lines differ:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(checked > 6000, "checked {checked}");
    assert!(errors_expected > 1000, "error cases {errors_expected}");
    assert_eq!(
        skipped, 2,
        "exactly the two lone-surrogate lines are skipped"
    );
}

/// UAX #15 conformance of the NFC the IDNA processing uses, against the
/// Unicode 17.0.0 `NormalizationTest.txt` (2.8 MB, not checked in). Run with
/// `OURO_UCD_NORMALIZATION_TEST=<path> cargo test -- --ignored nfc`; it fails
/// when the variable is unset rather than passing without evidence.
#[test]
#[ignore = "needs the 2.8 MB NormalizationTest.txt; see the doc comment"]
fn n03_nfc_normalization_test_17() {
    let path = std::env::var_os("OURO_UCD_NORMALIZATION_TEST")
        .expect("OURO_UCD_NORMALIZATION_TEST names Unicode 17.0.0 NormalizationTest.txt");
    let bytes = std::fs::read(path).expect("readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"
    );
    let text = String::from_utf8(bytes).expect("UTF-8");
    let decode = |column: &str| -> String {
        column
            .split_whitespace()
            .map(|hex| char::from_u32(u32::from_str_radix(hex, 16).expect("hex")).expect("scalar"))
            .collect()
    };
    let mut checked = 0usize;
    for line in text.lines() {
        let data = line.split('#').next().unwrap_or_default();
        if data.trim().is_empty() || data.starts_with('@') {
            continue;
        }
        let columns: Vec<String> = data.split(';').take(5).map(decode).collect();
        let [c1, c2, c3, c4, c5] = columns.as_slice() else {
            panic!("five columns: {line}");
        };
        for (source, want) in [(c1, c2), (c2, c2), (c3, c2), (c4, c4), (c5, c4)] {
            assert_eq!(&nfc(source), want, "{line}");
        }
        checked += 1;
    }
    assert!(checked > 19_000, "checked {checked}");
}
