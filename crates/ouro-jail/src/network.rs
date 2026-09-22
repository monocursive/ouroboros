//! Network policy values that narrowing needs.
//!
//! Implements the part of jail-v1 §6.3 and `network-rules.md` that the J1
//! resolver uses: `network.mode` and the allow-host rule set, compared as sets
//! of DNS labels so that `*.example.com` is "one or more labels beneath that
//! domain", never a string suffix.
//!
//! Deliberately absent in this slice: IDNA (UTS 46) mapping and the numeric
//! destination table. A non-ASCII host or a numeric literal therefore refuses;
//! it is never mapped by a homegrown approximation, because a wrong mapping
//! would silently change which destinations a rule covers. The proxy that needs
//! those rules is J3.

use std::fmt;

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

/// Why an allow-host rule cannot be used.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostRuleError {
    /// The host is not ASCII, so `ouro.jail.network/1` IDNA would be required.
    RequiresIdna,
    /// The host is a numeric literal, which needs the numeric rules of §10.
    RequiresNumericRules,
    /// The rule is malformed for the stated reason.
    Malformed(&'static str),
}

impl fmt::Display for HostRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostRuleError::RequiresIdna => f.write_str(
                "host is not ASCII; ouro.jail.network/1 IDNA processing is not implemented in \
                 this slice, so its label set is unknown",
            ),
            HostRuleError::RequiresNumericRules => f.write_str(
                "host is a numeric literal; ouro.jail.network/1 numeric destination rules are \
                 not implemented in this slice",
            ),
            HostRuleError::Malformed(reason) => write!(f, "malformed host rule: {reason}"),
        }
    }
}

/// A host pattern as a set of DNS labels, ordered from the top-level label up.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum HostPattern {
    /// Exactly these labels.
    Exact(Vec<String>),
    /// One or more labels beneath these labels; never the apex.
    Wildcard(Vec<String>),
}

impl HostPattern {
    fn labels(&self) -> &[String] {
        match self {
            HostPattern::Exact(labels) | HostPattern::Wildcard(labels) => labels,
        }
    }
}

/// One canonical allow rule: a host pattern and an explicit port.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct HostRule {
    /// The host pattern.
    pub pattern: HostPattern,
    /// The explicit destination port.
    pub port: u16,
}

impl HostRule {
    /// Parses one `HOST[:PORT]` rule.
    ///
    /// An omitted port expands to exactly two rules, port 80 and port 443
    /// (§10). The result is sorted so that a rule set has one canonical order.
    ///
    /// # Errors
    /// Returns [`HostRuleError`] for a non-ASCII host, a numeric literal or a
    /// malformed rule. None of these is mapped to something comparable.
    pub fn parse(raw: &str) -> Result<Vec<HostRule>, HostRuleError> {
        if raw.is_empty() {
            return Err(HostRuleError::Malformed("the rule is empty"));
        }
        if !raw.is_ascii() {
            return Err(HostRuleError::RequiresIdna);
        }
        for byte in raw.bytes() {
            match byte {
                b'/' | b'@' | b'?' | b'#' | b'%' | b'[' | b']' | b'\\' => {
                    return Err(HostRuleError::Malformed(
                        "the rule contains userinfo, a path, an escape or brackets",
                    ));
                }
                0..=0x20 | 0x7f => {
                    return Err(HostRuleError::Malformed(
                        "the rule contains a control character or whitespace",
                    ));
                }
                _ => {}
            }
        }

        let (host, port) = match raw.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port
                    .parse()
                    .map_err(|_| HostRuleError::Malformed("the port is not 1-65535"))?;
                if port == 0 {
                    return Err(HostRuleError::Malformed("the port is not 1-65535"));
                }
                (host, Some(port))
            }
            None => (raw, None),
        };
        if host.contains(':') {
            return Err(HostRuleError::Malformed(
                "the host contains a colon; an IPv6 literal needs the numeric rules",
            ));
        }
        let pattern = parse_pattern(host)?;
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

    /// The canonical `host:port` spelling recorded in the snapshot.
    #[must_use]
    pub fn canonical(&self) -> String {
        let joined = self.pattern.labels().join(".");
        match self.pattern {
            HostPattern::Exact(_) => format!("{joined}:{}", self.port),
            HostPattern::Wildcard(_) => format!("*.{joined}:{}", self.port),
        }
    }

    /// Whether this rule authorizes everything `other` authorizes.
    ///
    /// A wildcard covers strictly deeper names and deeper wildcards, never the
    /// apex and never a different domain that merely shares a string suffix
    /// (§6.3: "A host wildcard is a set of DNS labels, not an arbitrary string
    /// suffix").
    #[must_use]
    pub fn covers(&self, other: &HostRule) -> bool {
        if self.port != other.port {
            return false;
        }
        match (&self.pattern, &other.pattern) {
            (HostPattern::Exact(mine), HostPattern::Exact(theirs)) => mine == theirs,
            (HostPattern::Exact(_), HostPattern::Wildcard(_)) => false,
            (HostPattern::Wildcard(mine), HostPattern::Exact(theirs)) => {
                theirs.len() > mine.len() && theirs.ends_with(mine.as_slice())
            }
            (HostPattern::Wildcard(mine), HostPattern::Wildcard(theirs)) => {
                theirs.len() >= mine.len() && theirs.ends_with(mine.as_slice())
            }
        }
    }
}

fn parse_pattern(host: &str) -> Result<HostPattern, HostRuleError> {
    let host = host.to_ascii_lowercase();
    // Remove at most one terminal dot; more than one is an empty label.
    let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
    if host.is_empty() {
        return Err(HostRuleError::Malformed("the host is empty"));
    }
    if host.len() > 253 {
        return Err(HostRuleError::Malformed("the host exceeds 253 characters"));
    }
    let (wildcard, rest) = match host.strip_prefix("*.") {
        Some(rest) => (true, rest.to_owned()),
        None => (false, host),
    };
    if rest.contains('*') {
        return Err(HostRuleError::Malformed(
            "a wildcard is only valid as the whole leading label",
        ));
    }
    let labels: Vec<String> = rest.split('.').map(str::to_owned).collect();
    for label in &labels {
        if label.is_empty() {
            return Err(HostRuleError::Malformed("the host has an empty label"));
        }
        if label.len() > 63 {
            return Err(HostRuleError::Malformed("a label exceeds 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostRuleError::Malformed(
                "a label starts or ends with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(HostRuleError::Malformed(
                "a label has a character outside the LDH set",
            ));
        }
    }
    if !wildcard
        && labels
            .iter()
            .all(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(HostRuleError::RequiresNumericRules);
    }
    Ok(if wildcard {
        HostPattern::Wildcard(labels)
    } else {
        HostPattern::Exact(labels)
    })
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
    fn unmappable_and_malformed_hosts_refuse() {
        assert_eq!(
            HostRule::parse("bücher.example"),
            Err(HostRuleError::RequiresIdna)
        );
        assert_eq!(
            HostRule::parse("127.0.0.1:443"),
            Err(HostRuleError::RequiresNumericRules)
        );
        assert!(matches!(
            HostRule::parse("user@example.com"),
            Err(HostRuleError::Malformed(_))
        ));
        assert!(matches!(
            HostRule::parse("example..com"),
            Err(HostRuleError::Malformed(_))
        ));
        assert!(matches!(
            HostRule::parse("a.*.example.com"),
            Err(HostRuleError::Malformed(_))
        ));
        assert!(matches!(
            HostRule::parse("example.com:0"),
            Err(HostRuleError::Malformed(_))
        ));
    }

    #[test]
    fn one_terminal_dot_is_removed_and_two_refuse() {
        assert_eq!(rule("Example.COM.:443").canonical(), "example.com:443");
        assert!(matches!(
            HostRule::parse("example.com..:443"),
            Err(HostRuleError::Malformed(_))
        ));
    }
}
