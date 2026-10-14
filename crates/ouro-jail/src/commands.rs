//! Optional argv accident filters. These do not constrain program effects.
use serde::{Deserialize, Serialize};

/// The most command rules one configuration carries (jail-v2 §7.2: "the
/// rule set is capped (initial 64 rules, recorded)").
pub const RULES_MAX: usize = 64;
/// The longest command pattern, in bytes.
pub const PATTERN_BYTES_MAX: usize = 4096;
/// The pattern a hit names when the argv could not be read whole: rules are
/// active, so an argv that cannot be judged is refused (jail-v2 §7.2).
pub const UNREADABLE_ARGV_PATTERN: &str = "<unreadable-or-oversized-argv>";
/// Why such a hit carries no argv digest (jail-v1 §11.3: a digest is only
/// of an argv whose every byte was captured).
pub const UNREADABLE_ARGV_REASON: &str = "argv_unreadable_or_oversized";

/// The operator's `[jail.commands]` table, as written and as the policy
/// snapshot records it. [`Rules::compile`] turns it into the [`Filter`] the
/// observer matches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub forbid: Vec<String>,
}

/// One matched rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub pattern: String,
    /// The argv's `argv_digest`, the receipt's own construction
    /// ([`crate::canonical::argv_digest`]), or `None` when the argv could not
    /// be read whole ([`UNREADABLE_ARGV_REASON`]).
    pub digest: Option<String>,
    pub forbidden: bool,
}

impl Rules {
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.forbid.is_empty()
    }

    /// Validates the rules and tokenizes every pattern once.
    ///
    /// # Errors
    /// Returns why the rules are refused: more than [`RULES_MAX`], a pattern
    /// longer than [`PATTERN_BYTES_MAX`], an unfinished quote or escape, a
    /// NUL, no `argv[0]`, or a `**` before the last token.
    pub fn compile(&self) -> Result<Filter, String> {
        if self.deny.len() + self.forbid.len() > RULES_MAX {
            return Err(format!("at most {RULES_MAX} command rules are supported"));
        }
        // Forbid patterns first: a command matching both lists is forbidden.
        let lists = [(&self.forbid, true), (&self.deny, false)];
        let mut patterns = Vec::with_capacity(self.deny.len() + self.forbid.len());
        for (list, forbidden) in lists {
            for text in list {
                if text.len() > PATTERN_BYTES_MAX {
                    return Err(format!("command pattern exceeds {PATTERN_BYTES_MAX} bytes"));
                }
                let parts = tokens(text)?;
                if parts.is_empty()
                    || parts.first().is_some_and(|p| p == b"**")
                    || parts.iter().take(parts.len() - 1).any(|p| p == b"**")
                {
                    return Err(
                        "command rules need argv[0]; ** is only allowed as the final token".into(),
                    );
                }
                patterns.push(Pattern {
                    text: text.clone(),
                    parts,
                    forbidden,
                });
            }
        }
        Ok(Filter { patterns })
    }
}

/// Validated command rules with every pattern tokenized: what the observer
/// matches at each exec. Only [`Rules::compile`] builds one, so a pattern
/// that does not tokenize never reaches the matcher.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Forbid patterns before deny patterns, each list in its written order.
    patterns: Vec<Pattern>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    text: String,
    parts: Vec<Vec<u8>>,
    forbidden: bool,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The first rule `argv` (or, for element 0, the exec `path`) matches.
    ///
    /// With rules active, an argv that could not be read whole (`None`) is
    /// a hit on [`UNREADABLE_ARGV_PATTERN`], never a pass.
    pub fn check(&self, argv: Option<&[Vec<u8>]>, path: Option<&[u8]>) -> Option<Hit> {
        if self.is_empty() {
            return None;
        }
        let Some(argv) = argv else {
            return Some(Hit {
                pattern: UNREADABLE_ARGV_PATTERN.into(),
                digest: None,
                forbidden: false,
            });
        };
        let pattern = self
            .patterns
            .iter()
            .find(|pattern| matches(&pattern.parts, argv, path))?;
        Some(Hit {
            pattern: pattern.text.clone(),
            digest: Some(crate::canonical::argv_digest(argv)),
            forbidden: pattern.forbidden,
        })
    }
}
// Small quote tokenizer, with no expansions or shell syntax evaluation.
fn tokens(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut result = Vec::new();
    let mut part = Vec::new();
    let mut quote = None;
    let mut escape = false;
    let mut active = false;
    for b in text.bytes() {
        if escape {
            part.push(b);
            escape = false;
            active = true;
            continue;
        }
        if b == b'\\' && quote != Some(b'\'') {
            escape = true;
            active = true;
            continue;
        }
        if quote == Some(b) {
            quote = None;
            continue;
        }
        if quote.is_none() && (b == b'\'' || b == b'"') {
            quote = Some(b);
            active = true;
            continue;
        }
        if quote.is_none() && b.is_ascii_whitespace() {
            if active {
                result.push(std::mem::take(&mut part));
                active = false;
            }
        } else {
            if b == 0 {
                return Err("NUL in command rule".into());
            }
            part.push(b);
            active = true;
        }
    }
    if escape || quote.is_some() {
        return Err("unfinished quote or escape in command rule".into());
    }
    if active {
        result.push(part);
    }
    Ok(result)
}
fn glob(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(s) = star {
            retry += 1;
            v = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
fn matches(parts: &[Vec<u8>], argv: &[Vec<u8>], path: Option<&[u8]>) -> bool {
    if parts.is_empty() {
        return false;
    }
    // An `execve` with argc 0 carries no argv[0] to match or to spoof:
    // element 0 then matches the exec path alone, the identity the
    // first-position fallback already trusts.
    let synthesized;
    let argv: &[Vec<u8>] = if !argv.is_empty() {
        argv
    } else {
        match path {
            Some(path) => {
                synthesized = vec![path.to_vec()];
                &synthesized
            }
            None => return false,
        }
    };
    let rest = parts.last().is_some_and(|p| p == b"**");
    let count = parts.len() - usize::from(rest);
    if argv.len() < count || (!rest && argv.len() != count) {
        return false;
    }
    parts.iter().take(count).enumerate().all(|(i, p)| {
        glob(p, &argv[i])
            || (i == 0
                && (glob(p, argv[0].rsplit(|b| *b == b'/').next().unwrap_or_default())
                    || path.is_some_and(|path| {
                        glob(p, path)
                            || glob(p, path.rsplit(|b| *b == b'/').next().unwrap_or_default())
                    })))
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<Vec<u8>> {
        text.split(' ').map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn positional_and_tail() {
        let filter = Rules {
            deny: vec!["git push --force".into(), "rm -rf /*".into()],
            forbid: vec!["dangerous-tool **".into()],
        }
        .compile()
        .unwrap();
        assert!(
            filter
                .check(Some(&args("/usr/bin/git push --force")), None)
                .is_some()
        );
        assert!(
            filter
                .check(Some(&args("git push --force main")), None)
                .is_none()
        );
        assert!(
            filter
                .check(Some(&args("fake anything")), Some(b"/bin/dangerous-tool"))
                .unwrap()
                .forbidden
        );
        assert!(filter.check(Some(&args("sh -c rm")), None).is_none());
        assert!(filter.check(None, None).is_some());
        assert_eq!(
            tokens("cmd 'two words' \"\" **").unwrap(),
            vec![
                b"cmd".to_vec(),
                b"two words".to_vec(),
                vec![],
                b"**".to_vec()
            ]
        );
    }

    #[test]
    fn a_rule_with_no_argv0_refuses_instead_of_matching_everything() {
        assert!(
            Rules {
                deny: vec!["**".into()],
                forbid: Vec::new(),
            }
            .compile()
            .is_err(),
            "a lone ** has no argv[0] and must not validate"
        );
    }

    /// A pattern the tokenizer refuses is refused when the rules compile:
    /// the matcher never sees it, so it can never be skipped there.
    #[test]
    fn a_pattern_that_does_not_tokenize_refuses_at_compile() {
        for bad in ["git 'push", "git push\\", "tool \"open"] {
            let error = Rules {
                deny: vec!["ls".into(), bad.into()],
                forbid: Vec::new(),
            }
            .compile()
            .expect_err(bad);
            assert!(error.contains("unfinished"), "{bad}: {error}");
        }
    }

    /// jail-v2 K22: the documented bounds are enforced, not silently ignored.
    #[test]
    fn more_than_the_documented_rule_cap_refuses_at_validation() {
        let rules = |count: usize| Rules {
            deny: (0..count).map(|i| format!("tool-{i}")).collect(),
            forbid: Vec::new(),
        };
        rules(RULES_MAX)
            .compile()
            .expect("64 rules are the documented cap");
        let error = rules(RULES_MAX + 1).compile().expect_err("65 rules refuse");
        assert!(error.contains("at most 64 command rules"), "{error}");
        let long = Rules {
            deny: vec![format!("tool {}", "x".repeat(PATTERN_BYTES_MAX))],
            forbid: Vec::new(),
        };
        let error = long.compile().expect_err("an over-long pattern refuses");
        assert!(error.contains("exceeds 4096 bytes"), "{error}");
    }

    /// A command matching both a deny and a forbid rule yields the forbid:
    /// the forbid list is evaluated first, so forbid wins.
    #[test]
    fn forbid_wins_when_a_command_matches_both_a_deny_and_a_forbid() {
        let filter = Rules {
            deny: vec!["git **".into()],
            forbid: vec!["git push --force **".into()],
        }
        .compile()
        .unwrap();
        let argv = args("git push --force upstream");
        let hit = filter
            .check(Some(&argv), None)
            .expect("a doubly matched command still hits");
        assert!(hit.forbidden, "forbid wins over deny: {hit:?}");
        assert_eq!(hit.pattern, "git push --force **");
        // The same argv under deny alone is an ordinary (non-forbidden) hit.
        let deny_only = Rules {
            deny: vec!["git **".into()],
            forbid: Vec::new(),
        }
        .compile()
        .unwrap();
        let hit = deny_only.check(Some(&argv), None).expect("deny hits");
        assert!(!hit.forbidden);
    }

    #[test]
    fn an_exec_with_no_argv_matches_the_exec_path_alone() {
        let filter = Rules {
            deny: Vec::new(),
            forbid: vec!["dangerous-tool **".into()],
        }
        .compile()
        .unwrap();
        let hit = filter
            .check(Some(&[]), Some(b"/usr/bin/dangerous-tool"))
            .expect("argc 0 still matches through the exec path");
        assert!(hit.forbidden);
        assert!(
            filter
                .check(Some(&[]), Some(b"/usr/bin/other-tool"))
                .is_none()
        );
        assert!(filter.check(Some(&[]), None).is_none());
    }

    /// A hit names its argv by the receipt's own `argv_digest`, so one argv
    /// has one digest under that field name whichever record carries it.
    #[test]
    fn a_hit_carries_the_canonical_argv_digest() {
        let filter = Rules {
            deny: vec!["git push **".into()],
            forbid: Vec::new(),
        }
        .compile()
        .unwrap();
        let argv = vec![b"git".to_vec(), b"push".to_vec(), b"a\0b".to_vec()];
        let hit = filter.check(Some(&argv), None).expect("a hit");
        assert_eq!(
            hit.digest.as_deref(),
            Some(crate::canonical::argv_digest(&argv).as_str())
        );
    }

    /// An argv that could not be read whole is refused with no digest at
    /// all: a digest of what was read would not be the argv's.
    #[test]
    fn an_unreadable_argv_hits_with_no_digest() {
        let filter = Rules {
            deny: vec!["ls".into()],
            forbid: Vec::new(),
        }
        .compile()
        .unwrap();
        let hit = filter.check(None, Some(b"/bin/ls")).expect("refused");
        assert_eq!(hit.pattern, UNREADABLE_ARGV_PATTERN);
        assert_eq!(hit.digest, None);
        assert!(!hit.forbidden);
        assert_eq!(
            Filter::default().check(None, None),
            None,
            "no rules, no hit"
        );
    }
}
