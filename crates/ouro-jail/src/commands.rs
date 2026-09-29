//! Optional argv accident filters. These do not constrain program effects.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub forbid: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub pattern: String,
    pub digest: String,
    pub forbidden: bool,
}
impl Rules {
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.forbid.is_empty()
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.deny.len() + self.forbid.len() > 64 {
            return Err("at most 64 command rules are supported".into());
        }
        for pattern in self.deny.iter().chain(&self.forbid) {
            if pattern.len() > 4096 {
                return Err("command pattern exceeds 4096 bytes".into());
            }
            let parts = tokens(pattern)?;
            if parts.is_empty() || parts.iter().take(parts.len() - 1).any(|p| p == b"**") {
                return Err(
                    "command rules need argv[0]; ** is only allowed as the final token".into(),
                );
            }
        }
        Ok(())
    }
    pub fn check(&self, argv: Option<&[Vec<u8>]>, path: Option<&[u8]>) -> Option<Hit> {
        if self.is_empty() {
            return None;
        }
        let Some(argv) = argv else {
            return Some(Hit {
                pattern: "<unreadable-or-oversized-argv>".into(),
                digest: "unavailable".into(),
                forbidden: false,
            });
        };
        let mut hash = Sha256::new();
        for arg in argv {
            hash.update((arg.len() as u64).to_le_bytes());
            hash.update(arg);
        }
        let digest = format!("sha256:{:x}", hash.finalize());
        for (patterns, forbidden) in [(&self.forbid, true), (&self.deny, false)] {
            for pattern in patterns {
                if tokens(pattern).is_ok_and(|parts| matches(&parts, argv, path)) {
                    return Some(Hit {
                        pattern: pattern.clone(),
                        digest,
                        forbidden,
                    });
                }
            }
        }
        None
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
    if parts.is_empty() || argv.is_empty() {
        return false;
    }
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
    #[test]
    fn positional_and_tail() {
        let rules = Rules {
            deny: vec!["git push --force".into(), "rm -rf /*".into()],
            forbid: vec!["dangerous-tool **".into()],
        };
        rules.validate().unwrap();
        let args = |s: &str| {
            s.split(' ')
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert!(
            rules
                .check(Some(&args("/usr/bin/git push --force")), None)
                .is_some()
        );
        assert!(
            rules
                .check(Some(&args("git push --force main")), None)
                .is_none()
        );
        assert!(
            rules
                .check(Some(&args("fake anything")), Some(b"/bin/dangerous-tool"))
                .unwrap()
                .forbidden
        );
        assert!(rules.check(Some(&args("sh -c rm")), None).is_none());
        assert!(rules.check(None, None).is_some());
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
}
