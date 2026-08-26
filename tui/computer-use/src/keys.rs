//! The `key` grammar (doc §5.3): parse a chord like `Ctrl+L`, `Cmd+Shift+P`, `Enter`, or
//! `f5` into a structured [`KeyChord`], and reject anything outside the vocabulary.
//!
//! This is validation, not injection. Phase 2's `act` maps a [`KeyChord`] onto CGEvent key
//! codes; Phase 0 only proves that a string is a chord the helper is willing to press, so a
//! malformed `key` is refused at the tool boundary rather than forwarded. The vocabulary is
//! the Linux crate's, deliberately, so the two backends accept the same strings.
//!
//! Grammar: case-insensitive; `+`, `-`, and whitespace all separate tokens; a chord is any
//! number of modifiers followed by exactly one non-modifier key. Anything else is rejected.

use std::fmt;

/// A keyboard modifier. Aliases collapse here: `control`→`Ctrl`, `option`→`Alt`,
/// `super`/`cmd`/`command`→`Meta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modifier {
    Ctrl,
    Alt,
    Shift,
    Meta,
}

/// A named non-character key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedKey {
    Enter,
    Escape,
    Tab,
    Backspace,
    Delete,
    Space,
    Home,
    End,
    PageUp,
    PageDown,
    Up,
    Down,
    Left,
    Right,
}

/// The single non-modifier key of a chord.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A single US letter (`a`–`z`, stored lowercase) or digit (`0`–`9`).
    Char(char),
    Named(NamedKey),
    /// A function key `f1`–`f12`; the payload is `1..=12`.
    Function(u8),
}

/// A parsed chord: its modifiers in canonical order (Ctrl, Alt, Shift, Meta) and its one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChord {
    pub modifiers: Vec<Modifier>,
    pub key: Key,
}

/// Why a string is not a chord. Each is a distinct, reportable reason rather than one opaque
/// "invalid key", because the tool surfaces it to a model that has to correct itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyParseError {
    /// No tokens at all.
    Empty,
    /// A token that is neither a modifier nor a key.
    Unknown(String),
    /// Only modifiers, no key to press.
    NoKey,
    /// More than one non-modifier key.
    MultipleKeys,
}

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty key"),
            Self::Unknown(token) => write!(f, "unknown key token: {token}"),
            Self::NoKey => write!(f, "modifiers with no key to press"),
            Self::MultipleKeys => write!(f, "more than one non-modifier key"),
        }
    }
}

/// Parses one chord string. Case-insensitive; `+`, `-`, and whitespace separate tokens.
pub fn parse(input: &str) -> Result<KeyChord, KeyParseError> {
    let tokens: Vec<&str> = input
        .split(|c: char| c == '+' || c == '-' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .collect();

    if tokens.is_empty() {
        return Err(KeyParseError::Empty);
    }

    let mut modifiers: Vec<Modifier> = Vec::new();
    let mut key: Option<Key> = None;

    for token in tokens {
        let lower = token.to_ascii_lowercase();

        if let Some(modifier) = modifier(&lower) {
            if !modifiers.contains(&modifier) {
                modifiers.push(modifier);
            }
            continue;
        }

        let parsed = named(&lower)
            .map(Key::Named)
            .or_else(|| function_key(&lower).map(Key::Function))
            .or_else(|| single_char(&lower).map(Key::Char));

        match parsed {
            Some(found) => {
                if key.is_some() {
                    return Err(KeyParseError::MultipleKeys);
                }
                key = Some(found);
            }
            None => return Err(KeyParseError::Unknown(token.to_string())),
        }
    }

    match key {
        Some(key) => Ok(KeyChord {
            modifiers: canonical_order(modifiers),
            key,
        }),
        None => Err(KeyParseError::NoKey),
    }
}

fn modifier(token: &str) -> Option<Modifier> {
    match token {
        "ctrl" | "control" => Some(Modifier::Ctrl),
        "alt" | "option" => Some(Modifier::Alt),
        "shift" => Some(Modifier::Shift),
        "meta" | "super" | "cmd" | "command" => Some(Modifier::Meta),
        _ => None,
    }
}

fn named(token: &str) -> Option<NamedKey> {
    match token {
        "enter" | "return" => Some(NamedKey::Enter),
        "escape" | "esc" => Some(NamedKey::Escape),
        "tab" => Some(NamedKey::Tab),
        "backspace" => Some(NamedKey::Backspace),
        "delete" | "del" => Some(NamedKey::Delete),
        "space" => Some(NamedKey::Space),
        "home" => Some(NamedKey::Home),
        "end" => Some(NamedKey::End),
        "pageup" => Some(NamedKey::PageUp),
        "pagedown" => Some(NamedKey::PageDown),
        "up" => Some(NamedKey::Up),
        "down" => Some(NamedKey::Down),
        "left" => Some(NamedKey::Left),
        "right" => Some(NamedKey::Right),
        _ => None,
    }
}

/// `f1`–`f12`. `f` alone falls through to [`single_char`] as the letter key; `f0` and `f13`
/// are rejected.
fn function_key(token: &str) -> Option<u8> {
    let number = token.strip_prefix('f')?;
    match number.parse::<u8>() {
        Ok(n @ 1..=12) => Some(n),
        _ => None,
    }
}

/// A single US letter or digit. Punctuation is not a key in this grammar.
fn single_char(token: &str) -> Option<char> {
    let mut chars = token.chars();
    let first = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    if first.is_ascii_lowercase() || first.is_ascii_digit() {
        Some(first)
    } else {
        None
    }
}

fn canonical_order(mut modifiers: Vec<Modifier>) -> Vec<Modifier> {
    modifiers.sort_by_key(|modifier| match modifier {
        Modifier::Ctrl => 0,
        Modifier::Alt => 1,
        Modifier::Shift => 2,
        Modifier::Meta => 3,
    });
    modifiers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_named_key() {
        assert_eq!(
            parse("Enter"),
            Ok(KeyChord {
                modifiers: vec![],
                key: Key::Named(NamedKey::Enter),
            })
        );
    }

    #[test]
    fn modifier_plus_letter_is_case_insensitive() {
        let expected = Ok(KeyChord {
            modifiers: vec![Modifier::Ctrl],
            key: Key::Char('l'),
        });
        assert_eq!(parse("Ctrl+L"), expected);
        assert_eq!(parse("ctrl+l"), expected);
        assert_eq!(parse("CONTROL-L"), expected);
        assert_eq!(parse("ctrl l"), expected);
    }

    #[test]
    fn aliases_collapse_to_canonical_modifiers() {
        let expected = Ok(KeyChord {
            modifiers: vec![Modifier::Alt, Modifier::Shift, Modifier::Meta],
            key: Key::Char('p'),
        });
        // option→Alt, command→Meta, and canonical order regardless of input order.
        assert_eq!(parse("command+shift+option+p"), expected);
    }

    #[test]
    fn duplicate_modifiers_collapse() {
        assert_eq!(
            parse("ctrl+ctrl+a"),
            Ok(KeyChord {
                modifiers: vec![Modifier::Ctrl],
                key: Key::Char('a'),
            })
        );
    }

    #[test]
    fn function_keys() {
        assert_eq!(parse("f5").unwrap().key, Key::Function(5));
        assert_eq!(parse("F12").unwrap().key, Key::Function(12));
        assert_eq!(parse("f0"), Err(KeyParseError::Unknown("f0".to_string())));
        assert_eq!(parse("f13"), Err(KeyParseError::Unknown("f13".to_string())));
        // A bare `f` is the letter key.
        assert_eq!(parse("f").unwrap().key, Key::Char('f'));
    }

    #[test]
    fn digits_and_arrows_and_named() {
        assert_eq!(parse("3").unwrap().key, Key::Char('3'));
        assert_eq!(
            parse("PageDown").unwrap().key,
            Key::Named(NamedKey::PageDown)
        );
        assert_eq!(parse("esc").unwrap().key, Key::Named(NamedKey::Escape));
        assert_eq!(parse("up").unwrap().key, Key::Named(NamedKey::Up));
    }

    #[test]
    fn rejections() {
        assert_eq!(parse(""), Err(KeyParseError::Empty));
        assert_eq!(parse("+"), Err(KeyParseError::Empty));
        assert_eq!(parse("ctrl"), Err(KeyParseError::NoKey));
        assert_eq!(parse("ctrl+"), Err(KeyParseError::NoKey));
        assert_eq!(parse("a+b"), Err(KeyParseError::MultipleKeys));
        assert_eq!(parse("."), Err(KeyParseError::Unknown(".".to_string())));
        assert_eq!(
            parse("ctrl+frobnicate"),
            Err(KeyParseError::Unknown("frobnicate".to_string()))
        );
    }
}
