//! UTS 46 revision 35 ToASCII over Unicode 17.0.0, with exactly the flags
//! `network-rules.md` fixes: Transitional_Processing=false,
//! UseSTD3ASCIIRules=true, CheckHyphens=true, CheckBidi=true,
//! CheckJoiners=true, VerifyDnsLength=true, IgnoreInvalidPunycode=false.
//!
//! Any recorded processing error fails the whole name. There is no partial
//! result and no fallback: an input this cannot process is refused.

use super::unicode::{self, BidiClass, IdnaStatus, JoiningType};

/// Why UTS 46 processing failed. Codes follow the step numbering the UTS 46
/// conformance file uses, so a refusal names the step that failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdnaError {
    /// P1/P4: a disallowed code point, or invalid Punycode.
    Processing,
    /// V1: a label is not in NFC.
    NotNfc,
    /// V2: `--` in the third and fourth positions.
    HyphenThirdFourth,
    /// V3: a label begins or ends with `-`.
    HyphenEdge,
    /// V4: a decoded label contains a full stop.
    FullStop,
    /// V5: a label begins with a combining mark.
    LeadingMark,
    /// V6/U1: a code point whose status or STD3 class is not valid.
    InvalidCodePoint,
    /// C1/C2: a ZERO WIDTH (NON-)JOINER outside its ContextJ rule.
    Joiner,
    /// B1–B6: the RFC 5893 Bidi rule.
    Bidi,
    /// P4: an `xn--` label that is empty, all-ASCII or non-ASCII.
    BadALabel,
    /// A3: Punycode encoding overflow.
    Encoding,
    /// A4_1: the name is empty or longer than 253.
    NameLength,
    /// A4_2: a label is empty or longer than 63.
    LabelLength,
}

impl IdnaError {
    /// A short safe description.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IdnaError::Processing => "disallowed code point or invalid punycode",
            IdnaError::NotNfc => "label not in NFC",
            IdnaError::HyphenThirdFourth => "hyphens in the third and fourth positions",
            IdnaError::HyphenEdge => "label begins or ends with a hyphen",
            IdnaError::FullStop => "decoded label contains a full stop",
            IdnaError::LeadingMark => "label begins with a combining mark",
            IdnaError::InvalidCodePoint => "code point not valid under UseSTD3ASCIIRules",
            IdnaError::Joiner => "joiner outside its ContextJ rule",
            IdnaError::Bidi => "label violates the RFC 5893 Bidi rule",
            IdnaError::BadALabel => "malformed A-label",
            IdnaError::Encoding => "punycode encoding overflow",
            IdnaError::NameLength => "name is empty or longer than 253",
            IdnaError::LabelLength => "label is empty or longer than 63",
        }
    }
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492)
// ---------------------------------------------------------------------------

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
}

fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'a'..=b'z' => Some(u32::from(byte - b'a')),
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 26),
        _ => None,
    }
}

fn digit_char(value: u32) -> Option<char> {
    match value {
        0..=25 => char::from_u32(u32::from(b'a') + value),
        26..=35 => char::from_u32(u32::from(b'0') + value - 26),
        _ => None,
    }
}

fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

/// Decodes a Punycode string (without the `xn--` prefix). Every overflow and
/// every non-scalar result is a failure, never a wrapped value.
pub(super) fn punycode_decode(input: &str) -> Option<Vec<char>> {
    if !input.is_ascii() {
        return None;
    }
    let bytes = input.as_bytes();
    // RFC 3492 §6.2: b is the number of code points before the last
    // delimiter, and decoding starts after it only when b > 0. A leading
    // delimiter is therefore decoded as a digit, which fails.
    let (basic, extended): (&[u8], &[u8]) = match bytes.iter().rposition(|&b| b == b'-') {
        Some(position) if position > 0 => (bytes.get(..position)?, bytes.get(position + 1..)?),
        _ => (&[], bytes),
    };
    let mut output: Vec<char> = basic.iter().map(|&b| char::from(b)).collect();
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut position = 0usize;
    while position < extended.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let byte = *extended.get(position)?;
            position += 1;
            let digit = digit_value(byte)?;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        let length = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = adapt(i - old_i, length, old_i == 0);
        n = n.checked_add(i / length)?;
        i %= length;
        let c = char::from_u32(n)?;
        output.insert(usize::try_from(i).ok()?, c);
        i += 1;
    }
    Some(output)
}

/// Encodes code points as Punycode (without the `xn--` prefix).
pub(super) fn punycode_encode(input: &[char]) -> Option<String> {
    let mut output: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = u32::try_from(output.len()).ok()?;
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    let total = u32::try_from(input.len()).ok()?;
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while handled < total {
        let m = input
            .iter()
            .map(|&c| u32::from(c))
            .filter(|&c| c >= n)
            .min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in input {
            let c = u32::from(c);
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    output.push(digit_char(t + (q - t) % (BASE - t))?);
                    q = (q - t) / (BASE - t);
                    k = k.checked_add(BASE)?;
                }
                output.push(digit_char(q)?);
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

// ---------------------------------------------------------------------------
// Processing (UTS 46 §4) and validity criteria (§4.1)
// ---------------------------------------------------------------------------

/// Step 1 (Map), nontransitional: disallowed and valid stay, ignored goes,
/// mapped is replaced, deviation stays.
fn map(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match unicode::idna_status(c) {
            IdnaStatus::Valid | IdnaStatus::Deviation | IdnaStatus::Disallowed => out.push(c),
            IdnaStatus::Ignored => {}
            IdnaStatus::Mapped(value) => out.push_str(value),
        }
    }
    out
}

fn is_bidi_domain(labels: &[Vec<char>]) -> bool {
    labels.iter().flatten().any(|&c| {
        matches!(
            unicode::bidi_class(c),
            BidiClass::R | BidiClass::AL | BidiClass::AN
        )
    })
}

/// RFC 5893 §2, all six conditions, for one non-empty label.
fn bidi_rule(label: &[char]) -> bool {
    use BidiClass::{AL, AN, BN, CS, EN, ES, ET, L, Nsm, ON, R};
    let classes: Vec<BidiClass> = label.iter().map(|&c| unicode::bidi_class(c)).collect();
    let Some(&first) = classes.first() else {
        return true;
    };
    // The last class that is not NSM (conditions 3 and 6).
    let last = classes.iter().rev().find(|&&class| class != Nsm).copied();
    match first {
        R | AL => {
            // Condition 2.
            if !classes
                .iter()
                .all(|class| matches!(class, R | AL | AN | EN | ES | CS | ET | ON | BN | Nsm))
            {
                return false;
            }
            // Condition 3.
            if !matches!(last, Some(R | AL | EN | AN)) {
                return false;
            }
            // Condition 4.
            !(classes.contains(&EN) && classes.contains(&AN))
        }
        L => {
            // Condition 5.
            if !classes
                .iter()
                .all(|class| matches!(class, L | EN | ES | CS | ET | ON | BN | Nsm))
            {
                return false;
            }
            // Condition 6.
            matches!(last, Some(L | EN))
        }
        // Condition 1.
        _ => false,
    }
}

/// RFC 5892 Appendix A.1 and A.2 (CONTEXTJ).
fn joiners_ok(label: &[char]) -> bool {
    const VIRAMA: u8 = 9;
    for (index, &c) in label.iter().enumerate() {
        if c != '\u{200c}' && c != '\u{200d}' {
            continue;
        }
        let before = index
            .checked_sub(1)
            .and_then(|previous| label.get(previous))
            .copied();
        if before.is_some_and(|b| unicode::combining_class(b) == VIRAMA) {
            continue;
        }
        if c == '\u{200d}' {
            return false;
        }
        // (Joining_Type:{L,D})(Joining_Type:T)*‌(Joining_Type:T)*(Joining_Type:{R,D})
        let left = label
            .get(..index)
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|&x| unicode::joining_type(x))
            .find(|&kind| kind != JoiningType::T);
        let right = label
            .get(index + 1..)
            .unwrap_or_default()
            .iter()
            .map(|&x| unicode::joining_type(x))
            .find(|&kind| kind != JoiningType::T);
        let left_ok = matches!(left, Some(JoiningType::L | JoiningType::D));
        let right_ok = matches!(right, Some(JoiningType::R | JoiningType::D));
        if !(left_ok && right_ok) {
            return false;
        }
    }
    true
}

/// §4.1 for one non-empty label under nontransitional processing.
fn validate(label: &[char]) -> Result<(), IdnaError> {
    let text: String = label.iter().collect();
    if unicode::nfc(&text) != text {
        return Err(IdnaError::NotNfc);
    }
    if label.get(2) == Some(&'-') && label.get(3) == Some(&'-') {
        return Err(IdnaError::HyphenThirdFourth);
    }
    if label.first() == Some(&'-') || label.last() == Some(&'-') {
        return Err(IdnaError::HyphenEdge);
    }
    if label.contains(&'.') {
        return Err(IdnaError::FullStop);
    }
    if label.first().is_some_and(|&c| unicode::is_mark(c)) {
        return Err(IdnaError::LeadingMark);
    }
    for &c in label {
        let status_ok = matches!(
            unicode::idna_status(c),
            IdnaStatus::Valid | IdnaStatus::Deviation
        );
        let std3_ok = !c.is_ascii() || c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        if !status_ok || !std3_ok {
            return Err(IdnaError::InvalidCodePoint);
        }
    }
    if !joiners_ok(label) {
        return Err(IdnaError::Joiner);
    }
    Ok(())
}

fn record(error: IdnaError, slot: &mut Option<IdnaError>) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

/// UTS 46 ToASCII with the fixed flags.
///
/// `strip_one_terminal_dot` implements `network-rules.md` "Remove at most one
/// terminal dot after mapping": the dot is removed after step 1 and before
/// everything else, so a second trailing dot still leaves an empty root label,
/// which VerifyDnsLength refuses. With `false` this is exactly UTS 46 ToASCII,
/// which the conformance file checks.
///
/// # Errors
/// Returns the first [`IdnaError`] recorded. Processing continues only as far
/// as needed to report one error: any error fails the whole name.
pub fn to_ascii(input: &str, strip_one_terminal_dot: bool) -> Result<String, IdnaError> {
    // Step 1: Map.
    let mut mapped = map(input);
    if strip_one_terminal_dot && mapped.ends_with('.') {
        mapped.pop();
    }
    // Step 2: Normalize.
    let normalized = unicode::nfc(&mapped);
    // Step 3: Break.
    let mut labels: Vec<Vec<char>> = Vec::new();
    let mut first_error: Option<IdnaError> = None;
    // Step 4: Convert/Validate.
    for raw in normalized.split('.') {
        if let Some(rest) = raw.strip_prefix("xn--") {
            if !raw.is_ascii() {
                record(IdnaError::BadALabel, &mut first_error);
                labels.push(raw.chars().collect());
                continue;
            }
            let Some(decoded) = punycode_decode(rest) else {
                record(IdnaError::Processing, &mut first_error);
                labels.push(raw.chars().collect());
                continue;
            };
            if decoded.is_empty() || decoded.iter().all(char::is_ascii) {
                record(IdnaError::BadALabel, &mut first_error);
            }
            if let Err(error) = validate(&decoded) {
                record(error, &mut first_error);
            }
            labels.push(decoded);
        } else {
            let label: Vec<char> = raw.chars().collect();
            if !label.is_empty()
                && let Err(error) = validate(&label)
            {
                record(error, &mut first_error);
            }
            labels.push(label);
        }
    }
    // CheckBidi applies to every non-empty label of a Bidi domain name.
    if is_bidi_domain(&labels)
        && labels
            .iter()
            .any(|label| !label.is_empty() && !bidi_rule(label))
    {
        record(IdnaError::Bidi, &mut first_error);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    // ToASCII step 2: Punycode for every label with non-ASCII.
    let mut ascii_labels = Vec::with_capacity(labels.len());
    for label in &labels {
        if label.iter().all(char::is_ascii) {
            ascii_labels.push(label.iter().collect::<String>());
        } else {
            let encoded = punycode_encode(label).ok_or(IdnaError::Encoding)?;
            ascii_labels.push(format!("xn--{encoded}"));
        }
    }
    // ToASCII step 3: VerifyDnsLength. The empty root label is disallowed.
    let joined = ascii_labels.join(".");
    for label in &ascii_labels {
        if label.is_empty() || label.len() > 63 {
            return Err(IdnaError::LabelLength);
        }
    }
    if joined.is_empty() || joined.len() > 253 {
        return Err(IdnaError::NameLength);
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode_round_trips_the_rfc_3492_samples() {
        // RFC 3492 §7.1 (A) Arabic (Egyptian), lowercase.
        let arabic: Vec<char> = "\u{644}\u{64a}\u{647}\u{645}\u{627}\u{628}\u{62a}\u{643}\u{644}\u{645}\u{648}\u{634}\u{639}\u{631}\u{628}\u{64a}\u{61f}".chars().collect();
        assert_eq!(
            punycode_encode(&arabic).as_deref(),
            Some("egbpdaj6bu4bxfgehfvwxn")
        );
        assert_eq!(
            punycode_decode("egbpdaj6bu4bxfgehfvwxn").as_deref(),
            Some(arabic.as_slice())
        );
        let bucher: Vec<char> = "bücher".chars().collect();
        assert_eq!(punycode_encode(&bucher).as_deref(), Some("bcher-kva"));
        assert_eq!(
            punycode_decode("bcher-kva").as_deref(),
            Some(bucher.as_slice())
        );
    }

    #[test]
    fn punycode_overflow_and_bad_digits_fail() {
        assert_eq!(punycode_decode("99999999999999"), None);
        assert_eq!(punycode_decode("a-!"), None);
        assert_eq!(punycode_decode("ü"), None);
    }

    #[test]
    fn the_network_rules_idna_examples() {
        assert_eq!(
            to_ascii("BÜCHER.example.", true).as_deref(),
            Ok("xn--bcher-kva.example")
        );
        assert_eq!(to_ascii("faß.de", true).as_deref(), Ok("xn--fa-hia.de"));
        assert!(to_ascii("a..b", true).is_err());
        assert!(to_ascii("example..", true).is_err());
        assert!(to_ascii("example.", false).is_err(), "VerifyDnsLength");
        assert!(to_ascii("a\u{200d}b", true).is_err(), "joiner");
        assert!(to_ascii("xn--a", true).is_err(), "all-ASCII A-label");
        assert!(to_ascii("xn--ab-", true).is_err(), "malformed A-label");
    }
}
