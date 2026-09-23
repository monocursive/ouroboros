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

/// Why a Punycode label did not decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum DecodeError {
    /// Not valid Punycode (RFC 3492 decoding failed).
    Invalid,
    /// The decoded label would exceed `max` code points.
    TooLong,
}

/// Decodes a Punycode string (without the `xn--` prefix). Every overflow and
/// every non-scalar result is a failure, never a wrapped value.
///
/// Decoding stops with [`DecodeError::TooLong`] as soon as the output would
/// exceed `max` code points, so the work is O(input + max²) whatever the
/// input: each insertion shifts at most `max` code points, and every input
/// byte is read at most once.
pub(super) fn punycode_decode(input: &str, max: usize) -> Result<Vec<char>, DecodeError> {
    use DecodeError::{Invalid, TooLong};
    if !input.is_ascii() {
        return Err(Invalid);
    }
    let bytes = input.as_bytes();
    // RFC 3492 §6.2: b is the number of code points before the last
    // delimiter, and decoding starts after it only when b > 0. A leading
    // delimiter is therefore decoded as a digit, which fails.
    let (basic, extended): (&[u8], &[u8]) = match bytes.iter().rposition(|&b| b == b'-') {
        Some(position) if position > 0 => (
            bytes.get(..position).ok_or(Invalid)?,
            bytes.get(position + 1..).ok_or(Invalid)?,
        ),
        _ => (&[], bytes),
    };
    if basic.len() > max {
        return Err(TooLong);
    }
    let mut output: Vec<char> = basic.iter().map(|&b| char::from(b)).collect();
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut position = 0usize;
    while position < extended.len() {
        if output.len() >= max {
            return Err(TooLong);
        }
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let byte = *extended.get(position).ok_or(Invalid)?;
            position += 1;
            let digit = digit_value(byte).ok_or(Invalid)?;
            i = digit
                .checked_mul(w)
                .and_then(|step| i.checked_add(step))
                .ok_or(Invalid)?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t).ok_or(Invalid)?;
            k = k.checked_add(BASE).ok_or(Invalid)?;
        }
        let length = u32::try_from(output.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(Invalid)?;
        bias = adapt(i - old_i, length, old_i == 0);
        n = n.checked_add(i / length).ok_or(Invalid)?;
        i %= length;
        let c = char::from_u32(n).ok_or(Invalid)?;
        output.insert(usize::try_from(i).map_err(|_| Invalid)?, c);
        i += 1;
    }
    Ok(output)
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
///
/// Returns `None` as soon as the output would exceed `limit` code points, so
/// the work and the memory are bounded by `limit` plus one mapping value,
/// whatever the input: a short input can otherwise expand eighteenfold
/// (U+FDFA maps to eighteen code points).
fn map_bounded(input: &str, limit: usize) -> Option<String> {
    let mut out = String::new();
    let mut count = 0usize;
    for c in input.chars() {
        match unicode::idna_status(c) {
            IdnaStatus::Valid | IdnaStatus::Deviation | IdnaStatus::Disallowed => {
                count += 1;
                out.push(c);
            }
            IdnaStatus::Ignored => {}
            IdnaStatus::Mapped(value) => {
                count += value.chars().count();
                out.push_str(value);
            }
        }
        if count > limit {
            return None;
        }
    }
    Some(out)
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

/// The longest DNS label, in output bytes (VerifyDnsLength).
const MAX_LABEL: usize = 63;

/// The longest DNS name, in output bytes, without the root label
/// (VerifyDnsLength).
const MAX_NAME: usize = 253;

/// The most code points one code point's full canonical decomposition has in
/// Unicode 17.0.0 (U+1F82 and its kind: four). A unit test recomputes it
/// over every code point from the same tables.
pub(super) const MAX_DECOMPOSITION: usize = 4;

/// The most code points the mapping step (after removing the one allowed
/// terminal dot) can produce for a name that ToASCII accepts. Anything longer
/// refuses before normalization; the bound is exact, not a heuristic:
///
/// 1. Every label's output is at least as long as the label in the
///    normalized string. An ASCII label is copied. A non-ASCII label becomes
///    `xn--` plus at least one Punycode character per code point. An `xn--`
///    label is re-encoded to exactly itself, because RFC 3492 decoding of a
///    lowercase label is injective and its inverse is the encoder: the
///    decoder inserts code points in non-decreasing value and, for equal
///    values, increasing position (`n` never decreases, `i` only grows
///    between wraps), which is the order the encoder emits; each delta is a
///    generalized variable-length integer with one representation (every
///    digit but the last is at least the threshold); the basic code points
///    are copied in order, and extended code points are at least 128, so
///    none can come from the other part. Uppercase digits, the one
///    alternative spelling RFC 3492 allows, never reach the decoder: the
///    mapping step lowercases ASCII. A unit test round-trips every A-label
///    the conformance file decodes, and random ones.
/// 2. Dots are copied. So an accepted name's normalized string, which has no
///    empty root label (VerifyDnsLength), has at most [`MAX_NAME`] code
///    points.
/// 3. NFC shrinks by at most [`MAX_DECOMPOSITION`]: for any string `x`,
///    `len(x) <= len(NFD(x)) = len(NFD(NFC(x)))`, and each code point of
///    `NFC(x)` decomposes to at most `MAX_DECOMPOSITION` code points, so
///    `len(x) <= MAX_DECOMPOSITION * len(NFC(x))`.
///
/// Hence an accepted name's mapped string has at most
/// `MAX_DECOMPOSITION * MAX_NAME` code points.
pub(super) const MAX_MAPPED: usize = MAX_DECOMPOSITION * MAX_NAME;

/// UTS 46 ToASCII with the fixed flags.
///
/// `strip_one_terminal_dot` implements `network-rules.md` "Remove at most one
/// terminal dot after mapping": the dot is removed after step 1 and before
/// everything else, so a second trailing dot still leaves an empty root label,
/// which VerifyDnsLength refuses. With `false` this is exactly UTS 46 ToASCII,
/// which the conformance file checks.
///
/// The work is linear in the input plus a constant: the mapped string is
/// bounded by [`MAX_MAPPED`], every label is refused above [`MAX_LABEL`]
/// code points before it is validated or decoded any further, and the name
/// is refused when its shortest possible output exceeds [`MAX_NAME`] before
/// anything is encoded. Each early refusal is exact: the output of a label is
/// never shorter than its code point count (see [`MAX_MAPPED`]), so a name
/// refused early would have failed VerifyDnsLength after encoding.
///
/// # Errors
/// The first [`IdnaError`] found; any error fails the whole name.
pub fn to_ascii(input: &str, strip_one_terminal_dot: bool) -> Result<String, IdnaError> {
    // Step 1: Map, bounded (one extra code point for a terminal dot that the
    // network rules remove).
    let limit = MAX_MAPPED + usize::from(strip_one_terminal_dot);
    let mut mapped = map_bounded(input, limit).ok_or(IdnaError::NameLength)?;
    if strip_one_terminal_dot && mapped.ends_with('.') {
        mapped.pop();
    }
    if mapped.chars().count() > MAX_MAPPED {
        return Err(IdnaError::NameLength);
    }
    // Step 2: Normalize.
    let normalized = unicode::nfc(&mapped);
    // Steps 3 and 4: Break, then Convert/Validate each label.
    let mut labels: Vec<Vec<char>> = Vec::new();
    for raw in normalized.split('.') {
        if let Some(rest) = raw.strip_prefix("xn--") {
            if !raw.is_ascii() {
                return Err(IdnaError::BadALabel);
            }
            // More than MAX_LABEL decoded code points re-encode to more
            // than MAX_LABEL + 4 bytes.
            let decoded = punycode_decode(rest, MAX_LABEL).map_err(|error| match error {
                DecodeError::Invalid => IdnaError::Processing,
                DecodeError::TooLong => IdnaError::LabelLength,
            })?;
            if decoded.is_empty() || decoded.iter().all(char::is_ascii) {
                return Err(IdnaError::BadALabel);
            }
            validate(&decoded)?;
            labels.push(decoded);
        } else {
            let label: Vec<char> = raw.chars().collect();
            // An empty label, or one whose output could not fit, fails
            // VerifyDnsLength whatever else is true of it.
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(IdnaError::LabelLength);
            }
            validate(&label)?;
            labels.push(label);
        }
    }
    // CheckBidi applies to every label of a Bidi domain name.
    if is_bidi_domain(&labels) && labels.iter().any(|label| !bidi_rule(label)) {
        return Err(IdnaError::Bidi);
    }
    // VerifyDnsLength on the shortest possible output, before encoding: an
    // ASCII label is copied, any other is `xn--` plus at least one character
    // per code point, and labels are joined by dots.
    let shortest: usize = labels
        .iter()
        .map(|label| {
            if label.iter().all(char::is_ascii) {
                label.len()
            } else {
                label.len() + 4
            }
        })
        .sum::<usize>()
        + labels.len().saturating_sub(1);
    if shortest > MAX_NAME {
        return Err(IdnaError::NameLength);
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
    // ToASCII step 3: VerifyDnsLength on the actual output.
    for label in &ascii_labels {
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err(IdnaError::LabelLength);
        }
    }
    let joined = ascii_labels.join(".");
    if joined.is_empty() || joined.len() > MAX_NAME {
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
            punycode_decode("egbpdaj6bu4bxfgehfvwxn", 63).as_deref(),
            Ok(arabic.as_slice())
        );
        let bucher: Vec<char> = "bücher".chars().collect();
        assert_eq!(punycode_encode(&bucher).as_deref(), Some("bcher-kva"));
        assert_eq!(
            punycode_decode("bcher-kva", 63).as_deref(),
            Ok(bucher.as_slice())
        );
    }

    #[test]
    fn punycode_overflow_and_bad_digits_fail() {
        assert_eq!(
            punycode_decode("99999999999999", 63),
            Err(DecodeError::Invalid)
        );
        assert_eq!(punycode_decode("a-!", 63), Err(DecodeError::Invalid));
        assert_eq!(punycode_decode("ü", 63), Err(DecodeError::Invalid));
    }

    #[test]
    fn punycode_decoding_stops_at_the_label_bound() {
        // 64 digits `a` decode to 64 code points: one past the bound.
        assert_eq!(
            punycode_decode(&"a".repeat(64), 63),
            Err(DecodeError::TooLong)
        );
        assert_eq!(
            punycode_decode(&"a".repeat(63), 63).map(|d| d.len()),
            Ok(63)
        );
        assert_eq!(
            punycode_decode(&format!("{}-a", "b".repeat(64)), 63),
            Err(DecodeError::TooLong),
            "basic code points count too"
        );
    }

    /// A small deterministic generator, so the round trip is reproducible.
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    /// The injectivity argument behind [`MAX_MAPPED`]: every lowercase
    /// Punycode string that decodes re-encodes to exactly itself.
    #[test]
    fn punycode_decoding_is_inverted_by_encoding() {
        const DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
        let mut state = 0x5eed_u64;
        let mut decoded_count = 0usize;
        for _ in 0..200_000 {
            let length = 1 + usize::try_from(lcg(&mut state) % 12).expect("small");
            let text: String = (0..length)
                .map(|_| {
                    let index = usize::try_from(lcg(&mut state)).expect("fits") % DIGITS.len();
                    char::from(DIGITS[index])
                })
                .collect();
            if let Ok(decoded) = punycode_decode(&text, 63)
                && decoded.iter().any(|c| !c.is_ascii())
            {
                decoded_count += 1;
                assert_eq!(punycode_encode(&decoded).as_deref(), Some(text.as_str()));
            }
        }
        assert!(decoded_count > 10_000, "only {decoded_count} decoded");
        // Every A-label in the conformance file that decodes.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/unicode-17.0.0/IdnaTestV2.txt"
        );
        let text = std::fs::read_to_string(path).expect("the conformance file");
        let mut labels = 0usize;
        for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
            let Some(rest) = token.strip_prefix("xn--") else {
                continue;
            };
            if rest.bytes().any(|b| b.is_ascii_uppercase()) {
                continue;
            }
            if let Ok(decoded) = punycode_decode(rest, usize::MAX)
                && decoded.iter().any(|c| !c.is_ascii())
            {
                labels += 1;
                assert_eq!(punycode_encode(&decoded).as_deref(), Some(rest), "{token}");
            }
        }
        assert!(labels > 1000, "only {labels} A-labels");
    }

    #[test]
    fn max_decomposition_is_the_largest_full_canonical_decomposition() {
        let mut largest = 0usize;
        for cp in 0..=0x10_ffff_u32 {
            if let Some(c) = char::from_u32(cp) {
                let mut out = Vec::new();
                unicode::decompose_for_test(c, &mut out);
                largest = largest.max(out.len());
            }
        }
        assert_eq!(largest, MAX_DECOMPOSITION);
    }

    #[test]
    fn mapping_is_bounded_before_normalization() {
        // U+FDFA maps to eighteen code points.
        let expanding: String = std::iter::repeat_n('\u{fdfa}', 57).collect();
        assert_eq!(map_bounded(&expanding, MAX_MAPPED), None);
        assert!(map_bounded(&"a".repeat(MAX_MAPPED), MAX_MAPPED).is_some());
        assert_eq!(map_bounded(&"a".repeat(MAX_MAPPED + 1), MAX_MAPPED), None);
        assert_eq!(
            to_ascii(&expanding, true),
            Err(IdnaError::NameLength),
            "refused at the mapping bound, before normalization"
        );
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
