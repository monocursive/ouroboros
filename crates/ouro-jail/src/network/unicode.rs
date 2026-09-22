//! Unicode 17.0.0 property lookups and NFC for UTS 46 processing.
//!
//! Every table comes from `data/uts46_unicode17_tables.rs`, generated from the
//! Unicode 17.0.0 data files named (with their SHA-256) in that file's header.
//! Nothing here approximates a property: a code point absent from a run table
//! has that table's documented default, exactly as the source file states it.

#[allow(clippy::unreadable_literal)]
mod tables {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/uts46_unicode17_tables.rs"
    ));
}

/// The Unicode version the tables were generated from.
pub(super) const UNICODE_VERSION: &str = tables::UNICODE_VERSION;
/// The UTS 46 revision of the mapping table.
pub(super) const UTS46_REVISION: u32 = tables::UTS46_REVISION;
/// SHA-256 of the mapping table file.
pub(super) const IDNA_TABLE_SHA256: &str = tables::IDNA_TABLE_SHA256;

/// A code point's status in the UTS 46 mapping table (§5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum IdnaStatus {
    /// Valid, unchanged.
    Valid,
    /// Removed.
    Ignored,
    /// Replaced by the mapping.
    Mapped(&'static str),
    /// Valid under nontransitional processing; the mapping is transitional.
    Deviation,
    /// Not allowed.
    Disallowed,
}

/// Looks up a code point's status. The generated runs cover every code point
/// exactly once (the generator refuses a table with a gap).
pub(super) fn idna_status(c: char) -> IdnaStatus {
    let cp = u32::from(c);
    let index = tables::IDNA_RUNS.partition_point(|&(first, _, _, _)| first <= cp);
    // `partition_point` is at least 1 because the first run starts at 0.
    let Some(&(_, last, status, mapping)) = index
        .checked_sub(1)
        .and_then(|index| tables::IDNA_RUNS.get(index))
    else {
        return IdnaStatus::Disallowed;
    };
    if cp > last {
        return IdnaStatus::Disallowed;
    }
    match status {
        0 => IdnaStatus::Valid,
        1 => IdnaStatus::Ignored,
        2 => match tables::IDNA_MAPPINGS.get(usize::from(mapping)) {
            Some(value) => IdnaStatus::Mapped(value),
            None => IdnaStatus::Disallowed,
        },
        3 => IdnaStatus::Deviation,
        _ => IdnaStatus::Disallowed,
    }
}

fn run_value<T: Copy>(runs: &[(u32, u32, T)], cp: u32) -> Option<T> {
    let index = runs.partition_point(|&(first, _, _)| first <= cp);
    let &(_, last, value) = runs.get(index.checked_sub(1)?)?;
    (cp <= last).then_some(value)
}

/// Canonical_Combining_Class; absent means 0 (Not_Reordered).
pub(super) fn combining_class(c: char) -> u8 {
    run_value(&tables::CCC_RUNS, u32::from(c)).unwrap_or(0)
}

/// General_Category is Mn, Mc or Me.
pub(super) fn is_mark(c: char) -> bool {
    let cp = u32::from(c);
    let index = tables::MARK_RUNS.partition_point(|&(first, _)| first <= cp);
    index
        .checked_sub(1)
        .and_then(|index| tables::MARK_RUNS.get(index))
        .is_some_and(|&(_, last)| cp <= last)
}

/// The Bidi_Class values RFC 5893 names; every other class is `Other`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum BidiClass {
    /// Left-to-right.
    L,
    /// Right-to-left.
    R,
    /// Arabic letter.
    AL,
    /// Arabic number.
    AN,
    /// European number.
    EN,
    /// European separator.
    ES,
    /// Common separator.
    CS,
    /// European terminator.
    ET,
    /// Other neutral.
    ON,
    /// Boundary neutral.
    BN,
    /// Nonspacing mark.
    Nsm,
    /// A class RFC 5893 admits in no label.
    Other,
}

/// Bidi_Class; absent means L (the file's `@missing` default after the
/// generator applied every range-specific default).
pub(super) fn bidi_class(c: char) -> BidiClass {
    match run_value(&tables::BIDI_RUNS, u32::from(c)) {
        None => BidiClass::L,
        Some(2) => BidiClass::R,
        Some(3) => BidiClass::AL,
        Some(4) => BidiClass::AN,
        Some(5) => BidiClass::EN,
        Some(6) => BidiClass::ES,
        Some(7) => BidiClass::CS,
        Some(8) => BidiClass::ET,
        Some(9) => BidiClass::ON,
        Some(10) => BidiClass::BN,
        Some(11) => BidiClass::Nsm,
        Some(_) => BidiClass::Other,
    }
}

/// Joining_Type as RFC 5892 Appendix A.1 uses it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum JoiningType {
    /// Left joining.
    L,
    /// Dual joining.
    D,
    /// Right joining.
    R,
    /// Transparent.
    T,
    /// Join causing, which the A.1 expression does not admit.
    C,
    /// Non joining.
    U,
}

/// Joining_Type; absent means U (Non_Joining).
pub(super) fn joining_type(c: char) -> JoiningType {
    match run_value(&tables::JOINING_RUNS, u32::from(c)) {
        Some(1) => JoiningType::L,
        Some(2) => JoiningType::D,
        Some(3) => JoiningType::R,
        Some(4) => JoiningType::T,
        Some(5) => JoiningType::C,
        _ => JoiningType::U,
    }
}

// ---------------------------------------------------------------------------
// NFC (UAX #15): canonical decomposition, canonical ordering, composition.
// ---------------------------------------------------------------------------

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn decompose_into(c: char, out: &mut Vec<char>) {
    let cp = u32::from(c);
    if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
        let index = cp - S_BASE;
        let l = L_BASE + index / N_COUNT;
        let v = V_BASE + (index % N_COUNT) / T_COUNT;
        let t = T_BASE + index % T_COUNT;
        for part in [l, v] {
            out.extend(char::from_u32(part));
        }
        if t != T_BASE {
            out.extend(char::from_u32(t));
        }
        return;
    }
    let found = tables::CANONICAL_DECOMPOSITIONS.binary_search_by_key(&cp, |&(key, _, _)| key);
    match found
        .ok()
        .and_then(|index| tables::CANONICAL_DECOMPOSITIONS.get(index))
    {
        Some(&(_, first, second)) => {
            if let Some(first) = char::from_u32(first) {
                decompose_into(first, out);
            }
            if second != 0
                && let Some(second) = char::from_u32(second)
            {
                decompose_into(second, out);
            }
        }
        None => out.push(c),
    }
}

fn compose_pair(first: char, second: char) -> Option<char> {
    let (a, b) = (u32::from(first), u32::from(second));
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        let l = a - L_BASE;
        let v = b - V_BASE;
        return char::from_u32(S_BASE + (l * V_COUNT + v) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a)
        && (a - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&b)
    {
        return char::from_u32(a + (b - T_BASE));
    }
    let index = tables::COMPOSITIONS
        .binary_search_by(|&(x, y, _)| (x, y).cmp(&(a, b)))
        .ok()?;
    let &(_, _, composite) = tables::COMPOSITIONS.get(index)?;
    char::from_u32(composite)
}

/// Returns the NFC form of `input`.
pub(super) fn nfc(input: &str) -> String {
    let mut chars = Vec::with_capacity(input.len());
    for c in input.chars() {
        decompose_into(c, &mut chars);
    }
    // Canonical ordering: a stable sort of each run of non-starters by class.
    let mut start = 0;
    while start < chars.len() {
        if chars.get(start).is_some_and(|&c| combining_class(c) != 0) {
            let mut end = start;
            while chars.get(end).is_some_and(|&c| combining_class(c) != 0) {
                end += 1;
            }
            if let Some(run) = chars.get_mut(start..end) {
                run.sort_by_key(|&c| combining_class(c));
            }
            start = end;
        } else {
            start += 1;
        }
    }
    // Canonical composition.
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut starter: Option<usize> = None;
    let mut last_class: Option<u8> = None;
    for c in chars {
        let class = combining_class(c);
        if let Some(index) = starter {
            let blocked = match last_class {
                // The last character appended was the starter itself.
                None => false,
                Some(last) => last == 0 || last >= class,
            };
            if !blocked
                && let Some(&first) = out.get(index)
                && let Some(composite) = compose_pair(first, c)
            {
                if let Some(slot) = out.get_mut(index) {
                    *slot = composite;
                }
                continue;
            }
        }
        if class == 0 {
            starter = Some(out.len());
            last_class = None;
        } else {
            last_class = Some(class);
        }
        out.push(c);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_are_the_pinned_versions() {
        assert_eq!(UNICODE_VERSION, "17.0.0");
        assert_eq!(UTS46_REVISION, 35);
        assert_eq!(
            IDNA_TABLE_SHA256,
            "87f05505dc026fdb2bff16132bdc68a8014675836882a9a2b1844540ad3be382"
        );
    }

    #[test]
    fn the_idna_runs_cover_every_code_point_once() {
        let mut next = 0u32;
        for &(first, last, _, _) in &tables::IDNA_RUNS {
            assert_eq!(first, next, "gap or overlap at U+{first:04X}");
            assert!(last >= first);
            next = last + 1;
        }
        assert_eq!(next, 0x11_0000);
    }

    #[test]
    fn nfc_composes_decomposes_and_reorders() {
        assert_eq!(nfc("e\u{301}"), "\u{e9}");
        assert_eq!(nfc("\u{212b}"), "\u{c5}", "a singleton decomposes");
        assert_eq!(nfc("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}", "Hangul LVT");
        assert_eq!(
            nfc("a\u{323}\u{302}"),
            nfc("a\u{302}\u{323}"),
            "canonical order does not depend on input order"
        );
        assert_eq!(nfc("\u{344}"), "\u{308}\u{301}", "an excluded composite");
    }

    #[test]
    fn properties_match_their_source_files() {
        assert_eq!(combining_class('\u{94d}'), 9, "Devanagari virama");
        assert!(is_mark('\u{300}'));
        assert!(!is_mark('a'));
        assert_eq!(bidi_class('\u{5d0}'), BidiClass::R);
        assert_eq!(bidi_class('\u{627}'), BidiClass::AL);
        assert_eq!(bidi_class('\u{660}'), BidiClass::AN);
        assert_eq!(bidi_class('0'), BidiClass::EN);
        assert_eq!(bidi_class('a'), BidiClass::L);
        assert_eq!(joining_type('\u{628}'), JoiningType::D);
        assert_eq!(joining_type('\u{627}'), JoiningType::R);
        assert_eq!(joining_type('a'), JoiningType::U);
        assert_eq!(idna_status('A'), IdnaStatus::Mapped("a"));
        assert_eq!(idna_status('\u{df}'), IdnaStatus::Deviation);
        assert_eq!(idna_status('\u{ad}'), IdnaStatus::Ignored);
        assert_eq!(idna_status('\u{80}'), IdnaStatus::Disallowed);
    }
}
