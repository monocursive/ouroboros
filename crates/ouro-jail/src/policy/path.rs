//! Lexical path handling shared by policy resolution and launch profiles.
//!
//! One splitter, one normalizer and one `~/` expander, so the two places that
//! turn operator text into absolute paths cannot disagree about what a
//! spelling means. Nothing here touches the filesystem: symlinks are the
//! business of the no-follow walks that come later (§9.1).

/// Why a path cannot be normalized lexically.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refusal {
    /// The path is empty.
    Empty,
    /// The path contains a NUL byte.
    Nul,
    /// The path is relative and there is no directory to resolve it against.
    Relative,
    /// A `..` would climb above `/`.
    EscapesRoot,
    /// A leading `~/` with no operator home to expand it against.
    HomeUnavailable,
}

/// The non-empty components of `path`, in order: `a//b/` is `a`, `b`.
pub(crate) fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
}

/// Whether `ancestor` is `path` or one of its ancestors, compared component
/// by component so that `/work/a` is not an ancestor of `/work/ab`. On a
/// match, the rest of `path`'s components.
pub(crate) fn strip_ancestor<'a>(ancestor: &[u8], path: &'a [u8]) -> Option<Vec<&'a [u8]>> {
    let mut mine = components(ancestor);
    let mut theirs = components(path);
    loop {
        match (mine.next(), theirs.next()) {
            (None, Some(next)) => {
                let mut rest = vec![next];
                rest.extend(theirs);
                return Some(rest);
            }
            (None, None) => return Some(Vec::new()),
            (Some(left), Some(right)) if left == right => {}
            _ => return None,
        }
    }
}

/// Joins components with `/`, without a leading slash.
pub(crate) fn join(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    out
}

/// Expands a leading `~/` against the operator home; any other path is
/// returned as written.
///
/// # Errors
/// [`Refusal::HomeUnavailable`] for a `~/` path without a home: the literal
/// directory `~` beneath some base is never what the operator meant.
pub(crate) fn expand_home(raw: &[u8], home: Option<&[u8]>) -> Result<Vec<u8>, Refusal> {
    let Some(rest) = raw.strip_prefix(b"~/") else {
        return Ok(raw.to_vec());
    };
    let home = home.ok_or(Refusal::HomeUnavailable)?;
    let mut out = home.to_vec();
    out.push(b'/');
    out.extend_from_slice(rest);
    Ok(out)
}

/// Lexically normalizes `raw`, joined to `base` when it is relative: `.` and
/// empty segments drop, `..` pops, and a `..` above `/` refuses instead of
/// clamping. The result is absolute; `/` itself normalizes to `/`.
///
/// # Errors
/// The [`Refusal`] naming why the path has no normal form.
pub(crate) fn normalize(base: Option<&[u8]>, raw: &[u8]) -> Result<Vec<u8>, Refusal> {
    if raw.is_empty() {
        return Err(Refusal::Empty);
    }
    if raw.contains(&0) {
        return Err(Refusal::Nul);
    }
    let base = if raw.starts_with(b"/") {
        &[][..]
    } else {
        match base {
            Some(base) if base.starts_with(b"/") => base,
            _ => return Err(Refusal::Relative),
        }
    };
    if base.contains(&0) {
        return Err(Refusal::Nul);
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in base
        .split(|byte| *byte == b'/')
        .chain(raw.split(|byte| *byte == b'/'))
    {
        match part {
            b"" | b"." => {}
            b".." => {
                if parts.pop().is_none() {
                    return Err(Refusal::EscapesRoot);
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = Vec::with_capacity(raw.len() + base.len() + 1);
    for part in parts {
        out.push(b'/');
        out.extend_from_slice(part);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_lexical_and_refuses_an_escape() {
        assert_eq!(
            normalize(Some(b"/srv/demo"), b"./fixtures"),
            Ok(b"/srv/demo/fixtures".to_vec())
        );
        assert_eq!(
            normalize(Some(b"/srv/demo"), b"a/../b"),
            Ok(b"/srv/demo/b".to_vec())
        );
        assert_eq!(normalize(None, b"/srv//work/"), Ok(b"/srv/work".to_vec()));
        assert_eq!(normalize(None, b"/a/.."), Ok(b"/".to_vec()));
        assert_eq!(normalize(None, b"../../.."), Err(Refusal::Relative));
        assert_eq!(normalize(Some(b"/"), b"../.."), Err(Refusal::EscapesRoot));
        assert_eq!(normalize(Some(b"/srv"), b""), Err(Refusal::Empty));
        assert_eq!(normalize(None, b"/a\0b"), Err(Refusal::Nul));
        assert_eq!(normalize(Some(b"relative"), b"x"), Err(Refusal::Relative));
    }

    #[test]
    fn home_expansion_refuses_without_a_home() {
        assert_eq!(
            expand_home(b"~/x", Some(b"/home/op")),
            Ok(b"/home/op/x".to_vec())
        );
        assert_eq!(expand_home(b"~/x", None), Err(Refusal::HomeUnavailable));
        assert_eq!(expand_home(b"x/~/y", None), Ok(b"x/~/y".to_vec()));
        assert_eq!(expand_home(b"~x", None), Ok(b"~x".to_vec()));
    }

    #[test]
    fn ancestry_compares_components_not_string_prefixes() {
        assert_eq!(
            strip_ancestor(b"/work", b"/work/a/b"),
            Some(vec![&b"a"[..], &b"b"[..]])
        );
        assert_eq!(strip_ancestor(b"/work/", b"//work"), Some(Vec::new()));
        assert_eq!(strip_ancestor(b"/work/a", b"/work/ab"), None);
        assert_eq!(strip_ancestor(b"/work/a/b", b"/work/a"), None);
        assert_eq!(join(&[b"a", b"b"]), b"a/b".to_vec());
        assert_eq!(join(&[]), Vec::<u8>::new());
    }
}
