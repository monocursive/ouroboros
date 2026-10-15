//! `/proc/<pid>/mountinfo`, parsed strictly (proc(5)).
//!
//! One row per mount:
//!
//! ```text
//! 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//! (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
//! ```
//!
//! Fields are separated by single spaces; a space, tab, newline or backslash
//! inside a field is written as a three-digit octal escape, so splitting on
//! the byte is exact. The optional fields (7) end at a lone `-` (8), which
//! three fields follow. A table that is not exactly that shape, an escape
//! that is not three octal digits naming a byte, a file larger than its read
//! bound or more rows than the caller's bound is refused whole: a caller
//! never acts on part of a table as if it were all of it.
//!
//! The parser is plain byte work and builds everywhere; only Linux has the
//! file.

use std::io::{self, Read as _};
use std::path::Path;

/// One mount, its paths decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Row {
    /// The mount's id (1).
    pub mount_id: u64,
    /// Its parent's id (2).
    pub parent_id: u64,
    /// `major:minor` of the filesystem (3).
    pub device: Vec<u8>,
    /// The root of the mount within its filesystem (4), decoded. Not always
    /// a path: an nsfs mount names its namespace (`mnt:[4026532535]`).
    pub root: Vec<u8>,
    /// The mount point (5), decoded.
    pub mount_point: Vec<u8>,
    /// The per-mount options (6), comma-separated.
    pub options: Vec<u8>,
    /// The optional fields (7), such as `shared:1`.
    pub optional: Vec<Vec<u8>>,
    /// The filesystem type (9).
    pub fstype: Vec<u8>,
    /// The mount source (10), decoded.
    pub source: Vec<u8>,
    /// The per-superblock options (11).
    pub super_options: Vec<u8>,
}

impl Row {
    /// Whether the per-mount options include `option` (`ro`, `nosuid`, ...).
    #[must_use]
    pub fn has_option(&self, option: &[u8]) -> bool {
        self.options
            .split(|byte| *byte == b',')
            .any(|item| item == option)
    }
}

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// Decodes a field's octal escapes (`\040` for a space): exactly three
/// octal digits naming one byte; anything else after a backslash refuses.
///
/// # Errors
/// `InvalidData` for a malformed escape.
pub fn decode(field: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(field.len());
    let mut at = 0;
    while at < field.len() {
        if field[at] != b'\\' {
            out.push(field[at]);
            at += 1;
            continue;
        }
        let digits = field
            .get(at + 1..at + 4)
            .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
            .ok_or_else(|| invalid("a mountinfo escape is not three octal digits"))?;
        let value = digits
            .iter()
            .fold(0_u16, |value, digit| value * 8 + u16::from(digit - b'0'));
        out.push(u8::try_from(value).map_err(|_| invalid("a mountinfo escape names no byte"))?);
        at += 4;
    }
    Ok(out)
}

fn number(field: &[u8], what: &str) -> io::Result<u64> {
    std::str::from_utf8(field)
        .ok()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| invalid(format!("a mountinfo {what} is not a number")))
}

/// Parses one row.
///
/// # Errors
/// `InvalidData` when the row is not the shape proc(5) gives.
pub fn row(line: &[u8]) -> io::Result<Row> {
    let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
    let separator = fields
        .iter()
        .skip(6)
        .position(|field| *field == b"-")
        .map(|index| index + 6)
        .ok_or_else(|| invalid("a mountinfo row has no `-` after its sixth field"))?;
    let [fstype, source, super_options] = fields[separator + 1..] else {
        return Err(invalid(
            "a mountinfo row does not end in a type, a source and options",
        ));
    };
    if fields[..separator].iter().any(|field| field.is_empty()) || fstype.is_empty() {
        return Err(invalid("a mountinfo row has an empty field"));
    }
    Ok(Row {
        mount_id: number(fields[0], "mount id")?,
        parent_id: number(fields[1], "parent id")?,
        device: fields[2].to_vec(),
        root: decode(fields[3])?,
        mount_point: decode(fields[4])?,
        options: fields[5].to_vec(),
        optional: fields[6..separator]
            .iter()
            .map(|field| field.to_vec())
            .collect(),
        fstype: fstype.to_vec(),
        source: decode(source)?,
        super_options: super_options.to_vec(),
    })
}

/// Parses a whole table of at most `max_rows` rows.
///
/// # Errors
/// `InvalidData` for any malformed row or more than `max_rows` rows.
pub fn rows(bytes: &[u8], max_rows: usize) -> io::Result<Vec<Row>> {
    let mut out = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if out.len() == max_rows {
            return Err(invalid(format!(
                "the mount table has more than {max_rows} rows"
            )));
        }
        out.push(row(line)?);
    }
    Ok(out)
}

/// Reads a mountinfo file of at most `max_bytes` bytes and parses at most
/// `max_rows` rows of it.
///
/// # Errors
/// The read's error, `InvalidData` for a larger file, and [`rows`]'s.
pub fn read(path: &Path, max_bytes: usize, max_rows: usize) -> io::Result<Vec<Row>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(invalid(format!(
            "the mount table is larger than {max_bytes} bytes"
        )));
    }
    rows(&bytes, max_rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = concat!(
        "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n",
        "530 509 0:4 mnt:[4026532535] /run/snapd/ns/lxd.mnt rw - nsfs nsfs rw\n",
        "41 36 0:5 / /work/a\\040b ro,nosuid shared:2 master:3 - tmpfs a\\134b rw\n",
    );

    #[test]
    fn every_field_of_every_row_is_read() {
        let rows = rows(TABLE.as_bytes(), 16).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].mount_id, 36);
        assert_eq!(rows[0].parent_id, 35);
        assert_eq!(rows[0].device, b"98:0");
        assert_eq!(rows[0].root, b"/mnt1");
        assert_eq!(rows[0].mount_point, b"/mnt2");
        assert_eq!(rows[0].optional, [b"master:1".to_vec()]);
        assert_eq!(rows[0].fstype, b"ext3");
        assert_eq!(rows[0].source, b"/dev/root");
        assert_eq!(rows[0].super_options, b"rw,errors=continue");
        assert!(rows[0].has_option(b"noatime") && !rows[0].has_option(b"ro"));
        assert_eq!(rows[1].root, b"mnt:[4026532535]");
        assert!(rows[1].optional.is_empty());
        assert_eq!(rows[2].mount_point, b"/work/a b");
        assert_eq!(rows[2].source, b"a\\b");
        assert_eq!(rows[2].optional.len(), 2);
        assert!(rows[2].has_option(b"ro"));
    }

    #[test]
    fn a_row_of_another_shape_refuses_the_whole_table() {
        for bad in [
            "36 35 98:0 /a /b rw - ext3 /dev/root",
            "36 35 98:0 /a /b rw ext3 /dev/root rw",
            "36 35 98:0 /a /b - ext3 /dev/root rw",
            "36 35 98:0 /a /b rw - ext3 /dev/root rw extra",
            "36 35 98:0 /a  /b rw - ext3 /dev/root rw",
            "x 35 98:0 /a /b rw - ext3 /dev/root rw",
            "36 35 98:0 /a\\04 /b rw - ext3 /dev/root rw",
            "36 35 98:0 /a\\400 /b rw - ext3 /dev/root rw",
            "36 35 98:0 /a\\09x /b rw - ext3 /dev/root rw",
        ] {
            let table = format!("{bad}\n{TABLE}");
            assert!(rows(table.as_bytes(), 16).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn more_rows_than_the_bound_refuse_the_whole_table() {
        assert_eq!(rows(TABLE.as_bytes(), 3).unwrap().len(), 3);
        assert!(rows(TABLE.as_bytes(), 2).is_err());
    }

    #[test]
    fn a_file_larger_than_its_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mountinfo");
        std::fs::write(&path, TABLE).unwrap();
        assert_eq!(read(&path, TABLE.len(), 16).unwrap().len(), 3);
        assert!(read(&path, TABLE.len() - 1, 16).is_err());
    }
}
