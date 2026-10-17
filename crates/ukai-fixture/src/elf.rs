//! Synthetic ELF images for `--from-path` resolution tests: only the headers
//! the kernel and the dynamic loader read before any code runs (`PT_INTERP`,
//! one `PT_LOAD`, `PT_DYNAMIC` and the dynamic strings). Nothing in them is
//! executable; a test that must run a program copies a host binary instead.
//!
//! The one `PT_LOAD` maps the whole file at [`BASE`], so every address the
//! dynamic section holds differs from its file offset, as it does in a real
//! position-independent executable's writable segment.

/// `DT_NEEDED`: a library name.
pub const DT_NEEDED: u64 = 1;
/// `DT_RPATH`: the legacy library search path.
pub const DT_RPATH: u64 = 15;
/// `DT_RUNPATH`: the library search path.
pub const DT_RUNPATH: u64 = 29;
/// `DT_AUDIT`: `rtld-audit` libraries, colon-separated.
pub const DT_AUDIT: u64 = 0x6fff_fefc;
/// `DT_DEPAUDIT`: `rtld-audit` libraries for dependencies, colon-separated.
pub const DT_DEPAUDIT: u64 = 0x6fff_fefb;
/// `DT_AUXILIARY`: an auxiliary filter library name.
pub const DT_AUXILIARY: u64 = 0x7fff_fffd;
/// `DT_FILTER`: a filter library name.
pub const DT_FILTER: u64 = 0x7fff_ffff;

/// Where the image's one `PT_LOAD` maps offset 0.
pub const BASE: u64 = 0x10_000;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;

/// An ELF image under construction.
#[derive(Clone, Debug)]
pub struct Image {
    class64: bool,
    little: bool,
    interp: Option<Vec<u8>>,
    entries: Vec<(u64, Vec<u8>)>,
    after_null: Vec<(u64, Vec<u8>)>,
    decoy: bool,
    dynamic: bool,
}

impl Default for Image {
    fn default() -> Image {
        Image::new()
    }
}

impl Image {
    /// A 64-bit little-endian image with no loader and no dynamic section:
    /// a static executable.
    #[must_use]
    pub fn new() -> Image {
        Image {
            class64: true,
            little: true,
            interp: None,
            entries: Vec::new(),
            after_null: Vec::new(),
            decoy: false,
            dynamic: false,
        }
    }

    /// A 32-bit image.
    #[must_use]
    pub fn class32(mut self) -> Image {
        self.class64 = false;
        self
    }

    /// A big-endian image.
    #[must_use]
    pub fn big_endian(mut self) -> Image {
        self.little = false;
        self
    }

    /// `PT_INTERP` naming `path` (a NUL is appended).
    #[must_use]
    pub fn interp(mut self, path: impl AsRef<[u8]>) -> Image {
        self.interp = Some(path.as_ref().to_vec());
        self
    }

    /// A string-valued dynamic entry; the first one adds `PT_DYNAMIC`.
    #[must_use]
    pub fn entry(mut self, tag: u64, value: impl AsRef<[u8]>) -> Image {
        self.dynamic = true;
        self.entries.push((tag, value.as_ref().to_vec()));
        self
    }

    /// A string-valued entry after `DT_NULL`, which no loader reads.
    #[must_use]
    pub fn after_null(mut self, tag: u64, value: impl AsRef<[u8]>) -> Image {
        self.dynamic = true;
        self.after_null.push((tag, value.as_ref().to_vec()));
        self
    }

    /// `PT_DYNAMIC`'s file offset names a second table holding no library
    /// entry, while its address (what the dynamic loader reads) maps to the
    /// real one.
    #[must_use]
    pub fn decoy(mut self) -> Image {
        self.dynamic = true;
        self.decoy = true;
        self
    }

    fn put(&self, out: &mut Vec<u8>, value: u64, width: usize) {
        let bytes = value.to_le_bytes();
        if self.little {
            out.extend_from_slice(&bytes[..width]);
        } else {
            out.extend(bytes[..width].iter().rev());
        }
    }

    fn word(&self) -> usize {
        if self.class64 { 8 } else { 4 }
    }

    /// The image's bytes.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let word = self.word();
        let (ehsize, phentsize) = if self.class64 { (64, 56) } else { (52, 32) };
        let phnum = 1 + usize::from(self.interp.is_some()) + usize::from(self.dynamic);
        let mut body = Vec::new();
        let body_start = ehsize + phnum * phentsize;

        let interp = self.interp.as_ref().map(|path| {
            let at = body_start + body.len();
            body.extend_from_slice(path);
            body.push(0);
            (at, path.len() + 1)
        });

        let mut strings = vec![0u8];
        let mut offsets = Vec::new();
        for (tag, value) in self.entries.iter().chain(&self.after_null) {
            offsets.push((*tag, strings.len()));
            strings.extend_from_slice(value);
            strings.push(0);
        }
        let strtab = body_start + body.len();
        if self.dynamic {
            body.extend_from_slice(&strings);
            while (body_start + body.len()) % word != 0 {
                body.push(0);
            }
        }

        let table = |image: &Image, entries: &[(u64, usize)], trailing: &[(u64, usize)]| {
            let mut out = Vec::new();
            for (tag, value) in [
                (DT_STRTAB, BASE + strtab as u64),
                (DT_STRSZ, strings.len() as u64),
            ]
            .into_iter()
            .chain(entries.iter().map(|(tag, at)| (*tag, *at as u64)))
            .chain([(DT_NULL, 0)])
            .chain(trailing.iter().map(|(tag, at)| (*tag, *at as u64)))
            {
                image.put(&mut out, tag, word);
                image.put(&mut out, value, word);
            }
            out
        };
        let (real, trailing) = offsets.split_at(self.entries.len());
        let dynamic = self.dynamic.then(|| {
            let at = body_start + body.len();
            let bytes = table(self, real, trailing);
            body.extend_from_slice(&bytes);
            (at, bytes.len())
        });
        let decoy = (self.dynamic && self.decoy).then(|| {
            let at = body_start + body.len();
            body.extend_from_slice(&table(self, &[], &[]));
            at
        });
        let total = body_start + body.len();

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(b"\x7fELF");
        out.push(if self.class64 { 2 } else { 1 });
        out.push(if self.little { 1 } else { 2 });
        out.push(1);
        out.resize(16, 0);
        self.put(&mut out, 3, 2); // e_type: ET_DYN
        self.put(&mut out, 62, 2); // e_machine
        self.put(&mut out, 1, 4); // e_version
        self.put(&mut out, 0, word); // e_entry
        self.put(&mut out, ehsize as u64, word); // e_phoff
        self.put(&mut out, 0, word); // e_shoff
        self.put(&mut out, 0, 4); // e_flags
        self.put(&mut out, ehsize as u64, 2);
        self.put(&mut out, phentsize as u64, 2);
        self.put(&mut out, phnum as u64, 2);
        self.put(&mut out, 0, 2); // e_shentsize
        self.put(&mut out, 0, 2); // e_shnum
        self.put(&mut out, 0, 2); // e_shstrndx
        assert_eq!(out.len(), ehsize);

        let mut header = |kind: u32, offset: usize, length: usize, vaddr: u64| {
            let (offset, length) = (offset as u64, length as u64);
            self.put(&mut out, u64::from(kind), 4);
            if self.class64 {
                self.put(&mut out, 4, 4); // p_flags
                for value in [offset, vaddr, vaddr, length, length, 8] {
                    self.put(&mut out, value, 8);
                }
            } else {
                for value in [offset, vaddr, vaddr, length, length] {
                    self.put(&mut out, value, 4);
                }
                self.put(&mut out, 4, 4); // p_flags
                self.put(&mut out, 4, 4); // p_align
            }
        };
        if let Some((at, length)) = interp {
            header(PT_INTERP, at, length, BASE + at as u64);
        }
        header(PT_LOAD, 0, total, BASE);
        if let Some((at, length)) = dynamic {
            header(PT_DYNAMIC, decoy.unwrap_or(at), length, BASE + at as u64);
        }
        assert_eq!(out.len(), body_start);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_image_has_one_load_header_and_no_dynamic_section() {
        let bytes = Image::new().bytes();
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(u16::from_le_bytes([bytes[56], bytes[57]]), 1);
        assert_eq!(bytes.len(), 64 + 56);
    }

    #[test]
    fn strings_and_tables_land_where_the_headers_say() {
        let bytes = Image::new()
            .interp("/lib/ld.so")
            .entry(DT_RUNPATH, "$ORIGIN")
            .bytes();
        let interp_at = usize::try_from(u64::from_le_bytes(
            bytes[64 + 8..64 + 16].try_into().unwrap(),
        ))
        .unwrap();
        assert_eq!(&bytes[interp_at..interp_at + 11], b"/lib/ld.so\0");
        let dynamic = 64 + 2 * 56;
        let at = usize::try_from(u64::from_le_bytes(
            bytes[dynamic + 8..dynamic + 16].try_into().unwrap(),
        ))
        .unwrap();
        let vaddr = u64::from_le_bytes(bytes[dynamic + 16..dynamic + 24].try_into().unwrap());
        assert_eq!(vaddr - BASE, at as u64);
        let strtab = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap()) - BASE;
        let runpath = u64::from_le_bytes(bytes[at + 40..at + 48].try_into().unwrap());
        let start = usize::try_from(strtab + runpath).unwrap();
        assert_eq!(&bytes[start..start + 8], b"$ORIGIN\0");
    }
}
