//! One JSON line per operation, and the expectation that decides the exit code.

use std::ffi::{OsStr, c_int};
use std::os::unix::ffi::OsStrExt;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::errno;

/// The report line. The field order here is the field order on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct OpReport {
    pub op: String,
    pub args: Map<String, Value>,
    pub ret: i64,
    pub errno: Option<String>,
}

impl OpReport {
    #[must_use]
    pub fn new(op: &str) -> Self {
        OpReport {
            op: op.to_string(),
            args: Map::new(),
            ret: 0,
            errno: None,
        }
    }

    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.args.insert(key.to_string(), value.into());
        self
    }

    pub fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.args.insert(key.to_string(), value.into());
    }

    /// Record a raw syscall return and its errno name.
    pub fn result(&mut self, ret: i64, raw_errno: Option<c_int>) {
        self.ret = ret;
        self.errno = raw_errno.map(|e| {
            errno::name(e).map_or_else(|| format!("errno_{e}"), std::string::ToString::to_string)
        });
    }

    #[must_use]
    pub fn to_line(&self) -> String {
        // The struct has no value that can fail to serialize.
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!("{{\"op\":\"report_error\",\"args\":{{}},\"ret\":-1,\"errno\":\"{e}\"}}")
        })
    }
}

/// A path as JSON: always a lossy string for readability, plus the exact bytes
/// whenever the path is not valid UTF-8, so non-UTF-8 names stay comparable.
pub fn path_value(map: &mut Map<String, Value>, key: &str, p: &OsStr) {
    let bytes = p.as_bytes();
    map.insert(
        key.to_string(),
        Value::String(String::from_utf8_lossy(bytes).into_owned()),
    );
    if std::str::from_utf8(bytes).is_err() {
        map.insert(
            format!("{key}_bytes"),
            Value::Array(bytes.iter().map(|b| Value::from(*b)).collect()),
        );
    }
}

/// What the caller said should happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// The call must succeed (non-negative return, no errno).
    Ok,
    /// Any performed result is accepted. An absent syscall or a refused path
    /// is still a failure: those are not results.
    Any,
    /// The call must fail with exactly this errno.
    Errno(String),
}

impl Expect {
    /// Parse `ok`, `any` or an errno name known to this build.
    pub fn parse(s: &str) -> Result<Expect, String> {
        match s {
            "ok" => Ok(Expect::Ok),
            "any" => Ok(Expect::Any),
            name => {
                if errno::value(name).is_some() {
                    Ok(Expect::Errno(name.to_string()))
                } else {
                    Err(format!(
                        "unknown expectation `{name}`: use `ok`, `any`, or one of {}",
                        errno::known_names().join(", ")
                    ))
                }
            }
        }
    }

    #[must_use]
    pub fn satisfied_by(&self, report: &OpReport) -> bool {
        match self {
            Expect::Any => true,
            Expect::Ok => report.ret >= 0 && report.errno.is_none(),
            Expect::Errno(name) => report.errno.as_deref() == Some(name.as_str()),
        }
    }
}

impl std::str::FromStr for Expect {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Expect::parse(s)
    }
}

impl std::fmt::Display for Expect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expect::Ok => f.write_str("ok"),
            Expect::Any => f.write_str("any"),
            Expect::Errno(n) => f.write_str(n),
        }
    }
}

/// One emitted operation: the line, plus whether it can satisfy anything.
pub struct Emitted {
    pub report: OpReport,
    /// Set when the operation never reached the kernel (absent syscall,
    /// refused path). Such a line fails every expectation, including `any`:
    /// a fixture that silently did nothing must not report success.
    pub unusable: bool,
}

impl Emitted {
    #[must_use]
    pub fn done(report: OpReport) -> Self {
        Emitted {
            report,
            unusable: false,
        }
    }

    #[must_use]
    pub fn unusable(report: OpReport) -> Self {
        Emitted {
            report,
            unusable: true,
        }
    }

    #[must_use]
    pub fn satisfies(&self, expect: &Expect) -> bool {
        !self.unusable && expect.satisfied_by(&self.report)
    }
}

/// Where report lines go. `None` suppresses them entirely (`--no-report`),
/// which the byte-stream modes need so the JSON does not corrupt the stream
/// under comparison.
pub struct Reporter {
    fd: Option<c_int>,
}

impl Reporter {
    #[must_use]
    pub fn to_fd(fd: c_int) -> Self {
        Reporter { fd: Some(fd) }
    }

    #[must_use]
    pub fn silent() -> Self {
        Reporter { fd: None }
    }

    pub fn emit(&self, report: &OpReport) {
        if let Some(fd) = self.fd {
            let mut line = report.to_line();
            line.push('\n');
            write_all(fd, line.as_bytes());
        }
    }
}

/// Write every byte to a raw fd, retrying `EINTR`. Unbuffered on purpose: the
/// byte-stream modes write to the same descriptors and the order must hold.
pub fn write_all(fd: c_int, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: `fd` is a descriptor number supplied by the caller and
        // `buf` is a live slice; `write` reads at most `buf.len()` bytes from
        // it and never retains the pointer.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn the_line_has_the_four_contract_keys_in_order() {
        let mut r = OpReport::new("openat");
        r.set("path", "/tmp/x");
        r.result(-1, Some(libc::ENOENT));
        let line = r.to_line();
        assert!(line.starts_with(r#"{"op":"openat","args":{"#), "{line}");
        assert!(line.ends_with(r#""ret":-1,"errno":"ENOENT"}"#), "{line}");
        assert!(!line.contains('\n'));
    }

    #[test]
    fn a_success_reports_a_null_errno() {
        let mut r = OpReport::new("mkdirat");
        r.result(0, None);
        assert!(
            r.to_line().ends_with(r#""ret":0,"errno":null}"#),
            "{}",
            r.to_line()
        );
    }

    #[test]
    fn expectations_parse_and_reject() {
        assert_eq!(Expect::parse("ok").unwrap(), Expect::Ok);
        assert_eq!(Expect::parse("any").unwrap(), Expect::Any);
        assert_eq!(
            Expect::parse("EACCES").unwrap(),
            Expect::Errno("EACCES".into())
        );
        let err = Expect::parse("ENOSUCH").unwrap_err();
        assert!(err.starts_with("unknown expectation `ENOSUCH`"), "{err}");
    }

    #[test]
    fn ok_and_errno_expectations_discriminate() {
        let mut ok = OpReport::new("openat");
        ok.result(3, None);
        let mut denied = OpReport::new("openat");
        denied.result(-1, Some(libc::EACCES));

        assert!(Expect::Ok.satisfied_by(&ok));
        assert!(!Expect::Ok.satisfied_by(&denied));
        assert!(Expect::Errno("EACCES".into()).satisfied_by(&denied));
        assert!(!Expect::Errno("EACCES".into()).satisfied_by(&ok));
        assert!(!Expect::Errno("ENOENT".into()).satisfied_by(&denied));
    }

    #[test]
    fn an_unusable_line_satisfies_nothing_not_even_any() {
        let mut r = OpReport::new("openat2");
        r.set("unsupported", "openat2 is a Linux syscall");
        r.result(-1, None);
        let e = Emitted::unusable(r);
        assert!(!e.satisfies(&Expect::Any));
        assert!(!e.satisfies(&Expect::Ok));
        assert!(!e.satisfies(&Expect::Errno("ENOSYS".into())));
    }

    #[test]
    fn non_utf8_paths_carry_their_exact_bytes() {
        let mut m = Map::new();
        path_value(&mut m, "path", OsStr::new("/tmp/ok"));
        assert_eq!(m.get("path").unwrap(), "/tmp/ok");
        assert!(m.get("path_bytes").is_none());

        let raw = OsString::from_vec(vec![b'/', 0xff]);
        let mut m = Map::new();
        path_value(&mut m, "path", &raw);
        assert_eq!(
            m.get("path_bytes").unwrap(),
            &Value::Array(vec![Value::from(b'/'), Value::from(0xffu8)])
        );
    }
}
