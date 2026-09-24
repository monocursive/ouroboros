//! The host manifest `doctor --json` produces (jail-v1 §3.2, §14.1).
//!
//! §3.2: `doctor --json` "produces the host manifest, which the J0 report
//! and every conformance run record: kernel release and build,
//! architecture, distribution, bubblewrap and selected-backend versions and
//! hashes, cgroup v2 delegation as seen from the operator's session, the
//! values of [four sysctls], any operator-installed AppArmor profile", and
//! it supersedes the manual `host-manifest.sh`. §14.1 adds "binary
//! hashes/versions, operator identity category".
//!
//! Everything here reads; nothing changes the host (§14.1: `doctor` "does
//! not edit user namespaces policy ... or change capabilities"). A fact that
//! cannot be read is `null`, never a default that looks like a measurement.
//! The architecture is `platform.arch` beside this object; the tracing
//! capability provisioning §3.2 mentions is none, by the zero-host-
//! configuration requirement, and the `ptrace_seize_descendant` probe row
//! measures what the operator's identity already allows.
//!
//! The parsing is portable and unit-tested on every host; only the reads are
//! Linux's.

use std::io::{self, Read as _};
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// The sysctls the manifest records, by dotted name: the four §3.2 names,
/// then the two the manual manifest also recorded (user namespaces and
/// io_uring bear on S03 and S04).
pub const SYSCTLS: [&str; 6] = [
    "kernel.apparmor_restrict_unprivileged_userns",
    "kernel.unprivileged_bpf_disabled",
    "kernel.perf_event_paranoid",
    "kernel.yama.ptrace_scope",
    "user.max_user_namespaces",
    "kernel.io_uring_disabled",
];

/// Where AppArmor profiles are installed.
pub const APPARMOR_DIR: &str = "/etc/apparmor.d";

/// Profile file names worth recording: those that bear on user namespaces,
/// on the backend or on this product. The same selection as the manual
/// manifest; an unprivileged account cannot list the loaded set.
pub const APPARMOR_PROFILE_WORDS: [&str; 3] = ["userns", "bwrap", "ouro"];

/// Where logind records lingering: one file per user name.
pub const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// The procfs path of a dotted sysctl name.
#[must_use]
pub fn sysctl_path(name: &str) -> String {
    format!("/proc/sys/{}", name.replace('.', "/"))
}

/// The operator identity category of §14.1: who `doctor` ran as, in the
/// terms that decide what it could measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorIdentity {
    /// Effective uid 0.
    Root,
    /// Real and effective uid or gid differ: a set-id program.
    SetId,
    /// Not root, but with permitted, effective or ambient capabilities.
    Capable,
    /// An ordinary account with no capability: the reference host's
    /// `ouro-ci`, and the identity the product is built for.
    Unprivileged,
    /// The credentials could not be read.
    Unknown,
}

impl OperatorIdentity {
    /// The category's name in the report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::SetId => "set_id",
            Self::Capable => "capable",
            Self::Unprivileged => "unprivileged",
            Self::Unknown => "unknown",
        }
    }
}

/// Classifies `/proc/<pid>/status` text.
#[must_use]
pub fn classify_identity(status: &str) -> OperatorIdentity {
    let field = |name: &str| -> Option<Vec<&str>> {
        status.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(':')?;
            Some(rest.split_whitespace().collect())
        })
    };
    let (Some(uids), Some(gids)) = (field("Uid"), field("Gid")) else {
        return OperatorIdentity::Unknown;
    };
    let (Some(real_uid), Some(effective_uid), Some(real_gid), Some(effective_gid)) =
        (uids.first(), uids.get(1), gids.first(), gids.get(1))
    else {
        return OperatorIdentity::Unknown;
    };
    if *effective_uid == "0" {
        return OperatorIdentity::Root;
    }
    if real_uid != effective_uid || real_gid != effective_gid {
        return OperatorIdentity::SetId;
    }
    let mut capable = false;
    for name in ["CapPrm", "CapEff", "CapAmb"] {
        let Some(mask) = field(name).and_then(|values| values.first().copied()) else {
            return OperatorIdentity::Unknown;
        };
        let Ok(bits) = u64::from_str_radix(mask, 16) else {
            return OperatorIdentity::Unknown;
        };
        capable |= bits != 0;
    }
    if capable {
        OperatorIdentity::Capable
    } else {
        OperatorIdentity::Unprivileged
    }
}

/// `PRETTY_NAME` from os-release(5) text, with its shell quoting removed.
#[must_use]
pub fn os_release_pretty_name(text: &str) -> Option<String> {
    let raw = text
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("PRETTY_NAME="))?
        .trim_end();
    let unquoted = if let Some(inner) = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        // Inside double quotes, a backslash escapes the next character.
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else if let Some(inner) = raw
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        inner.to_owned()
    } else {
        raw.to_owned()
    };
    (!unquoted.is_empty()).then_some(unquoted)
}

/// The restriction's state, from the sysctl's value: `on` for any value
/// but `0`, `off` for `0`, `absent` when the kernel has no such sysctl.
#[must_use]
pub fn apparmor_state(value: Option<&str>) -> &'static str {
    match value {
        None => "absent",
        Some("0") => "off",
        Some(_) => "on",
    }
}

/// The AppArmor profile file names worth recording, sorted.
#[must_use]
pub fn apparmor_profile_files<I: IntoIterator<Item = String>>(names: I) -> Vec<String> {
    let mut out: Vec<String> = names
        .into_iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            APPARMOR_PROFILE_WORDS
                .iter()
                .any(|word| lower.contains(word))
        })
        .collect();
    out.sort();
    out
}

/// The lowercase hex SHA-256 of a file's bytes, read in chunks.
///
/// # Errors
/// Any failure opening or reading the file.
pub fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// This binary: the path it runs from and the SHA-256 of the image that is
/// running. On Linux the bytes are read through `/proc/self/exe`, which is
/// the executing inode even if the path has since been replaced.
#[must_use]
pub fn own_binary() -> serde_json::Value {
    let path = std::env::current_exe().ok();
    let image = if cfg!(target_os = "linux") {
        Some(std::path::PathBuf::from("/proc/self/exe"))
    } else {
        path.clone()
    };
    serde_json::json!({
        "path": path.as_ref().map(|path| path.to_string_lossy().into_owned()),
        "sha256": image.and_then(|image| file_sha256(&image).ok()),
    })
}

#[cfg(target_os = "linux")]
pub use self::linux::{bwrap_binary, manifest};

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    use super::{
        APPARMOR_DIR, LINGER_DIR, SYSCTLS, apparmor_profile_files, apparmor_state,
        classify_identity, file_sha256, os_release_pretty_name, sysctl_path,
    };

    fn read_trimmed(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|text| text.trim().to_owned())
    }

    /// The bubblewrap the product resolved (`platform::resolved_bwrap`, an
    /// absolute canonical path): its path, hash and version, or `null` when
    /// the operator's `PATH` provides none. A hash or version that cannot be
    /// read is `null`.
    #[must_use]
    pub fn bwrap_binary(path: Option<&Path>) -> serde_json::Value {
        let Some(path) = path else {
            return serde_json::Value::Null;
        };
        serde_json::json!({
            "path": path.to_string_lossy(),
            "sha256": file_sha256(path).ok(),
            "version": super::super::bwrap::bwrap_version(path).ok().map(|version| version.raw),
        })
    }

    /// The user name of `uid`, from the password database.
    fn user_name(uid: u32) -> Option<std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt as _;
        let mut buffer = vec![0_u8; 16 * 1024];
        // SAFETY: `passwd` is a plain C struct; all-zero is a valid value
        // that getpwuid_r overwrites before it is read.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local, the length is the
        // buffer's own, and getpwuid_r writes only within them.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if rc != 0 || result.is_null() || entry.pw_name.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so pw_name is a NUL-terminated
        // string inside `buffer`, which is still alive.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) };
        Some(std::ffi::OsString::from_vec(name.to_bytes().to_vec()))
    }

    /// Lingering as logind records it; `null` without logind's directory or
    /// a user name to look up.
    fn linger(uid: u32) -> Option<bool> {
        let dir = Path::new(LINGER_DIR);
        if !dir.is_dir() {
            return None;
        }
        let name = user_name(uid)?;
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(meta) => Some(meta.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    }

    fn uname() -> (Option<String>, Option<String>) {
        let mut buffer = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: `uname` fills the caller-provided, correctly sized struct
        // and returns 0 on success; it is read only after that.
        if unsafe { libc::uname(buffer.as_mut_ptr()) } != 0 {
            return (None, None);
        }
        // SAFETY: `uname` returned 0, so every field is initialized.
        let filled = unsafe { buffer.assume_init() };
        let field = |bytes: &[libc::c_char]| -> Option<String> {
            // SAFETY: on success every field is a NUL-terminated string
            // inside its own fixed-size array.
            let text = unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) };
            let text = text.to_string_lossy().trim().to_owned();
            (!text.is_empty()).then_some(text)
        };
        (field(&filled.release), field(&filled.version))
    }

    /// The `host` object of `doctor --json`.
    #[must_use]
    pub fn manifest() -> serde_json::Value {
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let (kernel_release, kernel_version) = uname();
        let distribution = std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .ok()
            .and_then(|text| os_release_pretty_name(&text));
        let sysctls: serde_json::Map<String, serde_json::Value> = SYSCTLS
            .iter()
            .map(|name| ((*name).to_owned(), read_trimmed(&sysctl_path(name)).into()))
            .collect();
        let restriction = read_trimmed(&sysctl_path(SYSCTLS[0]));
        let profile_files = std::fs::read_dir(APPARMOR_DIR).ok().map(|entries| {
            apparmor_profile_files(
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned()),
            )
        });
        let delegated_root = super::super::cgroup::delegated_root(uid);
        let controllers = delegated_root.as_ref().and_then(|root| {
            read_trimmed(&root.join("cgroup.controllers").to_string_lossy()).map(|text| {
                text.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
        });
        let identity = std::fs::read_to_string("/proc/self/status")
            .map_or(super::OperatorIdentity::Unknown, |status| {
                classify_identity(&status)
            });
        serde_json::json!({
            "kernel_release": kernel_release,
            "kernel_version": kernel_version,
            "distribution": distribution,
            "sysctls": sysctls,
            "apparmor_userns_restriction": {
                "state": apparmor_state(restriction.as_deref()),
                "profile_files": profile_files,
            },
            "cgroup": {
                "delegated_root": delegated_root
                    .as_ref()
                    .map(|root| root.to_string_lossy().into_owned()),
                "controllers": controllers,
            },
            "linger": linger(uid),
            "operator_identity": identity.as_str(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNPRIVILEGED: &str = "Name:\tdoctor\nUid:\t1001\t1001\t1001\t1001\n\
        Gid:\t1001\t1001\t1001\t1001\nCapInh:\t0000000000000000\n\
        CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
        CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";

    #[test]
    fn identity_categories_follow_the_credentials() {
        assert_eq!(
            classify_identity(UNPRIVILEGED),
            OperatorIdentity::Unprivileged
        );
        // A full bounding set is every process's; it grants nothing.
        let root = UNPRIVILEGED.replace("Uid:\t1001\t1001", "Uid:\t1001\t0");
        assert_eq!(classify_identity(&root), OperatorIdentity::Root);
        let setuid = UNPRIVILEGED.replace("Uid:\t1001\t1001", "Uid:\t1001\t1002");
        assert_eq!(classify_identity(&setuid), OperatorIdentity::SetId);
        let setgid = UNPRIVILEGED.replace("Gid:\t1001\t1001", "Gid:\t1001\t27");
        assert_eq!(classify_identity(&setgid), OperatorIdentity::SetId);
        for field in ["CapPrm", "CapEff", "CapAmb"] {
            let capable = UNPRIVILEGED.replace(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000200000"),
            );
            assert_eq!(
                classify_identity(&capable),
                OperatorIdentity::Capable,
                "{field}"
            );
        }
        for broken in [
            "",
            "Uid:\t1001\n",
            &UNPRIVILEGED.replace("CapEff:\t0000000000000000\n", ""),
            &UNPRIVILEGED.replace("CapPrm:\t0000000000000000", "CapPrm:\tzz"),
        ] {
            assert_eq!(classify_identity(broken), OperatorIdentity::Unknown);
        }
        assert_eq!(OperatorIdentity::SetId.as_str(), "set_id");
    }

    #[test]
    fn pretty_name_is_unquoted() {
        assert_eq!(
            os_release_pretty_name("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\n")
                .as_deref(),
            Some("Ubuntu 26.04.1 LTS")
        );
        assert_eq!(
            os_release_pretty_name("PRETTY_NAME='Debian GNU/Linux 13'").as_deref(),
            Some("Debian GNU/Linux 13")
        );
        assert_eq!(
            os_release_pretty_name("PRETTY_NAME=Plain").as_deref(),
            Some("Plain")
        );
        assert_eq!(
            os_release_pretty_name(r#"PRETTY_NAME="A \"quoted\" \\ name""#).as_deref(),
            Some(r#"A "quoted" \ name"#)
        );
        assert_eq!(os_release_pretty_name("NAME=x\n"), None);
        assert_eq!(os_release_pretty_name("PRETTY_NAME=\"\""), None);
    }

    #[test]
    fn sysctl_names_map_to_procfs() {
        assert_eq!(
            sysctl_path("kernel.yama.ptrace_scope"),
            "/proc/sys/kernel/yama/ptrace_scope"
        );
        assert_eq!(SYSCTLS.len(), 6);
        assert_eq!(SYSCTLS[0], "kernel.apparmor_restrict_unprivileged_userns");
    }

    #[test]
    fn the_restriction_state_follows_the_sysctl() {
        assert_eq!(apparmor_state(Some("1")), "on");
        assert_eq!(apparmor_state(Some("2")), "on");
        assert_eq!(apparmor_state(Some("0")), "off");
        assert_eq!(apparmor_state(None), "absent");
    }

    #[test]
    fn only_profiles_that_bear_on_the_jail_are_recorded() {
        let names = [
            "usr.bin.firefox",
            "bwrap-userns-restrict",
            "unprivileged_userns",
            "lxc-usernsexec",
            "ouro-jail",
            "glycin.bwrap",
            "abstractions",
        ]
        .map(str::to_owned);
        assert_eq!(
            apparmor_profile_files(names),
            [
                "bwrap-userns-restrict",
                "glycin.bwrap",
                "lxc-usernsexec",
                "ouro-jail",
                "unprivileged_userns"
            ]
        );
    }

    #[test]
    fn a_file_hash_is_its_sha256() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("abc");
        std::fs::write(&path, b"abc").expect("written");
        assert_eq!(
            file_sha256(&path).expect("read"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Bigger than one chunk, so the loop is exercised.
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; 200_000]).expect("written");
        let expected: String = Sha256::digest(vec![b'a'; 200_000])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(file_sha256(&big).expect("read"), expected);
        assert!(file_sha256(&dir.path().join("absent")).is_err());
    }
}
