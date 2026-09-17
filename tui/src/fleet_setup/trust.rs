//! Host-key verification: the private store, the scan, and the one decision an
//! operator has to make in person.
//!
//! Seam S7 and the proposal's "SSH methods and host verification". Strict host checking
//! is never turned off; `ssh` is always told to refuse an unknown host. What this module
//! does is the step *before* that: it asks the destination what keys it has, shows their
//! algorithms and SHA256 fingerprints beside the peer, address, port and account, and —
//! only on an explicit accept — appends the scanned line to a private deployment-host
//! store that `ssh` is then pointed at. A destination whose keys are all different from
//! the ones a store already trusts is [`Trust::Changed`], which blocks; the proposal
//! requires a separate verified repair rather than an override.
//!
//! Discovery is not host-key authentication, and `--yes` does not accept an unknown key.
//! Both facts live at the call site in [`super::engine`]; this module only reports.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};

use super::{refuse, sanitize_remote_text};

/// `ssh-keyscan` is given five seconds, the same bound seam S7 states.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// The key types offered, in `ssh-keyscan`'s own order of preference.
pub const SCAN_TYPES: &str = "ed25519,ecdsa,rsa";

/// Where the two programs live. Overridable so a test can point at a shim without
/// changing what production does.
#[derive(Clone, Debug)]
pub struct Tools {
    pub keyscan: PathBuf,
    pub keygen: PathBuf,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            keyscan: PathBuf::from("ssh-keyscan"),
            keygen: PathBuf::from("ssh-keygen"),
        }
    }
}

/// One host key a destination presented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedKey {
    pub algorithm: String,
    /// The base64 blob, which is what identifies the key.
    pub key: String,
    /// The exact `known_hosts` line, appended verbatim on accept.
    pub line: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

/// What the stores say about this destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Trust {
    /// A store marks one of the keys this destination presented `@revoked`. The
    /// strongest statement a `known_hosts` file can make about a key, and the one that
    /// must never be read as trust.
    Revoked {
        algorithm: String,
        fingerprint: String,
    },
    /// A store already holds one of the keys this destination presented.
    Known {
        algorithm: String,
        fingerprint: String,
    },
    /// No store holds any key for this destination.
    Unknown { keys: Vec<ScannedKey> },
    /// A store holds keys for this destination and none of them is one it presented.
    Changed {
        stored: Vec<String>,
        presented: Vec<ScannedKey>,
    },
}

/// `host:port` in the form `known_hosts` and `ssh-keyscan` both write.
pub fn host_spec(address: &str, port: u16) -> String {
    if port == 22 {
        address.to_string()
    } else {
        format!("[{address}]:{port}")
    }
}

/// Ask the destination for its host keys, and compare them with every store.
///
/// `stores` is the private deployment store first and the user's own file second, which
/// is the order seam S7 hands to `UserKnownHostsFile`. A missing store is not an error:
/// a deployment host that has never trusted anything has no private store yet.
pub fn examine(
    tools: &Tools,
    stores: &[PathBuf],
    address: &str,
    port: u16,
    scratch: &Path,
) -> Result<Trust> {
    let presented = scan(tools, address, port, scratch)?;
    if presented.is_empty() {
        return refuse(
            "host_scan_failed",
            format!(
                "{address} port {port} did not answer a host key scan; check that its SSH server is running and reachable on the private network"
            ),
        );
    }

    let spec = host_spec(address, port);
    let mut stored = Vec::new();
    for store in stores {
        stored.extend(stored_entries(tools, store, &spec)?);
    }
    Ok(decide(stored, presented))
}

/// What a set of stored entries says about the keys a destination presented.
///
/// Split out so the decision can be tested without a server: it is the whole of what
/// "does this machine trust this host?" means.
fn decide(stored: Vec<StoredEntry>, presented: Vec<ScannedKey>) -> Trust {
    // Revocation is checked first and against every presented key: a store that both
    // trusts and revokes a key has revoked it.
    for key in &presented {
        if stored.iter().any(|entry| {
            entry.marker.as_deref() == Some("@revoked")
                && entry.algorithm == key.algorithm
                && entry.key == key.key
        }) {
            return Trust::Revoked {
                algorithm: key.algorithm.clone(),
                fingerprint: key.fingerprint.clone(),
            };
        }
    }
    // `@cert-authority` names a CA that may *sign* host keys; it is not itself a key
    // this destination could present, and reading it as one would call an unknown host
    // known.
    let stored: Vec<StoredEntry> = stored
        .into_iter()
        .filter(|entry| entry.marker.is_none())
        .collect();
    if stored.is_empty() {
        return Trust::Unknown { keys: presented };
    }
    for key in &presented {
        if stored
            .iter()
            .any(|entry| entry.algorithm == key.algorithm && entry.key == key.key)
        {
            return Trust::Known {
                algorithm: key.algorithm.clone(),
                fingerprint: key.fingerprint.clone(),
            };
        }
    }
    Trust::Changed {
        stored: stored.into_iter().map(|entry| entry.algorithm).collect(),
        presented,
    }
}

/// Append an accepted key to the private store, creating it at 0600.
///
/// Only ever the private store: the proposal says to record explicitly accepted trust
/// on the deployment host, and rewriting the operator's own `~/.ssh/known_hosts` is not
/// this command's business.
pub fn accept(store: &Path, key: &ScannedKey) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = store.parent() {
        super::ensure_private_subdir(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(store)
        .with_context(|| format!("opening the private host key store {}", store.display()))?;
    writeln!(file, "{}", key.line)
        .with_context(|| format!("recording trust in {}", store.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", store.display()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredEntry {
    algorithm: String,
    key: String,
    /// `@revoked` or `@cert-authority`, when the line carried one. Stripping it and
    /// reading the rest as an ordinary entry turns a revocation into trust.
    marker: Option<String>,
}

/// `ssh-keygen -F <spec> -f <store>` prints the matching entries, and understands a
/// hashed store — which the operator's own file usually is, so parsing it by hand would
/// silently find nothing and call a known host unknown.
fn stored_entries(tools: &Tools, store: &Path, spec: &str) -> Result<Vec<StoredEntry>> {
    if !store
        .try_exists()
        .with_context(|| format!("inspecting {}", store.display()))?
    {
        return Ok(Vec::new());
    }
    let mut command = Command::new(&tools.keygen);
    command
        .arg("-F")
        .arg(spec)
        .arg("-f")
        .arg(store)
        .stdin(Stdio::null())
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE");
    let output = crate::subprocess::output(command, SCAN_TIMEOUT, || false)
        .with_context(|| format!("searching {} for {spec}", store.display()))?;
    // Exit 1 is "not found", which is an answer. Anything else is a broken store and
    // the caller must not conclude "unknown" from it.
    match output.status.code() {
        Some(0) => {}
        Some(1) => return Ok(Vec::new()),
        other => {
            return refuse(
                "host_store_unreadable",
                format!(
                    "ssh-keygen could not search {} (exit {}): {}",
                    store.display(),
                    other
                        .map(|code| code.to_string())
                        .unwrap_or("signal".into()),
                    sanitize_remote_text(&String::from_utf8_lossy(&output.stderr), 200)
                ),
            )
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_known_hosts_line)
        .collect())
}

fn parse_known_hosts_line(line: &str) -> Option<StoredEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace().peekable();
    // A marker line (`@cert-authority`, `@revoked`) puts one extra field in front of
    // the host patterns, shifting everything after it by one. It is *kept*: what the
    // marker says is the whole meaning of the line.
    let marker = fields
        .peek()
        .filter(|first| first.starts_with('@'))
        .map(|first| first.to_ascii_lowercase());
    if marker.is_some() {
        fields.next();
    }
    let _hosts = fields.next()?;
    let algorithm = fields.next()?;
    let key = fields.next()?;
    Some(StoredEntry {
        algorithm: algorithm.to_string(),
        key: key.to_string(),
        marker,
    })
}

/// Run `ssh-keyscan` and turn each line into a key with its fingerprint.
fn scan(tools: &Tools, address: &str, port: u16, scratch: &Path) -> Result<Vec<ScannedKey>> {
    let mut command = Command::new(&tools.keyscan);
    command
        .arg("-T")
        .arg("5")
        .arg("-t")
        .arg(SCAN_TYPES)
        .arg("-p")
        .arg(port.to_string())
        .arg(address)
        .stdin(Stdio::null())
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE");
    let output = crate::subprocess::output(command, SCAN_TIMEOUT, || false)
        .with_context(|| format!("scanning {address} port {port} for host keys"))?;

    let mut keys = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(entry) = parse_known_hosts_line(line) else {
            continue;
        };
        let fingerprint = fingerprint_of(tools, line, scratch)?;
        keys.push(ScannedKey {
            algorithm: entry.algorithm,
            key: entry.key,
            line: line.trim().to_string(),
            fingerprint,
        });
    }
    Ok(keys)
}

/// `ssh-keygen -lf` refuses a pipe for a `known_hosts` line, so the line goes through a
/// private file in the operation's own scratch directory.
fn fingerprint_of(tools: &Tools, line: &str, scratch: &Path) -> Result<String> {
    super::ensure_private_subdir(scratch)?;
    let path = scratch.join(format!("hostkey-{}.pub", super::random_hex(6)?));
    super::write_private_atomic(&path, format!("{line}\n").as_bytes())?;
    let mut command = Command::new(&tools.keygen);
    command
        .arg("-l")
        .arg("-f")
        .arg(&path)
        .stdin(Stdio::null())
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE");
    let output = crate::subprocess::output(command, SCAN_TIMEOUT, || false);
    let _ = std::fs::remove_file(&path);
    let output = output.context("computing a host key fingerprint")?;
    if !output.status.success() {
        return refuse(
            "host_scan_failed",
            format!(
                "ssh-keygen could not fingerprint a scanned host key: {}",
                sanitize_remote_text(&String::from_utf8_lossy(&output.stderr), 200)
            ),
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or_else(|| {
            super::SetupError {
                reason: "host_scan_failed",
                detail: "ssh-keygen printed no SHA256 fingerprint for a scanned host key".into(),
            }
            .into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec a store is searched with is the one `ssh-keyscan` writes, which is why
    /// port 22 is bare and every other port is bracketed.
    #[test]
    fn a_host_spec_matches_what_known_hosts_holds() {
        assert_eq!(host_spec("100.64.0.2", 22), "100.64.0.2");
        assert_eq!(host_spec("100.64.0.2", 2222), "[100.64.0.2]:2222");
    }

    /// Entry parsing has to survive comments, markers and hashed host fields, because
    /// the operator's own file contains all three.
    #[test]
    fn known_hosts_lines_are_parsed_including_markers_and_hashed_hosts() {
        assert!(parse_known_hosts_line("# a comment").is_none());
        assert!(parse_known_hosts_line("   ").is_none());

        let plain =
            parse_known_hosts_line("[127.0.0.1]:22 ssh-ed25519 AAAAC3blob").expect("an entry");
        assert_eq!(plain.algorithm, "ssh-ed25519");
        assert_eq!(plain.key, "AAAAC3blob");

        let hashed = parse_known_hosts_line("|1|abc=|def= ssh-rsa AAAAB3blob comment")
            .expect("a hashed entry");
        assert_eq!(hashed.algorithm, "ssh-rsa");
        assert_eq!(hashed.key, "AAAAB3blob");

        // The marker is the meaning of the line, so it is carried rather than stripped.
        let revoked =
            parse_known_hosts_line("@revoked host ssh-ed25519 AAAAC3blob").expect("a marker entry");
        assert_eq!(revoked.algorithm, "ssh-ed25519");
        assert_eq!(revoked.key, "AAAAC3blob");
        assert_eq!(revoked.marker.as_deref(), Some("@revoked"));

        let authority =
            parse_known_hosts_line("@cert-authority * ssh-rsa AAAAB3ca").expect("a CA entry");
        assert_eq!(authority.marker.as_deref(), Some("@cert-authority"));
    }

    /// A revoked key is not a trusted key, and a CA entry is not a host key. Both read
    /// as trust while the marker was stripped and forgotten.
    #[test]
    fn a_marker_decides_what_a_stored_entry_means() {
        let presented = vec![ScannedKey {
            algorithm: "ssh-ed25519".into(),
            key: "AAAAC3blob".into(),
            line: "[127.0.0.1]:22 ssh-ed25519 AAAAC3blob".into(),
            fingerprint: "SHA256:abc".into(),
        }];
        let entry = |algorithm: &str, key: &str, marker: Option<&str>| StoredEntry {
            algorithm: algorithm.into(),
            key: key.into(),
            marker: marker.map(str::to_string),
        };

        assert!(matches!(
            decide(
                vec![entry("ssh-ed25519", "AAAAC3blob", Some("@revoked"))],
                presented.clone()
            ),
            Trust::Revoked { .. }
        ));
        assert!(
            matches!(
                decide(
                    vec![entry("ssh-ed25519", "AAAAC3blob", Some("@cert-authority"))],
                    presented.clone()
                ),
                Trust::Unknown { .. }
            ),
            "a CA entry says nothing about this host's own key"
        );
        // Both at once: revoked wins.
        assert!(matches!(
            decide(
                vec![
                    entry("ssh-ed25519", "AAAAC3blob", None),
                    entry("ssh-ed25519", "AAAAC3blob", Some("@revoked")),
                ],
                presented.clone()
            ),
            Trust::Revoked { .. }
        ));
        assert!(matches!(
            decide(
                vec![entry("ssh-ed25519", "AAAAC3blob", None)],
                presented.clone()
            ),
            Trust::Known { .. }
        ));
        assert!(
            matches!(
                decide(vec![entry("ssh-rsa", "AAAAB3other", None)], presented),
                Trust::Changed { .. }
            ),
            "a different key of a different type is a changed host, not an unknown one"
        );
    }
}
