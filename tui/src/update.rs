//! Explicit self-update for standalone releases. This module never discovers,
//! starts, or stops a runtime and has no production override for its release host.
mod install;
mod transport;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ring::digest::{Context as Digest, SHA256};
use semver::Version;

use install::{hex, Destination, HashWriter};
use transport::{capture, check_cancelled, Curl, BINARY_CAP, MANIFEST_CAP};

const REPOSITORY: &str = "https://github.com/monocursive/ouroboros";
const ELIGIBLE: bool = cfg!(all(official_release, embedded_release, feature = "embed"));

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Current,
    Ahead,
    Available,
    Installed,
}
impl Outcome {
    pub fn exit_code(&self) -> u8 {
        if *self == Self::Available {
            10
        } else {
            0
        }
    }
}

/// Ctrl-C is handled cooperatively so all owned subprocesses are reaped and
/// staging is removed before the command exits. No runtime signal is sent.
pub async fn execute(check: bool, dev: bool) -> Result<Outcome> {
    if !check {
        if dev {
            bail!("`ouro update --dev` cannot replace a development executable; use `ouro update --check`");
        }
        if !ELIGIBLE {
            bail!("this is a local build; rebuild it from source or install an official standalone release. `ouro update --check` is available");
        }
        let (uid, euid, gid, egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        if euid == 0 || uid != euid || gid != egid {
            bail!("run `ouro update` as the user who owns the installation, without sudo or set-ID privileges");
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let mut worker = tokio::task::spawn_blocking(move || {
        let request = Request {
            current: Version::parse(env!("CARGO_PKG_VERSION"))?,
            local: !ELIGIBLE || dev,
            destination: if check {
                None
            } else {
                Some(std::env::current_exe().context("resolving this executable")?)
            },
            target: if check {
                None
            } else {
                Some(native_target(&worker_cancelled)?)
            },
        };
        perform(
            &request,
            &Curl::default(),
            &worker_cancelled,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )
    });
    tokio::select! {
        result = &mut worker => result.context("update worker failed")?,
        _ = tokio::signal::ctrl_c() => {
            cancelled.store(true, Ordering::Relaxed);
            worker.await.context("update worker failed after cancellation")?
        }
    }
}

struct Request {
    current: Version,
    local: bool,
    destination: Option<PathBuf>,
    target: Option<String>,
}

fn perform(
    request: &Request,
    curl: &Curl,
    cancelled: &AtomicBool,
    out: &mut impl Write,
    progress: &mut impl Write,
) -> Result<Outcome> {
    // Snapshot before the network. An updater waiting for discovery must notice
    // another updater winning, including when both were launched from old code.
    let destination = request
        .destination
        .as_deref()
        .map(|p| Destination::inspect(p, cancelled))
        .transpose()?;
    if let Some(destination) = &destination {
        verify_version(&destination.path, &request.current, cancelled)
            .context("installed file differs from this process; rerun the installed command")?;
        writeln!(
            progress,
            "Executable: {}",
            destination.path.display().to_string().escape_debug()
        )?;
    }
    writeln!(progress, "Checking the latest stable Ouroboros release...")?;
    let mut redirect = Vec::new();
    for attempt in 0..3 {
        redirect.clear();
        match curl.get(
            &format!("{REPOSITORY}/releases/latest"),
            true,
            &mut redirect,
            4096,
            cancelled,
        ) {
            Ok(()) => break,
            Err(e) if attempt < 2 && transport::retryable(&e) => continue,
            Err(e) => return Err(e).context("resolving the latest stable release"),
        }
    }
    let latest =
        latest_version(std::str::from_utf8(&redirect).context("release redirect is not UTF-8")?)?;
    let label = if request.local { " (local build)" } else { "" };
    let outcome = match request.current.cmp(&latest) {
        std::cmp::Ordering::Equal => {
            writeln!(
                out,
                "ouro {}{label} is already current (latest stable: {latest})",
                request.current
            )?;
            Outcome::Current
        }
        std::cmp::Ordering::Greater => {
            writeln!(
                out,
                "ouro {}{label} is ahead of latest stable {latest}; no downgrade performed",
                request.current
            )?;
            Outcome::Ahead
        }
        std::cmp::Ordering::Less => {
            if let Some(destination) = destination {
                let target = request
                    .target
                    .as_deref()
                    .context("update target is missing")?;
                let _lock = destination.lock()?;
                destination.revalidate(cancelled)?;
                let asset = format!("ouro-{latest}-{target}");
                let base = format!("{REPOSITORY}/releases/download/v{latest}");
                let mut manifest = Vec::new();
                for attempt in 0..3 {
                    manifest.clear();
                    match curl.get(
                        &format!("{base}/SHA256SUMS"),
                        false,
                        &mut manifest,
                        MANIFEST_CAP,
                        cancelled,
                    ) {
                        Ok(()) => break,
                        Err(e) if attempt < 2 && transport::retryable(&e) => continue,
                        Err(e) => return Err(e).context("downloading release checksums"),
                    }
                }
                let expected = checksum(&manifest, &asset)?;
                writeln!(progress, "Downloading ouro {latest} ({target})...")?;
                let mut stage = destination.stage()?;
                for attempt in 0..3 {
                    let mut writer = HashWriter {
                        writer: stage.reset()?,
                        digest: Digest::new(&SHA256),
                    };
                    match curl.get(
                        &format!("{base}/{asset}"),
                        false,
                        &mut writer,
                        BINARY_CAP,
                        cancelled,
                    ) {
                        Ok(()) => {
                            if hex(writer.digest.finish().as_ref()) != expected {
                                bail!("checksum mismatch; existing installation was not changed");
                            }
                            break;
                        }
                        Err(e) if attempt < 2 && transport::retryable(&e) => continue,
                        Err(e) => {
                            return Err(e).context(
                                "downloading executable; existing installation was not changed",
                            )
                        }
                    }
                }
                check_cancelled(cancelled)?;
                destination.seal(&mut stage)?;
                verify_version(&stage.path, &latest, cancelled).context("verified download cannot run as the selected version; existing installation was not changed")?;
                let warning = destination.commit(&stage, cancelled)?;
                // Every failure after commit says that installation already happened.
                (|| -> Result<()> {
                    writeln!(out, "Updated ouro {} -> {latest}", request.current)?;
                    writeln!(out, "Executable: {}", destination.path.display().to_string().escape_debug())?;
                    writeln!(out, "If a runtime is running, finish active work, run `ouro stop`, then start `ouro` again.")?;
                    if let Some(warning) = warning { writeln!(progress, "Warning: {warning}")?; }
                    Ok(())
                })().context("the new executable is installed, but reporting the result failed")?;
                Outcome::Installed
            } else {
                writeln!(
                    out,
                    "Update available: ouro {}{label} -> {latest}",
                    request.current
                )?;
                if request.local {
                    writeln!(out, "Rebuild from source or install the latest official release; local builds cannot self-update.")?;
                } else {
                    writeln!(out, "Run `ouro update` to install it.")?;
                }
                Outcome::Available
            }
        }
    };
    Ok(outcome)
}

fn latest_version(url: &str) -> Result<Version> {
    let tag = url
        .strip_prefix(&format!("{REPOSITORY}/releases/tag/v"))
        .context("latest release did not resolve to the official repository's stable tag")?;
    let version = Version::parse(tag).context("invalid latest release version")?;
    if !version.pre.is_empty() || !version.build.is_empty() || version.to_string() != tag {
        bail!("latest release must be a stable vX.Y.Z tag");
    }
    Ok(version)
}

fn checksum(manifest: &[u8], asset: &str) -> Result<String> {
    let text = std::str::from_utf8(manifest).context("checksum manifest is not UTF-8")?;
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2
            || fields[0].len() != 64
            || !fields[0]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("invalid SHA256SUMS entry");
        }
        if fields[1] == asset && found.replace(fields[0].to_owned()).is_some() {
            bail!("duplicate checksum for {asset}");
        }
    }
    found.with_context(|| format!("release checksums do not contain {asset}"))
}

fn verify_version(path: &Path, expected: &Version, cancelled: &AtomicBool) -> Result<()> {
    let mut command = Command::new(path);
    command
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    let bytes = capture(command, 4096, Duration::from_secs(15), cancelled)?;
    if bytes != format!("ouro {expected}\n").as_bytes() {
        bail!("executable does not report ouro {expected}");
    }
    Ok(())
}

fn probe(program: &str, args: &[&str], cancelled: &AtomicBool) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args);
    Ok(
        String::from_utf8(capture(command, 4096, Duration::from_secs(5), cancelled)?)?
            .trim()
            .to_owned(),
    )
}

fn native_target(cancelled: &AtomicBool) -> Result<String> {
    let arch = probe("/usr/bin/uname", &["-m"], cancelled)?;
    let (version, rosetta) = if cfg!(target_os = "macos") {
        (
            probe("/usr/bin/sw_vers", &["-productVersion"], cancelled)?,
            arch == "x86_64"
                && probe(
                    "/usr/sbin/sysctl",
                    &["-in", "sysctl.proc_translated"],
                    cancelled,
                )
                .unwrap_or_default()
                    == "1",
        )
    } else if cfg!(all(target_os = "linux", target_env = "gnu")) {
        (
            probe("/usr/bin/getconf", &["GNU_LIBC_VERSION"], cancelled)?,
            false,
        )
    } else {
        bail!("self-update supports macOS and glibc GNU/Linux only");
    };
    select_target(std::env::consts::OS, &arch, &version, rosetta)
}

fn select_target(os: &str, arch: &str, system_version: &str, rosetta: bool) -> Result<String> {
    let arch = match arch {
        "x86_64" | "amd64" if !(os == "macos" && rosetta) => "x86_64",
        "x86_64" | "amd64" | "arm64" | "aarch64" => "aarch64",
        _ => bail!("self-update supports x86-64 and ARM64 only"),
    };
    let os = match os {
        "macos" => {
            let major: u64 = system_version
                .split('.')
                .next()
                .unwrap_or("")
                .parse()
                .context("invalid macOS version")?;
            if major < 15 {
                bail!("release binaries require macOS 15 or newer");
            }
            "apple-darwin"
        }
        "linux" => {
            let version = system_version
                .strip_prefix("glibc ")
                .context("release binaries require glibc GNU/Linux")?;
            let parts: Vec<u64> = version
                .split('.')
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?;
            if parts.len() < 2 || (parts[0], parts[1]) < (2, 39) {
                bail!("release binaries require glibc 2.39 or newer");
            }
            "unknown-linux-gnu"
        }
        _ => bail!("self-update supports macOS and GNU/Linux only"),
    };
    Ok(format!("{arch}-{os}"))
}

#[cfg(test)]
mod tests;
