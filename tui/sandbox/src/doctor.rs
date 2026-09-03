//! `ouro-sandbox doctor` — what this kernel can actually enforce, as JSON.
//!
//! The daemon runs this once per node and caches it, the same way it runs `bwrap
//! --version`. It is the reason the Elixir side can put this helper *ahead* of bubblewrap
//! in the detection order without guessing: a helper binary that exists but sits on a
//! kernel without Landlock reports `"usable": false` and the daemon falls through to
//! bubblewrap instead of selecting a backend that would refuse every command.
//!
//! The probe is destructive to the process that runs it — it really does create a user
//! namespace, because the only honest way to answer "can this process unshare" is to try.
//! That is safe precisely because `doctor` prints and exits.

use serde_json::{json, Value};

/// What this *binary* can express, as against what this kernel can enforce.
///
/// The daemon reads it to answer one question — `Sandbox.fences_reads?/1` — and the reason
/// it is asked of the binary rather than assumed from the backend's name is upgrade skew:
/// an `ouro-sandbox` installed before W17 speaks the same protocol version, applies the
/// same policies, and silently has no read allow-set. A node that assumed the feature from
/// the name would run a build under a fence that helper does not have. So the capability
/// travels with the binary, and a report without it is a helper that does not claim it.
fn features() -> Value {
    json!({ "read_allow_set": true })
}

/// Runs the probe and returns the report.
pub fn report() -> Value {
    #[cfg(target_os = "linux")]
    {
        linux_report()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let os = std::env::consts::OS;
        json!({
            "helper": "ouro-sandbox",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": crate::request::PROTOCOL_VERSION,
            "os": os,
            "features": features(),
            "usable": false,
            "notes": format!(
                "ouro-sandbox enforces with Linux user namespaces, Landlock, and seccomp; \
                 on {os} there is nothing for it to do. This build exists so the portable \
                 policy core is compiled and tested here, not so it can sandbox anything."
            ),
        })
    }
}

#[cfg(target_os = "linux")]
fn linux_report() -> Value {
    use crate::linux;

    let abi = linux::landlock_abi();
    let kernel = linux::kernel_release();

    // Deliberately last: it leaves this process inside a new user namespace.
    let (user_mount, net) = linux::probe_namespaces();

    let usable = abi.is_some() && user_mount && crate::seccomp::ARCH_KNOWN;

    let notes = match (abi, user_mount) {
        (None, _) => "no Landlock on this kernel (needs 5.13 or newer)".to_string(),
        (Some(_), false) => "unprivileged user namespaces are unavailable: the kernel or an \
                             enclosing container policy refuses unshare(CLONE_NEWUSER)"
            .to_string(),
        (Some(abi), true) => format!(
            "Landlock ABI {abi}, user and mount namespaces, seccomp belt{}",
            if net {
                ""
            } else {
                "; no network namespace, so a network-denied policy cannot be enforced"
            }
        ),
    };

    json!({
        "helper": "ouro-sandbox",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": crate::request::PROTOCOL_VERSION,
        "os": "linux",
        "features": features(),
        "kernel": kernel,
        "landlock": {
            "available": abi.is_some(),
            "abi": abi,
        },
        "namespaces": {
            "user_mount": user_mount,
            "net": net,
        },
        "seccomp": {
            "arch_known": crate::seccomp::ARCH_KNOWN,
        },
        "usable": usable,
        "notes": notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_always_carries_the_fields_the_daemon_reads() {
        // `doctor` is a contract with `Ouroboros.Provider.Native.Sandbox.Helper`, which
        // keys its whole detection decision on `usable`. A report missing it would make
        // the daemon fall back silently.
        let report = report();
        assert_eq!(report["helper"], "ouro-sandbox");
        assert!(report["usable"].is_boolean());
        assert!(report["notes"].is_string());
        assert!(report["version"].is_string());
        assert_eq!(report["protocol"], crate::request::PROTOCOL_VERSION);
    }

    #[test]
    fn the_report_states_the_read_allow_set_on_every_platform() {
        // `Sandbox.Helper.probe/1` reads exactly this key and `Sandbox.fences_reads?/1`
        // keys the forge's whole backend choice on it, so a build of this helper that
        // stopped reporting it would be a node that stops forging rather than a node that
        // forges under a fence it does not have.
        assert_eq!(report()["features"]["read_allow_set"], true);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_non_linux_build_reports_itself_unusable_rather_than_pretending() {
        assert_eq!(report()["usable"], false);
    }
}
