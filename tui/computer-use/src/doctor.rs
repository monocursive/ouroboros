//! `doctor` (doc §7.1): probe host permissions with no side effects and report what the
//! helper can and cannot do, and what would unblock it.
//!
//! The probe and the report are split so the shaping is pure and testable without any TCC
//! state: [`probe`] reads the host (real on macOS, an honest "unsupported platform"
//! elsewhere), and [`build_report`] turns a [`Probe`] into the response JSON. The same value
//! serves the JSON-RPC `doctor` method ([`report`]) and the `doctor` subcommand
//! ([`report_pretty`]).
//!
//! Honesty notes the report carries:
//!   * Window *enumeration* via `CGWindowList` needs neither Accessibility nor Screen
//!     Recording, so `can_list_windows` stays true even when the accessibility tree is not
//!     available — but window *titles* and pixels do need Screen Recording (doc §7.1).
//!   * `secure_event_input` is a live global flag, not a grant; `can_input` is false while
//!     it is set even with Accessibility granted (Δ6).

use serde_json::{json, Value};

/// The raw readings a report is built from. Kept separate from the host so the shaping can be
/// tested for every combination without granting or revoking anything.
struct Probe {
    /// False on non-macOS builds: there is no helper capability to report.
    supported: bool,
    os: &'static str,
    arch: &'static str,
    screen_recording: bool,
    accessibility: bool,
    /// True means secure keyboard entry is ON somewhere, which *blocks* input.
    secure_event_input: bool,
}

/// The `doctor` response object, ready to be a JSON-RPC `result` or printed for an operator.
pub fn report() -> Value {
    build_report(&probe())
}

/// The `doctor` subcommand's output: the same object, pretty-printed for a human reading
/// `ouro desktop doctor`.
pub fn report_pretty() -> String {
    serde_json::to_string_pretty(&report()).unwrap_or_else(|_| {
        // Serializing a value we built ourselves cannot fail in practice; if it somehow did,
        // say so rather than print nothing.
        r#"{"error":"doctor report could not be encoded"}"#.to_string()
    })
}

#[cfg(target_os = "macos")]
fn probe() -> Probe {
    Probe {
        supported: true,
        os: "macos",
        arch: arch(),
        screen_recording: crate::macos::screen_recording_granted(),
        accessibility: crate::macos::accessibility_trusted(),
        secure_event_input: crate::macos::secure_event_input_enabled(),
    }
}

#[cfg(not(target_os = "macos"))]
fn probe() -> Probe {
    Probe {
        supported: false,
        os: std::env::consts::OS,
        arch: arch(),
        screen_recording: false,
        accessibility: false,
        secure_event_input: false,
    }
}

/// The contract shows `arm64`, which is Apple's name for what Rust calls `aarch64`.
fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    }
}

fn build_report(probe: &Probe) -> Value {
    if !probe.supported {
        return json!({
            "platform": { "os": probe.os, "arch": probe.arch },
            "permissions": {
                "screen_recording": { "ok": false, "detail": "unsupported platform" },
                "accessibility": { "ok": false, "detail": "unsupported platform" },
                "secure_event_input": { "enabled": false, "detail": "unsupported platform" }
            },
            "readiness": {
                "can_screenshot": false,
                "can_ax_tree": false,
                "can_list_windows": false,
                "can_focus_windows": false,
                "can_input": false,
                "recommended_next_step": "Computer Use is only supported on macOS.",
                "blockers": ["unsupported_platform"],
                "notes": []
            }
        });
    }

    let screen = probe.screen_recording;
    let ax = probe.accessibility;
    let secure = probe.secure_event_input;

    // Input needs Accessibility AND an absence of global secure keyboard entry.
    let can_input = ax && !secure;

    let mut blockers: Vec<&str> = Vec::new();
    if !screen {
        blockers.push("screen_recording");
    }
    if !ax {
        blockers.push("accessibility");
    }
    if secure {
        blockers.push("secure_event_input");
    }

    // Screen Recording is the widest gate, so it is named first; then Accessibility; then the
    // transient secure-input state. Phase 3 will refine the exact System Settings copy.
    let recommended_next_step = if !screen {
        "Grant Screen Recording to ouro-computer-use in System Settings → Privacy & Security → \
         Screen Recording, then relaunch it."
    } else if !ax {
        "Grant Accessibility to ouro-computer-use in System Settings → Privacy & Security → \
         Accessibility."
    } else if secure {
        "A secure keyboard-entry app (a password field or a terminal with secure input) is \
         active; typing and key presses are blocked until it releases secure input."
    } else {
        "Ready: Screen Recording and Accessibility are granted and secure input is off."
    };

    let mut notes: Vec<&str> = Vec::new();
    if !ax {
        notes.push(
            "Window enumeration via CGWindowList does not require Accessibility; the \
             accessibility tree and reliable input do.",
        );
    }
    if !screen {
        notes.push("Window titles and pixels require Screen Recording; bare enumeration does not.");
    }

    json!({
        "platform": { "os": probe.os, "arch": probe.arch },
        "permissions": {
            "screen_recording": { "ok": screen, "detail": if screen { "granted" } else { "not granted" } },
            "accessibility": { "ok": ax, "detail": if ax { "granted" } else { "not granted" } },
            "secure_event_input": { "enabled": secure, "detail": if secure { "enabled" } else { "disabled" } }
        },
        "readiness": {
            "can_screenshot": screen,
            "can_ax_tree": ax,
            // CGWindowList enumeration is available without any grant on macOS.
            "can_list_windows": true,
            // App activation does not require Accessibility (per-window focus, in Phase 1, does).
            "can_focus_windows": true,
            "can_input": can_input,
            "recommended_next_step": recommended_next_step,
            "blockers": blockers,
            "notes": notes
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macos(screen: bool, accessibility: bool, secure: bool) -> Probe {
        Probe {
            supported: true,
            os: "macos",
            arch: "arm64",
            screen_recording: screen,
            accessibility,
            secure_event_input: secure,
        }
    }

    #[test]
    fn all_granted_is_ready() {
        let report = build_report(&macos(true, true, false));
        let readiness = &report["readiness"];

        assert_eq!(readiness["can_screenshot"], true);
        assert_eq!(readiness["can_ax_tree"], true);
        assert_eq!(readiness["can_input"], true);
        assert_eq!(readiness["blockers"], json!([]));
        assert!(readiness["recommended_next_step"]
            .as_str()
            .unwrap()
            .starts_with("Ready"));
    }

    #[test]
    fn missing_accessibility_blocks_tree_and_input_but_not_listing() {
        let report = build_report(&macos(true, false, false));
        let readiness = &report["readiness"];

        assert_eq!(readiness["can_screenshot"], true);
        assert_eq!(readiness["can_ax_tree"], false);
        assert_eq!(readiness["can_input"], false);
        // The doc's key honesty: listing survives without Accessibility.
        assert_eq!(readiness["can_list_windows"], true);
        assert_eq!(readiness["can_focus_windows"], true);
        assert_eq!(readiness["blockers"], json!(["accessibility"]));
        assert!(readiness["recommended_next_step"]
            .as_str()
            .unwrap()
            .contains("Accessibility"));
    }

    #[test]
    fn secure_input_blocks_input_even_with_accessibility() {
        let report = build_report(&macos(true, true, true));
        let readiness = &report["readiness"];

        assert_eq!(readiness["can_input"], false);
        assert_eq!(report["permissions"]["secure_event_input"]["enabled"], true);
        assert_eq!(readiness["blockers"], json!(["secure_event_input"]));
    }

    #[test]
    fn screen_recording_is_named_first_when_missing() {
        let report = build_report(&macos(false, false, false));
        let readiness = &report["readiness"];

        assert_eq!(
            readiness["blockers"],
            json!(["screen_recording", "accessibility"])
        );
        assert!(readiness["recommended_next_step"]
            .as_str()
            .unwrap()
            .contains("Screen Recording"));
    }

    #[test]
    fn unsupported_platform_is_honest() {
        let probe = Probe {
            supported: false,
            os: "linux",
            arch: "x86_64",
            screen_recording: false,
            accessibility: false,
            secure_event_input: false,
        };
        let report = build_report(&probe);

        assert_eq!(report["platform"]["os"], "linux");
        assert_eq!(
            report["readiness"]["blockers"],
            json!(["unsupported_platform"])
        );
        assert_eq!(report["readiness"]["can_screenshot"], false);
        assert_eq!(
            report["permissions"]["screen_recording"]["detail"],
            "unsupported platform"
        );
    }
}
