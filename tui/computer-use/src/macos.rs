//! macOS permission probes for `doctor` — three host calls, none of which may prompt.
//!
//! Phase 1 will grow this into `macos/{capture,ax,input,windows}` (doc §13). Phase 0 needs
//! only to *read* the TCC state, so it is a single module of framework FFI: no objc2, no
//! ScreenCaptureKit, no crate dependency at all.
//!
//! Every function here is a "preflight"/query form chosen precisely because it does **not**
//! trigger a TCC authorization dialog (doc §7.1: "No side effects. Does not prompt TCC on
//! its own"):
//!   * [`CGPreflightScreenCaptureAccess`] reads Screen Recording state; the `Request` form
//!     would prompt.
//!   * [`AXIsProcessTrusted`] reads Accessibility trust; `AXIsProcessTrustedWithOptions`
//!     with the prompt option would prompt.
//!   * [`IsSecureEventInputEnabled`] reads a global flag (Δ6): whether some app has secure
//!     keyboard entry on, which will defeat synthetic `type`/`key` in Phase 1.

#![allow(non_snake_case)]

/// Carbon's `Boolean` is an unsigned char; any non-zero value is true.
type Boolean = std::os::raw::c_uchar;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    /// Whether this process already holds Screen Recording authorization. Preflight only —
    /// it never shows the TCC prompt (`CGRequestScreenCaptureAccess` is the one that does).
    fn CGPreflightScreenCaptureAccess() -> bool;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    /// Whether this process is a trusted Accessibility client. The no-argument form never
    /// prompts; `AXIsProcessTrustedWithOptions({prompt: true})` is the one that would.
    fn AXIsProcessTrusted() -> Boolean;
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    /// Whether secure keyboard entry is enabled anywhere on the system right now (a focused
    /// password field, a terminal with secure input on). Read-only global state; no prompt.
    fn IsSecureEventInputEnabled() -> Boolean;
}

/// Screen Recording granted to this binary (governs `screenshot`).
pub fn screen_recording_granted() -> bool {
    // SAFETY: a nullary C predicate with no arguments and no side effects.
    unsafe { CGPreflightScreenCaptureAccess() }
}

/// Accessibility trust for this binary (governs the AX tree and reliable input).
pub fn accessibility_trusted() -> bool {
    // SAFETY: a nullary C predicate with no arguments and no side effects.
    unsafe { AXIsProcessTrusted() != 0 }
}

/// Global secure keyboard entry (Δ6). When true, Phase 1 must refuse `type`/`key`.
pub fn secure_event_input_enabled() -> bool {
    // SAFETY: a nullary C predicate reading a global flag; no arguments, no side effects.
    unsafe { IsSecureEventInputEnabled() != 0 }
}
