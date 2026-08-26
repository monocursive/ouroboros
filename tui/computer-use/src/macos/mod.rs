//! The macOS host layer (doc §13): permission probes for `doctor`, plus the Phase-1 observe
//! backends split into [`windows`] (CGWindowList enumeration), [`capture`] (ScreenCaptureKit),
//! and [`ax`] (AXUIElement walk). Input (`macos::input`) is Phase 2 and absent here.
//!
//! This module root holds the probes and a handful of FFI helpers the backends share
//! (NSString/NSError conversion, an attribute-name interner, the send-across-a-completion-block
//! pointer wrapper). The backends themselves keep the objc2 calls; the probes stay raw
//! `#[link]` FFI because reading TCC state needs nothing from objc2.
//!
//! Every probe is a "preflight"/query form chosen precisely because it does **not** trigger a
//! TCC authorization dialog (doc §7.1: "No side effects. Does not prompt TCC on its own"):
//!   * [`CGPreflightScreenCaptureAccess`] reads Screen Recording state; the `Request` form
//!     would prompt.
//!   * [`AXIsProcessTrusted`] reads Accessibility trust; `AXIsProcessTrustedWithOptions`
//!     with the prompt option would prompt.
//!   * [`IsSecureEventInputEnabled`] reads a global flag (Δ6): whether some app has secure
//!     keyboard entry on, which will defeat synthetic `type`/`key` in Phase 2.

#![allow(non_snake_case)]

pub mod ax;
pub mod capture;
pub mod windows;

use objc2_core_foundation::{CFRetained, CFString};
use objc2_foundation::{NSError, NSString};

/// A raw pointer that a completion block, running on ScreenCaptureKit's own queue, hands back
/// to the waiting request thread. The Objective-C objects it points at are reference-counted
/// and thread-safe to use once retained; the pointer itself is not `Send`, so this wrapper
/// carries it across the channel. Callers retain the object before sending and reclaim
/// ownership (`Retained::from_raw` / `CFRetained::from_raw`) on the far side.
pub(crate) struct SendPtr(pub *mut std::ffi::c_void);

// SAFETY: the pointee is a retained, thread-safe CoreFoundation/Objective-C object (an
// `SCShareableContent`); moving the raw pointer to the request thread and reconstructing an
// owning handle there is sound because the +1 retain done before the send keeps it alive.
unsafe impl Send for SendPtr {}

/// A `CFString` for a stable, well-known attribute/key name (e.g. `"AXRole"`). objc2's
/// `application-services` bindings do not re-export the `kAX*Attribute` string constants, and
/// these names are documented and frozen, so building the `CFString` from the literal is both
/// correct and the only option.
pub(crate) fn cfstr(name: &'static str) -> CFRetained<CFString> {
    CFString::from_static_str(name)
}

/// An `NSString`'s contents as a Rust `String` (objc2's `NSString` renders through `Display`).
pub(crate) fn nsstring(s: &NSString) -> String {
    s.to_string()
}

/// A human-readable message for an `NSError` from a ScreenCaptureKit completion handler.
pub(crate) fn nserror_message(err: &NSError) -> String {
    let description = err.localizedDescription();
    format!("{} (code {})", nsstring(&description), err.code())
}

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
