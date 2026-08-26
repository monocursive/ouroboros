//! Window enumeration via `CGWindowList` (doc §7.2) — the macOS backend for the `windows`
//! method (whose JSON shaping lives in [`crate::windows`]).
//!
//! `CGWindowListCopyWindowInfo` needs neither Accessibility nor Screen Recording (doc §7.1,
//! confirmed by `doctor`), so `windows` works with no TCC grant — although window *titles* are
//! only populated once Screen Recording is granted, which is honest: a bare enumeration sees
//! geometry and ownership but not the on-screen text. Bundle ids come from
//! `NSRunningApplication`, which is process metadata and also grant-free.
//!
//! This is the only place raw CoreFoundation dictionary reads happen; the values in a
//! `CGWindowList` info dict have a fixed, documented schema, so the concrete-type casts below
//! are sound for that schema.

use std::ffi::c_void;

use objc2_app_kit::NSRunningApplication;
use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFNumberType, CFString, CGRect};
use objc2_core_graphics::{
    kCGWindowBounds, kCGWindowIsOnscreen, kCGWindowLayer, kCGWindowName, kCGWindowNumber,
    kCGWindowOwnerName, kCGWindowOwnerPID, CGRectMakeWithDictionaryRepresentation,
    CGWindowListCopyWindowInfo, CGWindowListOption,
};

use crate::geometry::Rect;
use crate::windows::RawWindow;

/// Enumerates on-screen windows in the window server's front-to-back z-order.
///
/// `kCGWindowListOptionOnScreenOnly` guarantees the front-to-back ordering the focus heuristic
/// relies on; `kCGWindowListExcludeDesktopElements` drops the desktop icons layer.
pub fn enumerate() -> Result<Vec<RawWindow>, String> {
    let option =
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements;

    // SAFETY: a documented CoreGraphics call; `kCGNullWindowID` (0) means "relative to no
    // window". Returns a +1 CFArray or None.
    let info = CGWindowListCopyWindowInfo(option, 0)
        .ok_or_else(|| "CGWindowListCopyWindowInfo returned no window list".to_string())?;

    let count = info.count();
    let mut windows = Vec::with_capacity(count.max(0) as usize);

    for i in 0..count {
        // SAFETY: `i` is in `0..count`; each element is a `CFDictionaryRef` per the API's
        // contract. The pointer is borrowed (Get rule), valid while `info` lives.
        let dict = unsafe {
            let ptr = info.value_at_index(i);
            if ptr.is_null() {
                continue;
            }
            &*(ptr as *const CFDictionary)
        };

        if let Some(window) = read_window(dict) {
            windows.push(window);
        }
    }

    Ok(windows)
}

fn read_window(dict: &CFDictionary) -> Option<RawWindow> {
    let window_id = number_i64(dict, unsafe { kCGWindowNumber })? as u32;
    let pid = number_i64(dict, unsafe { kCGWindowOwnerPID })? as i32;
    let layer = number_i64(dict, unsafe { kCGWindowLayer }).unwrap_or(0);
    let app_name = string_value(dict, unsafe { kCGWindowOwnerName });
    // Title needs Screen Recording; without it the key is absent or empty, which stays `None`.
    let title = string_value(dict, unsafe { kCGWindowName }).filter(|t| !t.is_empty());
    let on_screen = boolean_value(dict, unsafe { kCGWindowIsOnscreen }).unwrap_or(true);
    let bounds = rect_value(dict, unsafe { kCGWindowBounds })?;
    let app_id = bundle_id_for_pid(pid);

    Some(RawWindow {
        window_id,
        pid,
        app_id,
        app_name,
        title,
        layer,
        bounds,
        on_screen,
    })
}

/// The bundle id for a pid, via `NSRunningApplication` (grant-free process metadata). `None`
/// for a process with no bundle (a bare executable) or that has since exited.
fn bundle_id_for_pid(pid: i32) -> Option<String> {
    let app = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)?;
    app.bundleIdentifier().map(|id| id.to_string())
}

// --- typed reads over a fixed-schema CoreFoundation dictionary ---

/// The borrowed value for `key`, or `None` if absent. The returned pointer follows the Get
/// rule (borrowed, valid while `dict` lives).
fn dict_get(dict: &CFDictionary, key: &CFString) -> Option<*const c_void> {
    // SAFETY: `key` is a valid CFString; `CFDictionaryGetValue` returns a borrowed value or
    // null. The pointer is only dereferenced by the concrete-type readers below, each of which
    // knows the value's type from the `CGWindowList` schema.
    let value = unsafe { dict.value(key as *const CFString as *const c_void) };
    (!value.is_null()).then_some(value)
}

fn number_i64(dict: &CFDictionary, key: &CFString) -> Option<i64> {
    let value = dict_get(dict, key)?;
    let mut out: i64 = 0;
    // SAFETY: schema guarantees a CFNumber here; reading it as a 64-bit int is always valid.
    let ok = unsafe {
        let number = &*(value as *const CFNumber);
        number.value(
            CFNumberType::SInt64Type,
            &mut out as *mut i64 as *mut c_void,
        )
    };
    ok.then_some(out)
}

fn string_value(dict: &CFDictionary, key: &CFString) -> Option<String> {
    let value = dict_get(dict, key)?;
    // SAFETY: schema guarantees a CFString here.
    let string = unsafe { &*(value as *const CFString) };
    Some(string.to_string())
}

fn boolean_value(dict: &CFDictionary, key: &CFString) -> Option<bool> {
    let value = dict_get(dict, key)?;
    // SAFETY: schema guarantees a CFBoolean here.
    let boolean = unsafe { &*(value as *const CFBoolean) };
    Some(boolean.value())
}

fn rect_value(dict: &CFDictionary, key: &CFString) -> Option<Rect> {
    let value = dict_get(dict, key)?;
    // SAFETY: schema guarantees a CFDictionary (the bounds dict) here; the reference is
    // borrowed for the duration of the call.
    let bounds_dict = unsafe { &*(value as *const CFDictionary) };
    let mut cg = CGRect::default();
    let ok = unsafe { CGRectMakeWithDictionaryRepresentation(Some(bounds_dict), &mut cg) };
    ok.then_some(Rect::new(
        cg.origin.x,
        cg.origin.y,
        cg.size.width,
        cg.size.height,
    ))
}
