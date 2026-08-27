//! Input injection for `act` (doc §7.4–§7.6).
//!
//! AX actions first (`AXPress`, `AXSetValue`, `AXRaise`); CGEvent only when the AX path
//! was not attempted. A cancel flag is checked between events so a chord or drag releases
//! what it is holding. This module never decides allow/deny beyond the helper's own belts
//! (deny-app, self, permission sheet, secure input).

use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use objc2_core_foundation::CGPoint;
use serde_json::Value;

use crate::act::{
    assemble, is_cancelled, is_denied, is_self_target, permission_sheet, screen_point, ActRequest,
    Action, Direction, MouseButton, ACT_CANCELLED, ACT_ERROR,
};
use crate::geometry::Point;
use crate::keys::{self, KeyChord, Modifier};
use crate::macos::{self, ax};
use crate::server::DENIED_APP;
use crate::windows::parse_id;

/// Posts HID events at session level (the same tap a local user generates).
const HID_TAP: u32 = 0;
const SOURCE_HID: i32 = 1;

const LEFT_DOWN: u32 = 1;
const LEFT_UP: u32 = 2;
const RIGHT_DOWN: u32 = 3;
const RIGHT_UP: u32 = 4;
const MOVED: u32 = 5;
const LEFT_DRAGGED: u32 = 6;
const OTHER_DOWN: u32 = 25;
const OTHER_UP: u32 = 26;
const BUTTON_LEFT: u32 = 0;
const BUTTON_RIGHT: u32 = 1;
const BUTTON_CENTER: u32 = 2;

const FLAG_SHIFT: u64 = 0x0002_0000;
const FLAG_CONTROL: u64 = 0x0004_0000;
const FLAG_ALT: u64 = 0x0008_0000;
const FLAG_COMMAND: u64 = 0x0010_0000;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventSourceCreate(state_id: i32) -> *mut std::ffi::c_void;
    fn CGEventCreateMouseEvent(
        source: *mut std::ffi::c_void,
        mouse_type: u32,
        pos: CGPoint,
        button: u32,
    ) -> *mut std::ffi::c_void;
    fn CGEventCreateKeyboardEvent(
        source: *mut std::ffi::c_void,
        keycode: u16,
        key_down: bool,
    ) -> *mut std::ffi::c_void;
    fn CGEventCreateScrollWheelEvent(
        source: *mut std::ffi::c_void,
        units: u32,
        wheel_count: u32,
        wheel1: i32,
        ...
    ) -> *mut std::ffi::c_void;
    fn CGEventSetFlags(event: *mut std::ffi::c_void, flags: u64);
    fn CGEventKeyboardSetUnicodeString(
        event: *mut std::ffi::c_void,
        length: usize,
        string: *const u16,
    );
    fn CGEventPost(tap: u32, event: *mut std::ffi::c_void);
    fn CFRelease(cf: *const std::ffi::c_void);
}

pub fn perform(
    deny_apps: &[String],
    params: Value,
    cancel: &AtomicBool,
) -> Result<Value, (i64, String)> {
    if is_cancelled(cancel) {
        return Err((ACT_CANCELLED, "act: cancelled".into()));
    }

    let request = ActRequest::from_params(&params).map_err(|e| (ACT_ERROR, e))?;

    if macos::secure_event_input_enabled() && matches!(request.action, Action::Type | Action::Key) {
        return Err((
            ACT_ERROR,
            "act: secure keyboard entry is on; type and key are blocked".into(),
        ));
    }

    if !macos::accessibility_trusted()
        && matches!(
            request.action,
            Action::Click | Action::Type | Action::Key | Action::Scroll | Action::Drag
        )
    {
        return Err((
            ACT_ERROR,
            "act: Accessibility is not granted to ouro-computer-use".into(),
        ));
    }

    let resolved = resolve_target(&request).map_err(|e| (ACT_ERROR, format!("act: {e}")))?;

    if is_denied(&resolved.app_id, deny_apps) {
        return Err((
            DENIED_APP,
            format!(
                "act: {} is on the helper's --deny-app list; refusing to inject",
                resolved.app_id
            ),
        ));
    }
    if is_self_target(&resolved.app_id, Some(resolved.pid)) {
        return Err((
            ACT_ERROR,
            format!("act: refusing to inject input into {}", resolved.app_id),
        ));
    }
    if permission_sheet(&resolved.app_id, resolved.title.as_deref()) {
        return Err((
            ACT_ERROR,
            "act: target looks like a system permission sheet; refusing".into(),
        ));
    }

    if request.require_focus || request.action == Action::Focus {
        ax::set_frontmost(resolved.pid).map_err(|e| (ACT_ERROR, format!("act: {e}")))?;
        if let Some(bounds) = resolved.window_bounds {
            let _ = ax::raise_window(resolved.pid, bounds);
        }
        thread::sleep(Duration::from_millis(40));
        match ax::frontmost_app_id() {
            Some(front) if front.eq_ignore_ascii_case(&resolved.app_id) => {}
            Some(front) => {
                return Err((
                    ACT_ERROR,
                    format!(
                        "act: focused app is {front}, not {}; call desktop_state again",
                        resolved.app_id
                    ),
                ));
            }
            None => {
                return Err((
                    ACT_ERROR,
                    "act: could not verify the focused app; refusing".into(),
                ));
            }
        }
    }

    if is_cancelled(cancel) {
        return Err((ACT_CANCELLED, "act: cancelled".into()));
    }

    let outcome = match request.action {
        Action::Focus => Ok(Backend::Ax),
        Action::Click => click(&request, &resolved, cancel),
        Action::Type => type_text(&request, &resolved, cancel),
        Action::Key => press_key(&request, cancel),
        Action::Scroll => scroll(&request, &resolved, cancel),
        Action::Drag => drag(&request, &resolved, cancel),
    };

    let (ok, backend, error) = match outcome {
        Ok(backend) => (true, backend.as_str(), None),
        Err(ActFail::Cancelled) => {
            return Err((ACT_CANCELLED, "act: cancelled mid-input".into()));
        }
        Err(ActFail::Message(message)) => (false, "none", Some(message)),
    };

    let focused = ax::focused_summary(resolved.pid, resolved.window_bounds);
    let mut warnings = Vec::new();
    if matches!(request.action, Action::Type | Action::Key)
        && focused.as_ref().is_none_or(|el| !el.editable)
    {
        warnings
            .push("warning: no editable element holds focus — treat input as not landed".into());
    }

    Ok(assemble(
        ok,
        backend,
        Some(&resolved.app_id),
        resolved.window_id.as_deref(),
        focused.as_ref(),
        warnings,
        error.as_deref(),
    ))
}

enum Backend {
    Ax,
    Event,
}

impl Backend {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ax => "ax",
            Self::Event => "cgevent",
        }
    }
}

enum ActFail {
    Cancelled,
    Message(String),
}

struct Resolved {
    app_id: String,
    pid: i32,
    window_id: Option<String>,
    window_bounds: Option<crate::geometry::Rect>,
    title: Option<String>,
}

fn resolve_target(request: &ActRequest) -> Result<Resolved, String> {
    let windows = macos::windows::enumerate().map_err(|e| e.to_string())?;

    let want_id = request.target.window_id.as_deref().and_then(parse_id);
    let want_app = request.target.app_id.as_deref();
    let want_title = request.target.title.as_deref();
    let want_pid = request.target.pid;

    if want_id.is_none() && want_app.is_none() && want_title.is_none() && want_pid.is_none() {
        return Err("name an app, window_id, or title — untargeted inject is refused".into());
    }

    let found = windows.into_iter().find(|w| {
        if let Some(pid) = want_pid {
            if w.pid != pid {
                return false;
            }
        }
        if let Some(id) = want_id {
            if w.window_id != id {
                return false;
            }
        }
        if let Some(app) = want_app {
            match w.app_id.as_deref() {
                Some(got) if got.eq_ignore_ascii_case(app) => {}
                _ => return false,
            }
        }
        if let Some(title) = want_title {
            match w.title.as_deref() {
                Some(got)
                    if got
                        .to_ascii_lowercase()
                        .contains(&title.to_ascii_lowercase()) => {}
                _ => return false,
            }
        }
        true
    });

    let Some(window) = found else {
        return Err("target window is gone; call desktop_state again".into());
    };
    let app_id = window
        .app_id
        .clone()
        .or_else(|| want_app.map(str::to_string))
        .ok_or_else(|| "target did not resolve to an app".to_string())?;

    Ok(Resolved {
        app_id,
        pid: window.pid,
        window_id: Some(crate::windows::mint_id(window.window_id)),
        window_bounds: Some(window.bounds),
        title: window.title,
    })
}

fn click(
    request: &ActRequest,
    resolved: &Resolved,
    cancel: &AtomicBool,
) -> Result<Backend, ActFail> {
    check(cancel)?;
    if let Some(element) = &request.element {
        let needle = crate::act::element_in_global(element, request.coordinate_space);
        match ax::press_matching(resolved.pid, resolved.window_bounds, &needle) {
            Ok(()) => return Ok(Backend::Ax),
            Err(ax::MatchError::Gone) => {
                return Err(ActFail::Message("element gone; call state again".into()));
            }
            Err(ax::MatchError::Secure) => {
                return Err(ActFail::Message(
                    "act: refusing to interact with a secure field".into(),
                ));
            }
            Err(ax::MatchError::NoPress) => {
                // AXPress not listed — fall through to a coordinate click, once.
            }
            Err(ax::MatchError::Failed(message)) => return Err(ActFail::Message(message)),
        }
    }
    let point = click_point(request)?;
    post_click(point, request.button, cancel)?;
    Ok(Backend::Event)
}

fn type_text(
    request: &ActRequest,
    resolved: &Resolved,
    cancel: &AtomicBool,
) -> Result<Backend, ActFail> {
    check(cancel)?;
    let text = request
        .text
        .as_deref()
        .ok_or_else(|| ActFail::Message("act: type needs text".into()))?;

    if let Some(element) = &request.element {
        let needle = crate::act::element_in_global(element, request.coordinate_space);
        match ax::set_value_matching(resolved.pid, resolved.window_bounds, &needle, text) {
            Ok(()) => return Ok(Backend::Ax),
            Err(ax::MatchError::Gone) => {
                return Err(ActFail::Message("element gone; call state again".into()));
            }
            Err(ax::MatchError::Secure) => {
                return Err(ActFail::Message(
                    "act: refusing to type into a secure field".into(),
                ));
            }
            Err(ax::MatchError::NoPress) => {
                return Err(ActFail::Message(
                    "act: the field does not accept AXSetValue".into(),
                ));
            }
            Err(ax::MatchError::Failed(message)) => return Err(ActFail::Message(message)),
        }
    }

    type_unicode(text, cancel)?;
    Ok(Backend::Event)
}

fn press_key(request: &ActRequest, cancel: &AtomicBool) -> Result<Backend, ActFail> {
    check(cancel)?;
    let chord = request
        .parsed_key()
        .map_err(ActFail::Message)?
        .ok_or_else(|| ActFail::Message("act: key is required".into()))?;
    post_chord(&chord, cancel)?;
    Ok(Backend::Event)
}

fn scroll(
    request: &ActRequest,
    _resolved: &Resolved,
    cancel: &AtomicBool,
) -> Result<Backend, ActFail> {
    check(cancel)?;
    if let Some(point) = click_point(request).ok() {
        move_cursor(point);
    }
    let direction = request
        .direction
        .ok_or_else(|| ActFail::Message("act: scroll needs a direction".into()))?;
    let amount = (request.pages * 3.0).round() as i32;
    let (dy, dx) = match direction {
        Direction::Up => (amount, 0),
        Direction::Down => (-amount, 0),
        Direction::Left => (0, amount),
        Direction::Right => (0, -amount),
    };
    post_scroll(dy, dx);
    Ok(Backend::Event)
}

fn drag(
    request: &ActRequest,
    _resolved: &Resolved,
    cancel: &AtomicBool,
) -> Result<Backend, ActFail> {
    check(cancel)?;
    let from = request
        .from
        .and_then(|p| map_point(request, p))
        .ok_or_else(|| ActFail::Message("act: drag needs from_x/from_y".into()))?;
    let to = request
        .to
        .and_then(|p| map_point(request, p))
        .ok_or_else(|| ActFail::Message("act: drag needs to_x/to_y".into()))?;

    let source = event_source()?;
    let start = cgpoint(from);
    let end = cgpoint(to);
    unsafe {
        let down = CGEventCreateMouseEvent(source, LEFT_DOWN, start, BUTTON_LEFT);
        if down.is_null() {
            CFRelease(source);
            return Err(ActFail::Message("act: could not create mouse event".into()));
        }
        CGEventPost(HID_TAP, down);
        CFRelease(down);
    }
    if let Err(fail) = check(cancel) {
        unsafe {
            let up = CGEventCreateMouseEvent(source, LEFT_UP, start, BUTTON_LEFT);
            if !up.is_null() {
                CGEventPost(HID_TAP, up);
                CFRelease(up);
            }
            CFRelease(source);
        }
        return Err(fail);
    }
    unsafe {
        let drag = CGEventCreateMouseEvent(source, LEFT_DRAGGED, end, BUTTON_LEFT);
        if !drag.is_null() {
            CGEventPost(HID_TAP, drag);
            CFRelease(drag);
        }
        let up = CGEventCreateMouseEvent(source, LEFT_UP, end, BUTTON_LEFT);
        if !up.is_null() {
            CGEventPost(HID_TAP, up);
            CFRelease(up);
        }
        CFRelease(source);
    }
    Ok(Backend::Event)
}

fn click_point(request: &ActRequest) -> Result<Point, ActFail> {
    if let Some(point) = request.point {
        return map_point(request, point).ok_or_else(|| {
            ActFail::Message("act: click point is outside the coordinate space".into())
        });
    }
    if let Some(element) = &request.element {
        if let Some(bounds) = element.bounds {
            let centre = Point::new(bounds.x + bounds.w / 2.0, bounds.y + bounds.h / 2.0);
            return map_point(request, centre)
                .ok_or_else(|| ActFail::Message("act: element bounds could not be mapped".into()));
        }
    }
    Err(ActFail::Message(
        "act: click needs an element or a point".into(),
    ))
}

fn map_point(request: &ActRequest, point: Point) -> Option<Point> {
    match request.coordinate_space {
        Some(space) => Some(screen_point(point, space)),
        None => Some(point),
    }
}

fn post_click(point: Point, button: MouseButton, cancel: &AtomicBool) -> Result<(), ActFail> {
    check(cancel)?;
    let (down_ty, up_ty, btn) = match button {
        MouseButton::Left => (LEFT_DOWN, LEFT_UP, BUTTON_LEFT),
        MouseButton::Right => (RIGHT_DOWN, RIGHT_UP, BUTTON_RIGHT),
        MouseButton::Middle => (OTHER_DOWN, OTHER_UP, BUTTON_CENTER),
    };
    let source = event_source()?;
    let pos = cgpoint(point);
    unsafe {
        let down = CGEventCreateMouseEvent(source, down_ty, pos, btn);
        let up = CGEventCreateMouseEvent(source, up_ty, pos, btn);
        if down.is_null() || up.is_null() {
            if !down.is_null() {
                CFRelease(down);
            }
            if !up.is_null() {
                CFRelease(up);
            }
            CFRelease(source);
            return Err(ActFail::Message("act: could not create mouse event".into()));
        }
        CGEventPost(HID_TAP, down);
        CFRelease(down);
        if is_cancelled(cancel) {
            CGEventPost(HID_TAP, up);
            CFRelease(up);
            CFRelease(source);
            return Err(ActFail::Cancelled);
        }
        CGEventPost(HID_TAP, up);
        CFRelease(up);
        CFRelease(source);
    }
    Ok(())
}

fn move_cursor(point: Point) {
    let Ok(source) = event_source() else {
        return;
    };
    unsafe {
        let ev = CGEventCreateMouseEvent(source, MOVED, cgpoint(point), BUTTON_LEFT);
        if !ev.is_null() {
            CGEventPost(HID_TAP, ev);
            CFRelease(ev);
        }
        CFRelease(source);
    }
}

fn post_scroll(wheel1: i32, wheel2: i32) {
    let Ok(source) = event_source() else {
        return;
    };
    // 1 = line units.
    unsafe {
        let ev = CGEventCreateScrollWheelEvent(source, 1, 2, wheel1, wheel2);
        if !ev.is_null() {
            CGEventPost(HID_TAP, ev);
            CFRelease(ev);
        }
        CFRelease(source);
    }
}

fn post_chord(chord: &KeyChord, cancel: &AtomicBool) -> Result<(), ActFail> {
    check(cancel)?;
    let source = event_source()?;
    let flags = modifier_flags(&chord.modifiers);
    let code = keys::virtual_key(chord.key);
    unsafe {
        let down = CGEventCreateKeyboardEvent(source, code, true);
        let up = CGEventCreateKeyboardEvent(source, code, false);
        if down.is_null() || up.is_null() {
            if !down.is_null() {
                CFRelease(down);
            }
            if !up.is_null() {
                CFRelease(up);
            }
            CFRelease(source);
            return Err(ActFail::Message("act: could not create key event".into()));
        }
        if flags != 0 {
            CGEventSetFlags(down, flags);
            CGEventSetFlags(up, flags);
        }
        CGEventPost(HID_TAP, down);
        CFRelease(down);
        if is_cancelled(cancel) {
            CGEventPost(HID_TAP, up);
            CFRelease(up);
            CFRelease(source);
            return Err(ActFail::Cancelled);
        }
        CGEventPost(HID_TAP, up);
        CFRelease(up);
        CFRelease(source);
    }
    Ok(())
}

fn type_unicode(text: &str, cancel: &AtomicBool) -> Result<(), ActFail> {
    let source = event_source()?;
    for ch in text.chars() {
        if let Err(fail) = check(cancel) {
            unsafe {
                CFRelease(source);
            }
            return Err(fail);
        }
        let mut utf16 = [0u16; 2];
        let encoded = ch.encode_utf16(&mut utf16);
        unsafe {
            let down = CGEventCreateKeyboardEvent(source, 0, true);
            let up = CGEventCreateKeyboardEvent(source, 0, false);
            if down.is_null() || up.is_null() {
                if !down.is_null() {
                    CFRelease(down);
                }
                if !up.is_null() {
                    CFRelease(up);
                }
                CFRelease(source);
                return Err(ActFail::Message(
                    "act: could not create unicode event".into(),
                ));
            }
            CGEventKeyboardSetUnicodeString(down, encoded.len(), encoded.as_ptr());
            CGEventKeyboardSetUnicodeString(up, encoded.len(), encoded.as_ptr());
            CGEventPost(HID_TAP, down);
            CFRelease(down);
            CGEventPost(HID_TAP, up);
            CFRelease(up);
        }
    }
    unsafe {
        CFRelease(source);
    }
    Ok(())
}

fn modifier_flags(modifiers: &[Modifier]) -> u64 {
    let mut flags = 0u64;
    for modifier in modifiers {
        flags |= match modifier {
            Modifier::Shift => FLAG_SHIFT,
            Modifier::Ctrl => FLAG_CONTROL,
            Modifier::Alt => FLAG_ALT,
            Modifier::Meta => FLAG_COMMAND,
        };
    }
    flags
}

fn event_source() -> Result<*mut std::ffi::c_void, ActFail> {
    let source = unsafe { CGEventSourceCreate(SOURCE_HID) };
    if source.is_null() {
        Err(ActFail::Message(
            "act: could not create an event source".into(),
        ))
    } else {
        Ok(source)
    }
}

fn cgpoint(point: Point) -> CGPoint {
    CGPoint {
        x: point.x,
        y: point.y,
    }
}

fn check(cancel: &AtomicBool) -> Result<(), ActFail> {
    if is_cancelled(cancel) {
        Err(ActFail::Cancelled)
    } else {
        Ok(())
    }
}
