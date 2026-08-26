//! `act` (doc §5.3, §7.4): click, type, key, scroll, drag, or focus.
//!
//! Request parsing, element rematch, landing notes, and the response shape are pure and
//! unit-tested with no TCC. The macOS injection ([`handle`], gated to `target_os = "macos"`)
//! lives behind that gate; a non-macOS build returns the honest unsupported-platform error.
//!
//! ## Invariants (doc §7.4–§7.6)
//!
//! * Never inject into this helper or `ouro-desktop`.
//! * Honor `--deny-app` before any focus or event.
//! * Prefer `AXPress` / `AXSetValue` when the live node lists them; fall back to CGEvent
//!   only when the AX action was **not attempted**. A successful (or unknown) AXPress is
//!   never followed by a coordinate click.
//! * Re-find the element by role+name+similar live bounds. Stale snapshot bounds are not
//!   clicked.
//! * `require_focus` (default for `type` and `key`) focuses the window and refuses if the
//!   focused app is not the target.
//! * A cancel flag is checked between events so a drag or chord can release what it holds.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

use crate::geometry::{Point, Rect};
use crate::keys::{self, KeyChord};

/// JSON-RPC server-error band: an act that was understood but refused or failed at runtime.
pub const ACT_ERROR: i64 = -32004;
/// The in-flight act was cancelled (doc §7.5).
pub const ACT_CANCELLED: i64 = -32005;

/// How close (in coordinate-space pixels) two element centres may be to count as the same
/// control. Title-bar chrome and a one-frame layout shift stay under this; a different
/// button does not.
const CENTRE_TOLERANCE: f64 = 24.0;

/// A parsed `act` request. Elixir has already validated the tool-level table; the helper
/// is defensive and fills defaults rather than inventing a second schema.
#[derive(Clone, Debug, PartialEq)]
pub struct ActRequest {
    pub action: Action,
    pub target: Target,
    pub element: Option<ElementSnapshot>,
    pub point: Option<Point>,
    pub from: Option<Point>,
    pub to: Option<Point>,
    pub text: Option<String>,
    pub key: Option<String>,
    pub button: MouseButton,
    pub direction: Option<Direction>,
    pub pages: f64,
    pub require_focus: bool,
    pub coordinate_space: Option<CoordinateSpace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Click,
    Type,
    Key,
    Scroll,
    Drag,
    Focus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Target {
    pub app_id: Option<String>,
    pub window_id: Option<String>,
    pub title: Option<String>,
    pub pid: Option<i32>,
}

/// The element Elixir resolved from last_state. The helper re-finds this node live.
#[derive(Clone, Debug, PartialEq)]
pub struct ElementSnapshot {
    pub index: i64,
    pub role: Option<String>,
    pub name: Option<String>,
    pub bounds: Option<Rect>,
    pub actions: Vec<String>,
}

/// Capture origin + coordinate size so a model `x,y` maps back to screen points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoordinateSpace {
    pub origin: Point,
    pub width: f64,
    pub height: f64,
}

impl ActRequest {
    pub fn from_params(params: &Value) -> Result<Self, String> {
        let action = match params.get("action").and_then(Value::as_str) {
            Some("click") => Action::Click,
            Some("type") => Action::Type,
            Some("key") => Action::Key,
            Some("scroll") => Action::Scroll,
            Some("drag") => Action::Drag,
            Some("focus") => Action::Focus,
            Some(other) => return Err(format!("act: unknown action {other}")),
            None => return Err("act: action is required".into()),
        };

        let require_focus = params
            .get("require_focus")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(action, Action::Type | Action::Key));

        let pages = params
            .get("pages")
            .and_then(Value::as_f64)
            .filter(|n| n.is_finite() && *n > 0.0)
            .unwrap_or(1.0);

        Ok(Self {
            action,
            target: params.get("target").map(target_from).unwrap_or_default(),
            element: params.get("element").and_then(element_from),
            point: params.get("point").and_then(point_from),
            from: point_xy(params, "from_x", "from_y")
                .or_else(|| params.get("from").and_then(point_from)),
            to: point_xy(params, "to_x", "to_y").or_else(|| params.get("to").and_then(point_from)),
            text: string_field(params, "text"),
            key: string_field(params, "key"),
            button: match params.get("button").and_then(Value::as_str) {
                Some("right") => MouseButton::Right,
                Some("middle") => MouseButton::Middle,
                _ => MouseButton::Left,
            },
            direction: match params.get("direction").and_then(Value::as_str) {
                Some("up") => Some(Direction::Up),
                Some("down") => Some(Direction::Down),
                Some("left") => Some(Direction::Left),
                Some("right") => Some(Direction::Right),
                _ => None,
            },
            pages,
            require_focus,
            coordinate_space: params.get("coordinate_space").and_then(space_from),
        })
    }

    pub fn parsed_key(&self) -> Result<Option<KeyChord>, String> {
        match &self.key {
            Some(raw) => keys::parse(raw)
                .map(Some)
                .map_err(|e| format!("act: invalid key: {e}")),
            None => Ok(None),
        }
    }
}

fn target_from(value: &Value) -> Target {
    Target {
        app_id: string_field(value, "app_id"),
        window_id: string_field(value, "window_id"),
        title: string_field(value, "title"),
        pid: value.get("pid").and_then(Value::as_i64).map(|p| p as i32),
    }
}

fn element_from(value: &Value) -> Option<ElementSnapshot> {
    Some(ElementSnapshot {
        index: value.get("index").and_then(Value::as_i64).unwrap_or(-1),
        role: string_field(value, "role"),
        name: string_field(value, "name"),
        bounds: value.get("bounds").and_then(rect_from),
        actions: value
            .get("actions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn space_from(value: &Value) -> Option<CoordinateSpace> {
    let origin = Point {
        x: number_field(value, "origin_x")?,
        y: number_field(value, "origin_y")?,
    };
    let width = number_field(value, "width")?;
    let height = number_field(value, "height")?;
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some(CoordinateSpace {
        origin,
        width,
        height,
    })
}

fn point_from(value: &Value) -> Option<Point> {
    Some(Point {
        x: number_field(value, "x")?,
        y: number_field(value, "y")?,
    })
}

fn point_xy(value: &Value, x: &str, y: &str) -> Option<Point> {
    Some(Point {
        x: number_field(value, x)?,
        y: number_field(value, y)?,
    })
}

fn rect_from(value: &Value) -> Option<Rect> {
    Some(Rect::new(
        number_field(value, "x")?,
        number_field(value, "y")?,
        number_field(value, "w")?,
        number_field(value, "h")?,
    ))
}

fn number_field(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64).or_else(|| {
        value
            .get(key)
            .and_then(Value::as_i64)
            .map(|n| n as f64)
    })
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Maps a coordinate-space point onto global screen points using the capture origin and
/// the coordinate rect (whose size is `coordinate_width × coordinate_height` in the same
/// units the tree used).
pub fn screen_point(point: Point, space: CoordinateSpace) -> Point {
    let src = Rect::new(0.0, 0.0, space.width, space.height);
    let dst = Rect::new(space.origin.x, space.origin.y, space.width, space.height);
    // When width/height of src and dst match, this is a pure translate by origin.
    crate::geometry::map_point(point, src, dst).unwrap_or(Point {
        x: space.origin.x + point.x,
        y: space.origin.y + point.y,
    })
}

/// Whether a live node is the snapshot Elixir sent. Role is compared with the `AX` prefix
/// stripped; names are exact; bounds match when centres are close (or either side has none).
pub fn same_element(snapshot: &ElementSnapshot, live_role: &str, live_name: Option<&str>, live_bounds: Option<Rect>) -> bool {
    if let Some(want) = snapshot.role.as_deref() {
        if normalize_role(want) != normalize_role(live_role) {
            return false;
        }
    }
    match (snapshot.name.as_deref(), live_name) {
        (Some(want), Some(got)) if want != got => return false,
        (Some(_), None) => return false,
        _ => {}
    }
    match (snapshot.bounds, live_bounds) {
        (Some(a), Some(b)) => centres_close(a, b),
        _ => true,
    }
}

pub fn normalize_role(role: &str) -> String {
    let trimmed = role.trim();
    let stripped = trimmed
        .strip_prefix("AX")
        .or_else(|| trimmed.strip_prefix("ax"))
        .unwrap_or(trimmed);
    stripped.to_ascii_lowercase()
}

fn centres_close(a: Rect, b: Rect) -> bool {
    let ac = Point::new(a.x + a.w / 2.0, a.y + a.h / 2.0);
    let bc = Point::new(b.x + b.w / 2.0, b.y + b.h / 2.0);
    (ac.x - bc.x).abs() <= CENTRE_TOLERANCE && (ac.y - bc.y).abs() <= CENTRE_TOLERANCE
}

/// Whether a live action list includes AXPress (any capitalisation).
pub fn lists_press(actions: &[String]) -> bool {
    actions.iter().any(|a| a.eq_ignore_ascii_case("AXPress"))
}

/// Landing copy for the model: what holds focus after the act, or a warning that input
/// may not have landed.
pub fn landing_notes(focused: Option<&FocusedElement>, warnings: &[String]) -> String {
    match focused {
        Some(el) if el.editable => {
            format!("focused role={} editable=true name={}", el.role, el.name)
        }
        Some(el) => format!(
            "focused role={} editable=false name={} — treat input as not landed in a field",
            el.role, el.name
        ),
        None => {
            if warnings.iter().any(|w| w.contains("no editable")) {
                "warning: no editable element holds focus — treat input as not landed".into()
            } else {
                "warning: no focused element reported — treat input as not landed".into()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FocusedElement {
    pub role: String,
    pub name: String,
    pub editable: bool,
}

pub fn assemble(
    ok: bool,
    backend: &str,
    app_id: Option<&str>,
    window_id: Option<&str>,
    focused: Option<&FocusedElement>,
    warnings: Vec<String>,
    error: Option<&str>,
) -> Value {
    let mut body = json!({
        "ok": ok,
        "backend": backend,
        "warnings": warnings,
        "landing": landing_notes(focused, &warnings),
    });
    if let Some(app) = app_id {
        body["app_id"] = json!(app);
    }
    if let Some(window) = window_id {
        body["window_id"] = json!(window);
    }
    if let Some(el) = focused {
        body["focused_element"] = json!({
            "role": el.role,
            "name": el.name,
            "editable": el.editable,
        });
    }
    if let Some(error) = error {
        body["error"] = json!(error);
    }
    body
}

/// Denied-app belt, same comparison as `state`.
pub fn is_denied(app_id: &str, deny_list: &[String]) -> bool {
    crate::state::is_denied(app_id, deny_list)
}

pub fn is_cancelled(flag: &AtomicBool) -> bool {
    flag.load(Ordering::SeqCst)
}


/// Self / ouro surfaces the helper must never drive, even if Elixir failed to deny them.
pub fn is_self_target(app_id: &str, pid: Option<i32>) -> bool {
    if let Some(pid) = pid {
        if pid > 0 && pid == std::process::id() as i32 {
            return true;
        }
    }
    app_id.eq_ignore_ascii_case("com.ouroboros.desktop")
        || app_id.eq_ignore_ascii_case("com.ouroboros.tui")
        || app_id.eq_ignore_ascii_case("ouro-computer-use")
}

pub fn permission_sheet(app_id: &str, title: Option<&str>) -> bool {
    if app_id.eq_ignore_ascii_case("com.apple.SecurityAgent")
        || app_id.eq_ignore_ascii_case("com.apple.UserNotificationCenter")
        || app_id.eq_ignore_ascii_case("com.apple.loginwindow")
    {
        return true;
    }
    title
        .map(|t| {
            let t = t.to_ascii_lowercase();
            t.contains("would like to")
                || t.contains("wants to access")
                || t.contains("permission") && t.contains("accessibility")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub fn handle(
    deny_apps: &[String],
    params: Value,
    cancel: &AtomicBool,
) -> Result<Value, (i64, String)> {
    crate::macos::input::perform(deny_apps, params, cancel)
}

#[cfg(not(target_os = "macos"))]
pub fn handle(
    _deny_apps: &[String],
    _params: Value,
    _cancel: &AtomicBool,
) -> Result<Value, (i64, String)> {
    Err((
        crate::server::UNSUPPORTED_PLATFORM,
        "act: Computer Use input is only supported on macOS".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_click_by_element() {
        let req = ActRequest::from_params(&json!({
            "action": "click",
            "target": { "app_id": "com.apple.calculator", "window_id": "w_1" },
            "element": {
                "index": 1,
                "role": "AXButton",
                "name": "2",
                "bounds": { "x": 40, "y": 80, "w": 32, "h": 32 },
                "actions": ["AXPress"]
            },
            "require_focus": true
        }))
        .unwrap();
        assert_eq!(req.action, Action::Click);
        assert_eq!(req.target.app_id.as_deref(), Some("com.apple.calculator"));
        assert_eq!(req.element.unwrap().name.as_deref(), Some("2"));
        assert!(req.require_focus);
    }

    #[test]
    fn type_and_key_default_require_focus() {
        let typed = ActRequest::from_params(&json!({"action": "type", "text": "hi"})).unwrap();
        assert!(typed.require_focus);
        let key = ActRequest::from_params(&json!({"action": "key", "key": "Enter"})).unwrap();
        assert!(key.require_focus);
        let click = ActRequest::from_params(&json!({"action": "click", "point": {"x": 1, "y": 2}}))
            .unwrap();
        assert!(!click.require_focus);
    }

    #[test]
    fn rematch_ignores_ax_prefix_and_nearby_bounds() {
        let snap = ElementSnapshot {
            index: 1,
            role: Some("button".into()),
            name: Some("2".into()),
            bounds: Some(Rect::new(40.0, 80.0, 32.0, 32.0)),
            actions: vec!["AXPress".into()],
        };
        assert!(same_element(
            &snap,
            "AXButton",
            Some("2"),
            Some(Rect::new(42.0, 78.0, 32.0, 32.0))
        ));
        assert!(!same_element(
            &snap,
            "AXButton",
            Some("3"),
            Some(Rect::new(42.0, 78.0, 32.0, 32.0))
        ));
        assert!(!same_element(
            &snap,
            "AXButton",
            Some("2"),
            Some(Rect::new(400.0, 80.0, 32.0, 32.0))
        ));
    }

    #[test]
    fn landing_notes_warn_when_nothing_editable_is_focused() {
        let notes = landing_notes(None, &["warning: no editable element holds focus".into()]);
        assert!(notes.contains("treat input as not landed"));
        let focused = FocusedElement {
            role: "AXTextField".into(),
            name: "Name".into(),
            editable: true,
        };
        assert!(landing_notes(Some(&focused), &[]).contains("editable=true"));
    }

    #[test]
    fn self_and_permission_sheet_are_detected() {
        assert!(is_self_target("com.ouroboros.desktop", None));
        assert!(is_self_target("other", Some(std::process::id() as i32)));
        assert!(!is_self_target("com.apple.calculator", Some(1)));
        assert!(permission_sheet("com.apple.SecurityAgent", None));
        assert!(permission_sheet(
            "com.apple.calculator",
            Some("Calculator would like to receive keystrokes")
        ));
    }

    #[test]
    fn screen_point_translates_by_origin() {
        let space = CoordinateSpace {
            origin: Point::new(100.0, 200.0),
            width: 240.0,
            height: 320.0,
        };
        let mapped = screen_point(Point::new(10.0, 20.0), space);
        assert_eq!(mapped.x, 110.0);
        assert_eq!(mapped.y, 220.0);
    }

    #[test]
    fn assemble_carries_ok_and_error() {
        let value = assemble(
            false,
            "none",
            Some("com.apple.calculator"),
            Some("w_1"),
            None,
            vec!["offscreen".into()],
            Some("element gone; call state again"),
        );
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "element gone; call state again");
        assert_eq!(value["app_id"], "com.apple.calculator");
    }
}
