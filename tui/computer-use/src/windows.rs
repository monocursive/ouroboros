//! `windows` (doc §7.2): the platform-independent half of window enumeration — the window-id
//! grammar and the JSON shaping. The macOS `CGWindowList` walk that produces [`RawWindow`]s
//! lives in [`crate::macos::windows`]; everything here is pure and unit-tested with no TCC.
//!
//! ## Window ids are opaque but stateless
//!
//! `id` is `w_<CGWindowID>`. The doc (§7.2) prefers not to leak a raw `CGWindowID` as a
//! guessable integer, but the helper is deliberately stateless across calls (doc D5/D11: the
//! last snapshot lives in the BEAM, and `act` receives a fully resolved target), so a window
//! id must round-trip to something the helper can re-target **without holding a table**.
//! Wrapping the `CGWindowID` in an opaque `w_…` string is that round-trippable form; it is
//! stable while the window exists, and — as the doc allows when we must use `CGWindowID` —
//! the underlying number is recycled by the window server after the window closes, so an id
//! is only meaningful for a window that is currently alive.

use crate::geometry::{Point, Rect};
use serde_json::{json, Value};

/// One window as read from the host, before shaping. Field names mirror what `CGWindowList`
/// exposes; `app_id` (bundle id) is filled in from `NSRunningApplication`, and `title` stays
/// `None` when Screen Recording is not granted (bare enumeration cannot read titles).
#[derive(Clone, Debug, PartialEq)]
pub struct RawWindow {
    pub window_id: u32,
    pub pid: i32,
    pub app_id: Option<String>,
    pub app_name: Option<String>,
    pub title: Option<String>,
    pub layer: i64,
    pub bounds: Rect,
    pub on_screen: bool,
}

/// The `w_<id>` window-id string for a live `CGWindowID`.
pub fn mint_id(window_id: u32) -> String {
    format!("w_{window_id}")
}

/// Parses a `w_<id>` window-id string back to its `CGWindowID`, or `None` if it is not one
/// this helper minted. Used by `state` to re-target a window the caller names by id.
pub fn parse_id(id: &str) -> Option<u32> {
    id.strip_prefix("w_")
        .and_then(|rest| rest.parse::<u32>().ok())
}

/// Serves the `windows` method. Real on macOS (a `CGWindowList` enumeration shaped by
/// [`build_response`]); an honest unsupported-platform error elsewhere.
#[cfg(target_os = "macos")]
pub fn handle(cancel: &std::sync::atomic::AtomicBool) -> Result<Value, (i64, String)> {
    if crate::act::is_cancelled(cancel) {
        return Err((crate::server::OBSERVE_ERROR, "windows: cancelled".into()));
    }
    let raw = crate::macos::windows::enumerate()
        .map_err(|e| (crate::server::OBSERVE_ERROR, format!("windows: {e}")))?;
    Ok(build_response(&raw))
}

#[cfg(not(target_os = "macos"))]
pub fn handle(_cancel: &std::sync::atomic::AtomicBool) -> Result<Value, (i64, String)> {
    Err((
        crate::server::UNSUPPORTED_PLATFORM,
        "windows: Computer Use is only supported on macOS".to_string(),
    ))
}

/// Builds the `windows` response from the host's front-to-back window list.
///
/// `raw` must be in the window server's front-to-back z-order (what `CGWindowList` returns for
/// an on-screen query); [`focused_index`] uses that order to pick the focused window.
pub fn build_response(raw: &[RawWindow]) -> Value {
    let focused = focused_index(raw);
    let windows: Vec<Value> = raw
        .iter()
        .enumerate()
        .map(|(i, w)| window_json(w, Some(i) == focused))
        .collect();
    json!({ "windows": windows })
}

/// Which window is focused, by the only signal available without Accessibility: the frontmost
/// normal window. `CGWindowList` returns windows front-to-back, so the focused document window
/// is the first on-screen one at layer 0 (menus, the Dock, overlays sit at nonzero layers).
/// This is a derivation from real z-order, not a fabricated flag; Elixir/AX can refine it.
fn focused_index(raw: &[RawWindow]) -> Option<usize> {
    frontmost_normal(raw).and_then(|front| raw.iter().position(|window| window == front))
}

/// The normal window that currently owns focus, from a front-to-back CGWindowList snapshot.
pub fn frontmost_normal(raw: &[RawWindow]) -> Option<&RawWindow> {
    raw.iter().find(|w| w.on_screen && w.layer == 0)
}

/// The topmost on-screen window whose bounds own `point`. Unlike focus, this intentionally
/// includes nonzero layers: a menu, sheet, overlay, or permission surface above the target
/// would receive a CGEvent and therefore must make injection fail closed.
pub fn frontmost_at(raw: &[RawWindow], point: Point) -> Option<&RawWindow> {
    raw.iter()
        .find(|window| window.on_screen && window.bounds.contains(point))
}

fn window_json(w: &RawWindow, focused: bool) -> Value {
    json!({
        "id": mint_id(w.window_id),
        "pid": w.pid,
        "app_id": w.app_id,
        "name": w.app_name,
        "title": w.title,
        "focused": focused,
        "bounds": bounds_json(&w.bounds),
        "layer": w.layer,
    })
}

/// Window bounds serialize as integers: `CGWindowList` reports whole-pixel global bounds, and
/// the contract's examples are integer rectangles.
pub fn bounds_json(rect: &Rect) -> Value {
    json!({
        "x": rect.x.round() as i64,
        "y": rect.y.round() as i64,
        "w": rect.w.round() as i64,
        "h": rect.h.round() as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(id: u32, layer: i64, on_screen: bool) -> RawWindow {
        RawWindow {
            window_id: id,
            pid: 100 + id as i32,
            app_id: Some(format!("com.example.app{id}")),
            app_name: Some(format!("App{id}")),
            title: Some(format!("Window {id}")),
            layer,
            bounds: Rect::new(0.0, 0.0, 200.0, 100.0),
            on_screen,
        }
    }

    #[test]
    fn id_round_trips() {
        assert_eq!(mint_id(42), "w_42");
        assert_eq!(parse_id("w_42"), Some(42));
        assert_eq!(parse_id("w_0"), Some(0));
    }

    #[test]
    fn parse_rejects_non_ids() {
        assert_eq!(parse_id("42"), None);
        assert_eq!(parse_id("w_"), None);
        assert_eq!(parse_id("w_-1"), None);
        assert_eq!(parse_id("window_42"), None);
        assert_eq!(parse_id("w_abc"), None);
    }

    #[test]
    fn focused_is_the_frontmost_layer_zero_window() {
        // A high-layer overlay in front, then two normal windows: the first normal one wins.
        let raw = vec![win(1, 25, true), win(2, 0, true), win(3, 0, true)];
        let value = build_response(&raw);
        let windows = value["windows"].as_array().unwrap();
        assert_eq!(windows[0]["focused"], false, "overlay is not focused");
        assert_eq!(windows[1]["focused"], true, "frontmost normal window");
        assert_eq!(windows[2]["focused"], false);
    }

    #[test]
    fn point_hit_testing_keeps_front_to_back_order_and_includes_overlays() {
        let mut overlay = win(1, 25, true);
        overlay.bounds = Rect::new(20.0, 20.0, 40.0, 40.0);
        let target = win(2, 0, true);
        let raw = vec![overlay, target];

        assert_eq!(
            frontmost_at(&raw, Point::new(30.0, 30.0))
                .unwrap()
                .window_id,
            1
        );
        assert_eq!(
            frontmost_at(&raw, Point::new(80.0, 80.0))
                .unwrap()
                .window_id,
            2
        );
        assert!(frontmost_at(&raw, Point::new(250.0, 80.0)).is_none());
    }

    #[test]
    fn offscreen_layer_zero_is_not_focused() {
        let raw = vec![win(1, 0, false), win(2, 0, true)];
        let value = build_response(&raw);
        let windows = value["windows"].as_array().unwrap();
        assert_eq!(windows[0]["focused"], false);
        assert_eq!(windows[1]["focused"], true);
    }

    #[test]
    fn no_focus_when_nothing_qualifies() {
        let raw = vec![win(1, 25, true), win(2, 3, true)];
        let value = build_response(&raw);
        for w in value["windows"].as_array().unwrap() {
            assert_eq!(w["focused"], false);
        }
    }

    #[test]
    fn shape_matches_contract() {
        let raw = vec![RawWindow {
            window_id: 12,
            pid: 442,
            app_id: Some("com.apple.calculator".into()),
            app_name: Some("Calculator".into()),
            title: Some("Calculator".into()),
            layer: 0,
            bounds: Rect::new(100.0, 120.0, 240.0, 320.0),
            on_screen: true,
        }];
        let value = build_response(&raw);
        let w = &value["windows"][0];
        assert_eq!(w["id"], "w_12");
        assert_eq!(w["pid"], 442);
        assert_eq!(w["app_id"], "com.apple.calculator");
        assert_eq!(w["name"], "Calculator");
        assert_eq!(w["title"], "Calculator");
        assert_eq!(w["focused"], true);
        assert_eq!(w["layer"], 0);
        assert_eq!(
            w["bounds"],
            json!({ "x": 100, "y": 120, "w": 240, "h": 320 })
        );
    }

    #[test]
    fn missing_title_and_bundle_serialize_as_null() {
        let raw = vec![RawWindow {
            window_id: 5,
            pid: 9,
            app_id: None,
            app_name: Some("Owner".into()),
            title: None,
            layer: 0,
            bounds: Rect::new(0.0, 0.0, 10.0, 10.0),
            on_screen: true,
        }];
        let value = build_response(&raw);
        let w = &value["windows"][0];
        assert!(w["app_id"].is_null());
        assert!(w["title"].is_null());
        assert_eq!(w["name"], "Owner");
    }
}
