//! AX tree shaping (doc §7.3): turn the raw accessibility walk into the dense-indexed,
//! size-bounded node list `state` returns. Pure and unit-tested — the macOS
//! `AXUIElementCopyAttributeValue` recursion that produces [`RawAxNode`]s lives in
//! [`crate::macos::ax`]; the bounding, compaction, and — most importantly — the coordinate
//! transform are here, with no TCC needed to test them.
//!
//! ## The one invariant that matters
//!
//! Node bounds are emitted in the **same coordinate space as the screenshot's
//! `coordinate_width/height`**, so a model can address an `element_index` and an `x,y` in one
//! space (doc §7.3: "this is the Linux crate's most important lesson"). The accessibility API
//! reports element bounds in **global screen points, top-left origin** — the same origin
//! convention as the image — so the transform is a pure translate-then-scale: subtract the
//! capture region's origin (points) and multiply by its points→pixels [`CoordTransform::scale`]
//! (the content filter's `pointPixelScale`). No axis flip: AX and ScreenCaptureKit agree on
//! top-left. When there is no screenshot (`include_image=false`) the caller uses an identity
//! scale over the window's point origin, and bounds come back in window points.

use crate::geometry::{Point, Rect};
use serde_json::{json, Value};

/// The maximum length, in characters, of an emitted node `name`. AX names can be a whole text
/// field's contents (doc §9), so they are bounded before they reach the model or an event.
const MAX_NAME_CHARS: usize = 256;

/// Roles whose elements are treated as editable even when the AX value is not reported
/// settable (a field can be disabled, or its settability unqueryable, yet still be a text
/// input the model should recognise).
const EDITABLE_ROLES: &[&str] = &[
    "AXTextField",
    "AXTextArea",
    "AXComboBox",
    "AXSearchField",
    "AXSecureTextField",
];

/// One accessibility element as read from the host, before shaping. `value` is already `None`
/// for secure fields — the FFI never reads `AXValue` of a secure text field (doc §7.3), and
/// [`flatten`] enforces the same belt regardless.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawAxNode {
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub value: Option<String>,
    pub value_settable: bool,
    pub enabled: bool,
    pub focused: bool,
    pub secure: bool,
    pub actions: Vec<String>,
    /// Element bounds in global screen points (top-left origin), or `None` if the element
    /// does not report a position and size.
    pub bounds: Option<Rect>,
    pub children: Vec<RawAxNode>,
}

/// The translate-then-scale from global screen points to screenshot coordinate space.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoordTransform {
    /// The capture region's top-left in global points (the content filter's `contentRect`
    /// origin for a window capture, or the display/window origin otherwise).
    pub origin: Point,
    /// Points → coordinate-space pixels (the content filter's `pointPixelScale`; `1.0` when
    /// there is no screenshot and bounds stay in points).
    pub scale: f64,
}

impl CoordTransform {
    /// An identity transform in point space (origin at the global 0,0, scale 1) — a test
    /// convenience. Production paths build the transform from the capture's `contentRect`
    /// origin and `pointPixelScale`, or from the window origin at scale 1 when there is no
    /// screenshot, so nothing outside tests needs this.
    #[cfg(test)]
    pub fn identity() -> Self {
        Self {
            origin: Point::new(0.0, 0.0),
            scale: 1.0,
        }
    }

    /// Maps a global-point rect into coordinate space.
    fn apply(&self, rect: Rect) -> Rect {
        Rect::new(
            (rect.x - self.origin.x) * self.scale,
            (rect.y - self.origin.y) * self.scale,
            rect.w * self.scale,
            rect.h * self.scale,
        )
    }
}

/// The caller-supplied bounds on the emitted tree (doc §7.3: `max_nodes`, `max_depth`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Limits {
    pub max_nodes: usize,
    pub max_depth: usize,
}

/// The shaped tree: the dense-indexed node list and the focused element (if any), ready to be
/// dropped into the `state` response.
pub struct Shaped {
    pub nodes: Vec<Value>,
    pub focused_element: Option<Value>,
    /// True when the walk hit `max_nodes` and stopped emitting — surfaced as a warning so the
    /// model knows the tree is partial.
    pub truncated: bool,
}

/// Flattens a raw AX tree into the emitted node list.
///
/// Pre-order, dense 0-based indices over **emitted** nodes. A node is emitted when it has a
/// role (role-less wrapper elements are "ignored" per §7.3 but their descendants are still
/// visited, so nothing real is lost under one). Descent stops at `max_depth`; emission stops
/// at `max_nodes` (further nodes are not emitted, and `truncated` is set).
pub fn flatten(root: &RawAxNode, limits: &Limits, transform: &CoordTransform) -> Shaped {
    let mut nodes = Vec::new();
    let mut focused_element = None;
    let mut truncated = false;

    walk(
        root,
        0,
        limits,
        transform,
        &mut nodes,
        &mut focused_element,
        &mut truncated,
    );

    Shaped {
        nodes,
        focused_element,
        truncated,
    }
}

#[allow(clippy::too_many_arguments)]
fn walk(
    node: &RawAxNode,
    depth: usize,
    limits: &Limits,
    transform: &CoordTransform,
    nodes: &mut Vec<Value>,
    focused_element: &mut Option<Value>,
    truncated: &mut bool,
) {
    if depth > limits.max_depth {
        return;
    }

    // Emit this node if it carries a role; role-less nodes are skipped but still descended.
    let role = node.role.as_deref().filter(|r| !r.is_empty());
    if let Some(role) = role {
        if nodes.len() >= limits.max_nodes {
            *truncated = true;
            return;
        }

        let index = nodes.len();
        let name = node_name(node);
        let editable = is_editable(node);
        let states = node_states(node);
        let bounds = node.bounds.map(|b| transform.apply(b));

        if node.focused && focused_element.is_none() {
            *focused_element = Some(json!({
                "index": index,
                "role": role,
                "name": name,
                "editable": editable,
            }));
        }

        nodes.push(json!({
            "index": index,
            "role": role,
            "name": name,
            "actions": node.actions,
            "editable": editable,
            "bounds": bounds.map(|b| bounds_json(&b)),
            "states": states,
        }));
    }

    for child in &node.children {
        if nodes.len() >= limits.max_nodes {
            *truncated = true;
            break;
        }
        walk(
            child,
            depth + 1,
            limits,
            transform,
            nodes,
            focused_element,
            truncated,
        );
    }
}

/// A node's label: `AXTitle`, else `AXDescription`, else — only for a non-secure element — its
/// `AXValue`, so a text field shows its contents. Always length-bounded. Secure fields never
/// contribute a value (belt over the FFI, which already refuses to read it).
fn node_name(node: &RawAxNode) -> Option<String> {
    let raw = node
        .title
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(node.description.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| {
            if node.secure {
                None
            } else {
                node.value.as_deref().filter(|s| !s.is_empty())
            }
        })?;

    Some(truncate_chars(raw, MAX_NAME_CHARS))
}

fn is_editable(node: &RawAxNode) -> bool {
    if node.value_settable {
        return true;
    }
    match node.role.as_deref() {
        Some(role) => EDITABLE_ROLES.contains(&role),
        None => false,
    }
}

fn node_states(node: &RawAxNode) -> Vec<&'static str> {
    let mut states = Vec::new();
    if node.focused {
        states.push("focused");
    }
    if !node.enabled {
        states.push("disabled");
    }
    if node.secure {
        states.push("secure");
    }
    states
}

/// Bounds serialize as integers in coordinate space (the image is whole pixels).
fn bounds_json(rect: &Rect) -> Value {
    json!({
        "x": rect.x.round() as i64,
        "y": rect.y.round() as i64,
        "w": rect.w.round() as i64,
        "h": rect.h.round() as i64,
    })
}

/// Truncates to at most `max` characters on a char boundary (never mid-codepoint).
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(role: &str, title: &str) -> RawAxNode {
        RawAxNode {
            role: Some(role.into()),
            title: Some(title.into()),
            enabled: true,
            ..Default::default()
        }
    }

    fn limits(max_nodes: usize, max_depth: usize) -> Limits {
        Limits {
            max_nodes,
            max_depth,
        }
    }

    #[test]
    fn dense_preorder_indices() {
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("Calculator".into()),
            enabled: true,
            children: vec![leaf("AXButton", "2"), leaf("AXButton", "+")],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes.len(), 3);
        assert_eq!(shaped.nodes[0]["index"], 0);
        assert_eq!(shaped.nodes[0]["role"], "AXWindow");
        assert_eq!(shaped.nodes[1]["index"], 1);
        assert_eq!(shaped.nodes[1]["role"], "AXButton");
        assert_eq!(shaped.nodes[1]["name"], "2");
        assert_eq!(shaped.nodes[2]["index"], 2);
        assert_eq!(shaped.nodes[2]["name"], "+");
        assert!(!shaped.truncated);
    }

    #[test]
    fn roleless_nodes_are_skipped_but_descended() {
        // A wrapper with no role holds a real button; the button must still be emitted, and
        // the indices must stay dense (no gap for the skipped wrapper).
        let wrapper = RawAxNode {
            role: None,
            children: vec![leaf("AXButton", "ok")],
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![wrapper],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes.len(), 2);
        assert_eq!(shaped.nodes[0]["role"], "AXWindow");
        assert_eq!(shaped.nodes[1]["role"], "AXButton");
        assert_eq!(shaped.nodes[1]["index"], 1);
    }

    #[test]
    fn max_nodes_truncates() {
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![
                leaf("AXButton", "a"),
                leaf("AXButton", "b"),
                leaf("AXButton", "c"),
            ],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(2, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes.len(), 2);
        assert!(shaped.truncated);
    }

    #[test]
    fn max_depth_bounds_descent() {
        let deep = RawAxNode {
            role: Some("AXGroup".into()),
            title: Some("g2".into()),
            enabled: true,
            children: vec![leaf("AXButton", "deep")],
            ..Default::default()
        };
        let mid = RawAxNode {
            role: Some("AXGroup".into()),
            title: Some("g1".into()),
            enabled: true,
            children: vec![deep],
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![mid],
            ..Default::default()
        };
        // Depth 0=window, 1=g1, 2=g2; max_depth 1 emits window + g1 only.
        let shaped = flatten(&root, &limits(100, 1), &CoordTransform::identity());
        let roles: Vec<_> = shaped
            .nodes
            .iter()
            .map(|n| n["role"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(roles, vec!["AXWindow", "AXGroup"]);
    }

    #[test]
    fn secure_field_value_is_never_a_name() {
        // Even if a value slipped through, a secure node must not surface it as its name.
        let node = RawAxNode {
            role: Some("AXSecureTextField".into()),
            value: Some("hunter2".into()),
            secure: true,
            enabled: true,
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert!(shaped.nodes[1]["name"].is_null(), "no secret in name");
        let states = shaped.nodes[1]["states"].as_array().unwrap();
        assert!(states.iter().any(|s| s == "secure"));
        // A secure text field is still editable by role.
        assert_eq!(shaped.nodes[1]["editable"], true);
    }

    #[test]
    fn value_fills_name_when_no_title_and_not_secure() {
        let node = RawAxNode {
            role: Some("AXTextField".into()),
            value: Some("typed text".into()),
            enabled: true,
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes[1]["name"], "typed text");
    }

    #[test]
    fn name_is_length_bounded() {
        let long: String = "x".repeat(1000);
        let node = RawAxNode {
            role: Some("AXStaticText".into()),
            title: Some(long),
            enabled: true,
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        let name = shaped.nodes[1]["name"].as_str().unwrap();
        assert_eq!(name.chars().count(), MAX_NAME_CHARS);
    }

    #[test]
    fn disabled_and_focused_states() {
        let node = RawAxNode {
            role: Some("AXButton".into()),
            title: Some("go".into()),
            enabled: false,
            focused: true,
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        let states = shaped.nodes[1]["states"].as_array().unwrap();
        assert!(states.iter().any(|s| s == "focused"));
        assert!(states.iter().any(|s| s == "disabled"));
        // focused_element points at the focused node.
        let fe = shaped.focused_element.unwrap();
        assert_eq!(fe["index"], 1);
        assert_eq!(fe["role"], "AXButton");
    }

    #[test]
    fn editable_by_settable_value() {
        let node = RawAxNode {
            role: Some("AXUnknownInput".into()),
            title: Some("x".into()),
            value_settable: true,
            enabled: true,
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes[1]["editable"], true);
    }

    #[test]
    fn transform_translates_then_scales_into_coordinate_space() {
        // A window content rect origin at (100,120) points, retina scale 2.0. A button whose
        // global-point bounds are (140,160,32,32) maps to ((140-100)*2, (160-120)*2, 64, 64).
        let node = RawAxNode {
            role: Some("AXButton".into()),
            title: Some("2".into()),
            enabled: true,
            bounds: Some(Rect::new(140.0, 160.0, 32.0, 32.0)),
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            bounds: Some(Rect::new(100.0, 120.0, 240.0, 320.0)),
            children: vec![node],
            ..Default::default()
        };
        let transform = CoordTransform {
            origin: Point::new(100.0, 120.0),
            scale: 2.0,
        };
        let shaped = flatten(&root, &limits(100, 32), &transform);
        assert_eq!(
            shaped.nodes[0]["bounds"],
            json!({ "x": 0, "y": 0, "w": 480, "h": 640 })
        );
        assert_eq!(
            shaped.nodes[1]["bounds"],
            json!({ "x": 80, "y": 80, "w": 64, "h": 64 })
        );
    }

    #[test]
    fn missing_bounds_serialize_null() {
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            bounds: None,
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert!(shaped.nodes[0]["bounds"].is_null());
    }

    #[test]
    fn actions_pass_through() {
        let node = RawAxNode {
            role: Some("AXButton".into()),
            title: Some("2".into()),
            enabled: true,
            actions: vec!["AXPress".into()],
            ..Default::default()
        };
        let root = RawAxNode {
            role: Some("AXWindow".into()),
            title: Some("W".into()),
            enabled: true,
            children: vec![node],
            ..Default::default()
        };
        let shaped = flatten(&root, &limits(100, 32), &CoordTransform::identity());
        assert_eq!(shaped.nodes[1]["actions"], json!(["AXPress"]));
    }
}
