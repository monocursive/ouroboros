//! `state` (doc §5.2, §7.3): the observe primitive — a size-bounded screenshot plus a compact
//! accessibility tree for one app or window, in one shared coordinate space.
//!
//! The request parsing, the config-shaped clamping, the denied-app belt, and the response
//! assembly all live here as pure functions and are unit-tested with no TCC. The macOS
//! orchestration ([`handle`], gated to `target_os = "macos"`) wires them to
//! [`crate::macos::capture`] (ScreenCaptureKit) and [`crate::macos::ax`] (AXUIElement); a
//! non-macOS build compiles the honest "only supported on macOS" path instead.
//!
//! ## Review amendment Δ8: observe never raises the target
//!
//! `state` is read-mode. Capturing must not raise or activate the target window —
//! ScreenCaptureKit captures an unraised window through an `SCWindow` content filter, so the
//! macOS path uses that filter and never calls an activation/ordering API. If only a
//! full-display capture were possible, it would crop to the window (or say so in `warnings`)
//! rather than bring the window forward. Raising a window would make a read mutate the
//! desktop's stacking order, which this tool must never do.

use crate::screenshot::Format;
use serde_json::{json, Value};

/// Defaults and belt ceilings, shaped like the `:computer_use` config (doc §4). Elixir clamps
/// requests to its config maxima before sending; these are the helper's own belt, so an
/// out-of-range field can never widen a bound past what this process will do.
mod caps {
    pub const DEFAULT_MAX_WIDTH: u32 = 1920;
    pub const DEFAULT_MAX_HEIGHT: u32 = 1920;
    pub const CEIL_MAX_WIDTH: u32 = 8192;
    pub const CEIL_MAX_HEIGHT: u32 = 8192;

    pub const DEFAULT_MAX_BYTES: usize = 2 * 1024 * 1024;
    pub const CEIL_MAX_BYTES: usize = 16 * 1024 * 1024;

    pub const DEFAULT_MAX_NODES: usize = 1_000;
    pub const CEIL_MAX_NODES: usize = 10_000;
    pub const DEFAULT_MAX_DEPTH: usize = 32;
    pub const CEIL_MAX_DEPTH: usize = 128;

    pub const DEFAULT_QUALITY: u8 = 80;
}

/// A resolved capture target as the caller named it. Any subset may be present; the helper
/// resolves it against the live windows (doc §7.3 request `target`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Target {
    pub app_id: Option<String>,
    pub window_id: Option<String>,
    pub title: Option<String>,
    pub pid: Option<i32>,
}

/// A parsed, clamped `state` request.
#[derive(Clone, Debug, PartialEq)]
pub struct StateRequest {
    pub target: Target,
    pub include_image: bool,
    pub max_width: u32,
    pub max_height: u32,
    pub max_bytes: usize,
    pub format: Format,
    pub quality: u8,
    pub max_nodes: usize,
    pub max_depth: usize,
}

impl StateRequest {
    /// Parses the JSON-RPC `params` into a request, filling defaults and clamping every number
    /// to the helper's belt ceilings. Unknown or malformed fields fall back to defaults rather
    /// than failing — Elixir is the authority on request validity; the helper is defensive.
    pub fn from_params(params: &Value) -> Self {
        let target = params.get("target").map(target_from).unwrap_or_default();

        let include_image = params
            .get("include_image")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let max_width = clamp_u32(
            params.get("max_width"),
            caps::DEFAULT_MAX_WIDTH,
            1,
            caps::CEIL_MAX_WIDTH,
        );
        let max_height = clamp_u32(
            params.get("max_height"),
            caps::DEFAULT_MAX_HEIGHT,
            1,
            caps::CEIL_MAX_HEIGHT,
        );
        let max_bytes = clamp_usize(
            params.get("max_bytes"),
            caps::DEFAULT_MAX_BYTES,
            1,
            caps::CEIL_MAX_BYTES,
        );

        let format = match params.get("format").and_then(Value::as_str) {
            Some("png") => Format::Png,
            _ => Format::Jpeg,
        };
        let quality = params
            .get("quality")
            .and_then(Value::as_u64)
            .map(|q| q.clamp(1, 95) as u8)
            .unwrap_or(caps::DEFAULT_QUALITY);

        let max_nodes = clamp_usize(
            params.get("max_nodes"),
            caps::DEFAULT_MAX_NODES,
            1,
            caps::CEIL_MAX_NODES,
        );
        let max_depth = clamp_usize(
            params.get("max_depth"),
            caps::DEFAULT_MAX_DEPTH,
            1,
            caps::CEIL_MAX_DEPTH,
        );

        Self {
            target,
            include_image,
            max_width,
            max_height,
            max_bytes,
            format,
            quality,
            max_nodes,
            max_depth,
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

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn clamp_u32(value: Option<&Value>, default: u32, lo: u32, hi: u32) -> u32 {
    match value.and_then(Value::as_u64) {
        Some(n) => (n as u32).clamp(lo, hi),
        None => default,
    }
}

fn clamp_usize(value: Option<&Value>, default: usize, lo: usize, hi: usize) -> usize {
    match value.and_then(Value::as_u64) {
        Some(n) => (n as usize).clamp(lo, hi),
        None => default,
    }
}

/// The denied-app belt (doc §7.3): whether a resolved bundle id is on the helper's
/// `--deny-app` list. Comparison is case-insensitive — a belt errs toward refusing, and TCC
/// treats bundle ids case-insensitively — so a case-shifted id can never slip a denied app
/// past the helper even if Elixir's own denylist were incomplete.
pub fn is_denied(app_id: &str, deny_list: &[String]) -> bool {
    deny_list
        .iter()
        .any(|denied| denied.eq_ignore_ascii_case(app_id))
}

/// The resolved app identity for the `state` response.
#[derive(Clone, Debug, PartialEq)]
pub struct AppInfo {
    pub id: String,
    pub name: String,
    pub pid: i32,
}

/// The resolved window for the `state` response. Absent for a full-display capture.
#[derive(Clone, Debug, PartialEq)]
pub struct WindowInfo {
    pub id: String,
    pub title: Option<String>,
    pub focused: bool,
    pub bounds: crate::geometry::Rect,
}

/// The staged screenshot's metadata (doc §7.3 `image`). `path` is the `0600` temp the helper
/// wrote; Elixir stages and unlinks it.
#[derive(Clone, Debug, PartialEq)]
pub struct ImageMeta {
    pub path: String,
    pub mime: String,
    pub bytes: usize,
    pub width: u32,
    pub height: u32,
    pub coordinate_width: u32,
    pub coordinate_height: u32,
    pub scale: f64,
    pub sha256: String,
}

/// The three readiness signals `state` reports (doc §7.3 `readiness`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Readiness {
    pub screenshot: &'static str,
    pub ax: &'static str,
    pub input: &'static str,
}

/// Assembles the full `state` response from its already-shaped parts. Pure: every macOS call
/// has happened by the time this runs, so the shape is testable without a capture.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    app: &AppInfo,
    window: Option<&WindowInfo>,
    image: Option<&ImageMeta>,
    nodes: Vec<Value>,
    focused_element: Option<Value>,
    readiness: Readiness,
    warnings: Vec<String>,
) -> Value {
    let mut response = json!({
        "app": {
            "id": app.id,
            "name": app.name,
            "pid": app.pid,
        },
        "window": window.map(window_json),
        "nodes": nodes,
        "focused_element": focused_element,
        "readiness": {
            "screenshot": readiness.screenshot,
            "ax": readiness.ax,
            "input": readiness.input,
        },
        "warnings": warnings,
    });

    if let Some(image) = image {
        response["image"] = image_json(image);
    }
    response
}

fn window_json(window: &WindowInfo) -> Value {
    json!({
        "id": window.id,
        "title": window.title,
        "focused": window.focused,
        "bounds": crate::windows::bounds_json(&window.bounds),
    })
}

fn image_json(image: &ImageMeta) -> Value {
    json!({
        "path": image.path,
        "mime": image.mime,
        "bytes": image.bytes,
        "width": image.width,
        "height": image.height,
        "coordinate_width": image.coordinate_width,
        "coordinate_height": image.coordinate_height,
        "scale": image.scale,
        "sha256": image.sha256,
    })
}

#[cfg(target_os = "macos")]
pub use imp::handle;

#[cfg(not(target_os = "macos"))]
pub fn handle(_deny_apps: &[String], _params: Value) -> Result<Value, (i64, String)> {
    Err((
        crate::server::UNSUPPORTED_PLATFORM,
        "state: Computer Use observe is only supported on macOS".to_string(),
    ))
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::server::{DENIED_APP, OBSERVE_ERROR};
    use crate::tree::{self, CoordTransform};

    /// Serves one `state` request against the live desktop.
    ///
    /// Order matters: resolve the target and its bundle id first, refuse a denied app **before**
    /// any capture (doc §7.3), then capture (never raising, Δ8), then walk AX. A failure at any
    /// step is an honest JSON-RPC error — never a partial or fabricated snapshot.
    pub fn handle(deny_apps: &[String], params: Value) -> Result<Value, (i64, String)> {
        let request = StateRequest::from_params(&params);

        let resolved = crate::macos::capture::resolve(&request.target)
            .map_err(|e| (OBSERVE_ERROR, format!("state: {e}")))?;

        if is_denied(&resolved.app_id, deny_apps) {
            return Err((
                DENIED_APP,
                format!(
                    "state: {} is on the helper's --deny-app list; refusing to capture",
                    resolved.app_id
                ),
            ));
        }

        let mut warnings: Vec<String> = Vec::new();

        // Screenshot (Δ8: the resolve/capture path never raises the window).
        let (image_meta, transform, screenshot_readiness) = if request.include_image {
            let grabbed = crate::macos::capture::grab(&resolved)
                .map_err(|e| (OBSERVE_ERROR, format!("state: capture failed: {e}")))?;

            let encoded = crate::screenshot::encode(
                &grabbed.rgba,
                grabbed.width,
                grabbed.height,
                &crate::screenshot::EncodeParams {
                    format: request.format,
                    quality: request.quality,
                    max_width: request.max_width,
                    max_height: request.max_height,
                    max_bytes: request.max_bytes,
                },
            )
            .map_err(|e| (OBSERVE_ERROR, format!("state: encode failed: {e}")))?;

            if !encoded.budget_met {
                warnings.push(format!(
                    "screenshot could not fit max_bytes ({}); returned {} bytes at {}x{}",
                    request.max_bytes,
                    encoded.bytes.len(),
                    encoded.width,
                    encoded.height
                ));
            }

            let scale = match crate::geometry::image_scale(
                (encoded.width as f64, encoded.height as f64),
                (grabbed.width as f64, grabbed.height as f64),
            ) {
                Ok(scale) => scale,
                // `sx`/`sy` are the per-axis coordinate÷payload ratios. Independent integer
                // rounding of the downscaled payload makes them differ by a hair on almost any
                // non-square frame — that is not anamorphism. Report the x-axis scale, and warn
                // only when the disagreement is large enough (>1%) to signal a real
                // capture-geometry problem the model should know about.
                Err(crate::geometry::ScaleError::Disagree { sx, sy }) => {
                    let relative = (sx - sy).abs() / sx.max(sy);
                    if relative > 0.01 {
                        warnings.push(format!(
                            "capture axes disagree by {:.1}%; reported scale is the x-axis ratio",
                            relative * 100.0
                        ));
                    }
                    sx
                }
                Err(crate::geometry::ScaleError::ZeroDimension) => {
                    return Err((
                        OBSERVE_ERROR,
                        "state: encoded image has a zero dimension".to_string(),
                    ));
                }
            };

            let sha = crate::screenshot::sha256_hex(&encoded.bytes);
            let path = write_temp_0600(&sha, encoded.format.extension(), &encoded.bytes)
                .map_err(|e| (OBSERVE_ERROR, format!("state: staging failed: {e}")))?;

            let meta = ImageMeta {
                path,
                mime: encoded.format.mime().to_string(),
                bytes: encoded.bytes.len(),
                width: encoded.width,
                height: encoded.height,
                coordinate_width: grabbed.width,
                coordinate_height: grabbed.height,
                scale,
                sha256: sha,
            };
            let transform = CoordTransform {
                origin: grabbed.content_origin,
                scale: grabbed.point_pixel_scale,
            };
            (Some(meta), transform, "ok")
        } else {
            // No pixels: node bounds come back in window points (identity pixel scale) around
            // the window's global origin, so element_index still has a defined space.
            let transform = CoordTransform {
                origin: resolved.window_origin(),
                scale: 1.0,
            };
            (None, transform, "skipped")
        };

        // Accessibility tree, rooted at the captured window so its bounds share one space.
        let (nodes, focused_element, ax_readiness) = if crate::macos::accessibility_trusted() {
            let root = crate::macos::ax::walk(
                resolved.pid,
                request.max_nodes,
                request.max_depth,
                Some(resolved.window_bounds),
            );
            let shaped = tree::flatten(
                &root,
                &tree::Limits {
                    max_nodes: request.max_nodes,
                    max_depth: request.max_depth,
                },
                &transform,
            );
            if shaped.truncated {
                warnings.push(format!(
                    "accessibility tree truncated at max_nodes ({})",
                    request.max_nodes
                ));
            }
            let readiness = if shaped.truncated { "partial" } else { "ok" };
            (shaped.nodes, shaped.focused_element, readiness)
        } else {
            warnings.push(
                "Accessibility is not granted to ouro-computer-use; no accessibility tree"
                    .to_string(),
            );
            (Vec::new(), None, "unavailable")
        };

        let input_readiness = if crate::macos::secure_event_input_enabled() {
            "blocked"
        } else if crate::macos::accessibility_trusted() {
            "ok"
        } else {
            "unavailable"
        };

        let app = AppInfo {
            id: resolved.app_id.clone(),
            name: resolved.app_name.clone(),
            pid: resolved.pid,
        };
        let window = resolved.window_info();

        Ok(assemble(
            &app,
            window.as_ref(),
            image_meta.as_ref(),
            nodes,
            focused_element,
            Readiness {
                screenshot: screenshot_readiness,
                ax: ax_readiness,
                input: input_readiness,
            },
            warnings,
        ))
    }

    /// Writes the encoded screenshot to a `0600` temp under `$TMPDIR` (`NSTemporaryDirectory`,
    /// doc §7.3). The helper does not delete it — Elixir stages then unlinks. The name embeds
    /// the sha so a stale file from a crashed run is self-identifying, and `0600` keeps other
    /// users off it before Elixir moves it into the session dir.
    fn write_temp_0600(sha: &str, ext: &str, bytes: &[u8]) -> std::io::Result<String> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let mut dir = std::env::temp_dir();
        dir.push("ouro-cu");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;

        let mut path = dir;
        path.push(format!("{sha}.{ext}"));

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        file.flush()?;

        Ok(path.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::Rect;

    #[test]
    fn defaults_when_params_empty() {
        let request = StateRequest::from_params(&json!({}));
        assert_eq!(request.include_image, true);
        assert_eq!(request.max_width, 1920);
        assert_eq!(request.max_height, 1920);
        assert_eq!(request.max_bytes, 2 * 1024 * 1024);
        assert_eq!(request.format, Format::Jpeg);
        assert_eq!(request.quality, 80);
        assert_eq!(request.max_nodes, 1000);
        assert_eq!(request.max_depth, 32);
        assert_eq!(request.target, Target::default());
    }

    #[test]
    fn parses_and_clamps() {
        let request = StateRequest::from_params(&json!({
            "target": { "app_id": "com.apple.calculator", "window_id": "w_12", "pid": 442 },
            "include_image": false,
            "max_width": 100000,
            "max_height": 3000,
            "max_bytes": 999999999999u64,
            "format": "png",
            "quality": 200,
            "max_nodes": 999999,
            "max_depth": 9999
        }));
        assert_eq!(request.include_image, false);
        assert_eq!(request.max_width, caps::CEIL_MAX_WIDTH);
        assert_eq!(request.max_height, 3000);
        assert_eq!(request.max_bytes, caps::CEIL_MAX_BYTES);
        assert_eq!(request.format, Format::Png);
        assert_eq!(request.quality, 95);
        assert_eq!(request.max_nodes, caps::CEIL_MAX_NODES);
        assert_eq!(request.max_depth, caps::CEIL_MAX_DEPTH);
        assert_eq!(
            request.target.app_id.as_deref(),
            Some("com.apple.calculator")
        );
        assert_eq!(request.target.window_id.as_deref(), Some("w_12"));
        assert_eq!(request.target.pid, Some(442));
    }

    #[test]
    fn blank_target_strings_are_dropped() {
        let request = StateRequest::from_params(&json!({
            "target": { "app_id": "   ", "title": "" }
        }));
        assert_eq!(request.target.app_id, None);
        assert_eq!(request.target.title, None);
    }

    #[test]
    fn deny_is_case_insensitive_exact() {
        let deny = vec!["com.apple.Terminal".to_string()];
        assert!(is_denied("com.apple.Terminal", &deny));
        assert!(is_denied("com.apple.terminal", &deny));
        assert!(!is_denied("com.apple.TerminalX", &deny));
        assert!(!is_denied("com.apple.Safari", &deny));
    }

    #[test]
    fn deny_empty_list_denies_nothing() {
        assert!(!is_denied("com.apple.Terminal", &[]));
    }

    #[test]
    fn assemble_shape_with_image() {
        let app = AppInfo {
            id: "com.apple.calculator".into(),
            name: "Calculator".into(),
            pid: 442,
        };
        let window = WindowInfo {
            id: "w_12".into(),
            title: Some("Calculator".into()),
            focused: true,
            bounds: Rect::new(100.0, 120.0, 240.0, 320.0),
        };
        let image = ImageMeta {
            path: "/tmp/ouro-cu/abc.jpg".into(),
            mime: "image/jpeg".into(),
            bytes: 81234,
            width: 480,
            height: 640,
            coordinate_width: 960,
            coordinate_height: 1280,
            scale: 2.0,
            sha256: "deadbeef".into(),
        };
        let nodes = vec![json!({ "index": 0, "role": "window" })];
        let response = assemble(
            &app,
            Some(&window),
            Some(&image),
            nodes,
            Some(json!({ "index": 1, "role": "button" })),
            Readiness {
                screenshot: "ok",
                ax: "ok",
                input: "ok",
            },
            vec!["hi".into()],
        );

        assert_eq!(response["app"]["id"], "com.apple.calculator");
        assert_eq!(response["app"]["pid"], 442);
        assert_eq!(response["window"]["id"], "w_12");
        assert_eq!(
            response["window"]["bounds"],
            json!({ "x": 100, "y": 120, "w": 240, "h": 320 })
        );
        assert_eq!(response["image"]["coordinate_width"], 960);
        assert_eq!(response["image"]["scale"], 2.0);
        assert_eq!(response["image"]["sha256"], "deadbeef");
        assert_eq!(response["readiness"]["ax"], "ok");
        assert_eq!(response["focused_element"]["index"], 1);
        assert_eq!(response["warnings"], json!(["hi"]));
        assert!(response["nodes"].is_array());
    }

    #[test]
    fn assemble_omits_image_and_window_when_absent() {
        let app = AppInfo {
            id: "com.example".into(),
            name: "Example".into(),
            pid: 7,
        };
        let response = assemble(
            &app,
            None,
            None,
            Vec::new(),
            None,
            Readiness {
                screenshot: "skipped",
                ax: "unavailable",
                input: "unavailable",
            },
            Vec::new(),
        );
        assert!(response.get("image").is_none(), "no image key when omitted");
        assert!(response["window"].is_null());
        assert!(response["focused_element"].is_null());
        assert_eq!(response["readiness"]["screenshot"], "skipped");
    }
}
