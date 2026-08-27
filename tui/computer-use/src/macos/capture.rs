//! Screenshot capture via ScreenCaptureKit (doc §7.3, §7.6), and target resolution.
//!
//! Two stages, deliberately split so the denied-app belt sits between them (doc §7.3: refuse a
//! denied app *before* capturing):
//!   * [`resolve`] identifies the target window from `CGWindowList` alone — no Screen Recording,
//!     no ScreenCaptureKit — yielding the bundle id the caller's belt is checked against.
//!   * [`grab`] then captures that window's pixels through an `SCWindow` content filter.
//!
//! ## Review amendment Δ8: capture never raises the window
//!
//! The content filter is built with `initWithDesktopIndependentWindow:`, and the capture is a
//! one-shot `SCScreenshotManager` call. Neither raises, activates, nor reorders the window — a
//! read must not mutate the desktop's stacking. No activation/ordering API is called anywhere
//! in this file.
//!
//! ## Async made synchronous
//!
//! ScreenCaptureKit delivers `SCShareableContent` and the captured `CGImage` through completion
//! blocks that run on its own queue. Each stage waits on a bounded channel: the shareable-content
//! block retains the object and smuggles its pointer to the request thread; the capture block
//! converts the `CGImage` to RGBA in place and sends only plain bytes (so no Objective-C object
//! crosses the thread boundary). One request is ever in flight (doc §7.5), so a single wait per
//! stage is all that is needed.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_core_foundation::{CFRetained, CGPoint, CGRect, CGSize};
use objc2_core_graphics::{
    CGColorSpace, CGContext, CGImage, CGImageAlphaInfo, CGImageByteOrderInfo,
};
use objc2_foundation::NSError;
use objc2_screen_capture_kit::{
    SCContentFilter, SCScreenshotManager, SCShareableContent, SCStreamConfiguration, SCWindow,
};

use crate::geometry::{Point, Rect};
use crate::state::{Target, WindowInfo};
use crate::windows::{self, RawWindow};

/// Internal belt timeouts so a wedged ScreenCaptureKit call cannot hang the serve loop. Elixir
/// enforces the real `state_timeout_ms`; these only bound this process.
const SHAREABLE_TIMEOUT: Duration = Duration::from_secs(8);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(8);

/// A target resolved to a concrete window via `CGWindowList` — enough to run the denied-app
/// belt and to walk the accessibility tree, before any capture.
#[derive(Clone, Debug, PartialEq)]
pub struct Resolved {
    pub app_id: String,
    pub app_name: String,
    pub pid: i32,
    pub cg_window_id: u32,
    pub window_title: Option<String>,
    /// Window bounds in global screen points (top-left origin).
    pub window_bounds: Rect,
    pub window_focused: bool,
}

impl Resolved {
    /// The window's global top-left, used as the identity coordinate origin when there is no
    /// screenshot to define a pixel space.
    pub fn window_origin(&self) -> Point {
        Point::new(self.window_bounds.x, self.window_bounds.y)
    }

    /// The `window` block for the `state` response.
    pub fn window_info(&self) -> Option<WindowInfo> {
        Some(WindowInfo {
            id: windows::mint_id(self.cg_window_id),
            title: self.window_title.clone(),
            focused: self.window_focused,
            bounds: self.window_bounds,
        })
    }
}

/// A captured frame: native-resolution RGBA plus the coordinate transform that maps global AX
/// points into this frame's pixel space.
pub struct Grabbed {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// The capture region's top-left in global points.
    pub content_origin: Point,
    /// Points → captured pixels, derived from the actual returned image so node bounds land
    /// exactly (guards against any rounding between the requested and delivered pixel size).
    pub point_pixel_scale: f64,
}

/// Resolves a caller's target to a concrete on-screen window using `CGWindowList` only.
///
/// Selection is the frontmost window matching every named filter (app, title, pid,
/// window_id AND'd). Untargeted capture is refused.
pub fn resolve(target: &Target) -> Result<Resolved, String> {
    let all = super::windows::enumerate()?;
    let chosen = choose_window(&all, target)
        .ok_or_else(|| "no matching window found; call windows to list them".to_string())?;

    let app_id = chosen
        .app_id
        .clone()
        .or_else(|| chosen.app_name.clone())
        .unwrap_or_else(|| format!("pid:{}", chosen.pid));
    let app_name = chosen.app_name.clone().unwrap_or_else(|| app_id.clone());

    Ok(Resolved {
        app_id,
        app_name,
        pid: chosen.pid,
        cg_window_id: chosen.window_id,
        window_title: chosen.title.clone(),
        window_bounds: chosen.bounds,
        window_focused: is_frontmost_normal(&all, chosen.window_id),
    })
}

/// Picks the target window from the front-to-back list (see [`resolve`]).
///
/// Every named filter is AND'd: a `window_id` of Mail with `app_id` Safari is not a
/// match. Untargeted capture (no app, window, title, or pid) is refused — Elixir already
/// requires a target; this is the helper's own belt.
fn choose_window<'a>(all: &'a [RawWindow], target: &Target) -> Option<&'a RawWindow> {
    let has_filter = target.window_id.is_some()
        || target.app_id.is_some()
        || target.title.is_some()
        || target.pid.is_some();
    if !has_filter {
        return None;
    }
    all.iter().find(|w| matches_target(w, target))
}

fn matches_target(window: &RawWindow, target: &Target) -> bool {
    if let Some(id) = target.window_id.as_deref().and_then(windows::parse_id) {
        if window.window_id != id {
            return false;
        }
    }
    if let Some(pid) = target.pid {
        if window.pid != pid {
            return false;
        }
    }
    if let Some(app) = target.app_id.as_deref() {
        let bundle_hit = window
            .app_id
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case(app));
        let name_hit = window
            .app_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(app));
        if !bundle_hit && !name_hit {
            return false;
        }
    }
    if let Some(title) = target.title.as_deref() {
        let hit = window
            .title
            .as_deref()
            .is_some_and(|t| t.to_lowercase().contains(&title.to_lowercase()));
        if !hit {
            return false;
        }
    }
    true
}

/// Whether `cg_window_id` is the frontmost normal window (the focus heuristic, doc §7.2).
fn is_frontmost_normal(all: &[RawWindow], cg_window_id: u32) -> bool {
    all.iter()
        .find(|w| w.on_screen && w.layer == 0)
        .is_some_and(|w| w.window_id == cg_window_id)
}

/// Captures the resolved window's pixels through an `SCWindow` content filter (never raising it).
pub fn grab(resolved: &Resolved) -> Result<Grabbed, String> {
    let content = shareable_content()?;

    // Find the SCWindow for the resolved CGWindowID.
    let windows = unsafe { content.windows() };
    let mut target: Option<Retained<SCWindow>> = None;
    for window in windows.iter() {
        if unsafe { window.windowID() } == resolved.cg_window_id {
            target = Some(window);
            break;
        }
    }
    let window = target.ok_or_else(|| {
        "the window is not shareable (is Screen Recording granted to ouro-computer-use?)"
            .to_string()
    })?;

    // Content filter for just this window — the API that captures it without raising (Δ8).
    let filter = unsafe {
        SCContentFilter::initWithDesktopIndependentWindow(SCContentFilter::alloc(), &window)
    };
    let content_rect = unsafe { filter.contentRect() };
    let point_scale = unsafe { filter.pointPixelScale() } as f64;
    if content_rect.size.width <= 0.0 || content_rect.size.height <= 0.0 {
        return Err("resolved window has an empty content rect".to_string());
    }

    // Request native-resolution output (points × pointPixelScale).
    let config = unsafe { SCStreamConfiguration::new() };
    let px_width = (content_rect.size.width * point_scale).round().max(1.0) as usize;
    let px_height = (content_rect.size.height * point_scale).round().max(1.0) as usize;
    unsafe {
        config.setWidth(px_width);
        config.setHeight(px_height);
        config.setShowsCursor(false);
    }

    let bitmap = capture_image(&filter, &config)?;

    // Derive the exact points→pixels scale from the delivered image, so AX bounds land precisely.
    let scale_x = bitmap.width as f64 / content_rect.size.width;

    Ok(Grabbed {
        rgba: bitmap.rgba,
        width: bitmap.width,
        height: bitmap.height,
        content_origin: Point::new(content_rect.origin.x, content_rect.origin.y),
        point_pixel_scale: scale_x,
    })
}

/// Plain (Send) capture result: no Objective-C object crosses the completion-block boundary.
struct Bitmap {
    rgba: Vec<u8>,
    width: u32,
    height: u32,
}

fn shareable_content() -> Result<Retained<SCShareableContent>, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<super::SendPtr, String>>(1);

    let block = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: the completion contract hands a valid content object xor a valid error.
            let message = if let Some(error) = unsafe { error.as_ref() } {
                Err(super::nserror_message(error))
            } else if let Some(content) = NonNull::new(content) {
                // Retain (+1) and hand the raw pointer to the waiting thread, which reclaims it.
                match unsafe { Retained::retain(content.as_ptr()) } {
                    Some(retained) => Ok(super::SendPtr(Retained::into_raw(retained).cast())),
                    None => Err("could not retain shareable content".to_string()),
                }
            } else {
                Err("shareable content was null".to_string())
            };
            let _ = tx.send(message);
        },
    );

    // SAFETY: standard ScreenCaptureKit entry point; the block outlives the async call because
    // this frame blocks on `rx` until it has fired.
    unsafe {
        SCShareableContent::getShareableContentWithCompletionHandler(&block);
    }

    let sent = rx
        .recv_timeout(SHAREABLE_TIMEOUT)
        .map_err(|_| "timed out waiting for shareable content".to_string())??;

    let ptr = sent.0 as *mut SCShareableContent;
    // SAFETY: `ptr` is the +1 pointer the block handed over; `from_raw` takes that ownership.
    unsafe { Retained::from_raw(ptr) }.ok_or_else(|| "null shareable content".to_string())
}

fn capture_image(
    filter: &SCContentFilter,
    config: &SCStreamConfiguration,
) -> Result<Bitmap, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Bitmap, String>>(1);

    let block = RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
        // SAFETY: the completion contract hands a valid image xor a valid error. The CGImage is
        // converted to bytes here, on the delivery thread, so nothing Objective-C is sent.
        let message = if let Some(error) = unsafe { error.as_ref() } {
            Err(super::nserror_message(error))
        } else if let Some(image) = unsafe { image.as_ref() } {
            cgimage_to_rgba(image)
        } else {
            Err("capture returned no image".to_string())
        };
        let _ = tx.send(message);
    });

    // SAFETY: standard one-shot capture; the block outlives the call because this frame blocks
    // on `rx` until it fires.
    unsafe {
        SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
            filter,
            config,
            Some(&block),
        );
    }

    rx.recv_timeout(CAPTURE_TIMEOUT)
        .map_err(|_| "timed out waiting for screenshot".to_string())?
}

/// Redraws a `CGImage` into a tightly packed RGBA8 buffer via a bitmap context. The context's
/// `PremultipliedLast | Order32Big` format lays bytes out as R,G,B,A on every architecture,
/// regardless of the source image's native (BGRA) layout.
fn cgimage_to_rgba(image: &CGImage) -> Result<Bitmap, String> {
    let width = CGImage::width(Some(image));
    let height = CGImage::height(Some(image));
    if width == 0 || height == 0 {
        return Err("captured image has a zero dimension".to_string());
    }

    let color_space =
        CGColorSpace::new_device_rgb().ok_or_else(|| "no device RGB color space".to_string())?;
    let bytes_per_row = width
        .checked_mul(4)
        .ok_or_else(|| "image row overflow".to_string())?;
    let len = bytes_per_row
        .checked_mul(height)
        .ok_or_else(|| "image size overflow".to_string())?;
    let mut buffer = vec![0u8; len];

    let bitmap_info = CGImageAlphaInfo::PremultipliedLast.0 | CGImageByteOrderInfo::Order32Big.0;

    // SAFETY: a valid buffer of exactly `bytes_per_row * height`, a live color space, and the
    // documented 8-bit RGBA parameters. `CGBitmapContextCreate` draws into our buffer.
    let context = unsafe {
        let raw = CGBitmapContextCreate(
            buffer.as_mut_ptr() as *mut c_void,
            width,
            height,
            8,
            bytes_per_row,
            &*color_space as *const CGColorSpace,
            bitmap_info,
        );
        NonNull::new(raw).map(|p| CFRetained::from_raw(p))
    }
    .ok_or_else(|| "could not create bitmap context".to_string())?;

    let rect = CGRect {
        origin: CGPoint { x: 0.0, y: 0.0 },
        size: CGSize {
            width: width as f64,
            height: height as f64,
        },
    };
    CGContext::draw_image(Some(&context), rect, Some(image));

    Ok(Bitmap {
        rgba: buffer,
        width: width as u32,
        height: height as u32,
    })
}

// The classic bitmap-context constructor objc2-core-graphics 0.3 does not wrap (it exposes only
// the block-based `CGBitmapContextCreateAdaptive`). Declared directly, matching the crate's
// existing raw-`#[link]` idiom for CoreGraphics symbols.
extern "C" {
    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits_per_component: usize,
        bytes_per_row: usize,
        space: *const CGColorSpace,
        bitmap_info: u32,
    ) -> *mut CGContext;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(id: u32, pid: i32, app_id: &str, name: &str, title: &str, layer: i64) -> RawWindow {
        RawWindow {
            window_id: id,
            pid,
            app_id: Some(app_id.into()),
            app_name: Some(name.into()),
            title: Some(title.into()),
            layer,
            bounds: Rect::new(0.0, 0.0, 100.0, 100.0),
            on_screen: true,
        }
    }

    #[test]
    fn chooses_by_window_id() {
        let all = vec![win(1, 10, "a", "A", "t", 0), win(2, 20, "b", "B", "t", 0)];
        let target = Target {
            window_id: Some("w_2".into()),
            ..Default::default()
        };
        assert_eq!(choose_window(&all, &target).unwrap().window_id, 2);
    }

    #[test]
    fn chooses_frontmost_matching_app_by_bundle_or_name() {
        let all = vec![
            win(1, 10, "com.apple.Safari", "Safari", "Home", 0),
            win(2, 20, "com.apple.mail", "Mail", "Inbox", 0),
        ];
        let by_bundle = Target {
            app_id: Some("com.apple.mail".into()),
            ..Default::default()
        };
        assert_eq!(choose_window(&all, &by_bundle).unwrap().window_id, 2);
        let by_name = Target {
            app_id: Some("Safari".into()),
            ..Default::default()
        };
        assert_eq!(choose_window(&all, &by_name).unwrap().window_id, 1);
    }

    #[test]
    fn title_filter_is_case_insensitive_substring() {
        let all = vec![
            win(1, 10, "a", "A", "Untitled", 0),
            win(2, 10, "a", "A", "My Document", 0),
        ];
        let target = Target {
            title: Some("document".into()),
            ..Default::default()
        };
        assert_eq!(choose_window(&all, &target).unwrap().window_id, 2);
    }

    #[test]
    fn window_id_is_anded_with_app() {
        let all = vec![win(1, 10, "a", "A", "t", 0), win(2, 20, "b", "B", "t", 0)];
        let target = Target {
            window_id: Some("w_2".into()),
            app_id: Some("a".into()),
            ..Default::default()
        };
        assert!(choose_window(&all, &target).is_none());
        let matching = Target {
            window_id: Some("w_2".into()),
            app_id: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(choose_window(&all, &matching).unwrap().window_id, 2);
    }

    #[test]
    fn no_target_is_refused() {
        let all = vec![
            win(1, 10, "a", "A", "overlay", 25),
            win(2, 20, "b", "B", "doc", 0),
        ];
        assert!(choose_window(&all, &Target::default()).is_none());
    }

    #[test]
    fn no_match_returns_none() {
        let all = vec![win(1, 10, "a", "A", "t", 0)];
        let target = Target {
            app_id: Some("com.absent".into()),
            ..Default::default()
        };
        assert!(choose_window(&all, &target).is_none());
    }
}
