//! The accessibility-tree walk via `AXUIElement` (doc §7.3, §7.6).
//!
//! Produces the raw [`RawAxNode`] tree that [`crate::tree::flatten`] shapes; all bounding,
//! compaction, and coordinate mapping is that pure module's job. This one only reads the live
//! tree, honouring two rules from the contract as it goes:
//!   * **Never read `AXValue` of a secure text field** (doc §7.3): a node whose role or subrole
//!     is `AXSecureTextField` has its value left `None` here, before it is ever copied out.
//!   * **Bounds are global screen points, top-left origin** — read straight from `AXPosition`
//!     and `AXSize` and handed up untransformed, so the pure layer can place them in the
//!     screenshot's coordinate space (the single most important invariant, doc §7.3).
//!
//! Reading the tree requires the Accessibility grant; the caller checks that first and skips
//! this walk when it is missing (the response then carries an empty tree and a warning).

use std::ptr::NonNull;

use objc2_application_services::{AXUIElement, AXValue, AXValueType};
use objc2_core_foundation::{CFArray, CFBoolean, CFRetained, CFString, CFType, CGPoint, CGSize};

use crate::geometry::Rect;
use crate::macos::cfstr;
use crate::tree::RawAxNode;

/// How close (in points) a candidate `AXWindow`'s bounds must be to the resolved window's
/// bounds to be treated as the same window. A few points of slack absorbs title-bar/shadow
/// differences between the window-server rect and the AX rect.
const WINDOW_MATCH_TOLERANCE: f64 = 8.0;

/// Walks the accessibility tree for `pid`, rooted at the window matching `window_bounds` when
/// one is found (so the tree lines up with the captured window), else at the application
/// element. The returned tree is materialised eagerly and bounded by `max_depth` / `max_nodes`
/// so a pathological UI cannot make the walk unbounded; the pure layer re-applies the same
/// limits authoritatively.
pub fn walk(
    pid: i32,
    max_nodes: usize,
    max_depth: usize,
    window_bounds: Option<Rect>,
) -> RawAxNode {
    // SAFETY: `new_application` returns a valid application element for any pid (even a dead
    // one, whose later attribute reads simply fail and yield an empty node).
    let app = unsafe { AXUIElement::new_application(pid) };

    let mut budget = max_nodes.max(1);

    if let Some(bounds) = window_bounds {
        if let Some(root) = find_window_element(&app, bounds) {
            return build_node(&root, 0, max_depth, &mut budget);
        }
    }

    build_node(&app, 0, max_depth, &mut budget)
}

/// Finds the application's window element whose bounds match `target`, returning a *borrowed*
/// reference valid only while the returned array is alive — so the caller must consume it
/// immediately. Rather than juggle that lifetime, this returns nothing and callers that need to
/// keep the element root at it inside the same scope; see [`walk`], which builds the subtree
/// while the `AXWindows` array is still alive.
fn find_window_element(app: &AXUIElement, target: Rect) -> Option<WindowRoot<'_>> {
    let windows = copy_attr(app, &cfstr("AXWindows"))?;
    let array = windows.downcast_ref::<CFArray>()?;
    let count = array.count();
    for i in 0..count {
        // SAFETY: `i` in range; `AXWindows` holds `AXUIElement`s. Borrowed while `windows` lives.
        let element = unsafe { &*(array.value_at_index(i) as *const AXUIElement) };
        if let Some(bounds) = read_bounds(element) {
            if bounds_match(bounds, target) {
                return Some(WindowRoot {
                    _array: windows,
                    element,
                });
            }
        }
    }
    None
}

/// Keeps the `AXWindows` array alive alongside the borrowed window element, so the element
/// stays valid for the duration of the subtree build.
struct WindowRoot<'a> {
    _array: CFRetained<CFType>,
    element: &'a AXUIElement,
}

impl std::ops::Deref for WindowRoot<'_> {
    type Target = AXUIElement;
    fn deref(&self) -> &AXUIElement {
        self.element
    }
}

fn bounds_match(a: Rect, b: Rect) -> bool {
    (a.x - b.x).abs() <= WINDOW_MATCH_TOLERANCE
        && (a.y - b.y).abs() <= WINDOW_MATCH_TOLERANCE
        && (a.w - b.w).abs() <= WINDOW_MATCH_TOLERANCE
        && (a.h - b.h).abs() <= WINDOW_MATCH_TOLERANCE
}

fn build_node(elem: &AXUIElement, depth: usize, max_depth: usize, budget: &mut usize) -> RawAxNode {
    let role = string_attr(elem, "AXRole");
    let subrole = string_attr(elem, "AXSubrole");
    let secure = is_secure(role.as_deref(), subrole.as_deref());

    let title = string_attr(elem, "AXTitle");
    let description = string_attr(elem, "AXDescription");
    // The one value the contract forbids on secure fields is never even read.
    let value = if secure {
        None
    } else {
        string_attr(elem, "AXValue")
    };
    let value_settable = attr_settable(elem, "AXValue");
    let enabled = bool_attr(elem, "AXEnabled").unwrap_or(true);
    let focused = bool_attr(elem, "AXFocused").unwrap_or(false);
    let actions = read_actions(elem);
    let bounds = read_bounds(elem);

    *budget = budget.saturating_sub(1);

    let children = if depth < max_depth && *budget > 0 {
        read_children(elem, depth, max_depth, budget)
    } else {
        Vec::new()
    };

    RawAxNode {
        role,
        subrole,
        title,
        description,
        value,
        value_settable,
        enabled,
        focused,
        secure,
        actions,
        bounds,
        children,
    }
}

fn read_children(
    elem: &AXUIElement,
    depth: usize,
    max_depth: usize,
    budget: &mut usize,
) -> Vec<RawAxNode> {
    let Some(children) = copy_attr(elem, &cfstr("AXChildren")) else {
        return Vec::new();
    };
    let Some(array) = children.downcast_ref::<CFArray>() else {
        return Vec::new();
    };

    let count = array.count();
    let mut nodes = Vec::new();
    for i in 0..count {
        if *budget == 0 {
            break;
        }
        // SAFETY: `i` in range; `AXChildren` holds `AXUIElement`s, borrowed while `children`
        // (and thus `array`) is alive — which spans this whole loop and the recursive build.
        let child = unsafe { &*(array.value_at_index(i) as *const AXUIElement) };
        nodes.push(build_node(child, depth + 1, max_depth, budget));
    }
    nodes
}

fn is_secure(role: Option<&str>, subrole: Option<&str>) -> bool {
    role == Some("AXSecureTextField") || subrole == Some("AXSecureTextField")
}

// --- attribute reads ---

/// The owned value of an attribute, or `None` if the element does not have it. The copy
/// follows the CoreFoundation Copy rule (+1), so the returned handle owns its reference.
fn copy_attr(elem: &AXUIElement, attr: &CFString) -> Option<CFRetained<CFType>> {
    let mut value: *const CFType = std::ptr::null();
    // SAFETY: `attr` is a valid CFString; `value` is a valid out-slot. On success it holds a
    // +1 CFTypeRef, which `from_raw` takes ownership of.
    let err = unsafe { elem.copy_attribute_value(attr, NonNull::from(&mut value)) };
    if err.0 != 0 {
        return None;
    }
    NonNull::new(value as *mut CFType).map(|p| unsafe { CFRetained::from_raw(p) })
}

fn string_attr(elem: &AXUIElement, attr: &'static str) -> Option<String> {
    let value = copy_attr(elem, &cfstr(attr))?;
    let string = value.downcast_ref::<CFString>()?;
    let text = string.to_string();
    (!text.is_empty()).then_some(text)
}

fn bool_attr(elem: &AXUIElement, attr: &'static str) -> Option<bool> {
    let value = copy_attr(elem, &cfstr(attr))?;
    let boolean = value.downcast_ref::<CFBoolean>()?;
    Some(boolean.value())
}

fn attr_settable(elem: &AXUIElement, attr: &'static str) -> bool {
    let mut settable: u8 = 0;
    // SAFETY: valid element and attribute; `settable` is a valid out-slot for the Boolean.
    let err = unsafe { elem.is_attribute_settable(&cfstr(attr), NonNull::from(&mut settable)) };
    err.0 == 0 && settable != 0
}

fn read_actions(elem: &AXUIElement) -> Vec<String> {
    let mut array: *const CFArray = std::ptr::null();
    // SAFETY: valid element; `array` is a valid out-slot. On success it holds a +1 CFArray.
    let err = unsafe { elem.copy_action_names(NonNull::from(&mut array)) };
    if err.0 != 0 {
        return Vec::new();
    }
    let Some(array) = NonNull::new(array as *mut CFArray) else {
        return Vec::new();
    };
    let array = unsafe { CFRetained::from_raw(array) };

    let count = array.count();
    let mut actions = Vec::with_capacity(count.max(0) as usize);
    for i in 0..count {
        // SAFETY: `i` in range; action names are CFStrings, borrowed while `array` lives.
        let name = unsafe { &*(array.value_at_index(i) as *const CFString) };
        actions.push(name.to_string());
    }
    actions
}

fn read_bounds(elem: &AXUIElement) -> Option<Rect> {
    let position = copy_attr(elem, &cfstr("AXPosition"))?;
    let size = copy_attr(elem, &cfstr("AXSize"))?;
    let position = position.downcast_ref::<AXValue>()?;
    let size = size.downcast_ref::<AXValue>()?;

    let mut point = CGPoint::default();
    let mut dims = CGSize::default();
    // SAFETY: the out-slots match the requested AXValue types; `value` writes the struct and
    // returns whether the stored type matched.
    let got_point =
        unsafe { position.value(AXValueType::CGPoint, NonNull::from(&mut point).cast()) };
    let got_size = unsafe { size.value(AXValueType::CGSize, NonNull::from(&mut dims).cast()) };

    (got_point && got_size).then_some(Rect::new(point.x, point.y, dims.width, dims.height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_detection_by_role_or_subrole() {
        assert!(is_secure(Some("AXSecureTextField"), None));
        assert!(is_secure(Some("AXTextField"), Some("AXSecureTextField")));
        assert!(!is_secure(Some("AXTextField"), None));
        assert!(!is_secure(None, None));
    }

    #[test]
    fn bounds_match_within_tolerance() {
        let a = Rect::new(100.0, 120.0, 240.0, 320.0);
        assert!(bounds_match(a, Rect::new(103.0, 118.0, 242.0, 320.0)));
        assert!(!bounds_match(a, Rect::new(140.0, 120.0, 240.0, 320.0)));
    }
}
