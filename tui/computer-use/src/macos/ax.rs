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
/// one is found (so the tree lines up with the captured window). When `window_bounds` is
/// `Some` and no window root matches, returns `None` rather than falling back to the
/// application tree. The returned tree is materialised eagerly and bounded by `max_depth` /
/// `max_nodes` so a pathological UI cannot make the walk unbounded; the pure layer re-applies
/// the same limits authoritatively.
pub fn walk(
    pid: i32,
    max_nodes: usize,
    max_depth: usize,
    window_bounds: Option<Rect>,
) -> Option<RawAxNode> {
    // SAFETY: `new_application` returns a valid application element for any pid (even a dead
    // one, whose later attribute reads simply fail and yield an empty node).
    let app = unsafe { AXUIElement::new_application(pid) };

    let mut budget = max_nodes.max(1);

    if let Some(bounds) = window_bounds {
        // A window-rooted tree is required when the caller named a window. Falling back to
        // the whole application would mix other windows' nodes into the snapshot (M8).
        let root = find_window_element(&app, bounds)?;
        return Some(build_node(&root, 0, max_depth, &mut budget));
    }

    Some(build_node(&app, 0, max_depth, &mut budget))
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

fn passwordish(name: Option<&str>) -> bool {
    let name = name.unwrap_or("").to_ascii_lowercase();
    name.contains("password") || name.contains("passwd") || name.contains("pin")
}

fn injection_forbidden(node: &RawAxNode) -> bool {
    node.secure
        || passwordish(
            node.title
                .as_deref()
                .or(node.description.as_deref())
                .or(Some("")),
        )
}

/// Why a live rematch could not perform the requested AX action.
#[derive(Debug)]
pub enum MatchError {
    /// No live node matched the snapshot.
    Gone,
    /// A match was found but it does not list the AX action we wanted (caller may CGEvent).
    NoPress,
    /// The match was a secure text field; injection is refused (doc §7.3 / D12).
    Secure,
    /// More than one live node matched role+name+bounds; refuse rather than guess.
    Ambiguous,
    /// The AX action was attempted and the API returned a failure code. Not a signal to
    /// fall through to CGEvent — the click/type already happened, or failed, on this node.
    Failed(String),
}

/// Presses the live node that rematches `needle`, using `AXPress` or `AXConfirm` when listed.
pub fn press_matching(
    pid: i32,
    window_bounds: Option<Rect>,
    needle: &crate::act::ElementSnapshot,
) -> Result<(), MatchError> {
    with_match(pid, window_bounds, needle, |elem, node| {
        if node
            .actions
            .iter()
            .any(|action| action.eq_ignore_ascii_case("AXPress"))
        {
            return perform(elem, "AXPress");
        }
        if node
            .actions
            .iter()
            .any(|action| action.eq_ignore_ascii_case("AXConfirm"))
        {
            return perform(elem, "AXConfirm");
        }
        Err(MatchError::NoPress)
    })
}

/// Sets `AXValue` on the rematched node.
pub fn set_value_matching(
    pid: i32,
    window_bounds: Option<Rect>,
    needle: &crate::act::ElementSnapshot,
    text: &str,
) -> Result<(), MatchError> {
    with_match(pid, window_bounds, needle, |elem, _node| {
        set_value(elem, text)
    })
}

/// Makes the application frontmost so subsequent events land in it.
pub fn set_frontmost(pid: i32) -> Result<(), String> {
    let app = unsafe { AXUIElement::new_application(pid) };
    set_bool(&app, "AXFrontmost", true)
}

/// Raises the window whose bounds match `target`.
pub fn raise_window(pid: i32, target: Rect) -> Result<(), String> {
    let app = unsafe { AXUIElement::new_application(pid) };
    let Some(root) = find_window_element(&app, target) else {
        return Err("window element not found for raise".into());
    };
    perform(&root, "AXRaise").map_err(|e| match e {
        MatchError::Failed(message) => message,
        _other => "AXRaise failed".into(),
    })
}

/// Focused element after an act, for landing notes.
pub fn focused_summary(
    pid: i32,
    window_bounds: Option<Rect>,
) -> Option<crate::act::FocusedElement> {
    let root = walk(pid, 256, 16, window_bounds)?;
    find_focused(&root).map(|(role, name, editable)| crate::act::FocusedElement {
        role,
        name,
        editable,
    })
}

/// Refuses when the live focused node is a secure or password-ish field (D12).
pub fn refuse_secure_focus(pid: i32, window_bounds: Option<Rect>) -> Result<(), String> {
    let Some(root) = walk(pid, 256, 16, window_bounds) else {
        return Err(
            "act: could not read the window accessibility tree; call desktop_state again".into(),
        );
    };
    if let Some(node) = find_focused_node(&root) {
        if injection_forbidden(node) {
            return Err("act: refusing to interact with a secure field".into());
        }
    }
    Ok(())
}

/// Refuses when an AX node whose bounds contain `point` is a secure or password-ish field.
pub fn refuse_secure_at(
    pid: i32,
    window_bounds: Option<Rect>,
    point: crate::geometry::Point,
) -> Result<(), String> {
    let Some(root) = walk(pid, 256, 16, window_bounds) else {
        return Ok(());
    };
    if hits_forbidden(&root, point) {
        return Err("act: refusing to interact with a secure field".into());
    }
    Ok(())
}

fn find_focused(node: &RawAxNode) -> Option<(String, String, bool)> {
    find_focused_node(node).and_then(|node| {
        let role = node.role.clone()?;
        let name = node
            .title
            .clone()
            .or(node.description.clone())
            .unwrap_or_default();
        let editable = node.value_settable
            || matches!(
                role.as_str(),
                "AXTextField" | "AXTextArea" | "AXComboBox" | "AXSearchField" | "AXSecureTextField"
            );
        Some((role, name, editable))
    })
}

fn find_focused_node(node: &RawAxNode) -> Option<&RawAxNode> {
    if node.focused && node.role.is_some() {
        return Some(node);
    }
    node.children.iter().find_map(find_focused_node)
}

fn hits_forbidden(node: &RawAxNode, point: crate::geometry::Point) -> bool {
    let here = node.bounds.is_some_and(|bounds| {
        point.x >= bounds.x
            && point.y >= bounds.y
            && point.x < bounds.x + bounds.w
            && point.y < bounds.y + bounds.h
    }) && injection_forbidden(node);
    here || node
        .children
        .iter()
        .any(|child| hits_forbidden(child, point))
}

fn with_match<T>(
    pid: i32,
    window_bounds: Option<Rect>,
    needle: &crate::act::ElementSnapshot,
    mut f: impl FnMut(&AXUIElement, &RawAxNode) -> Result<T, MatchError>,
) -> Result<T, MatchError> {
    let app = unsafe { AXUIElement::new_application(pid) };
    if let Some(bounds) = window_bounds {
        let Some(root) = find_window_element(&app, bounds) else {
            return Err(MatchError::Gone);
        };
        match_in(&root, needle, &mut f)
    } else {
        match_in(&app, needle, &mut f)
    }
}

fn match_in<T>(
    root: &AXUIElement,
    needle: &crate::act::ElementSnapshot,
    f: &mut impl FnMut(&AXUIElement, &RawAxNode) -> Result<T, MatchError>,
) -> Result<T, MatchError> {
    let matches = count_matches(root, needle, 0, 32);
    if matches == 0 {
        return Err(MatchError::Gone);
    }
    if matches > 1 {
        return Err(MatchError::Ambiguous);
    }
    let mut result = None;
    search(root, needle, 0, 32, f, &mut result);
    result.unwrap_or(Err(MatchError::Gone))
}

fn count_matches(
    elem: &AXUIElement,
    needle: &crate::act::ElementSnapshot,
    depth: usize,
    max_depth: usize,
) -> usize {
    if depth > max_depth {
        return 0;
    }
    let node = describe(elem);
    let role = node.role.clone().unwrap_or_default();
    let name = node.title.clone().or(node.description.clone());
    let here = usize::from(crate::act::same_element(
        needle,
        &role,
        name.as_deref(),
        node.bounds,
    ));
    here + count_children(elem, needle, depth, max_depth)
}

fn count_children(
    elem: &AXUIElement,
    needle: &crate::act::ElementSnapshot,
    depth: usize,
    max_depth: usize,
) -> usize {
    let Some(children) = copy_attr(elem, &cfstr("AXChildren")) else {
        return 0;
    };
    let Some(array) = children.downcast_ref::<CFArray>() else {
        return 0;
    };
    let count = array.count();
    let mut total = 0usize;
    for i in 0..count {
        let child = unsafe { &*(array.value_at_index(i) as *const AXUIElement) };
        total += count_matches(child, needle, depth + 1, max_depth);
    }
    total
}

fn search<T>(
    elem: &AXUIElement,
    needle: &crate::act::ElementSnapshot,
    depth: usize,
    max_depth: usize,
    f: &mut impl FnMut(&AXUIElement, &RawAxNode) -> Result<T, MatchError>,
    out: &mut Option<Result<T, MatchError>>,
) -> bool {
    if out.is_some() || depth > max_depth {
        return out.is_some();
    }
    let node = describe(elem);
    let role = node.role.clone().unwrap_or_default();
    let name = node.title.clone().or(node.description.clone());
    if crate::act::same_element(needle, &role, name.as_deref(), node.bounds) {
        if injection_forbidden(&node) {
            *out = Some(Err(MatchError::Secure));
            return true;
        }
        *out = Some(f(elem, &node));
        return true;
    }
    let Some(children) = copy_attr(elem, &cfstr("AXChildren")) else {
        return false;
    };
    let Some(array) = children.downcast_ref::<CFArray>() else {
        return false;
    };
    let count = array.count();
    for i in 0..count {
        let child = unsafe { &*(array.value_at_index(i) as *const AXUIElement) };
        if search(child, needle, depth + 1, max_depth, f, out) {
            return true;
        }
    }
    false
}

fn describe(elem: &AXUIElement) -> RawAxNode {
    let role = string_attr(elem, "AXRole");
    let subrole = string_attr(elem, "AXSubrole");
    let secure = is_secure(role.as_deref(), subrole.as_deref());
    RawAxNode {
        role,
        subrole,
        title: string_attr(elem, "AXTitle"),
        description: string_attr(elem, "AXDescription"),
        value: None,
        value_settable: attr_settable(elem, "AXValue"),
        enabled: bool_attr(elem, "AXEnabled").unwrap_or(true),
        focused: bool_attr(elem, "AXFocused").unwrap_or(false),
        secure,
        actions: read_actions(elem),
        bounds: read_bounds(elem),
        children: Vec::new(),
    }
}

fn perform(elem: &AXUIElement, action: &'static str) -> Result<(), MatchError> {
    let err = unsafe { elem.perform_action(&cfstr(action)) };
    if err.0 == 0 {
        Ok(())
    } else {
        Err(MatchError::Failed(format!(
            "{action} failed (AX error {})",
            err.0
        )))
    }
}

fn set_value(elem: &AXUIElement, text: &str) -> Result<(), MatchError> {
    let value = CFString::from_str(text);
    let err = unsafe { elem.set_attribute_value(&cfstr("AXValue"), value.as_ref()) };
    if err.0 == 0 {
        Ok(())
    } else {
        Err(MatchError::Failed(format!(
            "AXSetValue failed (AX error {})",
            err.0
        )))
    }
}

fn set_bool(elem: &AXUIElement, attr: &'static str, value: bool) -> Result<(), String> {
    let boolean = CFBoolean::new(value);
    let err = unsafe { elem.set_attribute_value(&cfstr(attr), boolean.as_ref()) };
    if err.0 == 0 {
        Ok(())
    } else {
        Err(format!("{attr} failed (AX error {})", err.0))
    }
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
    fn passwordish_labels_are_treated_as_forbidden() {
        assert!(passwordish(Some("Password")));
        assert!(passwordish(Some("Enter PIN")));
        assert!(!passwordish(Some("Username")));
    }

    #[test]
    fn bounds_match_within_tolerance() {
        let a = Rect::new(100.0, 120.0, 240.0, 320.0);
        assert!(bounds_match(a, Rect::new(103.0, 118.0, 242.0, 320.0)));
        assert!(!bounds_match(a, Rect::new(140.0, 120.0, 240.0, 320.0)));
    }
}
