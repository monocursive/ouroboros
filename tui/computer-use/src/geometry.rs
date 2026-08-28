//! Coordinate arithmetic (doc §7.3): the `coordinate_width/height` ↔ payload `width/height`
//! ↔ `scale` relationship, and mapping a point between two rects.
//!
//! This encodes the Linux crate's most important lesson: **the model always addresses
//! coordinate space, never payload space.** A screenshot is downscaled to fit a token
//! budget — the JPEG the model sees is `width × height` pixels — but the model is told to
//! address `coordinate_width × coordinate_height`, and node bounds are reported in that same
//! coordinate space. `scale = coordinate / payload`. Downscaling for the budget therefore
//! never invalidates a coordinate: a click the model computes in coordinate space maps back
//! onto the real window no matter how small the JPEG was.
//!
//! Two things this module refuses to paper over:
//!   * **Disagreeing axes.** If the width and height scale factors differ by more than
//!     [`SCALE_EPSILON`], the capture geometry is inconsistent and any single `scale` would
//!     be a lie. [`image_scale`] and [`map_point_uniform`] return an error rather than
//!     picking one axis and hoping.
//!   * **Off-target points.** A mapped point is clamped into the destination rect, so a
//!     coordinate the model put just outside a window lands on the edge, never off in
//!     another window's pixels. (The observe step still warns; this is the arithmetic floor.)

/// How far the per-axis scale factors may drift before they are treated as disagreeing. A
/// pixel or two of rounding across a 4K axis stays well under this; a real aspect-ratio
/// mismatch blows past it.
pub const SCALE_EPSILON: f64 = 1e-3;

/// A point in some coordinate space.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// An axis-aligned rectangle: origin (`x`, `y`) and size (`w`, `h`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Rect {
    pub fn new(x: f64, y: f64, w: f64, h: f64) -> Self {
        Self { x, y, w, h }
    }

    /// Whether a screen point is inside this non-degenerate rectangle. The far edge is
    /// exclusive, matching window-server pixel ownership when two windows meet at an edge.
    pub fn contains(&self, point: Point) -> bool {
        self.w > 0.0
            && self.h > 0.0
            && point.x >= self.x
            && point.y >= self.y
            && point.x < self.x + self.w
            && point.y < self.y + self.h
    }

    /// Clamps a point into this rect's closed interval `[x, x+w] × [y, y+h]`.
    #[cfg(test)]
    fn clamp(&self, point: Point) -> Point {
        Point {
            x: point.x.clamp(self.x, self.x + self.w),
            y: point.y.clamp(self.y, self.y + self.h),
        }
    }
}

/// Why a scale could not be computed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScaleError {
    /// A payload or coordinate dimension was zero or negative.
    ZeroDimension,
    /// The width and height scale factors disagreed beyond [`SCALE_EPSILON`].
    Disagree { sx: f64, sy: f64 },
}

/// Why a point could not be mapped.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg(test)]
pub enum MapError {
    /// The source rect had zero (or negative) width or height, so a position within it is
    /// undefined.
    DegenerateSource,
    /// The source→destination axis scales disagreed beyond [`SCALE_EPSILON`]
    /// (uniform mapping only).
    ScaleDisagree { sx: f64, sy: f64 },
}

/// The payload↔coordinate `scale`: the single factor such that
/// `coordinate = payload × scale`, refusing when the two axes disagree.
///
/// `payload` and `coordinate` are `(width, height)`. This is the number the `state`
/// response reports as `scale`; computing it here — with the disagreement check — is what
/// keeps a downscaled JPEG from ever claiming a scale its two axes do not actually share.
pub fn image_scale(payload: (f64, f64), coordinate: (f64, f64)) -> Result<f64, ScaleError> {
    let (payload_w, payload_h) = payload;
    let (coord_w, coord_h) = coordinate;

    if payload_w <= 0.0 || payload_h <= 0.0 || coord_w <= 0.0 || coord_h <= 0.0 {
        return Err(ScaleError::ZeroDimension);
    }

    let sx = coord_w / payload_w;
    let sy = coord_h / payload_h;

    if (sx - sy).abs() > SCALE_EPSILON {
        return Err(ScaleError::Disagree { sx, sy });
    }

    // They agree within epsilon; the mean is symmetric in the two axes.
    Ok((sx + sy) / 2.0)
}

/// Maps `point` from `src` into `dst`, scaling each axis by that axis's ratio, rounding to
/// the nearest integer, then clamping into `dst`.
///
/// This is the general "point between two rects" map — coordinate space onto a window's
/// on-screen bounds, or the reverse. Axes are scaled independently because both rects are
/// real spaces whose aspect ratios should already match; where they *must* match, use
/// [`map_point_uniform`], which refuses instead of silently distorting.
#[cfg(test)]
pub fn map_point(point: Point, src: Rect, dst: Rect) -> Result<Point, MapError> {
    if src.w <= 0.0 || src.h <= 0.0 {
        return Err(MapError::DegenerateSource);
    }

    let fx = (point.x - src.x) / src.w;
    let fy = (point.y - src.y) / src.h;

    let mapped = Point {
        x: (dst.x + fx * dst.w).round(),
        y: (dst.y + fy * dst.h).round(),
    };

    Ok(dst.clamp(mapped))
}

/// Like [`map_point`], but refuses when the source→destination axis scales disagree beyond
/// [`SCALE_EPSILON`]. Use this for the payload↔coordinate mapping, where a single uniform
/// `scale` is the contract and an anamorphic map would mean the capture geometry is wrong.
#[cfg(test)]
pub fn map_point_uniform(point: Point, src: Rect, dst: Rect) -> Result<Point, MapError> {
    if src.w <= 0.0 || src.h <= 0.0 {
        return Err(MapError::DegenerateSource);
    }

    let sx = dst.w / src.w;
    let sy = dst.h / src.h;

    if (sx - sy).abs() > SCALE_EPSILON {
        return Err(MapError::ScaleDisagree { sx, sy });
    }

    map_point(point, src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalars are compared with a tolerance; float `==` would be brittle and clippy-flagged.
    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn scale_is_the_uniform_ratio() {
        // A 480×640 JPEG standing in for a 960×1280 coordinate space: scale 2.0.
        assert!(close(
            image_scale((480.0, 640.0), (960.0, 1280.0)).unwrap(),
            2.0
        ));
    }

    #[test]
    fn scale_refuses_disagreeing_axes() {
        // Width scales ×2.0, height ×2.0016 — beyond epsilon, so no single scale is honest.
        assert!(matches!(
            image_scale((480.0, 640.0), (960.0, 1281.0)),
            Err(ScaleError::Disagree { .. })
        ));
    }

    #[test]
    fn scale_refuses_zero_dimension() {
        assert_eq!(
            image_scale((0.0, 640.0), (960.0, 1280.0)),
            Err(ScaleError::ZeroDimension)
        );
    }

    #[test]
    fn maps_center_across_scale() {
        // The center of the payload maps to the center of coordinate space.
        let mapped = map_point(
            Point::new(240.0, 320.0),
            Rect::new(0.0, 0.0, 480.0, 640.0),
            Rect::new(0.0, 0.0, 960.0, 1280.0),
        )
        .unwrap();
        assert_eq!(mapped, Point::new(480.0, 640.0));
    }

    #[test]
    fn maps_with_a_translated_destination() {
        // Halfway into a 100×100 source, onto a destination offset to (10, 20).
        let mapped = map_point(
            Point::new(50.0, 50.0),
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Rect::new(10.0, 20.0, 200.0, 200.0),
        )
        .unwrap();
        assert_eq!(mapped, Point::new(110.0, 120.0));
    }

    #[test]
    fn out_of_bounds_points_clamp_into_the_destination() {
        let dst = Rect::new(0.0, 0.0, 100.0, 100.0);
        let mapped = map_point(
            Point::new(150.0, -10.0),
            Rect::new(0.0, 0.0, 100.0, 100.0),
            dst,
        )
        .unwrap();
        assert_eq!(mapped, Point::new(100.0, 0.0));
    }

    #[test]
    fn fractional_results_round_to_the_nearest_pixel() {
        // 1/3 of the way across a 3-wide source into a 10-wide destination → 3.33… → 3.
        let mapped = map_point(
            Point::new(1.0, 1.0),
            Rect::new(0.0, 0.0, 3.0, 3.0),
            Rect::new(0.0, 0.0, 10.0, 10.0),
        )
        .unwrap();
        assert_eq!(mapped, Point::new(3.0, 3.0));
    }

    #[test]
    fn degenerate_source_is_refused() {
        assert_eq!(
            map_point(
                Point::new(1.0, 1.0),
                Rect::new(0.0, 0.0, 0.0, 100.0),
                Rect::new(0.0, 0.0, 100.0, 100.0),
            ),
            Err(MapError::DegenerateSource)
        );
    }

    #[test]
    fn uniform_mapping_refuses_anamorphic_rects() {
        // Source square, destination 2:1 — the axes scale differently, so refuse.
        assert!(matches!(
            map_point_uniform(
                Point::new(50.0, 50.0),
                Rect::new(0.0, 0.0, 100.0, 100.0),
                Rect::new(0.0, 0.0, 200.0, 100.0),
            ),
            Err(MapError::ScaleDisagree { .. })
        ));
    }

    #[test]
    fn uniform_mapping_allows_matching_aspect() {
        let mapped = map_point_uniform(
            Point::new(50.0, 50.0),
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Rect::new(0.0, 0.0, 200.0, 200.0),
        )
        .unwrap();
        assert_eq!(mapped, Point::new(100.0, 100.0));
    }
}
