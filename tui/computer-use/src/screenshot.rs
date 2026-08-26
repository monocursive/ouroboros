//! The screenshot pixel pipeline (doc §7.3): downscale a captured RGBA frame to the size
//! budget, encode it JPEG (with quality) or PNG, and hash it. This is deliberately kept out of
//! the objc2 capture FFI so the whole budget/format/scale path is pure and unit-testable with
//! no Screen-Recording grant — the macOS side ([`crate::macos::capture`]) does nothing but
//! hand a raw RGBA buffer and its native pixel dimensions to [`encode`].
//!
//! The frame arrives at the capture's native pixel size, which is the screenshot's
//! **coordinate space** (`coordinate_width/height`). Fitting the request's `max_width/height`
//! and `max_bytes` only ever shrinks the encoded *payload*; the coordinate space and the node
//! bounds reported against it never move, and the `scale = coordinate / payload` the response
//! carries (computed in [`crate::geometry::image_scale`]) is what maps a payload-space pixel
//! back onto the real window.

use sha2::{Digest, Sha256};

/// The encoded image formats the contract allows (doc §5.2). JPEG is the default; PNG is
/// lossless for when the caller asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Jpeg,
    Png,
}

impl Format {
    pub fn mime(self) -> &'static str {
        match self {
            Format::Jpeg => "image/jpeg",
            Format::Png => "image/png",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Jpeg => "jpg",
            Format::Png => "png",
        }
    }
}

/// The size budget and format for one encode. `0` on any of the maxima means "no limit on
/// this axis"; Elixir clamps real requests to config maxima before they reach the helper.
#[derive(Clone, Copy, Debug)]
pub struct EncodeParams {
    pub format: Format,
    /// JPEG quality 1..=95 (ignored for PNG). The starting quality; the budget pass may lower
    /// it before it downscales further.
    pub quality: u8,
    pub max_width: u32,
    pub max_height: u32,
    pub max_bytes: usize,
}

/// A finished encode.
pub struct Encoded {
    pub bytes: Vec<u8>,
    /// Payload pixel dimensions (post-downscale).
    pub width: u32,
    pub height: u32,
    pub format: Format,
    /// False when even the smallest attempt could not fit `max_bytes`; the caller surfaces a
    /// warning rather than pretending the budget was met.
    pub budget_met: bool,
}

/// The lowest JPEG quality the budget pass will drop to before it resorts to downscaling.
const MIN_JPEG_QUALITY: u8 = 20;
/// Each downscale step multiplies the fit ratio by this once quality is exhausted.
const DOWNSCALE_STEP: f64 = 0.8;
/// A hard cap on downscale rounds, so a pathological `max_bytes` can never loop forever.
const MAX_DOWNSCALE_ROUNDS: u32 = 8;

/// Encodes a native-resolution RGBA frame to the requested format within the size budget.
///
/// `rgba` is tightly packed `src_width × src_height` RGBA8 (4 bytes/pixel, no row padding).
/// Downscaling preserves aspect ratio; JPEG first lowers quality, then — like PNG — downscales.
pub fn encode(
    rgba: &[u8],
    src_width: u32,
    src_height: u32,
    params: &EncodeParams,
) -> Result<Encoded, String> {
    if src_width == 0 || src_height == 0 {
        return Err("capture has a zero dimension".to_string());
    }
    let expected = src_width as usize * src_height as usize * 4;
    if rgba.len() != expected {
        return Err(format!(
            "rgba buffer is {} bytes, expected {expected} for {src_width}x{src_height}",
            rgba.len()
        ));
    }

    let base = image::RgbaImage::from_raw(src_width, src_height, rgba.to_vec())
        .ok_or_else(|| "rgba buffer did not fit the given dimensions".to_string())?;
    let base = image::DynamicImage::ImageRgba8(base);

    let mut ratio = fit_ratio(src_width, src_height, params.max_width, params.max_height);
    let no_byte_limit = params.max_bytes == 0;

    // The best (smallest) attempt seen, returned if nothing meets the budget.
    let mut best: Option<Encoded> = None;

    for _ in 0..MAX_DOWNSCALE_ROUNDS {
        let (tw, th) = target_dims(src_width, src_height, ratio);
        let resized = if tw == src_width && th == src_height {
            base.clone()
        } else {
            base.resize_exact(tw, th, image::imageops::FilterType::Triangle)
        };

        for quality in quality_ladder(params) {
            let bytes = encode_once(&resized, tw, th, params.format, quality)?;
            let size = bytes.len();
            let met = no_byte_limit || size <= params.max_bytes;
            let candidate = Encoded {
                bytes,
                width: tw,
                height: th,
                format: params.format,
                budget_met: met,
            };
            if met {
                return Ok(candidate);
            }
            if best.as_ref().is_none_or(|b| size < b.bytes.len()) {
                best = Some(candidate);
            }
        }

        ratio *= DOWNSCALE_STEP;
        // A 1px floor: once both axes are at 1, further downscaling changes nothing.
        if (src_width as f64 * ratio) < 1.0 && (src_height as f64 * ratio) < 1.0 {
            break;
        }
    }

    best.ok_or_else(|| "image encoding produced no output".to_string())
}

/// The largest ratio ≤ 1 that fits the frame inside `max_width × max_height` (a `0` maximum is
/// "unbounded" on that axis).
fn fit_ratio(src_w: u32, src_h: u32, max_w: u32, max_h: u32) -> f64 {
    let mut ratio = 1.0_f64;
    if max_w > 0 && src_w > max_w {
        ratio = ratio.min(max_w as f64 / src_w as f64);
    }
    if max_h > 0 && src_h > max_h {
        ratio = ratio.min(max_h as f64 / src_h as f64);
    }
    ratio
}

/// Payload dimensions for a fit ratio: aspect-preserving, at least 1px per axis.
fn target_dims(src_w: u32, src_h: u32, ratio: f64) -> (u32, u32) {
    let w = ((src_w as f64 * ratio).round() as u32).max(1);
    let h = ((src_h as f64 * ratio).round() as u32).max(1);
    (w, h)
}

/// The qualities to try at one size. PNG has no quality knob, so a single pass. JPEG starts at
/// the requested quality and steps down toward [`MIN_JPEG_QUALITY`] before the caller downscales.
fn quality_ladder(params: &EncodeParams) -> Vec<u8> {
    match params.format {
        Format::Png => vec![0],
        Format::Jpeg => {
            let start = params.quality.clamp(1, 95);
            let mut ladder = Vec::new();
            let mut q = start;
            loop {
                ladder.push(q);
                if q <= MIN_JPEG_QUALITY {
                    break;
                }
                q = q.saturating_sub(15).max(MIN_JPEG_QUALITY);
            }
            ladder
        }
    }
}

fn encode_once(
    img: &image::DynamicImage,
    width: u32,
    height: u32,
    format: Format,
    quality: u8,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    match format {
        Format::Jpeg => {
            // JPEG has no alpha channel; drop it rather than let the encoder reject Rgba8.
            let rgb = img.to_rgb8();
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
            encoder
                .encode(rgb.as_raw(), width, height, image::ExtendedColorType::Rgb8)
                .map_err(|e| format!("jpeg encode failed: {e}"))?;
        }
        Format::Png => {
            use image::ImageEncoder;
            let rgba = img.to_rgba8();
            image::codecs::png::PngEncoder::new(&mut out)
                .write_image(
                    rgba.as_raw(),
                    width,
                    height,
                    image::ExtendedColorType::Rgba8,
                )
                .map_err(|e| format!("png encode failed: {e}"))?;
        }
    }
    Ok(out)
}

/// Lowercase hex SHA-256 of the encoded bytes (doc §7.3, §8.1: the artifact is named by sha).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A solid-colour RGBA frame of the given size.
    fn frame(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
        rgba.iter()
            .copied()
            .cycle()
            .take((w * h * 4) as usize)
            .collect()
    }

    fn params(format: Format) -> EncodeParams {
        EncodeParams {
            format,
            quality: 80,
            max_width: 0,
            max_height: 0,
            max_bytes: 0,
        }
    }

    #[test]
    fn jpeg_round_trips_dimensions() {
        let rgba = frame(64, 48, [10, 20, 30, 255]);
        let out = encode(&rgba, 64, 48, &params(Format::Jpeg)).unwrap();
        assert_eq!(out.format, Format::Jpeg);
        assert_eq!((out.width, out.height), (64, 48));
        assert!(out.budget_met);
        // JPEG magic.
        assert_eq!(&out.bytes[0..2], &[0xff, 0xd8]);
    }

    #[test]
    fn png_has_signature_and_full_size() {
        let rgba = frame(32, 16, [0, 128, 255, 255]);
        let out = encode(&rgba, 32, 16, &params(Format::Png)).unwrap();
        assert_eq!(out.format, Format::Png);
        assert_eq!((out.width, out.height), (32, 16));
        assert_eq!(
            &out.bytes[0..8],
            &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n']
        );
    }

    #[test]
    fn max_width_downscales_preserving_aspect() {
        let rgba = frame(200, 100, [50, 60, 70, 255]);
        let p = EncodeParams {
            max_width: 100,
            ..params(Format::Jpeg)
        };
        let out = encode(&rgba, 200, 100, &p).unwrap();
        // Fit ratio 0.5 on both axes.
        assert_eq!((out.width, out.height), (100, 50));
    }

    #[test]
    fn max_height_is_the_binding_axis() {
        let rgba = frame(100, 400, [0, 0, 0, 255]);
        let p = EncodeParams {
            max_width: 1000,
            max_height: 200,
            ..params(Format::Jpeg)
        };
        let out = encode(&rgba, 100, 400, &p).unwrap();
        assert_eq!((out.width, out.height), (50, 200));
    }

    #[test]
    fn no_upscaling_when_already_within_bounds() {
        let rgba = frame(40, 40, [1, 2, 3, 255]);
        let p = EncodeParams {
            max_width: 1920,
            max_height: 1920,
            ..params(Format::Jpeg)
        };
        let out = encode(&rgba, 40, 40, &p).unwrap();
        assert_eq!((out.width, out.height), (40, 40));
    }

    #[test]
    fn tiny_byte_budget_downscales_and_flags_when_impossible() {
        // A large noisy frame with an absurd 10-byte budget: encoding can never fit, so the
        // pipeline returns its smallest best-effort and honestly flags the budget unmet.
        let mut rgba = Vec::with_capacity(256 * 256 * 4);
        for i in 0..(256 * 256) {
            let v = (i % 256) as u8;
            rgba.extend_from_slice(&[v, v.wrapping_mul(3), v.wrapping_add(7), 255]);
        }
        let p = EncodeParams {
            max_bytes: 10,
            ..params(Format::Jpeg)
        };
        let out = encode(&rgba, 256, 256, &p).unwrap();
        assert!(!out.budget_met);
        assert!(out.width <= 256 && out.height <= 256);
    }

    #[test]
    fn generous_byte_budget_is_met() {
        let rgba = frame(64, 64, [200, 100, 50, 255]);
        let p = EncodeParams {
            max_bytes: 1_000_000,
            ..params(Format::Jpeg)
        };
        let out = encode(&rgba, 64, 64, &p).unwrap();
        assert!(out.budget_met);
        assert!(out.bytes.len() <= 1_000_000);
    }

    #[test]
    fn rejects_buffer_length_mismatch() {
        let rgba = vec![0u8; 10];
        assert!(encode(&rgba, 64, 48, &params(Format::Jpeg)).is_err());
    }

    #[test]
    fn rejects_zero_dimension() {
        assert!(encode(&[], 0, 10, &params(Format::Jpeg)).is_err());
    }

    #[test]
    fn sha256_is_stable_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }
}
