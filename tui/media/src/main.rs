//! One-shot image decoder. The runtime supplies a private directory and enforces
//! an OS sandbox and wall-clock timeout; no daemon, network, or terminal lives here.
use anyhow::{ensure, Context, Result};
use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_BYTES: usize = 20 * 1024 * 1024;
const MAX_PIXELS: u64 = 40_000_000;
const MAX_MEMORY: usize = 512 * 1024 * 1024;
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
struct BoundedAllocator;
#[global_allocator]
static ALLOCATOR: BoundedAllocator = BoundedAllocator;

// Unlike decoder soft limits, this covers allocations by codecs, color profiles,
// and encoders too. Allocation failure terminates this disposable child.
unsafe impl GlobalAlloc for BoundedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed)
            > MAX_MEMORY.saturating_sub(layout.size())
        {
            ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        if ptr.is_null() {
            ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    limits
}

fn decode(bytes: &[u8]) -> Result<DynamicImage> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BYTES,
        "attachment_too_large"
    );
    let format = image::guess_format(bytes).context("attachment_invalid")?;
    ensure!(
        matches!(
            format,
            ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP
        ),
        "attachment_format_unsupported"
    );
    if format == ImageFormat::Png {
        let decoder = image::codecs::png::PngDecoder::new(Cursor::new(bytes))?;
        ensure!(!decoder.is_apng()?, "attachment_animation_unsupported");
    }
    if format == ImageFormat::WebP {
        let decoder = image::codecs::webp::WebPDecoder::new(Cursor::new(bytes))?;
        ensure!(!decoder.has_animation(), "attachment_animation_unsupported");
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits());
    let mut decoder = reader.into_decoder()?;
    let (width, height) = decoder.dimensions();
    ensure!(
        width > 0 && height > 0 && u64::from(width) * u64::from(height) <= MAX_PIXELS,
        "attachment_dimensions_exceeded"
    );
    let orientation = decoder.orientation()?;
    let profile = decoder.icc_profile()?;
    // Iteration is bounded to two frames: an animated GIF is refused rather than
    // allocating all of its frames or silently selecting its first frame.
    let mut image = if format == ImageFormat::Gif {
        drop(decoder);
        let mut gif = image::codecs::gif::GifDecoder::new(Cursor::new(bytes))?;
        gif.set_limits(limits())?;
        let mut frames = gif.into_frames();
        let first = frames.next().context("attachment_invalid")??;
        ensure!(
            frames.next().transpose()?.is_none(),
            "attachment_animation_unsupported"
        );
        DynamicImage::ImageRgba8(first.into_buffer())
    } else {
        DynamicImage::from_decoder(decoder)?
    };
    image.apply_orientation(orientation);
    if let Some(profile) = profile {
        let source = moxcms::ColorProfile::new_from_slice(&profile)
            .context("attachment_color_profile_invalid")?;
        let transform = source
            .create_transform_8bit(
                moxcms::Layout::Rgba,
                &moxcms::ColorProfile::new_srgb(),
                moxcms::Layout::Rgba,
                moxcms::TransformOptions::default(),
            )
            .context("attachment_color_profile_unsupported")?;
        let mut rgba = image.into_rgba8();
        let mut row = vec![0u8; width.max(height) as usize * 4];
        let stride = rgba.width() as usize * 4;
        for pixels in rgba.as_mut().chunks_exact_mut(stride) {
            transform.transform(pixels, &mut row[..stride])?;
            pixels.copy_from_slice(&row[..stride]);
        }
        image = DynamicImage::ImageRgba8(rgba);
    } else {
        image.apply_color_space(
            image::metadata::Cicp::SRGB,
            image::ConvertColorOptions::default(),
        )?;
    }
    Ok(image)
}

struct BoundedBytes {
    bytes: Vec<u8>,
    max: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("attachment_too_large"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn png(image: &DynamicImage, max: usize) -> Result<Vec<u8>> {
    use image::ImageEncoder;
    let mut output = BoundedBytes {
        bytes: Vec::new(),
        max,
    };
    image::codecs::png::PngEncoder::new(&mut output).write_image(
        image.as_bytes(),
        image.width(),
        image.height(),
        image.color().into(),
    )?;
    Ok(output.bytes)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 1, "expected private working directory");
    let root = Path::new(&args[0]);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("source"))?;
    ensure!(file.metadata()?.is_file(), "attachment_invalid");
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    let image = decode(&bytes)?;
    drop(bytes);
    let content = png(&image, MAX_BYTES)?;
    let mut edge = 320.min(image.width().max(image.height()));
    let thumbnail = loop {
        match png(&image.thumbnail(edge, edge), 256 * 1024) {
            Ok(bytes) => break bytes,
            Err(_) if edge > 40 => edge /= 2,
            Err(error) => return Err(error),
        }
    };
    write_private(&root.join("content.png"), &content)?;
    write_private(&root.join("thumbnail.png"), &thumbnail)?;
    let metadata = serde_json::json!({"width": image.width(), "height": image.height(), "media_type": "image/png"});
    write_private(
        &root.join("metadata.json"),
        serde_json::to_string(&metadata)?.as_bytes(),
    )?;
    Ok(())
}
fn main() {
    // An independent CPU bound also holds if a parent dies before its wall timer.
    let limit = libc::rlimit {
        rlim_cur: 5,
        rlim_max: 5,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &limit) } != 0 {
        eprintln!("attachment_resource_limit_unavailable");
        std::process::exit(1);
    }
    if let Err(error) = run() {
        eprintln!("attachment_invalid: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_pixels_and_strips_metadata() {
        let original = DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            3,
            2,
            image::Rgba([12, 34, 56, 78]),
        ));
        let bytes = png(&original, MAX_BYTES).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.into_rgba8(), original.into_rgba8());
    }
    #[test]
    fn refuses_truncated_and_unsupported_bytes() {
        assert!(decode(b"\x89PNG\r\n\x1a\n").is_err());
        assert!(decode(b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_err());
        assert!(decode(&vec![0; MAX_BYTES + 1]).is_err());
    }
    #[test]
    fn refuses_animation_instead_of_taking_first_frame() {
        let mut bytes = Vec::new();
        {
            let mut encoder = image::codecs::gif::GifEncoder::new(&mut bytes);
            for _ in 0..2 {
                encoder
                    .encode_frame(image::Frame::new(image::RgbaImage::new(2, 2)))
                    .unwrap();
            }
        }
        assert!(decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("animation"));
    }
    #[test]
    fn output_writer_enforces_cap() {
        let image = DynamicImage::new_rgba8(4, 4);
        assert!(png(&image, 16).is_err());
    }
}
