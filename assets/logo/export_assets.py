# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow==12.3.0", "resvg-py==0.5.0"]
# ///
"""Render the approved vector sources: uv run assets/logo/export_assets.py.

The mark, favicon and outlined wordmark SVGs are the editable sources. This
exporter uses no fonts, external SVG resources, or image-generation service.
"""
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

from PIL import Image, ImageDraw
import resvg_py

ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(__file__).resolve().parent
PUBLIC = ROOT / "website/public"
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)
INK, AMBER, IVORY = "#151817", "#E79425", "#F3F0E8"


def render(path, width, height=None, background=None):
    return resvg_py.svg_to_bytes(svg_path=str(path), width=width,
                                height=height or width, background=background)


def nested_svg(path, x, y, width, height):
    source = ET.parse(path).getroot()
    group = ET.Element(f"{{{NS}}}svg", {
        "x": str(x), "y": str(y), "width": str(width), "height": str(height),
        "viewBox": source.attrib["viewBox"],
    })
    for child in source:
        if child.tag.rsplit("}", 1)[-1] not in {"title", "desc"}:
            group.append(deepcopy(child))
    return group


mark = ASSETS / "ukai-mark.svg"
dark = ASSETS / "ukai-mark-on-dark.svg"
dark.write_text(mark.read_text().replace(f'fill="{INK}"', f'fill="{IVORY}"'))
for source in (mark, dark):
    source.with_suffix(".png").write_bytes(render(source, 1000))

banner = ET.Element(f"{{{NS}}}svg", {
    "width": "1600", "height": "480", "viewBox": "0 0 1600 480",
    "role": "img", "aria-labelledby": "ukai-banner-title",
})
ET.SubElement(banner, f"{{{NS}}}title", {"id": "ukai-banner-title"}).text = "Ukai"
ET.SubElement(banner, f"{{{NS}}}rect", {"width": "1600", "height": "480", "fill": IVORY})
banner.append(nested_svg(mark, 235, 40, 400, 400))
banner.append(nested_svg(ASSETS / "ukai-wordmark.svg", 700, 104, 650, 272))
banner_path = ASSETS / "ukai-readme-banner.svg"
banner_path.write_text(ET.tostring(banner, encoding="unicode") + "\n")
banner_path.with_suffix(".png").write_bytes(render(banner_path, 1600, 480))

favicon = ASSETS / "ukai-favicon.svg"
sizes = (16, 24, 32, 48)
icons = []
for size in sizes:
    raw = render(favicon, size)
    (ASSETS / f"ukai-favicon-{size}.png").write_bytes(raw)
    icons.append(Image.open(BytesIO(raw)).convert("RGBA"))
icons[-1].save(ASSETS / "ukai-favicon.ico", sizes=[(s, s) for s in sizes],
               append_images=icons[:-1], bitmap_format="bmp")

# Public copies remain byte-identical to the editable source artifacts.
(PUBLIC / "brand").mkdir(exist_ok=True)
for source, target in (
    (mark, PUBLIC / "brand/ukai.svg"),
    (dark, PUBLIC / "brand/ukai-on-dark.svg"),
    (favicon, PUBLIC / "favicon.svg"),
    (ASSETS / "ukai-favicon.ico", PUBLIC / "favicon.ico"),
):
    shutil.copyfile(source, target)

# Review sheet: both transparent mark variants, native-size icons and a banner.
sheet = Image.new("RGB", (1600, 1080), "#E6E4DE")
draw = ImageDraw.Draw(sheet)
draw.rectangle((30, 30, 785, 525), fill=IVORY)
draw.rectangle((815, 30, 1570, 525), fill="#0B0D0C")
for path, origin in ((mark, (180, 50)), (dark, (965, 50))):
    picture = Image.open(BytesIO(render(path, 440))).convert("RGBA")
    sheet.paste(picture, origin, picture)
draw.text((55, 495), "PRIMARY / TRANSPARENT", fill=INK)
draw.text((840, 495), "REVERSED / TRANSPARENT", fill=IVORY)
for offset, background, foreground in ((30, IVORY, INK), (815, "#0B0D0C", IVORY)):
    draw.rectangle((offset, 550, offset + 755, 750), fill=background)
    draw.text((offset + 25, 570), "FAVICON / ACTUAL PIXELS", fill=foreground)
    for i, size in enumerate(sizes):
        icon = icons[i]
        x = offset + 45 + i * 110
        sheet.paste(icon, (x, 615), icon)
        draw.text((x, 675), f"{size} px", fill=foreground)
    enlarged = icons[0].resize((96, 96), Image.Resampling.NEAREST)
    sheet.paste(enlarged, (offset + 590, 595), enlarged)
    draw.text((offset + 590, 700), "16 px / 6x", fill=foreground)
banner_preview = Image.open(banner_path.with_suffix(".png")).resize((900, 270), Image.Resampling.LANCZOS)
sheet.paste(banner_preview, (350, 780))
sheet.save(ASSETS / "ukai-asset-preview.png")

files = ["ukai-mark.svg", "ukai-mark.png", "ukai-mark-on-dark.svg", "ukai-mark-on-dark.png",
         "ukai-wordmark.svg", "ukai-favicon.svg", "ukai-favicon.ico",
         *[f"ukai-favicon-{s}.png" for s in sizes],
         "ukai-readme-banner.svg", "ukai-readme-banner.png", "ukai-asset-preview.png"]
source = ASSETS / "ukai-concepts-2026-10-15/06-firelit-profile-wide-arc.png"
manifest = {
    "brand": "Ukai", "approved_concept": str(source.relative_to(ROOT)),
    "approved_concept_sha256": sha256(source.read_bytes()).hexdigest(),
    "palette": {"ink": INK, "amber": AMBER, "ivory": IVORY},
    "master": "ukai-mark.svg",
    "provenance": {
        "mark": "Approved raster separated into silhouette/firelight/arc; fitted with Potracer 0.0.4, curve tolerance 0.55, then flattened to two solid inks. Eye and wing are transparent negative space. No embedded bitmap.",
        "favicon": "Optically redrawn head and neck, enlarged amber edge, heavier detached arc; eye, wing, feet and tail omitted. Ivory tile preserves contrast on both browser themes.",
        "wordmark": "Manrope variable 5.3.0 at weight 650, lowercase ukai, tracking -0.025 em, converted to paths with FontTools 4.67.0. Font license: Manrope-OFL.txt.",
        "banner": "1600 x 480 opaque ivory canvas; embedded vector mark and outlined wordmark, no external resources.",
        "on_dark": "Identical mark geometry; ink is replaced with ivory for dark backgrounds.",
    },
    "rebuild": "uv run assets/logo/export_assets.py",
    "files": [{"path": name, "bytes": (ASSETS/name).stat().st_size,
               "sha256": sha256((ASSETS/name).read_bytes()).hexdigest()} for name in files],
}
(ASSETS / "ukai-assets.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Exported {len(files)} assets, public copies, and manifest.")
