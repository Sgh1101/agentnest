#!/usr/bin/env python3
"""Generates the placeholder icons of the desktop shell (flat colours, rounded shapes; tiny PNG/ICO files).

    python3 desktop/tools/gen_icons.py

Writes into desktop/apps/desktop/src-tauri/icons/:
  32x32.png, 128x128.png, icon.png (app icon), icon.ico (16/32/48/256),
  tray-gray.png, tray-blue.png, tray-yellow.png, tray-red.png (32x32 status dots used by the tray).
Needs Pillow. Replace the output with real artwork whenever a designer delivers it; nothing else depends on the look.
"""
import os
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(__file__), "..", "apps", "desktop", "src-tauri", "icons")
SS = 4  # supersampling for smooth edges


def app_icon(size: int) -> Image.Image:
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.22), fill=(38, 50, 72, 255))
    # a nest (ring) with an egg
    cx, cy = s // 2, int(s * 0.56)
    d.ellipse((int(s * 0.20), int(s * 0.46), int(s * 0.80), int(s * 0.80)), outline=(214, 170, 96, 255), width=max(2, int(s * 0.06)))
    d.ellipse((cx - int(s * 0.15), cy - int(s * 0.30), cx + int(s * 0.15), cy + int(s * 0.05)), fill=(245, 245, 235, 255))
    return img.resize((size, size), Image.LANCZOS)


def dot(size: int, rgb) -> Image.Image:
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = int(s * 0.08)
    d.ellipse((m, m, s - 1 - m, s - 1 - m), fill=rgb + (255,), outline=(0, 0, 0, 90), width=max(1, int(s * 0.04)))
    return img.resize((size, size), Image.LANCZOS)


def save_png(img: Image.Image, name: str) -> None:
    img.save(os.path.join(OUT, name), format="PNG", optimize=True)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    save_png(app_icon(32), "32x32.png")
    save_png(app_icon(128), "128x128.png")
    save_png(app_icon(256), "icon.png")
    big = app_icon(256)
    big.save(os.path.join(OUT, "icon.ico"), format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    for name, rgb in [("gray", (154, 160, 166)), ("blue", (59, 130, 246)), ("yellow", (245, 180, 0)), ("red", (229, 72, 77))]:
        save_png(dot(32, rgb), f"tray-{name}.png")


if __name__ == "__main__":
    main()
