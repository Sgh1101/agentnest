"""Prints selected screenshots into the job log as base64 (shrunk), because the artifact download host is not reachable
from the review box but job logs are. Lines look like:  PNGB64 <name> <chunk>   between PNGB64-BEGIN / PNGB64-END.
Selection: android/tools/emit-pattern.txt, one "glob [scale-percent]" per line ('#' comments)."""
import base64
import fnmatch
import io
import os
import sys

from PIL import Image

shots = sys.argv[1] if len(sys.argv) > 1 else "android/app/build/screenshots"
patterns = sys.argv[2] if len(sys.argv) > 2 else "android/tools/emit-pattern.txt"
names = sorted(f[:-4] for f in os.listdir(shots) if f.endswith(".png"))
done = set()
total = 0
for line in open(patterns, encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    glob = parts[0]
    scale = int(parts[1]) if len(parts) > 1 else 50
    colors = int(parts[2]) if len(parts) > 2 else 96
    for name in names:
        if name in done or not fnmatch.fnmatch(name, glob):
            continue
        done.add(name)
        im = Image.open(os.path.join(shots, name + ".png")).convert("RGB")
        im = im.resize((max(1, im.width * scale // 100), max(1, im.height * scale // 100)), Image.LANCZOS)
        im = im.quantize(colors=colors, dither=Image.Dither.NONE)
        buf = io.BytesIO()
        im.save(buf, "PNG", optimize=True)
        data = buf.getvalue()
        total += len(data)
        b64 = base64.b64encode(data).decode()
        print(f"PNGB64-BEGIN {name} {len(data)}")
        for i in range(0, len(b64), 3000):
            print(f"PNGB64 {name} {b64[i:i + 3000]}")
        print(f"PNGB64-END {name}")
print(f"PNGB64-TOTAL {total} images {len(done)}")
