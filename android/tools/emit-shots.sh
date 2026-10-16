#!/usr/bin/env bash
# Prints selected screenshots into the job log as base64 (shrunk), because the artifact download host is not reachable
# from the review box but job logs are. Lines look like:  PNGB64 <name> <chunk>   between PNGB64-BEGIN / PNGB64-END.
# Selection: android/tools/emit-pattern.txt, one "glob [scale-percent]" per line ('#' comments). Empty file = nothing.
set -u
dir="${1:-android/app/build/screenshots}"
patterns="${2:-android/tools/emit-pattern.txt}"
conv="convert"
command -v magick >/dev/null 2>&1 && conv="magick"
tmp="$(mktemp -d)"
shopt -s nullglob
total=0
while read -r glob scale; do
  case "$glob" in ""|\#*) continue;; esac
  scale="${scale:-50}"
  for f in "$dir"/$glob.png; do
    name="$(basename "$f" .png)"
    [ -f "$tmp/$name.done" ] && continue
    out="$tmp/$name.png"
    $conv "$f" -resize "${scale}%" +dither -colors 96 -strip -define png:compression-level=9 "PNG8:$out" || continue
    size="$(stat -c%s "$out")"
    total=$((total + size))
    echo "PNGB64-BEGIN $name $size"
    base64 -w 3000 "$out" | sed "s/^/PNGB64 $name /"
    echo "PNGB64-END $name"
    touch "$tmp/$name.done"
  done
done < "$patterns"
echo "PNGB64-TOTAL $total"
