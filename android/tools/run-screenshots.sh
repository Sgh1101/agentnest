#!/usr/bin/env bash
# Runs the Compose screenshot tests on the already-booted emulator and pulls the PNGs.
# The tests copy their PNGs to /data/local/tmp/agentnest-shots (Gradle uninstalls the app after the run, which would
# delete anything inside the app's own storage). A failing test must not hide the screenshots that were taken, so the
# Gradle exit code is stored in a file and judged by the workflow after the artifact upload.
set -u
cd "$(dirname "$0")/.."

OUT="$PWD/app/build/screenshots"
rm -rf "$OUT"
mkdir -p "$OUT"

adb shell rm -rf /data/local/tmp/agentnest-shots || true
# A 411 dp wide, ~1190 dp tall window: the 360x800 and 411x914 dp frames of the tests fit without clipping.
adb shell wm density 420 || true
sleep 5
adb shell wm size || true
adb shell wm density || true

status=0
./gradlew :app:connectedDebugAndroidTest --no-daemon --console=plain || status=$?

adb pull /data/local/tmp/agentnest-shots/. "$OUT" || echo "adb pull failed"
echo "$status" > "$OUT/gradle-exit.txt"
echo "gradle exit code: $status"
ls "$OUT" | wc -l
if [ -f "$OUT/log.txt" ]; then echo "--- log.txt ---"; cat "$OUT/log.txt"; fi
exit 0
