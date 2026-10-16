#!/usr/bin/env bash
# Prepare the `agentnest-hook` sidecar that Tauri bundles next to the app (tauri.conf.json `bundle.externalBin`).
#
# Claude Code never sends `SessionStart` to `type:"http"` hooks, so that event always goes through the command hook
# `agentnest-hook` (docs/integrations/claude-code.md). The installed app finds it next to its own executable
# (`startup.rs::hook_cli_path`), so the installer has to ship it.
#
# Tauri names a sidecar `<name>-<target-triple>[.exe]` and `tauri-build` checks that the file exists on EVERY build
# (even `cargo check`), so type-check-only jobs create an empty placeholder instead of a real build:
#
#   tools/prepare-hook-sidecar.sh                      # real release build for the host triple (CI Windows, releases)
#   tools/prepare-hook-sidecar.sh --placeholder TRIPLE # empty file, never executed (Linux type checks)
set -euo pipefail

cd "$(dirname "$0")/.."

placeholder=0
if [ "${1:-}" = "--placeholder" ]; then
    placeholder=1
    shift
fi

triple="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$triple" in
    *windows*) ext=".exe" ;;
    *) ext="" ;;
esac

dest_dir="apps/desktop/src-tauri/binaries"
dest="$dest_dir/agentnest-hook-$triple$ext"
mkdir -p "$dest_dir"

if [ "$placeholder" = "1" ]; then
    : > "$dest"
else
    cargo build --locked --release -p agentnest-hook --target "$triple"
    cp "target/$triple/release/agentnest-hook$ext" "$dest"
    # a real build is never empty: a placeholder must not be bundled by accident
    [ -s "$dest" ] || { echo "sidecar $dest is empty" >&2; exit 1; }
fi
echo "sidecar ready: $dest"
