#!/bin/sh
# C compiler shim for `cargo check --target x86_64-pc-windows-msvc` on a Linux machine (docs/testing-and-ci.md 2.1).
#
# `ring` and the bundled SQLite compile C code in their build scripts even for `cargo check`. Without the MSVC CRT
# headers (the Windows SDK cannot be downloaded here) that fails. `cargo check` never links, so the objects only have to
# compile: this shim compiles them with clang against the mingw-w64 headers (`apt install mingw-w64-x86-64-dev clang`).
# The later `--target` wins in clang, so the object files are mingw-flavoured; nothing ever uses them.
#
#   export CC_x86_64_pc_windows_msvc=$PWD/tools/cc-msvc-check.sh AR_x86_64_pc_windows_msvc=llvm-ar
#   cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc
INC="${MINGW_INCLUDE:-/usr/x86_64-w64-mingw32/include}"
exec clang "$@" --target=x86_64-w64-windows-gnu -isystem "$INC"
