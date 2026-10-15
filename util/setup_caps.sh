#!/usr/bin/env bash
set -e

echo "[*] Setting capabilities on SIRFZ binary..."
TARGET_BIN="target/release/sirfz"

if [ ! -f "$TARGET_BIN" ]; then
    echo "[!] Target binary $TARGET_BIN not found. Did you run 'cargo build --release'?"
    TARGET_BIN="target/debug/sirfz"
    if [ ! -f "$TARGET_BIN" ]; then
        exit 1
    fi
    echo "[*] Found debug binary instead: $TARGET_BIN"
fi

sudo setcap cap_ipc_lock,cap_sys_admin+ep "$TARGET_BIN"

echo "[SUCCESS] Capabilities applied. You can now execute $TARGET_BIN without sudo/root."
