#!/bin/bash
# Assemble DragonWatch.app from the SwiftPM release build.
set -euo pipefail
cd "$(dirname "$0")/.."

# Universal: a host-arch build only runs on the machine that made it, and
# GitHub's runners are Apple silicon while some users' Macs are Intel.
swift build -c release --arch arm64 --arch x86_64
BIN=.build/apple/Products/Release/DragonWatch

# The Dock/Finder icon, drawn from the same eye geometry as the menu bar mark.
swift Scripts/make-icon.swift

APP=build/DragonWatch.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/DragonWatch"
cp Resources/Info.plist "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
cp Resources/DragonWatch.icns "$APP/Contents/Resources/DragonWatch.icns"

# Ad-hoc signature: enough to run locally and to use UserNotifications later.
# Real releases should use Developer ID + notarization instead.
codesign --force --sign - "$APP"

# Refuse to ship a single-architecture binary: the failure mode is a zip that
# opens fine on the release machine and "can't be opened" on the other kind.
ARCHS=$(lipo -archs "$APP/Contents/MacOS/DragonWatch")
case "$ARCHS" in
    *arm64*x86_64* | *x86_64*arm64*) ;;
    *) echo "error: expected a universal binary, got: $ARCHS" >&2; exit 1 ;;
esac

echo "Built $APP ($ARCHS)"
