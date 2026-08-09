#!/bin/bash
# Assemble DragonWatch.app from the SwiftPM release build.
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release

# The Dock/Finder icon, drawn from the same eye geometry as the menu bar mark.
swift Scripts/make-icon.swift

APP=build/DragonWatch.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/DragonWatch "$APP/Contents/MacOS/DragonWatch"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/DragonWatch.icns "$APP/Contents/Resources/DragonWatch.icns"

# Ad-hoc signature: enough to run locally and to use UserNotifications later.
# Real releases should use Developer ID + notarization instead.
codesign --force --sign - "$APP"

echo "Built $APP"
