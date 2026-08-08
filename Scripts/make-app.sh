#!/bin/bash
# Assemble DragonWatch.app from the SwiftPM release build.
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release

APP=build/DragonWatch.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/DragonWatch "$APP/Contents/MacOS/DragonWatch"
cp Resources/Info.plist "$APP/Contents/Info.plist"

# Ad-hoc signature: enough to run locally and to use UserNotifications later.
# Real releases should use Developer ID + notarization instead.
codesign --force --sign - "$APP"

echo "Built $APP"
