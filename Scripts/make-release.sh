#!/bin/bash
# Build, zip, and checksum a release artifact. The published SHA-256 is the
# defense against someone shipping a trojanized build under our name.
set -euo pipefail
cd "$(dirname "$0")/.."

./Scripts/make-app.sh

VERSION=$(plutil -extract CFBundleShortVersionString raw Resources/Info.plist)
OUT="build/DragonWatch-$VERSION.zip"
rm -f "$OUT" "$OUT.sha256"
ditto -c -k --keepParent build/DragonWatch.app "$OUT"
(cd build && shasum -a 256 "$(basename "$OUT")" | tee "$(basename "$OUT").sha256")

echo "Built $OUT"
