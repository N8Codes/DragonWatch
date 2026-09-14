#!/bin/bash
# Verify the alert pipeline end to end against a running DragonWatch.
#
# Unit tests cover the rules; this proves the wiring — that something appearing
# on disk becomes an alert. It plants five benign cases, reads DragonWatch's
# own observation ledger to see which alerts actually fired, and removes
# everything it created.
#
# Nothing here is malware. Case 1 is a sleep loop you compile yourself; case 2
# is an inert plist (no RunAtLoad, never registered with launchctl, and its
# program is /usr/bin/true); case 3 overwrites a file in a scratch directory
# under your home; case 4 is the same sleep loop, ad-hoc signed and then
# patched so the signature no longer matches; case 5 runs one `yes >/dev/null`
# per core for about four minutes. No network, no elevation, and no writes
# outside /tmp/dw_verify*, ~/dwtest-verify/, and one plist in
# ~/Library/LaunchAgents.
#
# Usage:  ./Scripts/verify-watcher.sh          # ~12 min
#         DW_SKIP_CPU=1 ./Scripts/verify-watcher.sh   # skip the slow case 5
# Cleanup runs on exit, including if you interrupt with ^C.

set -uo pipefail

LEDGER="$HOME/Library/Application Support/DragonWatch/observations.json"
PLIST=""  # set once RUN_ID exists
# The ledger records every path permanently, and alerts fire once per path.
# Fixed names therefore pass on the first run and silently test nothing after
# that, so each run gets its own identity.
RUN_ID="$$-$(date +%s)"
PLIST="$HOME/Library/LaunchAgents/com.dragonwatch.verify.$RUN_ID.plist"
SCRATCH="$HOME/dwtest-verify-$RUN_ID"
PLIST_LABEL="com.dragonwatch.verify.$RUN_ID"
CANARY_PID=""
SWAP_PID=""
PATCHED_PID=""
BURN_PIDS=""
PLIST_CREATED=0

# Fixed /tmp names are attackable: /tmp is world-writable, so anything could
# pre-place a symlink at a predictable path and shell redirection would follow
# it, overwriting the target (CWE-377). mktemp -d gives an unguessable 0700
# directory, and keeping it under /tmp preserves the suspicious-location
# signal the first case is meant to exercise.
WORKDIR="$(mktemp -d /tmp/dw_verify.XXXXXXXX)" || { echo "mktemp failed"; exit 1; }
CANARY_SRC="$WORKDIR/canary.c"
CANARY="$WORKDIR/canary"

# The background cadence is user-configurable (15/25/60s). Wait comfortably
# past the longest so a slow setting cannot produce a false failure.
TICK_WAIT="${DW_TICK_WAIT:-70}"

cleanup() {
    echo
    echo "Cleaning up…"
    [ -n "$CANARY_PID" ] && kill "$CANARY_PID" 2>/dev/null
    [ -n "$SWAP_PID" ] && kill "$SWAP_PID" 2>/dev/null
    [ -n "$PATCHED_PID" ] && kill "$PATCHED_PID" 2>/dev/null
    # shellcheck disable=SC2086  # intentionally split: one pid per word
    [ -n "$BURN_PIDS" ] && kill $BURN_PIDS 2>/dev/null
    rm -rf "$WORKDIR" "$SCRATCH"
    # Only delete the plist if this run created it — never remove a file that
    # happened to be there already.
    [ "$PLIST_CREATED" -eq 1 ] && rm -f "$PLIST"
    echo "Removed: $WORKDIR, $SCRATCH$([ "$PLIST_CREATED" -eq 1 ] && echo ", $PLIST")"
    echo "Your ledger still holds the entries these created — clear them with"
    echo "Settings → Reset Baseline, or mark them Expected in the review queue."
}
trap cleanup EXIT INT TERM

fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
pass() { echo "  pass: $1"; }
FAILURES=0

# Compare counts defensively: an unreadable ledger or a missing python3 would
# otherwise yield empty strings, and `[ "" -gt "" ]` reports a shell error that
# reads like a passing test.
grew() {
    # Validate each side separately: concatenating them lets "0" and "" pass
    # as one valid number, and the comparison then errors out.
    case "${1:-}" in '' | *[!0-9]*) return 1 ;; esac
    case "${2:-}" in '' | *[!0-9]*) return 1 ;; esac
    [ "$2" -gt "$1" ]
}

# Poll the ledger until $1 appears as a recorded identity, up to $2 seconds.
# Waiting a fixed interval and hoping a tick lands inside it is how the swap
# case silently tested nothing: the signed phase was never observed, so there
# was no earlier tier to downgrade from.
wait_for_tier() {
    local path="$1" want="$2" limit="${3:-180}" waited=0
    while [ "$waited" -lt "$limit" ]; do
        if python3 - "$LEDGER" "$path" "$want" <<'PY'
import json, sys
try:
    ids = json.load(open(sys.argv[1])).get("identities", {})
except Exception:
    raise SystemExit(1)
entry = ids.get(sys.argv[2])
raise SystemExit(0 if entry and entry.get("tier") == sys.argv[3] else 1)
PY
        then return 0; fi
        sleep 5; waited=$((waited + 5))
    done
    return 1
}

# Count how many events of a given kind mention a given path fragment.
events_matching() {
    python3 - "$LEDGER" "$1" "$2" <<'PY'
import json, sys
try:
    events = json.load(open(sys.argv[1])).get("events", [])
except Exception:
    print(0); raise SystemExit
kind, needle = sys.argv[2], sys.argv[3]
print(sum(1 for e in events
          if e.get("kind") == kind and needle in (e.get("detail", "") + e.get("title", ""))))
PY
}

echo "DragonWatch watcher verification"
echo

if ! pgrep -f "DragonWatch.app/Contents/MacOS/DragonWatch" >/dev/null; then
    echo "DragonWatch is not running. Start it first:"
    echo "  open build/DragonWatch.app"
    exit 1
fi
if ! command -v python3 >/dev/null; then
    echo "python3 is required to read the ledger (ships with Xcode command line tools)."
    exit 1
fi
if [ ! -f "$LEDGER" ]; then
    echo "No observation ledger at $LEDGER — let the app run for a tick first."
    exit 1
fi
echo "App is running; ledger found."
echo "Keep the popover CLOSED so this exercises the background watcher."
echo
echo "Note: if you just used Settings -> Reset Baseline, let the app complete one"
echo "sweep first. The seeding pass records existing state WITHOUT alerting, so"
echo "running now would fail every case for the wrong reason."
echo

# ---------------------------------------------------------------- case 1
echo "[1/5] Unsigned binary in /tmp  → expects: newUntrustedProcess"
before=$(events_matching newUntrustedProcess dw_verify)
printf '#include <unistd.h>\nint main(void){for(;;)sleep(1);}\n' > "$CANARY_SRC"
if ! cc -o "$CANARY" "$CANARY_SRC" 2>/dev/null; then
    echo "  SKIP: no C compiler (install Xcode command line tools)"
else
    codesign --remove-signature "$CANARY" 2>/dev/null
    "$CANARY" & CANARY_PID=$!
    echo "  planted (pid $CANARY_PID), waiting ${TICK_WAIT}s for a background tick…"
    sleep "$TICK_WAIT"
    after=$(events_matching newUntrustedProcess dw_verify)
    grew "$before" "$after" && pass "alert fired" || fail "no newUntrustedProcess alert for $CANARY"
fi
echo

# ---------------------------------------------------------------- case 2
echo "[2/5] Inert LaunchAgent        → expects: newPersistenceItem"
before=$(events_matching newPersistenceItem "$PLIST_LABEL")
if [ -e "$PLIST" ]; then
    echo "  SKIP: $PLIST already exists — not overwriting a file we did not create"
else
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$PLIST_LABEL</string>
    <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
</dict></plist>
PLISTEOF
PLIST_CREATED=1
echo "  planted $PLIST (not loaded), waiting ${TICK_WAIT}s…"
sleep "$TICK_WAIT"
after=$(events_matching newPersistenceItem "$PLIST_LABEL")
grew "$before" "$after" && pass "alert fired" || fail "no newPersistenceItem alert"
fi
echo

# ---------------------------------------------------------------- case 3
echo "[3/5] Binary replaced in place → expects: binaryReplaced"
# Ad-hoc signed (Caution) replaced by unsigned (Suspicious) at the same path is
# a genuine tier downgrade, and both phases are binaries we build ourselves.
# A copied Apple binary cannot be used: macOS validates platform binaries
# against its trust cache by cdhash and SIGKILLs a copy on exec (verified:
# exit 137), so the "signed phase" process never runs at all.
before=$(events_matching binaryReplaced "dwtest-verify-$RUN_ID")
mkdir -p "$SCRATCH"
if ! cc -o "$SCRATCH/tool" "$CANARY_SRC" 2>/dev/null || ! codesign -s - "$SCRATCH/tool" 2>/dev/null; then
    echo "  SKIP: could not build and ad-hoc sign the first binary"
else
    "$SCRATCH/tool" & SWAP_PID=$!
    echo "  ran the ad-hoc signed binary (pid $SWAP_PID); waiting for the watcher…"
    if ! wait_for_tier "$SCRATCH/tool" "Ad-hoc signed" 240; then
        fail "the ad-hoc binary was never recorded — cannot test a downgrade from it"
        kill "$SWAP_PID" 2>/dev/null; SWAP_PID=""
    else
        echo "  recorded as Ad-hoc signed. swapping in an unsigned build…"
        kill "$SWAP_PID" 2>/dev/null; SWAP_PID=""
        cc -o "$SCRATCH/tool" "$CANARY_SRC" 2>/dev/null
        codesign --remove-signature "$SCRATCH/tool" 2>/dev/null
        "$SCRATCH/tool" & SWAP_PID=$!
        if wait_for_tier "$SCRATCH/tool" "Unsigned" 240; then
            sleep 5   # let the alert land after the tier is recorded
            after=$(events_matching binaryReplaced "dwtest-verify-$RUN_ID")
            grew "$before" "$after" && pass "alert fired" || fail "tier downgraded but no binaryReplaced alert"
        else
            fail "the unsigned replacement was never recorded"
        fi
    fi
fi
echo

# ---------------------------------------------------------------- case 4
echo "[4/5] Signature patched after signing → expects: invalidSignature"
# The marker string lives in the binary's __TEXT segment, which the ad-hoc
# signature seals. Rewriting one byte of it after signing leaves a signature
# that no longer matches the code pages — the tampered-in-place case. The
# patch is same-length, so nothing else about the file moves.
#
# Whether the patched binary runs at all is up to the kernel: Intel Macs let a
# non-hardened binary with an invalid signature execute; Apple silicon kills
# it on exec. A kill is reported as a skip, not a failure — the app never got
# a process to look at.
PATCHED_DIR="$SCRATCH/patched"
PATCHED="$PATCHED_DIR/tool"
before=$(events_matching invalidSignature "$PATCHED")
mkdir -p "$PATCHED_DIR"
printf '#include <unistd.h>\nconst char marker[] = "DRAGONWATCH-VERIFY-MARKER";\nint main(void){for(;;)sleep(1);}\n' > "$WORKDIR/patched.c"
if ! cc -o "$PATCHED" "$WORKDIR/patched.c" 2>/dev/null || ! codesign -s - "$PATCHED" 2>/dev/null; then
    echo "  SKIP: could not build and ad-hoc sign the binary"
elif ! python3 - "$PATCHED" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
marker = b"DRAGONWATCH-VERIFY-MARKER"
at = data.find(marker)
if at < 0:
    raise SystemExit(1)
data[at:at + len(marker)] = b"DRAGONWATCH-VERIFY-PATCHD"
open(path, "wb").write(data)
PY
then
    echo "  SKIP: could not patch the marker string"
elif codesign --verify "$PATCHED" 2>/dev/null; then
    fail "the patch did not invalidate the signature — cannot test this case"
else
    "$PATCHED" & PATCHED_PID=$!
    sleep 2
    if ! kill -0 "$PATCHED_PID" 2>/dev/null; then
        echo "  SKIP: the kernel refused to run the patched binary (expected on Apple silicon);"
        echo "        DragonWatch never saw a process, so there is nothing to rate."
        PATCHED_PID=""
    else
        echo "  running (pid $PATCHED_PID); waiting for the watcher…"
        if wait_for_tier "$PATCHED" "Invalid signature" 240; then
            sleep 5   # let the alert land after the tier is recorded
            after=$(events_matching invalidSignature "$PATCHED")
            grew "$before" "$after" && pass "alert fired" || fail "rated Invalid signature but no invalidSignature alert"
        else
            fail "the patched binary was never recorded as Invalid signature"
        fi
    fi
fi
echo

# ---------------------------------------------------------------- case 5
echo "[5/5] Sustained CPU load        → expects: sustainedCPU"
# The rule wants every sample across a 3-minute window at or above the
# threshold (85% unless changed in Settings), and it re-fires at most once
# per 30 minutes. So: saturate every core, hold for the window plus a tick,
# and poll for the event instead of guessing when a tick lands.
CPU_WINDOW=180
CPU_COOLDOWN=1800
if [ -n "${DW_SKIP_CPU:-}" ]; then
    echo "  SKIP: DW_SKIP_CPU is set"
elif python3 - "$LEDGER" "$CPU_COOLDOWN" <<'PY'
import json, sys, time
# Ledger dates are seconds since 2001-01-01 UTC (Foundation's reference date).
now = time.time() - 978307200
try:
    events = json.load(open(sys.argv[1])).get("events", [])
except Exception:
    raise SystemExit(1)
recent = [e for e in events
          if e.get("kind") == "sustainedCPU" and now - e.get("date", 0) < float(sys.argv[2])]
raise SystemExit(0 if recent else 1)
PY
then
    echo "  SKIP: a sustainedCPU alert fired within the last 30 min, so the rule"
    echo "        is inside its cooldown and cannot fire again yet."
else
    before=$(events_matching sustainedCPU "")
    NCPU=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
    i=0
    while [ "$i" -lt "$NCPU" ]; do
        yes > /dev/null & BURN_PIDS="$BURN_PIDS $!"
        i=$((i + 1))
    done
    limit=$((CPU_WINDOW + TICK_WAIT * 2))
    echo "  $NCPU cores loaded; polling for up to ${limit}s (the rule's window is ${CPU_WINDOW}s)…"
    waited=0
    fired=0
    while [ "$waited" -lt "$limit" ]; do
        sleep 10; waited=$((waited + 10))
        after=$(events_matching sustainedCPU "")
        if grew "$before" "$after"; then fired=1; break; fi
    done
    # shellcheck disable=SC2086
    kill $BURN_PIDS 2>/dev/null; BURN_PIDS=""
    [ "$fired" -eq 1 ] && pass "alert fired after ${waited}s" || fail "no sustainedCPU alert after ${limit}s of full load"
fi
echo

echo "────────────────────────────────────────"
if [ "$FAILURES" -eq 0 ]; then
    echo "Every planted case that could run produced its alert. The pipeline works end to end."
else
    echo "$FAILURES case(s) did not alert."
    echo "Check: is the rule enabled in Settings? Was the popover left open"
    echo "(that changes cadence, not correctness)? Did the ledger update?"
fi
exit "$FAILURES"
