# Contributing to DragonWatch

macOS menu bar app (Swift/SwiftUI, SwiftPM, no dependencies) that rates every
running process from its code signature and context. The rating rules are
documented for users in `README.md` and in the app's own Criteria tab; the
invariants below are the ones a change must not break, and most were learned
by getting them wrong first.

Everything here applies to human and AI contributors alike.

## Commands

```sh
swift build && swift test                       # unit tests run offline
swift format lint --strict --recursive Sources Tests   # CI gate; must be clean
swift format --in-place --recursive Sources Tests      # apply
./Scripts/make-app.sh                           # build/DragonWatch.app (ad-hoc signed)
./Scripts/make-release.sh                       # zip + SHA-256 for a release
```

Run the app from the **bundle**, not `swift run` — notifications and
launch-at-login need a bundle identifier.

## Verifying the watcher for real

Unit tests cover the logic; these prove the wiring. Each should raise exactly
one alert, and each cleans up after itself.

```sh
# new-suspicious-process: an unsigned binary in /tmp
printf '#include <unistd.h>\nint main(void){for(;;)sleep(1);}\n' > /tmp/dw_canary.c
cc -o /tmp/dw_canary /tmp/dw_canary.c && codesign --remove-signature /tmp/dw_canary
/tmp/dw_canary &            # cleanup: kill %1; rm /tmp/dw_canary*

# new-persistence-item: an inert LaunchAgent (no RunAtLoad, points at /usr/bin/true)
printf '<plist version="1.0"><dict><key>Label</key><string>com.dragonwatch.test</string>\
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>' \
  > ~/Library/LaunchAgents/com.dragonwatch.test.plist
# cleanup: rm ~/Library/LaunchAgents/com.dragonwatch.test.plist

# binary-replaced: run a signed binary, then swap an unsigned one onto its path
mkdir -p ~/dwtest && cp /bin/sleep ~/dwtest/tool && ~/dwtest/tool 60 &
sleep 65 && cc -o ~/dwtest/tool /tmp/dw_canary.c && codesign --remove-signature ~/dwtest/tool
~/dwtest/tool &             # cleanup: kill %1; rm -rf ~/dwtest
```

Also measure rather than assume: idle CPU and memory with the popover closed
(Activity Monitor, after a few minutes at the background cadence), and whether
a quiet machine stays quiet over 24 h. Figures belong in the README only once
someone has measured them — the app's credibility rests on not publishing
numbers nobody checked.

## Definition of done

A change is not finished until all of these are true:

1. `swift test` passes, with **new tests covering the new behaviour** —
   especially its edge cases and the reason it was written.
2. `swift format lint --strict --recursive Sources Tests` is clean.
3. **`README.md` reflects the change** if it altered anything a user sees or
   any claim the README makes — features, behaviour, privacy, requirements.
   Treat a stale README as a failing test.
4. Comments still match the code they describe; delete any that no longer do.
5. New scoring rules or alert kinds have matching text in `TrustExplanation`
   and `CriteriaView` (see the transparency invariant below).

## Invariants — do not break these

- **Everything the app stores is owner-only.** Create the storage directory via
  `AppSupport.directory` (0700) and write through `AppSupport.writePrivately`
  (0600) — never `FileManager.createDirectory` or `Data.write` directly for
  anything describing this machine. Atomic writes replace the file, so the mode
  must be re-applied on every save — `writePrivately` does that. Every store
  goes through it, including the public intel caches: uniform beats a
  per-file judgement call about sensitivity. `AppSupportTests` enforces both
  halves, and no `Data.write`/`createDirectory` should appear outside
  `AppSupport.swift`.
- **Closed means silent.** With the popover closed and intel off, the app makes
  no network requests at all. Anything recurring that only feeds a view must be
  gated on `popoverOpen` — see `AppModel.shouldProbeLatency`, which is unit
  tested precisely so this cannot regress.
- **Read-only.** DragonWatch never kills, quarantines, modifies, or elevates.
  The only exceptions are self-management (quitting our own older instance,
  our own login item) and writing our own files. If a change needs elevation,
  the design is wrong.
- **Minimum permissions.** No entitlements, no TCC usage-description keys, no
  helper tools, no sandbox exception requests. Keep `Resources/Info.plist`
  boring.
- **Context can only lower a rating, never raise it.** External intel can add
  suspicion, never trust. The only paths to trust are a strong signature, the
  pid-verified self exemption, and a verified bundle seal.
- **Seal vouches name specific binaries** (path + mtime + size), never bundle
  membership — vouching a whole bundle would let a planted binary inherit
  trust.
- **Intel that sends data is on-demand only.** MalwareBazaar is the one
  background exception because matching is local. Every provider carries a
  `privacyDisclosure` and defaults to off.
- **List order is stable** — badge severity then name; never per-sample
  numbers like CPU, which made rows jump mid-read.
- **Every rating explains itself.** New scoring rules need matching text in
  `TrustExplanation` and `CriteriaView`, and tests asserting the explanation
  agrees with the score.
- **Never signal state with colour alone.** Every badge carries a distinct SF
  Symbol and an `accessibilityLabel`; `.help()` is a mouse tooltip and reaches
  neither VoiceOver nor the keyboard. `testEveryBadgeHasADistinctNonColourSymbol`
  enforces the shape half.

## Conventions

- Sampling and I/O live in actors; UI state is `@MainActor` and `@Observable`.
  Views read models directly and use `@Bindable` only where they need a
  two-way binding. Do not reintroduce `ObservableObject`/`@Published`: nested
  ones do not republish through `AppModel`, which is the bug `@Observable`
  removes.
- Kernel counters (`cpu_ticks`, `ifi_ibytes`) are `UInt32` and wrap. Use
  wrapping subtraction; both wraps have regression tests.
- Feed data is untrusted input: byte-cap before parsing, validate per entry,
  drop rather than trust, and keep last-known-good on failure.
- Comments explain *why*, especially where a rule looks wrong but isn't
  (quarantine exemption, latched network signal, self exemption).
