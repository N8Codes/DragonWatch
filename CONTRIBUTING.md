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
./Scripts/make-app.sh                           # build/DragonWatch.app (universal, ad-hoc signed)
./Scripts/make-release.sh                       # zip + SHA-256 for a release
```

Run the app from the **bundle**, not `swift run` — notifications and
launch-at-login need a bundle identifier.

## Verifying the watcher for real

Unit tests cover the rules; this proves the wiring — that something appearing
on disk becomes an alert.

```sh
open build/DragonWatch.app     # must be running; leave the popover closed
./Scripts/verify-watcher.sh    # ~12 min; DW_SKIP_CPU=1 skips the slow case
```

It plants five benign cases — an unsigned binary in a private temp directory,
an inert LaunchAgent, an ad-hoc-signed binary replaced by an unsigned one at
the same path, an ad-hoc-signed binary patched after signing, and a CPU load
held above the alert threshold for the rule's full window — reads the app's
own observation ledger to confirm each alert fired, and removes everything it
created on any exit. That covers every alert kind.

It proves the alert reached the ledger, not that a banner appeared: banners
are gated by the per-app permission in System Settings → Notifications, which
the app's Settings tab reports (and logs under the `notifications` category
of the `com.dragonwatch.DragonWatch` subsystem). One install had that
permission denied for months and the only symptom was silence.

The watcher also logs one line per tick under the `watcher` category — the
CPU sample and everything the sustained-CPU rule sees — so "why did it not
fire" can be answered from `log stream --info --predicate 'subsystem ==
"com.dragonwatch.DragonWatch" AND category == "watcher"'` without a rebuild.
Remember the 30-minute cooldown: a run that just alerted will not alert again,
and the script's CPU case says so rather than failing.

Two things it has to work around, both learned the hard way:

- **macOS SIGKILLs a copied Apple platform binary** (exit 137) — the kernel
  validates platform binaries against its trust cache by cdhash, so a copy
  never executes. The downgrade case therefore uses an ad-hoc-signed binary we
  build ourselves, not a copy of `/bin/sleep`.
- **The ledger records every path permanently and alerts fire once per path**,
  so each run uses unique paths. A fixed name passes once and silently tests
  nothing afterwards.

Also measure rather than assume: idle CPU and memory with the popover closed,
over at least half an hour — a single reading minutes after launch missed a
memory leak that only appeared once provenance hashing had worked through the
queue. Figures belong in the README only once someone has measured them.

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
6. **Anything in `Scripts/` is reviewed like shipped code**, because it runs on
   a contributor's machine with their privileges. Never write to a predictable
   path under `/tmp` — shell redirection follows symlinks, so a pre-placed link
   redirects the write to any file the user can modify; use `mktemp -d`. Put
   cleanup in `trap … EXIT INT TERM`, and delete only what the run created.

## Invariants — do not break these

- **Everything the app stores is owner-only.** Create the storage directory via
  `AppSupport.directory` (0700) and write through `AppSupport.writePrivately`
  (0600) — never `FileManager.createDirectory` or `Data.write` directly for
  anything describing this machine. Atomic writes replace the file, so the mode
  must be re-applied on every save — `writePrivately` does that. Every store
  goes through it, including the public intel caches: uniform beats a
  per-file judgement call about sensitivity. `AppSupportTests` enforces both
  halves, and no `Data.write`/`createDirectory` should appear outside
  `AppSupport.swift` — the one exception is the user-driven history export,
  which writes to a path the user chose and then sets 0600 on it.
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
- **`TrustScoring.applies` is the only place a modifier's relevance is
  decided.** `badge` and `TrustExplanation` both read it, so an explanation
  can never list a demotion the score did not apply. They drifted apart once
  and the UI showed stock Apple binaries a "lowered" step above a `Trusted`
  result.
- **Signature validation must include the executable.** Use
  `SecCSFlags(rawValue: 4)` (`kSecCSDoNotValidateResources`), never
  `kSecCSBasicValidateOnly` (6) — 6 also skips the code pages, so a binary
  patched in place validates clean. Verified by execution; there is a test.
- **Seal vouches name specific binaries**, identified by their *contents*
  (cdhash, or SHA-256 when unsigned), never bundle membership and never
  `mtime`/`size` — both of those are settable by whoever can write the file,
  so a swapped binary kept its vouch. The fingerprint is re-checked on every
  assessment, not only when the vouch map is loaded.
- **Nothing about this Mac is ever sent anywhere.** Intel is on-demand only,
  matches locally, and may download public feeds but never upload — no hash,
  no path, no name. Every provider carries a `privacyDisclosure` and defaults
  to off. A feature that needs to send data to work does not belong here.
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
