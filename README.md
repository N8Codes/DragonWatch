# DragonWatch 🐉

**A lightweight macOS process trust monitor.**

> **Beta.** Three alert paths are confirmed firing on real hardware (new
> unsigned process, new LaunchAgent, replaced binary). The known-malware,
> invalid-signature, sustained-CPU and network-change alerts are unit-tested
> but unproven live. Tested by one person on one Mac — treat a *missing*
> notification as unproven, not impossible.

DragonWatch lives in your menu bar behind a dragon-eye icon. Open it and you see
every app and process running on your Mac, grouped the way you think about
them, each with a trust badge derived from macOS's own security signals —
plus your machine's vital signs.

- ✅ **Trusted** — Apple system binary, App Store app, or Developer ID signed
- ⚠️ **Caution** — signed but unverified authority, or trusted-with-an-asterisk
- ⛔ **Suspicious** — unsigned, invalid signature, or multiple risk signals

Each rating has its own shape as well as its own colour, and is labelled for
VoiceOver — the trusted/suspicious distinction never depends on telling red
from green.

The dragon eye in your menu bar is the summary: plain when all is clear, with
an orange or red warning badge when something deserves a look.

## What it is (and isn't)

Makes your machine's state **visible and legible**. It is **not an antivirus** —
macOS already runs XProtect and Gatekeeper underneath.

- **Read-only.** Never stops, kills, quarantines, or modifies another program,
  and never asks for elevated privileges.
- **Quiet.** With intel off — how it ships — the only network request is a
  latency probe to Apple's captive-portal URL, once a minute and only while
  the popover is open. Enabling a provider adds background downloads of public
  threat lists.
- **Private.** No data about your machine is sent anywhere. Opt-in intel is the
  only exception, and each provider says exactly what it sends.

## How trust is determined

Every process's executable is checked against the Security framework:

1. **Signature tier** — Apple platform binary → App Store → Developer ID →
   other valid signature → ad-hoc → unsigned/invalid.
2. **Context modifiers** that can only *lower* the rating — running from a
   temp or Downloads folder, and (for weakly-signed code only) a quarantine
   attribute, hidden directories, injection-friendly entitlements, or active
   network connections.

Signatures anchor the rating; context refines it. A notarized driver running
from a hidden folder stays trusted — an unsigned binary in `/tmp` does not.

**Every rating explains itself.** Click any process and the detail view walks
through the reasoning in the order the engine applied it — including signals
that were considered and deliberately *not* counted, so nothing is silent.
The **Criteria** tab lists the complete rulebook: every signature tier, every
context signal with why it's treated as risk, every exemption, and what the
app deliberately doesn't do. No cloud verdicts, no hidden heuristics — if you
disagree with a judgement, you can see exactly which rule produced it.

## Finding things

Search filters the list as you type, matching app and process names, paths,
and origin hints — so `chrome`, `/tmp`, and a version-numbered binary all
find what you'd expect. Sorting defaults to risk first (anything suspicious
at the top) and can switch to name A→Z or Z→A. Order never depends on
changing numbers like CPU, so rows stay put while you read them.

Binaries whose filename says nothing on its own get their origin alongside
it — a bare `2.1.222` shows as `2.1.222 · toolkit`, naming the folder it
came from.

## Vitals

CPU and memory, free disk space, network status with round-trip latency, live
up/down throughput, and each display's resolution and refresh rate.

Sampling is built to stay cheap: signature checks are cached per executable,
the refresh slows down when the popover is closed, and nothing is written to
disk on a routine tick.

## Background watcher

Watches while the popover is closed and notifies you when something changes: a
new non-trusted process, a new LaunchAgent/LaunchDaemon, an invalid signature,
a binary replaced in place, a sustained CPU spike, a network drop.

- **Baseline ledger** decides what counts as "new". On first run anything not
  clearly trusted is shown for your verdict — asked once, remembered forever.
- **Observation history** records when each binary first appeared, its hash,
  and any signature change. Binaries are hashed a few per tick and re-hashed
  when the file changes on disk, so a replacement is noticed. Survives
  restarts, owner-only, exportable as JSON.
- **Settings** tune cadence and CPU threshold, switch individual rules off, and
  reset the baseline after installing a batch of software.

## Opt-in threat intel

Off by default, and each provider states exactly what leaves the machine.
Anything that sends data runs only when you press **Run intel checks** on a
process; the one provider whose matching is fully local (MalwareBazaar) also
watches in the background.

- **CISA KEV + NVD** — downloads CISA's public known-exploited-vulnerabilities
  catalog (daily) plus NVD version ranges for every listed CVE, and matches
  locally. Nothing about your Mac is sent — all KEV CVEs are synced precisely
  so the traffic reveals nothing about what you run. With version data a hit
  can say "your version is in the affected range"; without it, matches stay
  product-level and informational.
- **MalwareBazaar** — downloads abuse.ch's public malware-hash list (~40 MB
  weekly plus daily deltas) and matches SHA-256s locally. Because the check
  never sends anything, it also runs automatically: a non-trusted process
  whose hash is in the list raises a "known malware" alert. Community-sourced
  data, labeled as such.
- **VirusTotal** — sends the executable's SHA-256 hash (and only the hash) to
  VirusTotal, which still reveals *what* you run to a third party. Needs your
  own free API key.

## Installing

Download the latest release, unzip, and drag `DragonWatch.app` to
`/Applications`. It lives in the menu bar — there is no Dock icon while it
runs.

Releases are ad-hoc signed, so the **first** launch needs **right-click →
Open** instead of a double-click; macOS only offers the override from the
context menu. Every launch after that is normal. Signing it any other way
needs a paid Apple Developer account, which this project does not have.

Would rather not trust a binary at all? Build it yourself — that is the
stronger option for a tool like this, and it sidesteps the warning entirely.

## Building

```sh
git clone https://github.com/N8Codes/DragonWatch.git
cd DragonWatch
./Scripts/make-app.sh    # builds build/DragonWatch.app (ad-hoc signed)
open build/DragonWatch.app
```

Or during development: `swift build && swift test`.

Requires macOS 14+ and Xcode command line tools. No dependencies.

## Verifying a release

Every GitHub release ships with a SHA-256 checksum, published so a
trojanized rebuild can't quietly impersonate a real one:

```sh
shasum -a 256 -c DragonWatch-<version>.zip.sha256
```

## Contributing

Issues and pull requests welcome — especially reports of an alert that should
have fired and didn't. `CONTRIBUTING.md` has the build and test commands, how
to verify the watcher against planted test cases, and the invariants a change
must not break.

## License

[MIT](LICENSE)
