# DragonWatch 🐉

**A lightweight macOS process trust monitor.**

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
macOS already runs XProtect and Gatekeeper underneath. It has no malware corpus,
no signature feed and no cloud lookup. The file inspector does read contents,
but only to answer whether a file is what it claims to be — never whether it is
dangerous.

- **Read-only.** Never stops, kills, quarantines, or modifies another program,
  and never asks for elevated privileges.
- **Quiet.** As it ships, the only network request is a latency probe to
  Apple's captive-portal URL, once a minute and only while the popover is
  open. Enabling the optional CISA catalog adds nothing until you run a check
  on a process; that fetches the public list (at most once a day) and NVD's
  version data for it.
- **Private.** Nothing about your machine is ever sent anywhere. There is no
  cloud lookup, no API key, and no toggle that changes that.

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
It also shows **who launched it** (parent process, captured the first time the
binary was seen) and, for Homebrew installs, the keg's install receipt — the
two facts a "was this expected?" verdict actually turns on.
The **Criteria** tab lists the complete rulebook: every signature tier, every
context signal with why it's treated as risk, every exemption, and what the
app deliberately doesn't do. No cloud verdicts, no hidden heuristics — if you
disagree with a judgement, you can see exactly which rule produced it.

## Finding things

Apps group with their helpers under the app's icon, and Apple's own daemons —
the hundreds of `trustd`s and `cfprefsd`s that make a Mac a Mac — fold into
one **macOS system** row, so the list is about what *you* run. A fold never
hides anything: a group's badge is always its worst member's.

Two ways to see everything: the ⓘ on any group opens it as a **tree** — every
process nested under what started it, with pid, start time, CPU and memory,
each row clickable for its rating and history — and the **Process tree** tab
does the same for the whole machine, rooted at `launchd`.

Search filters the list as you type, matching app and process names, paths,
and origin hints — so `chrome`, `/tmp`, and a version-numbered binary all
find what you'd expect. Sorting defaults to risk first (anything suspicious
at the top) and can switch to name A→Z or Z→A. Order never depends on
changing numbers like CPU, so rows stay put while you read them.

Binaries whose filename says nothing on its own are grouped and named by
the folder they came from — a bare `2.1.222` shows as `toolkit · 2.1.222`,
and several sessions of one tool running different versions are one row with
the versions inside it. Known AI agent CLIs (Claude Code, Codex, Gemini CLI,
Aider, Copilot CLI) get their product name, and the matching desktop app's
icon when it is installed — otherwise a terminal-with-spark glyph. Nothing
third-party is bundled.

## Inspecting a file

**Inspect a file**, beside the search field, opens a window that answers one
question about a file sitting on disk: **are these contents what the file
claims to be?** Choose files or folders, or drag them onto the window. It is a
window rather than a popover pane so it stays open while you pick files.

It is not a malware scan and never claims to be. There is no malware corpus, no
signature feed and no cloud lookup, and every report carries that sentence.
Verdicts are **Consistent**, **Caution**, **Inconsistent** or **Unreadable** —
never "clean" or "safe", because a green pass on a novel malicious file would be
a claim the app cannot back. "Unreadable" is its own verdict so that *we could
not look* never reads as *we looked and it was fine*.

What it checks:

- **Contents against the extension.** A Mach-O named `.png` is the headline
  case. An image under another image's name is only Caution: common on the
  web, nothing in it can run, and the name is still wrong.
- **Data past the end of the file.** Most formats declare their own length, so
  this is an exact byte count, not a guess — it is how a second file rides
  inside an innocuous-looking one.
- **Deceptive filenames.** Unicode direction overrides that make
  `report‮fdp.exe` display as `reportexe.pdf`, zero-width characters, and
  runnable extensions hiding behind a document one.
- **Things that run.** PDF JavaScript and launch actions, Office macro
  projects, script inside an SVG.
- **Archives, from the index only.** Path traversal, lopsided expansion and
  prepended data — read from the central directory, never extracted.
- **Source and text.** Trojan Source (CVE-2021-42574), encoded blobs, and code
  that decodes a string and executes it.
- **Provenance.** C2PA Content Credentials are read and shown, including
  whether a file declares itself AI-generated. They are **read, not verified**:
  the signature is not checked, and credentials can be stripped by resaving.

Three rules it never breaks, each enforced by tests:

1. Nothing inspected is ever **executed**.
2. Nothing is handed to a system media decoder — ImageIO and AVFoundation are
   the historical attack surface for malicious images, so structure is parsed
   over bounded reads instead.
3. No archive is ever **extracted**.

Structural checks on a large file are sampled: the first and last 64 KB, plus
whatever the format's own structure declares. Hashing is the exception — a file
is streamed end to end for its SHA-256, up to a 2 GB ceiling. Reports export as Markdown,
JSON, PDF or plain text, written owner-only wherever you save them.

Every rule, with its rationale and what it cannot tell you, is listed in the
app's Criteria tab.

## Vitals

CPU and memory, free disk space, network status with round-trip latency, live
up/down throughput, and each display's resolution and refresh rate.

Sampling is built to stay cheap: signature checks are cached per executable,
the refresh slows down when the popover is closed, and nothing is written to
disk on a routine tick.

## Background watcher

Watches while the popover is closed and notifies you when something changes: a
new non-trusted process, a new LaunchAgent/LaunchDaemon, an invalid signature,
a binary replaced in place, a sustained CPU spike.

- **Baseline ledger** decides what counts as "new". On first run anything not
  clearly trusted is shown for your verdict — asked once, remembered forever.
  Three answers: **Expected** (accepted as normal), **Not expected** (stays
  listed as one you flagged), or **Ignore** (hidden for good, no verdict —
  it won't alert again, but nothing vouches for it).
- **Alerts carry provenance.** A new-process alert names the parent that
  started it ("Launched by zsh (pid 7083) — /bin/zsh"), says when that parent
  sits inside an AI agent session (Claude Code, Codex, Gemini CLI, Aider,
  Copilot CLI — "an AI agent, not you, started it"), and, inside a Homebrew
  keg, the install receipt ("Homebrew receipt: node 25.9.0_3, poured from
  bottle, installed 2 May 2026"). Context only — no rating ever rises because
  of it.
- **Observation history** records when each binary first appeared, its hash,
  and any signature change. Binaries are hashed a few per tick and re-hashed
  when the file changes on disk, so a replacement is noticed. Survives
  restarts, owner-only, exportable as JSON.
- **Settings** tune cadence and CPU threshold, switch individual rules off, and
  reset the baseline after installing a batch of software. It also shows
  whether macOS is allowing DragonWatch's notifications: the banner is a
  per-app permission in System Settings → Notifications, and if it is off
  the alert still lands in the Alerts tab and on the menu bar icon — it just
  does not interrupt you.
- **Alerts tab** lists every alert raised, newest first. Dismiss one with its
  ✕ or clear them all; both are durable. Dismissing is history-keeping only —
  the binary's expected/not-expected verdict lives in the Review tab and is
  what decides whether it alerts again.

## Opt-in vulnerability catalog

Off by default, and runs only when you press **Run intel checks** on a
process. **CISA KEV + NVD** downloads CISA's public catalog of known exploited
vulnerabilities (at most daily) plus NVD version ranges for every listed CVE,
and matches locally. Nothing about your Mac is sent — every KEV CVE is synced
precisely so the traffic reveals nothing about what you run. With version data
a hit can say "your version is in the affected range"; without it, matches
stay product-level and informational.

DragonWatch deliberately has no cloud reputation lookup and no malware-hash
list. A hash lookup reveals what you run to a third party, and a hash list
only catches catalogued samples that XProtect already blocks — neither earned
the privacy cost or the download.

## Installing

Download the latest release, unzip, and drag `DragonWatch.app` to
`/Applications`. The build is universal (Apple silicon and Intel). It lives
in the menu bar — there is no Dock icon while it runs.

Releases are ad-hoc signed, not notarized, so macOS refuses the **first**
launch. The override depends on your macOS version:

- **macOS 15 or later:** open the app once and let it be refused, then go to
  **System Settings → Privacy & Security**, scroll to the message about
  DragonWatch, and click **Open Anyway**.
- **macOS 14:** right-click the app and choose **Open**; the context menu
  offers an Open button the double-click does not.

Every launch after that is normal. Notarizing needs a paid Apple Developer
account, which this project deliberately does not have.

Would rather not trust a binary at all? Build it yourself — that is the
stronger option for a tool like this, and it sidesteps the warning entirely.

## Building

```sh
git clone https://github.com/N8Codes/DragonWatch.git
cd DragonWatch
./Scripts/make-app.sh    # builds build/DragonWatch.app (universal, ad-hoc signed)
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
have fired and didn't. Every alert kind has a planted test case in
`Scripts/verify-watcher.sh`; still, this has been tested by few people on few
Macs, so treat a missing notification as a bug report worth filing, not as
impossible.
`CONTRIBUTING.md` has the build and test commands, how to verify the watcher,
and the invariants a change must not break.

## License

[MIT](LICENSE)
