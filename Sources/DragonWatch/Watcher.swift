import AppKit
import Foundation
import os

/// One item awaiting the user's "expected or not?" verdict.
struct ReviewItem: Identifiable, Sendable {
    let path: String
    let tier: SignatureTier
    let firstSeen: Date
    /// Who started it and whether a package manager installed it — the two
    /// facts a verdict actually turns on.
    var launchedBy: LaunchContext?
    var keg: HomebrewKeg?

    var id: String { path }
    var name: String { UniversalChecks.lineSafe((path as NSString).lastPathComponent) }

    init(path: String, entry: BaselineLedger.Entry) {
        self.path = path
        tier = entry.tier
        firstSeen = entry.firstSeen
    }
}

/// The background watcher: what is new since the baseline, what changed in
/// place, and the alert rules over both. Owns the two ledgers and the review
/// lists read from them; `AppModel` hands it each sample.
@MainActor
@Observable final class Watcher {
    /// What one tick observed.
    struct Sample {
        let processes: [MonitoredProcess]
        let launches: [pid_t: LaunchContext]
        /// System CPU history, oldest first, this tick's reading last.
        let cpuHistory: [(date: Date, value: Double)]
        /// The group using the most CPU among those the kernel reports for.
        let topConsumer: String?
        let cadence: TimeInterval
        let popoverOpen: Bool
        let now: Date
    }

    private(set) var pendingReview: [ReviewItem] = []
    /// Items the user answered "not expected" about. Kept separate from
    /// `pendingReview` — the question has been answered, but the answer was
    /// "no", and a verdict nothing displays is a verdict the user cannot tell
    /// they gave.
    private(set) var markedUnexpected: [ReviewItem] = []

    private let alerts: AlertCenter
    private let settings: SettingsModel
    private let trustEngine: TrustEngine
    private let baseline: BaselineStore
    private let observations: ObservationStore
    /// Cached per (path, mtime); the provenance queue hashes a few binaries per tick.
    private let hasher = FileHasher()
    private let persistenceContents = PersistenceContents()

    private enum Rule {
        static let cpuWindow: TimeInterval = 180
        static let cpuCooldown: TimeInterval = 1800
        // Path-keyed alerts fire once by construction (the ledger gates them);
        // the long cooldown is belt and braces.
        static let oncePerPathCooldown: TimeInterval = 86400
        // Provenance hashing trickles a few binaries per tick — the ledger
        // fills within the first hour instead of a startup I/O storm.
        static let hashQueuePerTick = 3
    }

    /// One line per tick with the numbers the sustained-CPU rule sees. Info
    /// level, numbers only, so `log stream` can answer "why did it not fire"
    /// without a rebuild — a question that once cost an evening.
    nonisolated private static let watcherLog = Logger(
        subsystem: "com.dragonwatch.DragonWatch", category: "watcher")

    init(
        baseline: BaselineStore, observations: ObservationStore, alerts: AlertCenter,
        settings: SettingsModel, trustEngine: TrustEngine
    ) {
        self.baseline = baseline
        self.observations = observations
        self.alerts = alerts
        self.settings = settings
        self.trustEngine = trustEngine
    }

    /// Restores past alerts from the durable record at launch.
    func restoreAlertHistory() async {
        alerts.seedHistory(AlertCenter.displayable(await observations.events()))
    }

    // MARK: - Verdicts and history

    func resolveReview(path: String, asExpected expected: Bool) {
        Task {
            await baseline.recordVerdict(
                path: path, verdict: expected ? .expected : .keepFlagging)
            await refreshReviewLists()
        }
    }

    /// "Stop asking" without a verdict: the item leaves both lists and will
    /// not alert again, and the ledger records that nobody vouched for it.
    func ignoreReview(path: String) {
        Task {
            await baseline.recordVerdict(path: path, verdict: .ignored)
            await refreshReviewLists()
        }
    }

    /// "Reset baseline": both ledgers go, and the next sample re-seeds.
    func reset() async {
        await baseline.reset()
        await observations.wipe()
        alerts.clearHistory()
        pendingReview = []
        markedUnexpected = []
    }

    /// Clears the alert list *and* the durable record behind it, so it stays
    /// cleared across a relaunch.
    func clearAlertHistory() {
        alerts.clearHistory()
        Task { await observations.clearEvents() }
    }

    /// Dismisses one alert from the list and the durable record. History
    /// only: the binary's baseline verdict is untouched, so a genuinely new
    /// sighting still alerts.
    func dismissAlert(_ event: AlertEvent) {
        alerts.dismiss(event.id)
        Task {
            await observations.remove(
                event: ObservationLedger.Event(
                    date: event.date, kind: event.kind.rawValue,
                    title: event.title, detail: event.detail))
        }
    }

    func observation(for path: String) async -> ObservationLedger.Identity? {
        await observations.identity(for: path)
    }

    func exportHistory() {
        Task {
            guard let data = await observations.exportData() else { return }
            FileExport.save(data, suggestedName: "dragonwatch-history.json")
        }
    }

    // MARK: - Each sample

    /// The background watcher: baseline diffs, persistence diffs, and the
    /// vitals-derived alert rules.
    func observe(_ sample: Sample) async {
        let processes = sample.processes
        let launches = sample.launches
        let now = sample.now
        let retention = TimeInterval(settings.historyRetentionDays) * 86400
        let batch = await baseline.observeBatch(
            processes.map { ($0.record.path, $0.trust) }, now: now,
            unseenRetention: retention)
        let persistenceItems = PersistenceWatcher.currentItems()
        let persistenceNews = await baseline.observePersistenceItems(persistenceItems)
        let fingerprints = await persistenceContents.fingerprints(of: persistenceItems)
        let persistenceChanged = await baseline.observePersistenceContents(fingerprints)

        // Provenance: record sightings, alert on the replaced-in-place
        // masquerade case (same path, materially weaker signature), and
        // trickle-hash a few binaries per tick, non-trusted first.
        let sightings = await observations.observeBatch(
            processes.map { ($0.record.path, $0.trust.tier, launches[$0.record.pid]) },
            now: now, eventRetention: retention)
        if settings.isEnabled(.binaryReplaced) {
            for process in processes {
                if case .tierDowngraded(let from, let to) =
                    sightings[process.record.path]
                {
                    raiseAndRecord(
                        .binaryReplaced, key: process.record.path,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "Binary replaced: \(process.record.name)",
                        detail:
                            "\(process.record.path) — signature went from \(from.rawValue) to \(to.rawValue).",
                        now: now)
                }
            }
        }
        // Non-trusted first, then by path: Swift's sort is not stable, so
        // without the tiebreak the queue picks a different few each tick and
        // some paths stay unhashed for longer than they should.
        let hashCandidates =
            processes
            .sorted { lhs, rhs in
                lhs.trust.badge == rhs.trust.badge
                    ? lhs.record.path < rhs.record.path
                    : lhs.trust.badge > rhs.trust.badge
            }
            .map(\.record.path)
        let toHash = await observations.pathsNeedingHash(
            among: hashCandidates, limit: Rule.hashQueuePerTick)
        if !toHash.isEmpty {
            Task { [weak self] in
                guard let self else { return }
                for path in toHash {
                    // Stamped before the read: a file replaced mid-hash then
                    // mismatches its stamp and is hashed again, where a stamp
                    // taken afterwards would mark the old digest current.
                    let stamp = ObservationLedger.FileStamp(path: path)
                    guard let hash = await self.hasher.sha256(ofPath: path) else {
                        // Record the failure, or an unreadable binary sits at
                        // the head of this queue forever.
                        await self.observations.recordHashAttemptFailed(
                            path: path, now: Date())
                        continue
                    }
                    await self.observations.recordHash(
                        path: path, sha256: hash, stamp: stamp, now: Date())
                }
            }
        }

        // A seeding pass (first run or post-reset) records existing state for
        // review instead of alerting on it.
        if !batch.wasSeedingPass {
            for process in processes
            where batch.observations[process.record.path] == .addedForReview {
                let name = process.record.name
                let path = process.record.path
                // A weak signature inside a strongly-signed bundle (Xcode's
                // ad-hoc dev agents, say) alerts like any other — but the
                // alert points at the resolution: seal verification, the
                // earned path to trusted.
                let enclosing =
                    process.record.executableMissing
                    ? nil : await trustEngine.strongEnclosingBundle(for: path)
                let sealNote = enclosing.map {
                    " Inside signed \(($0 as NSString).lastPathComponent) — open the detail view to verify the bundle's seal."
                }
                // The alert is the moment the question gets asked; answer
                // "who started it" and "did a package manager put it here"
                // right there instead of one investigation later.
                let provenance = ProvenanceNote.suffix(
                    launch: launches[process.record.pid],
                    keg: await Task.detached { HomebrewKeg.locate(path: path) }.value)
                if process.trust.tier == .invalid, settings.isEnabled(.invalidSignature) {
                    raiseAndRecord(
                        .invalidSignature, key: path,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "Invalid signature: \(name)",
                        detail: "Tampered or revoked signature — \(path)\(provenance)", now: now)
                } else if process.trust.tier != .invalid,
                    settings.isEnabled(.newUntrustedProcess)
                {
                    // Simulator test runs put the same build at a new path
                    // every run; throttle those per build, and say so.
                    let simulator = SimulatorApp.matches(
                        path: path, launch: launches[process.record.pid])
                    let simulatorKey =
                        simulator
                        ? SimulatorApp.throttleKey(
                            cdhash: await Task.detached {
                                CodeIdentity.codeDirectoryHash(path: path)
                            }.value)
                        : nil
                    let fired = raiseAndRecord(
                        .newUntrustedProcess,
                        key: simulatorKey ?? path,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "New \(process.trust.badge.label.lowercased()) process: \(name)",
                        detail:
                            "\(process.trust.tier.rawValue) — \(path)\(sealNote ?? "")\(provenance)\(simulator ? SimulatorApp.note : "")",
                        now: now)
                    // The same build in another device folder was already
                    // asked about; a second row for it is not a new question.
                    if simulatorKey != nil, !fired {
                        await baseline.recordVerdict(path: path, verdict: .ignored)
                    }
                }
            }
            if settings.isEnabled(.newPersistenceItem) {
                for item in persistenceNews {
                    raiseAndRecord(
                        .newPersistenceItem, key: item,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "New persistence item",
                        detail: item, now: now)
                }
                for item in persistenceChanged {
                    // Keyed by the new contents, so each distinct rewrite
                    // alerts once and a file flapping between two does not.
                    raiseAndRecord(
                        .newPersistenceItem, key: "\(item)#\(fingerprints[item] ?? "")",
                        cooldown: Rule.oncePerPathCooldown,
                        title: "Persistence item changed",
                        detail:
                            "\(item) — its contents changed since DragonWatch last read it. "
                            + "Check what it launches.",
                        now: now)
                }
            }
        }

        let windowed = sample.cpuHistory.filter {
            now.timeIntervalSince($0.date) <= Rule.cpuWindow
        }
        Self.watcherLog.info(
            """
            tick cpu=\(sample.cpuHistory.last?.value ?? 0, format: .fixed(precision: 0)) \
            windowed=\(windowed.count) \
            span=\(windowed.first.map { now.timeIntervalSince($0.date) } ?? 0, format: .fixed(precision: 0))s \
            min=\(windowed.map(\.value).min() ?? 0, format: .fixed(precision: 0)) \
            threshold=\(self.settings.cpuThresholdPercent, format: .fixed(precision: 0)) \
            popoverOpen=\(sample.popoverOpen)
            """)
        if settings.isEnabled(.sustainedCPU),
            SustainedSpikeRule.isSpiking(
                samples: sample.cpuHistory,
                threshold: settings.cpuThresholdPercent,
                window: Rule.cpuWindow,
                cadence: sample.cadence,
                now: now)
        {
            raiseAndRecord(
                .sustainedCPU, key: "system",
                cooldown: Rule.cpuCooldown,
                title: "Sustained high CPU",
                detail: String(
                    format: "System CPU above %.0f%% for %.0f min%@",
                    settings.cpuThresholdPercent, Rule.cpuWindow / 60,
                    sample.topConsumer.map { " — top: \($0)" } ?? ""),
                now: now)
        }

        await refreshReviewLists()
    }

    private func refreshReviewLists() async {
        pendingReview = await reviewItems()
        markedUnexpected = await unexpectedItems()
    }

    /// Raises through the alert center and, when the alert actually fires,
    /// mirrors it into the durable observation record.
    @discardableResult
    private func raiseAndRecord(
        _ kind: AlertKind, key: String, cooldown: TimeInterval,
        title: String, detail: String, now: Date
    ) -> Bool {
        // Titles and details embed paths, and a path may hold anything.
        let title = UniversalChecks.lineSafe(title)
        let detail = UniversalChecks.lineSafe(detail)
        guard
            alerts.raise(
                kind, key: key, cooldown: cooldown,
                title: title, detail: detail, now: now)
        else { return false }
        Task {
            await observations.record(
                event: ObservationLedger.Event(
                    date: now, kind: kind.rawValue, title: title, detail: detail))
        }
        return true
    }

    private func reviewItems() async -> [ReviewItem] {
        await enrich(baseline.pendingReview().map(ReviewItem.init))
    }

    private func unexpectedItems() async -> [ReviewItem] {
        await enrich(baseline.markedUnexpected().map(ReviewItem.init))
    }

    /// Review lists are short (a handful of items, asked once), so a ledger
    /// lookup and a receipt read per item is cheap enough to do every tick.
    private func enrich(_ items: [ReviewItem]) async -> [ReviewItem] {
        var enriched = items
        for index in enriched.indices {
            let path = enriched[index].path
            enriched[index].launchedBy = await observations.identity(for: path)?.launchedBy
            enriched[index].keg = await Task.detached { HomebrewKeg.locate(path: path) }.value
        }
        return enriched
    }
}
