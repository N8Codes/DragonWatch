import AppKit
import Foundation

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
    var name: String { (path as NSString).lastPathComponent }

    init(path: String, entry: BaselineLedger.Entry) {
        self.path = path
        tier = entry.tier
        firstSeen = entry.firstSeen
    }
}

/// Owns the sampling loop and holds the observable state the UI reads.
@MainActor
@Observable final class AppModel {
    private(set) var groups: [ProcessGroup] = []
    private(set) var vitals = Vitals()
    private(set) var overallBadge: TrustBadge = .trusted
    private(set) var hasSampled = false
    private(set) var pendingReview: [ReviewItem] = []
    /// Items the user answered "not expected" about. Kept separate from
    /// `pendingReview` — the question has been answered, but the answer was
    /// "no", and a verdict nothing displays is a verdict the user cannot tell
    /// they gave.
    private(set) var markedUnexpected: [ReviewItem] = []

    let network = NetworkMonitor()
    let alerts = AlertCenter()
    let settings: SettingsModel
    let intel: IntelCenter

    init() {
        let settings = SettingsModel()
        self.settings = settings
        intel = IntelCenter(settings: settings)
    }

    private let processSampler = ProcessSampler()
    private let vitalsSampler = VitalsSampler()
    private let throughputSampler = ThroughputSampler()
    private let trustEngine = TrustEngine()
    private let sealVerifier = BundleSealVerifier()
    private let baseline = BaselineStore()
    private let observations = ObservationStore()
    private var loop: Task<Void, Never>?
    private var ticking = false

    // Adaptive cadence: quick refresh while the popover is open, slow trickle
    // in the background. Signature checks only hit never-before-seen
    // executables either way (TrustEngine cache).
    private var popoverOpen = false
    private var interval: Duration {
        popoverOpen ? .seconds(3) : .seconds(settings.backgroundCadenceSeconds)
    }

    private enum Rule {
        static let cpuWindow: TimeInterval = 180
        static let cpuCooldown: TimeInterval = 1800
        static let networkCooldown: TimeInterval = 300
        static let latencyProbeInterval: TimeInterval = 60
        // Path-keyed alerts fire once by construction (the ledger gates them);
        // the long cooldown is belt and braces.
        static let oncePerPathCooldown: TimeInterval = 86400
        // Provenance hashing trickles a few binaries per tick — the ledger
        // fills within the first hour instead of a startup I/O storm.
        static let hashQueuePerTick = 3
    }

    private var cpuHistory = RingBuffer<(date: Date, value: Double)>(capacity: 64)
    private var latencyHistory = RingBuffer<Double>(capacity: 32)
    private var lastNetworkUp: Bool?
    private var lastLatencyProbe = Date.distantPast

    func start() {
        guard loop == nil else { return }
        network.start()
        alerts.requestAuthorizationIfNeeded()
        Task { [weak self] in
            guard let self else { return }
            let vouches = await self.sealVerifier.vouches()
            guard !vouches.isEmpty else { return }
            await self.trustEngine.setVouchedBinaries(
                vouches.mapValues { ($0.bundle, $0.identity.fingerprint) })
            for bundle in Set(vouches.values.map(\.bundle)) {
                self.sealStates[bundle] = .verified
            }
        }
        Task { [weak self] in
            guard let self else { return }
            let events = await self.observations.events()
            self.alerts.seedHistory(
                events.suffix(100).reversed().map {
                    AlertEvent(
                        kind: AlertKind(rawValue: $0.kind) ?? .newUntrustedProcess,
                        title: $0.title, detail: $0.detail, date: $0.date)
                })
        }
        runLoop()
    }

    func popoverDidOpen() {
        popoverOpen = true
        // Restart the loop so an open popover refreshes now, not in ≤25 s.
        loop?.cancel()
        runLoop()
    }

    func popoverDidClose() {
        popoverOpen = false
    }

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

    func resetBaseline() {
        Task {
            await baseline.reset()
            await observations.wipe()
            pendingReview = []
            markedUnexpected = []
        }
    }

    private(set) var sweeping = false

    /// Re-inspects every running process from scratch, right now, instead of
    /// waiting for the next tick. Clears the signature cache first — it is
    /// keyed on the file being unchanged, so a sweep that kept it would just
    /// replay the previous verdicts.
    func runFullSweep() {
        guard !sweeping else { return }
        sweeping = true
        Task { [weak self] in
            guard let self else { return }
            await self.trustEngine.invalidateCache()
            await self.tick()
            self.sweeping = false
        }
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

    enum SealState: Equatable {
        case running
        case verified
        case failed
    }
    private(set) var sealStates: [String: SealState] = [:]

    /// The enclosing bundle when it carries a strong (trusted-tier) signature
    /// — the precondition for both the quiet tier and seal verification.
    func strongEnclosingBundle(for path: String) async -> String? {
        guard let root = ContextInspector.bundleRoot(of: path), root != path else {
            return nil
        }
        let bundleTrust = await trustEngine.assess(path: root)
        return TrustScoring.base(for: bundleTrust.tier) == .trusted ? root : nil
    }

    /// Verifies the bundle's seal, vouching the specific flagged binaries the
    /// user is resolving — never the bundle wholesale.
    func verifySeal(bundlePath: String, vouching binaryPath: String) {
        guard sealStates[bundlePath] != .running else { return }
        sealStates[bundlePath] = .running
        Task { [weak self] in
            guard let self else { return }
            let vouchable = self.groups
                .flatMap(\.members)
                .map(\.record.path)
                .filter { $0.hasPrefix(bundlePath + "/") }
            let verified = await self.sealVerifier.verify(
                bundlePath: bundlePath,
                vouching: Array(Set(vouchable + [binaryPath])))
            self.sealStates[bundlePath] = verified ? .verified : .failed
            if verified {
                await self.trustEngine.setVouchedBinaries(
                    await self.sealVerifier.vouches().mapValues {
                        ($0.bundle, $0.identity.fingerprint)
                    })
            }
        }
    }

    func exportHistory() {
        Task {
            guard let data = await observations.exportData() else { return }
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "dragonwatch-history.json"
            NSApp.activate(ignoringOtherApps: true)
            if panel.runModal() == .OK, let url = panel.url {
                try? data.write(to: url)
                // The export carries the same machine inventory as the ledger;
                // default to owner-only wherever the user puts it.
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
        }
    }

    private func runLoop() {
        loop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.tick()
                try? await Task.sleep(for: self.interval)
            }
        }
    }

    private func tick() async {
        guard !ticking else { return }
        ticking = true
        defer { ticking = false }

        let now = Date()
        let records = await processSampler.sample()
        var processes: [MonitoredProcess] = []
        processes.reserveCapacity(records.count)
        let ownPID = ProcessInfo.processInfo.processIdentifier
        for record in records {
            var trust = await trustEngine.assess(path: record.path, pid: record.pid)
            if record.pid == ownPID { trust.isSelf = true }
            processes.append(MonitoredProcess(record: record, trust: trust))
        }
        // Parents resolve against this same listing, so "who launched it" is
        // answered from the tick that noticed it — a parent that exits a
        // second later would otherwise be unrecoverable.
        let pathsByPID = Dictionary(
            records.map { ($0.pid, $0.path) }, uniquingKeysWith: { first, _ in first })
        let parentsByPID = Dictionary(
            records.compactMap { record in record.parentPID.map { (record.pid, $0) } },
            uniquingKeysWith: { first, _ in first })
        var launches: [pid_t: LaunchContext] = [:]
        for record in records {
            launches[record.pid] = LaunchContext.resolve(
                for: record, pathsByPID: pathsByPID, parentsByPID: parentsByPID,
                lookup: ProcessSampler.path(forPID:))
        }
        let grouped = ProcessGrouper.group(processes)

        let (cpu, memUsed) = await vitalsSampler.sampleCPUAndMemory()
        let storage = await vitalsSampler.sampleStorage()
        let throughput = await throughputSampler.sample(now: now)
        cpuHistory.append((date: now, value: cpu))
        var updated = vitals
        updated.cpuPercent = cpu
        updated.cpuSparkline = cpuHistory.elements.map(\.value)
        updated.memoryUsedBytes = memUsed
        updated.networkSummary = network.summary
        updated.networkUp = network.isUp
        updated.rxBytesPerSec = throughput?.rxPerSec
        updated.txBytesPerSec = throughput?.txPerSec
        updated.storageFreeBytes = storage.freeBytes
        updated.storageTotalBytes = storage.totalBytes
        updated.displays = DisplayInfo.current()

        groups = grouped
        vitals = updated
        overallBadge = grouped.map(\.worstBadge).max() ?? .trusted
        hasSampled = true

        await watch(processes: processes, launches: launches, cpu: cpu, now: now)
    }

    /// The background watcher: baseline diffs, persistence diffs, and the
    /// vitals-derived alert rules.
    private func watch(
        processes: [MonitoredProcess], launches: [pid_t: LaunchContext], cpu: Double,
        now: Date
    ) async {
        let batch = await baseline.observeBatch(
            processes.map { ($0.record.path, $0.trust) }, now: now)
        let persistenceNews = await baseline.observePersistenceItems(
            PersistenceWatcher.currentItems())

        // Provenance: record sightings, alert on the replaced-in-place
        // masquerade case (same path, materially weaker signature), and
        // trickle-hash a few binaries per tick, non-trusted first.
        let sightings = await observations.observeBatch(
            processes.map { ($0.record.path, $0.trust.tier, launches[$0.record.pid]) },
            now: now,
            eventRetention: TimeInterval(settings.historyRetentionDays) * 86400)
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
                    guard let hash = await self.intel.hash(ofPath: path) else {
                        // Record the failure, or an unreadable binary sits at
                        // the head of this queue forever.
                        await self.observations.recordHashAttemptFailed(
                            path: path, now: Date())
                        continue
                    }
                    _ = await self.observations.recordHash(
                        path: path, sha256: hash, now: Date())
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
                let enclosing = await strongEnclosingBundle(for: path)
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
                    raiseAndRecord(
                        .newUntrustedProcess, key: path,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "New \(process.trust.badge.label.lowercased()) process: \(name)",
                        detail:
                            "\(process.trust.tier.rawValue) — \(path)\(sealNote ?? "")\(provenance)",
                        now: now)
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
            }
        }

        // Local malware-hash check: exempt from "intel is on-demand only"
        // because the list is downloaded wholesale and lookups never leave
        // the machine. Only non-trusted processes are hashed (few, and the
        // hasher caches), so steady-state cost is a binary search.
        if settings.mbEnabled, settings.isEnabled(.knownMalware) {
            let suspectPaths =
                processes
                .filter { $0.trust.badge != .trusted }
                .map(\.record.path)
            Task { [weak self] in
                guard let self else { return }
                await self.intel.malwareStore.refreshIfNeeded()
                for path in await self.intel.knownMalwareHits(paths: suspectPaths) {
                    self.raiseAndRecord(
                        .knownMalware, key: path,
                        cooldown: Rule.oncePerPathCooldown,
                        title: "Known malware hash: \((path as NSString).lastPathComponent)",
                        detail:
                            "\(path) — SHA-256 listed in MalwareBazaar (community-sourced).",
                        now: Date())
                }
            }
        }

        if settings.isEnabled(.sustainedCPU),
            SustainedSpikeRule.isSpiking(
                samples: cpuHistory.elements,
                threshold: settings.cpuThresholdPercent,
                window: Rule.cpuWindow, now: now)
        {
            // Groups whose metrics the kernel withheld cannot be "the top
            // consumer"; rank only those we can actually measure.
            let top = groups.max { ($0.totalCPU ?? -1) < ($1.totalCPU ?? -1) }
            raiseAndRecord(
                .sustainedCPU, key: "system",
                cooldown: Rule.cpuCooldown,
                title: "Sustained high CPU",
                detail: String(
                    format: "System CPU above %.0f%% for %.0f min%@",
                    settings.cpuThresholdPercent, Rule.cpuWindow / 60,
                    top.map { " — top: \($0.name)" } ?? ""),
                now: now)
        }

        if settings.isEnabled(.networkChange),
            let last = lastNetworkUp, last != network.isUp
        {
            raiseAndRecord(
                .networkChange, key: "status",
                cooldown: Rule.networkCooldown,
                title: network.isUp ? "Network restored" : "Network dropped",
                detail: network.summary, now: now)
        }
        lastNetworkUp = network.isUp

        if Self.shouldProbeLatency(
            popoverOpen: popoverOpen, networkUp: network.isUp,
            lastProbe: lastLatencyProbe, now: now)
        {
            lastLatencyProbe = now
            Task { [weak self] in
                let ms = await LatencyProbe.measure()
                guard let self else { return }
                self.vitals.latencyMs = ms
                if let ms {
                    self.latencyHistory.append(ms)
                    self.vitals.latencySparkline = self.latencyHistory.elements
                }
            }
        }

        await refreshReviewLists()
    }

    private func refreshReviewLists() async {
        pendingReview = await reviewItems()
        markedUnexpected = await unexpectedItems()
    }

    /// Latency is displayed in the popover and nowhere else, so it is measured
    /// only while the popover is open. Probing in the background would be
    /// ~1,400 requests a day that nobody reads — closed, DragonWatch makes no
    /// network requests at all unless intel is enabled.
    static func shouldProbeLatency(
        popoverOpen: Bool, networkUp: Bool, lastProbe: Date, now: Date,
        interval: TimeInterval = Rule.latencyProbeInterval
    ) -> Bool {
        popoverOpen && networkUp && now.timeIntervalSince(lastProbe) >= interval
    }

    /// Raises through the alert center and, when the alert actually fires,
    /// mirrors it into the durable observation record.
    private func raiseAndRecord(
        _ kind: AlertKind, key: String, cooldown: TimeInterval,
        title: String, detail: String, now: Date
    ) {
        guard
            alerts.raise(
                kind, key: key, cooldown: cooldown,
                title: title, detail: detail, now: now)
        else { return }
        Task {
            await observations.record(
                event: ObservationLedger.Event(
                    date: now, kind: kind.rawValue, title: title, detail: detail))
        }
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
