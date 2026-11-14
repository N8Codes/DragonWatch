import Foundation

/// Owns the sampling loop and the observable state the popover reads. Each
/// sample goes to `Watcher`, which owns the ledgers and the alert rules; file
/// inspection is `InspectionModel`.
@MainActor
@Observable final class AppModel {
    private(set) var groups: [ProcessGroup] = []
    private(set) var vitals = Vitals()
    private(set) var overallBadge: TrustBadge = .trusted
    private(set) var hasSampled = false
    /// Signatures checked so far in the first sample, which is the wait at
    /// launch. nil once the list is up.
    private(set) var launchProgress: (done: Int, total: Int)?

    let network = NetworkMonitor()
    let alerts = AlertCenter()
    let settings: SettingsModel
    let intel: IntelCenter
    let watcher: Watcher
    let inspection: InspectionModel

    /// `storageDirectory` and `defaults` are for tests, which must never open
    /// the installed app's ledgers: a store that cannot decode its file moves
    /// it aside.
    init(storageDirectory: URL? = nil, defaults: UserDefaults = .standard) {
        let settings = SettingsModel(defaults: defaults)
        let observations = ObservationStore(directory: storageDirectory)
        self.settings = settings
        intel = IntelCenter(settings: settings, cacheDirectory: storageDirectory)
        sealVerifier = BundleSealVerifier(cacheDirectory: storageDirectory)
        watcher = Watcher(
            baseline: BaselineStore(directory: storageDirectory), observations: observations,
            alerts: alerts, settings: settings, trustEngine: trustEngine)
        inspection = InspectionModel(observations: observations)
        AppSupport.removeRetiredFiles(in: storageDirectory)
    }

    private let processSampler = ProcessSampler()
    private let vitalsSampler = VitalsSampler()
    private let throughputSampler = ThroughputSampler()
    private let trustEngine = TrustEngine()
    private let sealVerifier: BundleSealVerifier
    private var loop: Task<Void, Never>?
    private var ticking = false

    // Adaptive cadence: quick refresh while the popover is open, slow trickle
    // in the background. Signature checks only hit never-before-seen
    // executables either way (TrustEngine cache).
    private var popoverOpen = false
    private var cadenceSeconds: Int {
        popoverOpen ? 3 : settings.backgroundCadenceSeconds
    }

    nonisolated static let latencyProbeInterval: TimeInterval = 60
    private var cpuHistory = RingBuffer<(date: Date, value: Double)>(capacity: 64)
    private var latencyHistory = RingBuffer<Double>(capacity: 32)
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
        Task { [watcher] in await watcher.restoreAlertHistory() }
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

    func resetBaseline() {
        Task {
            await watcher.reset()
            inspection.forgetUnclassifiedFormats()
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

    enum SealState: Equatable {
        case running
        case verified
        case failed
    }
    private(set) var sealStates: [String: SealState] = [:]

    /// The enclosing bundle when it carries a strong (trusted-tier) signature
    /// — the precondition for both the quiet tier and seal verification.
    func strongEnclosingBundle(for path: String) async -> String? {
        await trustEngine.strongEnclosingBundle(for: path)
    }

    /// Verifies the bundle's seal, vouching the specific flagged binaries the
    /// user is resolving — never the bundle wholesale.
    func verifySeal(bundlePath: String, vouching binaryPath: String) {
        guard binaryPath.hasPrefix(bundlePath + "/"),
            sealStates[bundlePath] != .running
        else { return }
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
                await self.tick()
            }
        }
    }

    private func runLoop() {
        loop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.tick()
                try? await Task.sleep(for: .seconds(self.cadenceSeconds))
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
        let reportsProgress = !hasSampled
        await trustEngine.warm(
            paths: records.lazy.filter { !$0.executableMissing }.map(\.path),
            progress: { [weak self] done, total in
                guard reportsProgress else { return }
                Task { @MainActor in self?.launchProgress = (done, total) }
            })
        for record in records {
            var trust = await trustEngine.assess(
                path: record.path, pid: record.pid,
                executableMissing: record.executableMissing)
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
        let identifiedPIDs = Set(
            processes.filter { TrustScoring.base(for: $0.trust.tier) == .trusted }.map(\.id))
        var launches: [pid_t: LaunchContext] = [:]
        for record in records {
            launches[record.pid] = LaunchContext.resolve(
                for: record, pathsByPID: pathsByPID, parentsByPID: parentsByPID,
                identifiedPIDs: identifiedPIDs,
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
        launchProgress = nil

        await watcher.observe(
            Watcher.Sample(
                processes: processes, launches: launches,
                cpuHistory: cpuHistory.elements,
                // Groups whose metrics the kernel withheld cannot be "the top
                // consumer"; rank only those we can actually measure.
                topConsumer: grouped.max { ($0.totalCPU ?? -1) < ($1.totalCPU ?? -1) }?.name,
                cadence: TimeInterval(cadenceSeconds), popoverOpen: popoverOpen, now: now))
        probeLatencyIfDue(now: now)
    }

    private func probeLatencyIfDue(now: Date) {
        guard
            Self.shouldProbeLatency(
                popoverOpen: popoverOpen, networkUp: network.isUp,
                lastProbe: lastLatencyProbe, now: now)
        else { return }
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

    /// Latency is displayed in the popover and nowhere else, so it is measured
    /// only while the popover is open. Probing in the background would be
    /// ~1,400 requests a day that nobody reads — closed, DragonWatch makes no
    /// network requests at all unless intel is enabled.
    static func shouldProbeLatency(
        popoverOpen: Bool, networkUp: Bool, lastProbe: Date, now: Date,
        interval: TimeInterval = latencyProbeInterval
    ) -> Bool {
        popoverOpen && networkUp && now.timeIntervalSince(lastProbe) >= interval
    }
}
