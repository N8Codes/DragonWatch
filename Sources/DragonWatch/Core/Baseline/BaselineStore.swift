import Foundation

/// Owns the ledger's disk copy — plain JSON in Application Support. A missing
/// file means first run: the next observation batch is a *seeding* sweep, which
/// populates the ledger without firing alerts (Trusted items join silently and
/// everything else queues for review — never a blind "trust what's running").
actor BaselineStore {
    struct BatchResult: Sendable {
        let observations: [String: BaselineLedger.Observation]
        let wasSeedingPass: Bool
    }

    private(set) var ledger: BaselineLedger
    private var seeding: Bool
    private let fileURL: URL

    init(directory: URL? = nil) {
        let dir = AppSupport.directory(override: directory)
        fileURL = dir.appendingPathComponent("baseline.json")
        if let data = try? Data(contentsOf: fileURL),
            let loaded = try? JSONDecoder().decode(BaselineLedger.self, from: data)
        {
            ledger = loaded
            seeding = false
        } else {
            ledger = BaselineLedger()
            seeding = true
        }
    }

    func observeBatch(
        _ items: [(path: String, assessment: TrustAssessment)], now: Date
    ) -> BatchResult {
        var observations: [String: BaselineLedger.Observation] = [:]
        for item in items {
            observations[item.path] = ledger.observe(
                path: item.path, assessment: item.assessment, now: now)
        }
        let wasSeeding = seeding
        seeding = false
        if observations.values.contains(where: { $0 != .known }) || wasSeeding {
            persist()
        }
        return BatchResult(observations: observations, wasSeedingPass: wasSeeding)
    }

    /// Returns the items that were not yet in the baseline. During a seeding
    /// pass callers should treat these as existing state, not news.
    func observePersistenceItems(_ paths: [String]) -> [String] {
        let fresh = paths.filter { ledger.observePersistenceItem($0) }
        if !fresh.isEmpty { persist() }
        return fresh
    }

    func recordVerdict(path: String, verdict: BaselineLedger.Verdict) {
        ledger.recordVerdict(path: path, verdict: verdict)
        persist()
    }

    func pendingReview() -> [(path: String, entry: BaselineLedger.Entry)] {
        ledger.pendingReview
    }

    /// "Reset baseline": wipe the ledger and re-run the reviewed first-run
    /// sweep on the next tick — for after big legitimate changes.
    func reset() {
        ledger = BaselineLedger()
        seeding = true
        persist()
    }

    private func persist() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try AppSupport.writePrivately(try encoder.encode(ledger), to: fileURL)
        } catch {
            // Best-effort: a failed save costs re-review next launch, nothing worse.
        }
    }
}
