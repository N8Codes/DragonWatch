import Foundation

/// Disk owner of the observation ledger. A history of everything ever run is
/// sensitive even local-only, so the file is owner-read-only (0600), events
/// honor the retention setting, and "reset baseline" wipes it. Material
/// changes persist immediately; lastSeen-only churn flushes every few
/// minutes rather than every tick.
actor ObservationStore {
    private static let lightFlushInterval: TimeInterval = 300

    private let fileURL: URL
    private var ledger: ObservationLedger
    private var lastPersist = Date.distantPast
    private var lightDirty = false

    init(directory: URL? = nil) {
        let dir = AppSupport.directory(override: directory)
        fileURL = dir.appendingPathComponent("observations.json")
        if let data = try? Data(contentsOf: fileURL) {
            if let decoded = try? JSONDecoder().decode(ObservationLedger.self, from: data),
                decoded.schemaVersion == ObservationLedger.currentSchemaVersion
            {
                ledger = decoded
            } else {
                // Unknown schema: move aside rather than destroy. The old
                // backup has to go first — `moveItem` throws when the
                // destination exists, and with the error swallowed the file
                // stayed put and was overwritten by the next save, which is
                // exactly the destruction this branch exists to prevent.
                let backup = fileURL.appendingPathExtension("bak")
                try? FileManager.default.removeItem(at: backup)
                try? FileManager.default.moveItem(at: fileURL, to: backup)
                ledger = ObservationLedger()
            }
        } else {
            ledger = ObservationLedger()
        }
    }

    func observeBatch(
        _ items: [(path: String, tier: SignatureTier)],
        now: Date,
        eventRetention: TimeInterval
    ) -> [String: ObservationLedger.Sighting] {
        var sightings: [String: ObservationLedger.Sighting] = [:]
        for item in items {
            sightings[item.path] = ledger.observe(
                path: item.path, tier: item.tier, now: now)
        }
        ledger.prune(now: now, eventRetention: eventRetention)
        if sightings.values.contains(where: { $0 != .known }) {
            persist(now: now)
        } else {
            lightDirty = true
            flushIfDue(now: now)
        }
        return sightings
    }

    func recordHash(path: String, sha256: String, now: Date) -> Bool {
        let changed = ledger.recordHash(
            path: path, sha256: sha256,
            stamp: ObservationLedger.FileStamp(path: path), now: now)
        if changed {
            persist(now: now)
        } else {
            lightDirty = true
        }
        return changed
    }

    func recordHashAttemptFailed(path: String, now: Date) {
        ledger.recordHashAttemptFailed(path: path, now: now)
        lightDirty = true
    }

    func record(event: ObservationLedger.Event) {
        ledger.record(event: event)
        persist(now: event.date)
    }

    func pathsNeedingHash(among paths: [String], limit: Int, now: Date = Date())
        -> [String]
    {
        ledger.pathsNeedingHash(among: paths, limit: limit, now: now) {
            ObservationLedger.FileStamp(path: $0)
        }
    }

    func identity(for path: String) -> ObservationLedger.Identity? {
        ledger.identities[path]
    }

    func events() -> [ObservationLedger.Event] {
        ledger.events
    }

    func exportData() -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try? encoder.encode(ledger)
    }

    /// Drops the durable alert record while keeping the provenance history.
    /// "Clear" has to reach disk: clearing only the in-memory list left the
    /// events in the ledger, and the next launch re-seeded the list straight
    /// back from them.
    func clearEvents(now: Date = Date()) {
        ledger.events = []
        persist(now: now)
    }

    func wipe() {
        ledger = ObservationLedger()
        try? FileManager.default.removeItem(at: fileURL)
        lastPersist = .distantPast
        lightDirty = false
    }

    private func persist(now: Date) {
        do {
            try AppSupport.writePrivately(
                try JSONEncoder().encode(ledger), to: fileURL)
        } catch {
            return  // best-effort; retried on the next material change
        }
        lastPersist = now
        lightDirty = false
    }

    private func flushIfDue(now: Date) {
        if lightDirty, now.timeIntervalSince(lastPersist) > Self.lightFlushInterval {
            persist(now: now)
        }
    }
}
