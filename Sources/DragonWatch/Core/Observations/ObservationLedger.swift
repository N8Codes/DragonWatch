import Foundation

/// What DragonWatch itself has seen: per-executable provenance plus the
/// durable alert record. Local-only, bounded by design — transitions record
/// *changes*, not sightings, so an unchanged binary costs one lastSeen
/// timestamp no matter how long it runs.
struct ObservationLedger: Codable, Sendable {
    static let currentSchemaVersion = 1
    static let transitionCap = 20
    static let eventCap = 1000

    struct Transition: Codable, Equatable, Sendable {
        let date: Date
        let field: String  // "tier" | "hash"
        let from: String
        let to: String
    }

    struct Identity: Codable, Sendable {
        var firstSeen: Date
        var lastSeen: Date
        var tier: SignatureTier
        var sha256: String?
        /// The file as it was when `sha256` was taken. Without it there is no
        /// way to know the hash is stale, so a binary replaced on disk kept
        /// its original hash forever and the change was never noticed.
        var hashedMtime: Date?
        var hashedSize: Int64?
        /// Stamped on every attempt, including ones that fail. An executable
        /// we cannot read — mode 0500 root daemons, of which a Mac runs many
        /// — otherwise stayed at the head of the queue permanently and
        /// starved every other binary behind it.
        var hashAttemptedAt: Date?
        var transitions: [Transition] = []
    }

    /// How long before another attempt at a path whose last one did not settle
    /// the question.
    static let hashRetryInterval: TimeInterval = 3600

    struct Event: Codable, Sendable {
        let date: Date
        let kind: String
        let title: String
        let detail: String
    }

    /// A file as it was at a moment, used to notice that it is no longer that
    /// file. Cheap to take (one `lstat`) compared with re-hashing.
    struct FileStamp: Equatable, Sendable {
        let mtime: Date
        let size: Int64

        init(mtime: Date, size: Int64) {
            self.mtime = mtime
            self.size = size
        }

        init?(path: String) {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                let mtime = attributes[.modificationDate] as? Date,
                let size = attributes[.size] as? Int64
            else { return nil }
            self.init(mtime: mtime, size: size)
        }
    }

    enum Sighting: Equatable, Sendable {
        case new
        case known
        /// Same path now carries a materially weaker signature — the
        /// replaced-in-place masquerade case. Routine self-updates (hash
        /// change, equal-or-better tier) record a transition and stay quiet.
        case tierDowngraded(from: SignatureTier, to: SignatureTier)
    }

    var schemaVersion = ObservationLedger.currentSchemaVersion
    var identities: [String: Identity] = [:]
    var events: [Event] = []

    mutating func observe(path: String, tier: SignatureTier, now: Date) -> Sighting {
        guard var identity = identities[path] else {
            identities[path] = Identity(firstSeen: now, lastSeen: now, tier: tier)
            return .new
        }
        identity.lastSeen = now
        var sighting: Sighting = .known
        if identity.tier != tier {
            append(
                Transition(
                    date: now, field: "tier",
                    from: identity.tier.rawValue, to: tier.rawValue),
                to: &identity)
            if TrustScoring.base(for: tier) > TrustScoring.base(for: identity.tier) {
                sighting = .tierDowngraded(from: identity.tier, to: tier)
            }
            identity.tier = tier
        }
        identities[path] = identity
        return sighting
    }

    /// Returns true when the hash changed from a previously recorded one.
    mutating func recordHash(
        path: String, sha256: String, stamp: FileStamp?, now: Date
    ) -> Bool {
        guard var identity = identities[path] else { return false }
        defer { identities[path] = identity }
        identity.hashAttemptedAt = now
        identity.hashedMtime = stamp?.mtime
        identity.hashedSize = stamp?.size
        guard let previous = identity.sha256 else {
            identity.sha256 = sha256
            return false
        }
        guard previous != sha256 else { return false }
        append(
            Transition(date: now, field: "hash", from: previous, to: sha256),
            to: &identity)
        identity.sha256 = sha256
        return true
    }

    /// Records that we tried and could not read the file, so the queue moves on.
    mutating func recordHashAttemptFailed(path: String, now: Date) {
        identities[path]?.hashAttemptedAt = now
    }

    mutating func record(event: Event) {
        events.append(event)
    }

    /// Candidates for the rate-limited hashing queue, in the caller's order.
    ///
    /// A path needs hashing when it has never been hashed *or* when the file
    /// has changed since it was. The second case used to be missing entirely:
    /// only `sha256 == nil` was returned, so `recordHash`'s change-detection
    /// branch could never run and the provenance record the hash exists to
    /// provide silently never updated.
    ///
    /// `stamp` is injected rather than read here so the ledger stays a pure
    /// value type, and so this is testable without a filesystem.
    func pathsNeedingHash(
        among paths: [String], limit: Int, now: Date, stamp: (String) -> FileStamp?
    ) -> [String] {
        var result: [String] = []
        for path in paths {
            guard let identity = identities[path] else { continue }
            // Back off from anything tried recently. On success the need below
            // goes away on its own, so this only ever delays a repeat failure.
            if let attempted = identity.hashAttemptedAt,
                now.timeIntervalSince(attempted) < Self.hashRetryInterval,
                now >= attempted
            {
                continue
            }

            let current = stamp(path)
            let needed =
                identity.sha256 == nil
                || current?.mtime != identity.hashedMtime
                || current?.size != identity.hashedSize
            guard needed else { continue }

            result.append(path)
            if result.count == limit { break }
        }
        return result
    }

    mutating func prune(now: Date, eventRetention: TimeInterval) {
        let cutoff = now.addingTimeInterval(-eventRetention)
        events.removeAll { $0.date < cutoff }
        if events.count > Self.eventCap {
            events.removeFirst(events.count - Self.eventCap)
        }
    }

    private func append(_ transition: Transition, to identity: inout Identity) {
        identity.transitions.append(transition)
        if identity.transitions.count > Self.transitionCap {
            identity.transitions.removeFirst(
                identity.transitions.count - Self.transitionCap)
        }
    }
}
