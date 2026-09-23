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
        /// Who started it, the first time it was seen. Optional so ledgers
        /// written before this field existed still decode.
        var launchedBy: LaunchContext?
    }

    /// How long before another attempt at a path whose last one did not settle
    /// the question.
    static let hashRetryInterval: TimeInterval = 3600

    struct Event: Codable, Equatable, Sendable {
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

    /// A file format this Mac has seen that the signature table does not
    /// know, so an unknown format can be recognised as recurring rather than
    /// reported fresh every time.
    struct UnclassifiedFormat: Codable, Sendable, Hashable, Identifiable {
        /// First 16 bytes as hex, which is what identifies the format.
        let magicPrefix: String
        /// Lowercase, no dot. Empty when the file had none.
        let fileExtension: String
        var firstSeen: Date
        var lastSeen: Date
        var timesSeen: Int
        /// A name the user attached.
        ///
        /// **Annotates only.** The baseline's "expected" verdict silences a
        /// path forever, and that would be exactly wrong here: naming a format
        /// says what it is, not that any particular file carrying it is fine.
        /// Structural findings are unaffected by a label.
        var label: String?

        var id: String { "\(magicPrefix)|\(fileExtension)" }
    }

    static let unclassifiedCap = 200

    var schemaVersion = ObservationLedger.currentSchemaVersion
    var identities: [String: Identity] = [:]
    var events: [Event] = []
    /// Optional on purpose. Synthesised `Decodable` throws `keyNotFound` for a
    /// missing non-optional key even when the property has a default, so a
    /// required field here would fail to decode every `observations.json`
    /// already on disk — and the loader treats a decode failure as an unknown
    /// schema and moves the file aside. Adding this as non-optional would have
    /// discarded every user's history on upgrade.
    var unclassified: [UnclassifiedFormat]?

    /// Records one sighting of an unrecognised format, keyed by its magic
    /// bytes and extension together: the same bytes under a different
    /// extension is a different thing to have seen.
    mutating func observeUnclassified(magicPrefix: String, fileExtension: String, now: Date) {
        var list = unclassified ?? []
        if let index = list.firstIndex(where: {
            $0.magicPrefix == magicPrefix && $0.fileExtension == fileExtension
        }) {
            list[index].lastSeen = now
            list[index].timesSeen += 1
        } else {
            guard list.count < Self.unclassifiedCap else { return }
            list.append(
                UnclassifiedFormat(
                    magicPrefix: magicPrefix, fileExtension: fileExtension,
                    firstSeen: now, lastSeen: now, timesSeen: 1, label: nil))
        }
        unclassified = list
    }

    /// Attaches or clears a user's name for a format. Returns whether
    /// anything changed, so the caller can skip a write.
    @discardableResult
    mutating func labelUnclassified(id: String, label: String?) -> Bool {
        guard var list = unclassified, let index = list.firstIndex(where: { $0.id == id })
        else { return false }
        let trimmed = label?.trimmingCharacters(in: .whitespacesAndNewlines)
        let newLabel = (trimmed?.isEmpty ?? true) ? nil : trimmed
        guard list[index].label != newLabel else { return false }
        list[index].label = newLabel
        unclassified = list
        return true
    }

    /// `launch` is recorded only on the first sighting: the parent that
    /// started the process the alert was about is the one worth keeping.
    mutating func observe(
        path: String, tier: SignatureTier, now: Date, launch: LaunchContext? = nil
    ) -> Sighting {
        guard var identity = identities[path] else {
            var identity = Identity(firstSeen: now, lastSeen: now, tier: tier)
            identity.launchedBy = launch
            identities[path] = identity
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

    /// Removes exactly this event. Returns whether anything was removed, so
    /// a caller can skip the disk write when the ledger already lacked it.
    @discardableResult
    mutating func remove(event: Event) -> Bool {
        let before = events.count
        events.removeAll { $0 == event }
        return events.count != before
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
