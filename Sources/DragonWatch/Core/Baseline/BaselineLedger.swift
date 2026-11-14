import Foundation

/// The living ledger of what is normal on this machine: every executable
/// identity ever seen and whether it was acceptable, plus known persistence
/// items. It answers a membership question — "have I seen this before, and was
/// it acceptable?" — so there is exactly one ledger, updated in place.
struct BaselineLedger: Codable, Sendable {
    static let currentSchemaVersion = 1

    /// Optional on purpose. Swift's synthesized `Decodable` does **not** fall
    /// back to a property's default value for a missing key (verified by
    /// execution — it throws `keyNotFound`), and every baseline written so far
    /// predates this field. A non-optional version here would fail to decode
    /// on upgrade, move the file aside, and discard every verdict the user had
    /// recorded — the exact loss the field was added to prevent.
    var schemaVersion: Int? = BaselineLedger.currentSchemaVersion

    /// A file with no recorded version is version 1.
    var effectiveSchemaVersion: Int { schemaVersion ?? 1 }

    enum Verdict: String, Codable, Sendable {
        case autoTrusted  // Trusted tier when first seen; added silently
        case expected  // user reviewed and accepted
        case keepFlagging  // user reviewed and wants it to stay flagged
        case pendingReview  // awaiting the user's verdict
        /// User declined to answer. Hidden from both lists and never asked
        /// or alerted again — but nothing vouches for it, which is what
        /// separates it from `expected` in the ledger.
        case ignored
    }

    struct Entry: Codable, Sendable {
        var tier: SignatureTier
        var verdict: Verdict
        var firstSeen: Date
        /// Day-granular, and optional so ledgers written before it decode.
        var lastSeen: Date?
    }

    var executables: [String: Entry] = [:]
    var persistenceItems: Set<String> = []
    /// SHA-256 of each persistence item's contents when last read. Optional
    /// so ledgers written before it decode.
    var persistenceFingerprints: [String: String]?

    enum Observation: Equatable, Sendable {
        case known
        case addedTrusted
        case addedForReview
    }

    /// Records a sighting. Trusted-tier binaries join silently; anything else
    /// joins as pending review — the caller decides whether that also alerts
    /// (it does not during the first-run/reset seeding sweep).
    mutating func observe(
        path: String, assessment: TrustAssessment, now: Date
    ) -> Observation {
        if var entry = executables[path] {
            entry.tier = assessment.tier
            // A pending question about something the (possibly improved)
            // trust model now rates Trusted is moot — resolve it instead of
            // asking the user to vouch for a green-badged item.
            if entry.verdict == .pendingReview, assessment.badge == .trusted {
                entry.verdict = .autoTrusted
            }
            executables[path] = entry
            return .known
        }
        if assessment.badge == .trusted {
            executables[path] = Entry(
                tier: assessment.tier, verdict: .autoTrusted, firstSeen: now, lastSeen: now)
            return .addedTrusted
        }
        executables[path] = Entry(
            tier: assessment.tier, verdict: .pendingReview, firstSeen: now, lastSeen: now)
        return .addedForReview
    }

    /// Records a persistence item; returns true when it was not yet known.
    mutating func observePersistenceItem(_ path: String) -> Bool {
        persistenceItems.insert(path).inserted
    }

    /// Records an item's contents. Returns true only when they differ from a
    /// fingerprint recorded earlier — the first reading of an item, new or
    /// long known, is stored silently.
    mutating func observePersistenceFingerprint(path: String, fingerprint: String) -> Bool {
        let previous = persistenceFingerprints?[path]
        guard previous != fingerprint else { return false }
        persistenceFingerprints = (persistenceFingerprints ?? [:])
            .merging([path: fingerprint]) { _, new in new }
        return previous != nil
    }

    /// How stale `lastSeen` may get before it is rewritten. A day, so a
    /// long-running process costs one write a day, not one a tick.
    static let lastSeenGranularity: TimeInterval = 86400

    /// Stamps the entries seen in this sample. Returns whether any moved.
    mutating func refreshLastSeen(_ paths: some Sequence<String>, now: Date) -> Bool {
        var moved = false
        for path in paths {
            guard let seen = executables[path]?.lastSeen ?? executables[path]?.firstSeen,
                executables[path]?.lastSeen == nil
                    || now.timeIntervalSince(seen) >= Self.lastSeenGranularity
            else { continue }
            executables[path]?.lastSeen = now
            moved = true
        }
        return moved
    }

    /// Forgets entries nobody has ruled on that have not run for `unseenFor`.
    ///
    /// The ledger used to keep every path forever, and build tools, test
    /// runners and updaters mint new paths daily, so it only ever grew. A
    /// verdict the user gave is kept regardless: that is their work, and
    /// there are few of them. A forgotten path that runs again is simply new
    /// again — a silent re-add if trusted, a fresh question if not.
    mutating func prune(now: Date, unseenFor: TimeInterval) -> Int {
        let cutoff = now.addingTimeInterval(-unseenFor)
        let before = executables.count
        executables = executables.filter { _, entry in
            switch entry.verdict {
            case .expected, .keepFlagging, .ignored: true
            case .autoTrusted, .pendingReview: (entry.lastSeen ?? entry.firstSeen) >= cutoff
            }
        }
        return before - executables.count
    }

    /// The user's answer to "is this expected?" — recorded so it is asked
    /// exactly once.
    mutating func recordVerdict(path: String, verdict: Verdict) {
        executables[path]?.verdict = verdict
    }

    /// Oldest first, then by path. The tiebreak is load-bearing: the
    /// first-run sweep stamps every item with the same `firstSeen`, and
    /// sorting a Dictionary on a tied key leaves the rest to iteration
    /// order — which changes between runs, reshuffling the list under the
    /// user mid-review.
    var pendingReview: [(path: String, entry: Entry)] {
        entries(withVerdict: .pendingReview)
    }

    /// Items the user answered "not expected" about. They stay listed —
    /// otherwise the verdict is indistinguishable from "expected", which is
    /// what "Keep flagging" used to do: both answers simply removed the row.
    var markedUnexpected: [(path: String, entry: Entry)] {
        entries(withVerdict: .keepFlagging)
    }

    private func entries(withVerdict verdict: Verdict) -> [(path: String, entry: Entry)] {
        executables
            .filter { $0.value.verdict == verdict }
            .sorted {
                $0.value.firstSeen == $1.value.firstSeen
                    ? $0.key < $1.key
                    : $0.value.firstSeen < $1.value.firstSeen
            }
            .map { (path: $0.key, entry: $0.value) }
    }
}
