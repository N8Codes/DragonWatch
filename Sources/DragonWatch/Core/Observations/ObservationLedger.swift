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
        var transitions: [Transition] = []
    }

    struct Event: Codable, Sendable {
        let date: Date
        let kind: String
        let title: String
        let detail: String
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
    mutating func recordHash(path: String, sha256: String, now: Date) -> Bool {
        guard var identity = identities[path] else { return false }
        defer { identities[path] = identity }
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

    mutating func record(event: Event) {
        events.append(event)
    }

    /// Candidates for the rate-limited hashing queue, in the caller's order.
    func unhashedPaths(among paths: [String], limit: Int) -> [String] {
        var result: [String] = []
        for path in paths where identities[path] != nil && identities[path]?.sha256 == nil {
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
