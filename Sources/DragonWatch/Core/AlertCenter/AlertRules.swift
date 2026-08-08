import Foundation

/// Per-key cooldowns so a flapping condition never becomes a notification
/// storm: a key fires at most once per cooldown window.
struct AlertThrottle {
    private var lastFired: [String: Date] = [:]

    mutating func shouldFire(key: String, cooldown: TimeInterval, now: Date) -> Bool {
        if let last = lastFired[key], now.timeIntervalSince(last) < cooldown {
            return false
        }
        lastFired[key] = now
        return true
    }
}

/// The "sustained spike" rule: fires only when the threshold is exceeded
/// across the whole window, so a brief legitimate burst never alerts.
enum SustainedSpikeRule {
    static func isSpiking(
        samples: [(date: Date, value: Double)],
        threshold: Double,
        window: TimeInterval,
        now: Date
    ) -> Bool {
        let windowed = samples.filter { now.timeIntervalSince($0.date) <= window }
        guard windowed.count >= 3, let oldest = windowed.first else { return false }
        // Coverage check: the samples must actually span (most of) the window —
        // two hot samples right after launch are not "sustained".
        guard now.timeIntervalSince(oldest.date) >= window * 0.8 else { return false }
        return windowed.allSatisfy { $0.value >= threshold }
    }
}
