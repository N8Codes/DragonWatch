import Foundation

/// One tiny HTTPS request against Apple's captive-portal endpoint — a host
/// every Mac already talks to, so it reveals nothing new about the machine.
/// Reports round-trip in milliseconds, nil when offline or timed out.
enum LatencyProbe {
    private static let url = URL(string: "https://captive.apple.com/hotspot-detect.html")!

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForResource = 5
        return URLSession(configuration: config)
    }()

    static func measure() async -> Double? {
        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await session.data(from: url)
        } catch {
            return nil
        }
        let elapsed = clock.now - start
        return Double(elapsed.components.seconds) * 1000
            + Double(elapsed.components.attoseconds) / 1e15
    }
}
