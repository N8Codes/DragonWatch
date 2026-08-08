import Foundation

/// Lists launchd persistence entry points readable without elevation. Login
/// items have no public enumeration API (SMAppService only covers our own
/// app), so the LaunchAgents/LaunchDaemons directories are the honest,
/// watchable surface. (/System/Library variants are SIP-sealed OS state.)
enum PersistenceWatcher {
    static var watchedDirectories: [String] {
        [
            NSHomeDirectory() + "/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
    }

    static func currentItems() -> [String] {
        watchedDirectories
            .flatMap { dir -> [String] in
                let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
                return
                    names
                    .filter { $0.hasSuffix(".plist") }
                    .map { dir + "/" + $0 }
            }
            .sorted()
    }
}
