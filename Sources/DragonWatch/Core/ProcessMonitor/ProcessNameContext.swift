import Foundation

/// Human context for executables whose filename says nothing on its own —
/// "2.1.222", "helper", "agent". The hint is the nearest ancestor directory
/// that carries meaning, skipping filesystem plumbing ("bin", "versions",
/// "Contents") and version-number directories.
enum ProcessNameContext {
    private static let genericNames: Set<String> = [
        "main", "helper", "daemon", "agent", "server", "worker", "launcher",
        "updater", "service", "tool", "run", "start", "app", "bin",
    ]

    private static let genericDirectories: Set<String> = [
        "bin", "sbin", "libexec", "exec", "macos", "contents", "resources",
        "helpers", "versions", "current", "usr", "local", "share", "lib",
        "opt", "frameworks", "plugins", "support", "application support",
        "library", "system", "users", "applications", "cellar", "homebrew",
    ]

    static func isAmbiguous(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower.count <= 2 || genericNames.contains(lower) || isVersionLike(lower)
    }

    static func isVersionLike(_ value: String) -> Bool {
        value.contains(where: \.isNumber)
            && value.allSatisfy {
                $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" || $0 == "v"
            }
    }

    /// nil when the name stands on its own, or when no ancestor adds meaning.
    static func hint(name: String, path: String) -> String? {
        guard isAmbiguous(name) else { return nil }
        let parents = (path as NSString).deletingLastPathComponent
        for component in parents.split(separator: "/").reversed() {
            let clean = String(component).trimmingCharacters(
                in: CharacterSet(charactersIn: "."))
            let lower = clean.lowercased()
            if lower.isEmpty || genericDirectories.contains(lower)
                || isVersionLike(lower) || clean == NSUserName()
            {
                continue
            }
            return clean
        }
        return nil
    }
}
