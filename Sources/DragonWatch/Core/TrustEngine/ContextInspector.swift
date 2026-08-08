import Darwin
import Foundation

/// Filesystem-context signals about an executable's location and provenance.
enum ContextInspector {
    static func modifiers(forPath path: String) -> [RiskModifier] {
        var mods: [RiskModifier] = []

        let suspiciousPrefixes = [
            "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
            NSHomeDirectory() + "/Downloads/",
        ]
        if suspiciousPrefixes.contains(where: path.hasPrefix) {
            mods.append(.suspiciousLocation)
        }

        let components = (path as NSString).pathComponents
        if components.contains(where: { $0.hasPrefix(".") && $0 != "." && $0 != ".." }) {
            mods.append(.hiddenPath)
        }

        if hasQuarantineAttribute(path)
            || bundleRoot(of: path).map(hasQuarantineAttribute) == true
        {
            mods.append(.quarantined)
        }

        return mods
    }

    static func hasQuarantineAttribute(_ path: String) -> Bool {
        getxattr(path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    /// Outermost .app bundle containing this path, if any — also used to group
    /// helper processes under their owning application.
    static func bundleRoot(of path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return nil }
        return String(path[..<range.lowerBound]) + ".app"
    }
}
