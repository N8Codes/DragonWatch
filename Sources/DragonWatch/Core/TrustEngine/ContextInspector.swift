import Darwin
import Foundation

/// Filesystem-context signals about an executable's location and provenance.
enum ContextInspector {
    static func modifiers(forPath path: String) -> [RiskModifier] {
        var mods: [RiskModifier] = []

        if isSuspiciousLocation(path) {
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

    /// Locations a program has no durable reason to live in: the temp
    /// directories and the browser's drop folder.
    ///
    /// `/tmp` alone missed the temp directory macOS actually hands out.
    /// `$TMPDIR` is `/var/folders/<xx>/<yyy>/T/`, so a payload staged there
    /// matched no prefix and lost the signal this modifier exists for.
    ///
    /// Deliberately *not* included: App Translocation
    /// (`/private/var/folders/<xx>/<yyy>/d/Wrapper/`). A translocated app is
    /// Gatekeeper working correctly on a downloaded bundle, `.quarantined`
    /// already covers that case, and flagging it would demote apps the user
    /// opened exactly as Apple intends.
    static func isSuspiciousLocation(_ path: String) -> Bool {
        let staticPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
        if staticPrefixes.contains(where: path.hasPrefix) { return true }

        // Ask the OS rather than composing NSHomeDirectory(): under a sandbox
        // that returns the container, which would silently disable this check.
        if let downloads = try? FileManager.default.url(
            for: .downloadsDirectory, in: .userDomainMask, appropriateFor: nil, create: false),
            path.hasPrefix(downloads.path + "/")
        {
            return true
        }

        return isPerUserTemporaryDirectory(path)
    }

    /// True for `/var/folders/<xx>/<yyy>/T/…`, the real `$TMPDIR`, matched by
    /// shape so it holds for every user and every boot rather than only the
    /// one this process happens to have.
    static func isPerUserTemporaryDirectory(_ path: String) -> Bool {
        var components = (path as NSString).pathComponents
        if components.starts(with: ["/", "private"]) {
            components.remove(at: 1)
        }
        // ["/", "var", "folders", xx, yyy, "T", ...]
        guard components.count > 6,
            components[1] == "var", components[2] == "folders", components[5] == "T"
        else { return false }
        return true
    }

    /// Directories that ship with macOS and that System Integrity Protection
    /// keeps read-only even for root. `/usr/local` is explicitly excluded —
    /// it is the one part of `/usr` that SIP leaves writable.
    static func isOSManagedLocation(_ path: String) -> Bool {
        if path.hasPrefix("/usr/local/") { return false }
        return ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"]
            .contains(where: path.hasPrefix)
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
