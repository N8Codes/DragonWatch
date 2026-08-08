import Foundation

/// The app's private directory in Application Support, and the one place that
/// creates it. Everything DragonWatch stores describes this machine — which
/// executables exist, which were flagged, which intel providers are on — so
/// the directory is owner-only (0700) and so is every file in it.
///
/// 0600 files inside a 0755 directory still leak: anyone can list the names
/// and learn which features are enabled. Restrict both.
enum AppSupport {
    static let directoryName = "DragonWatch"

    /// Resolves the storage directory, creating it owner-only if needed.
    /// `override` is for tests, which pass a temp directory.
    static func directory(override: URL? = nil) -> URL {
        let url =
            override
            ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(directoryName)
        try? FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        // createDirectory only applies attributes when it creates the
        // directory, so re-assert for directories that already existed.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }

    /// Writes owner-only. Atomic writes replace the file, so the mode must be
    /// re-applied after every save, not just the first.
    static func writePrivately(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
