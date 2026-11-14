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

/// Fingerprints the watched plists so a *rewritten* one is noticed, not only
/// a new filename: pointing an existing LaunchAgent at a different program
/// is as much a persistence change as adding one.
///
/// Each file is re-read only when its inode, size, modification time or
/// status-change time moves. The last of those cannot be set from user space,
/// so restoring the mtime after an edit does not hide it.
actor PersistenceContents {
    private struct Stamp: Equatable {
        let inode: UInt64
        let size: Int64
        let modified: Int
        let modifiedNanos: Int
        let changed: Int
        let changedNanos: Int
    }

    /// A launchd plist is a few kilobytes; anything past this is not one.
    static let maxBytes = 1 << 20
    private var cache: [String: (stamp: Stamp, fingerprint: String)] = [:]

    /// `path -> SHA-256` for every item that could be read. An unreadable
    /// item is simply absent: no fingerprint is not a changed fingerprint.
    func fingerprints(of paths: [String]) -> [String: String] {
        var result: [String: String] = [:]
        for path in paths {
            var info = stat()
            guard stat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { continue }
            let stamp = Stamp(
                inode: UInt64(info.st_ino), size: Int64(info.st_size),
                modified: info.st_mtimespec.tv_sec, modifiedNanos: info.st_mtimespec.tv_nsec,
                changed: info.st_ctimespec.tv_sec, changedNanos: info.st_ctimespec.tv_nsec)
            if let hit = cache[path], hit.stamp == stamp {
                result[path] = hit.fingerprint
                continue
            }
            guard info.st_size <= off_t(Self.maxBytes),
                let digest = FileHasher.sha256Data(path: path)
            else { continue }
            let fingerprint = digest.map { String(format: "%02x", $0) }.joined()
            cache[path] = (stamp, fingerprint)
            result[path] = fingerprint
        }
        cache = cache.filter { result[$0.key] != nil }
        return result
    }
}
