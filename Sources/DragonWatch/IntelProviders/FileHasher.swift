import CryptoKit
import Foundation

/// SHA-256 of executables, streamed in chunks (binaries can be hundreds of
/// MB) and cached by (path, mtime) like the signature checks.
actor FileHasher {
    private var cache: [String: (mtime: Date, digest: String)] = [:]

    func sha256(ofPath path: String) -> String? {
        let mtime =
            ((try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate]
                as? Date) ?? .distantPast
        if let hit = cache[path], hit.mtime == mtime {
            return hit.digest
        }
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        cache[path] = (mtime, digest)
        return digest
    }
}
