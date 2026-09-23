import CryptoKit
import Foundation

/// SHA-256 of executables, streamed in chunks (binaries can be hundreds of
/// MB) and cached by (path, mtime) like the signature checks. Feeds the
/// observation ledger's replaced-binary detection; the digest never leaves
/// this Mac.
actor FileHasher {
    private var cache: [String: (mtime: Date, digest: String)] = [:]

    func sha256(ofPath path: String) async -> String? {
        let mtime =
            ((try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate]
                as? Date) ?? .distantPast
        if let hit = cache[path], hit.mtime == mtime {
            return hit.digest
        }
        // Streamed off the actor: hashing inside it serialised every caller
        // behind the current file, so four inspection workers hashed one at a
        // time and Cancel waited for a 2 GB read to finish. The detached task
        // is cancelled with the caller so the read stops at the next chunk.
        let job = Task.detached(priority: .utility) { Self.sha256Data(path: path) }
        let digest = await withTaskCancellationHandler {
            await job.value
        } onCancel: {
            job.cancel()
        }
        guard let digest else { return nil }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        cache[path] = (mtime, hex)
        return hex
    }

    /// Streams the file and returns the raw digest, or nil if the file could
    /// not be read **in full**.
    ///
    /// A read error partway through must not finalize the digest. Treating a
    /// throw as end-of-file yields the hash of a prefix: a well-formed, wrong
    /// answer that then gets cached and recorded in the ledger, where the
    /// next correct read shows up as a phantom "binary changed" transition.
    nonisolated static func sha256Data(path: String) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }

        // Each chunk must be released inside the loop. Without the pool,
        // Foundation retains every 1 MB Data until the enclosing autorelease
        // pool drains — which in an async actor may not happen until the whole
        // task finishes. Measured: hashing a 300 MB binary grew RSS by 300 MB
        // without this, and 8 MB with it.
        var hasher = SHA256()
        var reachedEnd = false
        var failed = false
        while !reachedEnd && !failed {
            if Task.isCancelled { return nil }
            autoreleasepool {
                do {
                    guard let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty
                    else {
                        reachedEnd = true
                        return
                    }
                    hasher.update(data: chunk)
                } catch {
                    failed = true
                }
            }
        }
        guard !failed else { return nil }
        return Data(hasher.finalize())
    }
}
