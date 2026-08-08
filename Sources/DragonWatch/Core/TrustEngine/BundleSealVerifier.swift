import Foundation
import Security

/// Full static validation of a bundle's signature seal — every sealed
/// resource hashed, nested executables checked against their sealed cdhashes.
/// This is the expensive proof that a weakly-signed binary inside a
/// strongly-signed bundle is exactly what the vendor shipped, not something
/// planted. Minutes for something Xcode-sized, so it runs on demand and the
/// verdict is cached.
///
/// The cache vouches **specific binaries**, identified by (path, mtime, size)
/// captured at verification time — never "anything inside this bundle". A
/// file planted into a verified bundle afterwards has a path that was never
/// vouched, so it stays flagged; a binary swapped at a vouched path has a
/// different mtime/size, so its vouch lapses. Vouching by bundle membership
/// would recreate exactly the hiding spot this feature exists to avoid.
actor BundleSealVerifier {
    struct BinaryIdentity: Codable, Hashable, Sendable {
        let path: String
        let mtime: Date
        let size: Int64

        init?(path: String) {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                let mtime = attributes[.modificationDate] as? Date,
                let size = attributes[.size] as? Int64
            else { return nil }
            self.path = path
            self.mtime = mtime
            self.size = size
        }
    }

    private struct Record: Codable {
        var bundlePath: String
        var verifiedAt: Date
        var binaries: [BinaryIdentity]
    }

    private let cacheURL: URL
    private var records: [String: Record]

    init(cacheDirectory: URL? = nil) {
        let dir = AppSupport.directory(override: cacheDirectory)
        cacheURL = dir.appendingPathComponent("seal-verifications.json")
        records =
            (try? Data(contentsOf: cacheURL))
            .flatMap { try? JSONDecoder().decode([String: Record].self, from: $0) } ?? [:]
    }

    /// Every still-valid binary vouch: the file must be byte-identical (by
    /// mtime and size) to what was present when its bundle was verified.
    func validVouches() -> [String: String] {
        var vouches: [String: String] = [:]
        for (bundle, record) in records {
            for binary in record.binaries
            where BinaryIdentity(path: binary.path) == binary {
                vouches[binary.path] = bundle
            }
        }
        return vouches
    }

    /// Verifies the bundle's seal and, on success, vouches exactly the
    /// binaries named by the caller (the flagged executables the user is
    /// resolving). Returns whether verification passed.
    func verify(bundlePath: String, vouching binaryPaths: [String]) async -> Bool {
        guard await Self.runFullValidation(bundlePath: bundlePath) else { return false }
        var identities = Set(records[bundlePath]?.binaries ?? [])
        // Drop stale identities for the same paths, then record current ones.
        identities = identities.filter { !binaryPaths.contains($0.path) }
        identities.formUnion(binaryPaths.compactMap(BinaryIdentity.init(path:)))
        records[bundlePath] = Record(
            bundlePath: bundlePath, verifiedAt: Date(), binaries: Array(identities))
        persist()
        return true
    }

    /// Blocking Security-framework work happens off the cooperative pool —
    /// a large bundle keeps a worker thread busy for minutes.
    private static func runFullValidation(bundlePath: String) async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                var codeOpt: SecStaticCode?
                guard
                    SecStaticCodeCreateWithPath(
                        URL(fileURLWithPath: bundlePath) as CFURL, SecCSFlags(), &codeOpt)
                        == errSecSuccess,
                    let code = codeOpt
                else {
                    continuation.resume(returning: false)
                    return
                }
                // Default flags = full validation: executable pages and the
                // whole resource envelope, which seals nested code by cdhash —
                // a planted or modified nested binary fails here.
                continuation.resume(
                    returning: SecStaticCodeCheckValidity(code, SecCSFlags(), nil)
                        == errSecSuccess)
            }
        }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(records) {
            try? AppSupport.writePrivately(data, to: cacheURL)
        }
    }
}
