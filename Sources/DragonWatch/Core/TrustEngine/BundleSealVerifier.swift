import Foundation
import Security

/// Full static validation of a bundle's signature seal — every sealed
/// resource hashed, nested executables checked against their sealed cdhashes.
/// This is the expensive proof that a weakly-signed binary inside a
/// strongly-signed bundle is exactly what the vendor shipped, not something
/// planted. Minutes for something Xcode-sized, so it runs on demand and the
/// verdict is cached.
///
/// The cache vouches **specific binaries**, identified by path and a
/// content-bound fingerprint captured at verification time — never "anything
/// inside this bundle". A file planted into a verified bundle afterwards has a
/// path that was never vouched, so it stays flagged; a binary swapped at a
/// vouched path has different bytes, so its vouch lapses. Vouching by bundle
/// membership would recreate exactly the hiding spot this feature exists to
/// avoid.
///
/// The fingerprint is the file's bytes (cdhash, or SHA-256 when unsigned), not
/// its mtime and size. Those are both settable by anyone who can write the
/// file, so identifying by them meant an attacker who replaced a vouched
/// binary could keep its vouch just by padding to the same length and calling
/// `utimensat`.
actor BundleSealVerifier {
    struct BinaryIdentity: Codable, Hashable, Sendable {
        let path: String
        let fingerprint: Data

        init?(path: String) {
            guard let fingerprint = CodeIdentity.fingerprint(path: path) else { return nil }
            self.path = path
            self.fingerprint = fingerprint
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

    /// Every recorded vouch, as `path -> (vouching bundle, fingerprint at
    /// verification time)`.
    ///
    /// Freshness is deliberately *not* checked here. This used to return only
    /// the vouches whose files still matched, which made the result a snapshot
    /// — and `TrustEngine` holds that snapshot for the life of the process, so
    /// a file replaced after launch kept a vouch that had already lapsed. The
    /// engine re-checks the fingerprint at assessment time instead; handing it
    /// the fingerprint is what lets it do so.
    ///
    /// Sorted by bundle path so a binary vouched by two overlapping bundles
    /// names the same one on every launch.
    func vouches() -> [String: (bundle: String, identity: BinaryIdentity)] {
        var result: [String: (bundle: String, identity: BinaryIdentity)] = [:]
        for (bundle, record) in records.sorted(by: { $0.key < $1.key }) {
            for binary in record.binaries {
                result[binary.path] = (bundle, binary)
            }
        }
        return result
    }

    /// Verifies the bundle's seal and, on success, vouches exactly the
    /// binaries named by the caller (the flagged executables the user is
    /// resolving). Returns whether verification passed.
    func verify(bundlePath: String, vouching binaryPaths: [String]) async -> Bool {
        // Pin the identities *before* validation and confirm them after.
        // Validating a large bundle takes minutes, and recording identities
        // only on the way out would vouch whatever is on disk when it
        // finishes: replace a helper mid-run and the validator's pass — made
        // against the original bytes — is applied to the replacement.
        let before = binaryPaths.compactMap(BinaryIdentity.init(path:))
        guard await Self.runFullValidation(bundlePath: bundlePath) else { return false }
        let after = Set(binaryPaths.compactMap(BinaryIdentity.init(path:)))
        let unchanged = before.filter(after.contains)

        let vouchedPaths = Set(unchanged.map(\.path))
        var identities = (records[bundlePath]?.binaries ?? []).filter {
            !vouchedPaths.contains($0.path)
        }
        identities.append(contentsOf: unchanged)
        records[bundlePath] = Record(
            bundlePath: bundlePath, verifiedAt: Date(),
            binaries: identities.sorted { $0.path < $1.path })
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
