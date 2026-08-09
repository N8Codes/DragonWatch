import Foundation

/// CISA's Known Exploited Vulnerabilities catalog — vulnerabilities with
/// confirmed in-the-wild exploitation.
struct KEVCatalog: Codable, Sendable {
    struct Entry: Codable, Sendable {
        let cveID: String
        let vendorProject: String
        let product: String
        let vulnerabilityName: String
        let dateAdded: String
        let shortDescription: String
    }

    let catalogVersion: String
    let vulnerabilities: [Entry]

    /// Guardrail: feed data is untrusted input. Entries that don't look like
    /// KEV entries are dropped, not trusted.
    static func validated(_ entries: [Entry]) -> [Entry] {
        entries.filter { CVEID.isValid($0.cveID) && !$0.product.isEmpty }
    }
}

/// Pure name matching, kept honest: a product-name match alone means "this
/// *product* has known-exploited CVEs". Only NVD version ranges can upgrade
/// that to "your version is affected".
enum KEVMatcher {
    static func matches(appName: String, in entries: [KEVCatalog.Entry])
        -> [KEVCatalog.Entry]
    {
        let app = normalize(appName)
        guard !app.isEmpty else { return [] }
        return entries.filter { entry in
            let product = normalize(entry.product)
            guard !product.isEmpty else { return false }
            // Exact always counts; containment only for names long enough to
            // not false-positive ("Word" is a product; "Chrome" in
            // "Google Chrome" is the case we want).
            return product == app
                || (product.count >= 5 && app.contains(product))
                || (app.count >= 5 && product.contains(app))
        }
    }

    private static func normalize(_ value: String) -> String {
        value.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// Downloads CISA's public catalog and NVD's version data for its CVEs. Both
/// are machine-independent downloads — every KEV CVE is synced, not just ones
/// matching installed apps, so the traffic reveals nothing about this Mac.
actor KEVProvider: IntelProvider {
    nonisolated let name = "CISA KEV"
    nonisolated let privacyDisclosure =
        "Downloads CISA's public exploited-vulnerabilities catalog and NVD version data; nothing about your Mac is sent."

    private static let feedURL = URL(
        string:
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )!
    private static let refreshInterval: TimeInterval = 86400
    private static let feedByteCap = 20 << 20

    private var catalog: KEVCatalog?
    /// When the in-memory catalog was obtained. Freshness used to be inferred
    /// from the cache file's mtime, so a silently failed write (disk full, or
    /// a directory we cannot write) left the catalog permanently "stale" and
    /// re-downloaded the whole feed on every single intel check.
    private var catalogFetchedAt: Date?
    private let cacheURL: URL
    private let nvd: NVDEnrichment

    init(cacheDirectory: URL? = nil) {
        let dir = AppSupport.directory(override: cacheDirectory)
        cacheURL = dir.appendingPathComponent("kev-catalog.json")
        nvd = NVDEnrichment(cacheDirectory: cacheDirectory)
    }

    func findings(for subject: IntelSubject) async throws -> [IntelFinding] {
        guard let appName = subject.appName else { return [] }
        let entries = try await loadCatalog().vulnerabilities
        let matched = KEVMatcher.matches(appName: appName, in: entries)
        guard !matched.isEmpty else { return [] }

        let version = subject.appVersion.flatMap(AppVersion.init)
        var confirmed: [KEVCatalog.Entry] = []
        var unknownVersionData = false
        for entry in matched {
            guard let ranges = await nvd.ranges(for: entry.cveID) else {
                unknownVersionData = true
                continue
            }
            if let version, ranges.contains(where: { $0.contains(version) }) {
                confirmed.append(entry)
            }
        }

        if !confirmed.isEmpty, let versionString = subject.appVersion {
            let examples = confirmed.prefix(3).map(\.cveID).joined(separator: ", ")
            return [
                IntelFinding(
                    providerName: name,
                    severity: .warning,
                    summary:
                        "Version \(versionString) is in the affected range of \(confirmed.count) exploited CVE\(confirmed.count == 1 ? "" : "s")",
                    detail:
                        "\(examples) — exploited in the wild per CISA, and NVD lists this version as affected. Update \(confirmed[0].product)."
                )
            ]
        }

        let latest = matched.map(\.dateAdded).max() ?? "?"
        let examples = matched.prefix(3).map(\.cveID).joined(separator: ", ")
        let versionNote =
            if version == nil {
                "Version unknown, so this is product-level only."
            } else if unknownVersionData {
                "Version data still syncing from NVD; product-level only for now."
            } else {
                "Your version is outside the known affected ranges."
            }
        return [
            IntelFinding(
                providerName: name,
                severity: .informational,
                summary:
                    "\(matched.count) known-exploited CVE\(matched.count == 1 ? "" : "s") on record for \(matched[0].product)",
                detail:
                    "Latest added \(latest). \(examples). \(versionNote) Keeping the app updated is the fix."
            )
        ]
    }

    private func loadCatalog() async throws -> KEVCatalog {
        // Staleness first, decoding second. Reversed, every check on a stale
        // in-memory catalog read and JSON-decoded the whole ~1.5 MB cache file
        // purely to discard the result.
        if let catalog, !memoryCatalogIsStale() { return catalog }
        if !cacheFileIsStale(), let cached = decodeCache() {
            startVersionSync(for: cached)
            catalog = cached
            catalogFetchedAt = Date()
            return cached
        }
        do {
            guard
                let data = await IntelSession.fetch(Self.feedURL, byteCap: Self.feedByteCap)
            else { throw URLError(.badServerResponse) }
            let decoded = try JSONDecoder().decode(KEVCatalog.self, from: data)
            let fresh = KEVCatalog(
                catalogVersion: decoded.catalogVersion,
                vulnerabilities: KEVCatalog.validated(decoded.vulnerabilities))
            catalog = fresh
            catalogFetchedAt = Date()
            if let encoded = try? JSONEncoder().encode(fresh) {
                try? AppSupport.writePrivately(encoded, to: cacheURL)
            }
            startVersionSync(for: fresh)
            return fresh
        } catch {
            // Last known good: a failed or oversized fetch falls back to the
            // stale cache rather than wiping intel for the day.
            if let cached = decodeCache() {
                catalog = cached
                catalogFetchedAt = Date()
                startVersionSync(for: cached)
                return cached
            }
            throw error
        }
    }

    private func decodeCache() -> KEVCatalog? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode(KEVCatalog.self, from: data)
    }

    private func startVersionSync(for catalog: KEVCatalog) {
        let ids = catalog.vulnerabilities.map(\.cveID)
        Task { await nvd.syncMissing(cveIDs: ids) }
    }

    private func memoryCatalogIsStale() -> Bool {
        guard let catalogFetchedAt else { return true }
        return Date().timeIntervalSince(catalogFetchedAt) > Self.refreshInterval
    }

    private func cacheFileIsStale() -> Bool {
        guard
            let mtime =
                (try? FileManager.default
                .attributesOfItem(atPath: cacheURL.path))?[.modificationDate] as? Date
        else { return true }
        return Date().timeIntervalSince(mtime) > Self.refreshInterval
    }
}
