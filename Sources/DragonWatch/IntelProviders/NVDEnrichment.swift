import Foundation

/// A dotted version, compared numerically per component ("2.10" > "2.9",
/// missing components read as zero, non-numeric suffixes are ignored).
struct AppVersion: Comparable, Equatable, Sendable {
    let components: [Int]

    init?(_ string: String) {
        var parts = string.split(separator: ".").map { part in
            Int(part.prefix { $0.isNumber }) ?? 0
        }
        guard !parts.isEmpty, parts.contains(where: { $0 > 0 }) || string.first == "0"
        else { return nil }
        // Normalize trailing zeros so "1.2" == "1.2.0" under synthesized
        // equality, matching what `<` already treats as equal.
        while parts.count > 1, parts.last == 0 { parts.removeLast() }
        components = parts
    }

    static func < (lhs: AppVersion, rhs: AppVersion) -> Bool {
        let count = max(lhs.components.count, rhs.components.count)
        for i in 0..<count {
            let l = i < lhs.components.count ? lhs.components[i] : 0
            let r = i < rhs.components.count ? rhs.components[i] : 0
            if l != r { return l < r }
        }
        return false
    }
}

/// One vulnerable version constraint from an NVD CPE match.
struct CPEVersionRange: Codable, Equatable, Sendable {
    var exact: String?
    var startIncluding: String?
    var startExcluding: String?
    var endIncluding: String?
    var endExcluding: String?

    func contains(_ version: AppVersion) -> Bool {
        if let exact { return AppVersion(exact) == version }
        if let bound = startIncluding.flatMap(AppVersion.init), version < bound {
            return false
        }
        if let bound = startExcluding.flatMap(AppVersion.init), !(bound < version) {
            return false
        }
        if let bound = endIncluding.flatMap(AppVersion.init), bound < version {
            return false
        }
        if let bound = endExcluding.flatMap(AppVersion.init), !(version < bound) {
            return false
        }
        return true
    }
}

/// Downloads NVD's version-range data for KEV CVEs — every KEV CVE, not just
/// ones matching installed apps, so the query pattern reveals nothing about
/// this machine. Results persist; the free-tier rate limit (5 req/30 s) makes
/// the initial backfill a slow background trickle by design.
actor NVDEnrichment {
    static let requestSpacing: Duration = .seconds(6.5)
    private static let responseByteCap = 5 << 20

    private var ranges: [String: [CPEVersionRange]]
    private var failedThisSession: Set<String> = []
    private var syncing = false
    private let cacheURL: URL

    init(cacheDirectory: URL? = nil) {
        let dir = AppSupport.directory(override: cacheDirectory)
        cacheURL = dir.appendingPathComponent("nvd-ranges.json")
        ranges =
            (try? Data(contentsOf: cacheURL))
            .flatMap { try? JSONDecoder().decode([String: [CPEVersionRange]].self, from: $0) }
            ?? [:]
    }

    /// nil means "not synced yet" — the caller must not treat it as "no ranges".
    func ranges(for cveID: String) -> [CPEVersionRange]? {
        ranges[cveID]
    }

    /// Fetches any CVEs not yet cached, one at a time, honoring the NVD rate
    /// limit. Safe to call repeatedly; only one sync runs at a time.
    func syncMissing(cveIDs: [String]) async {
        guard !syncing else { return }
        syncing = true
        defer { syncing = false }

        for cveID in cveIDs
        where ranges[cveID] == nil && !failedThisSession.contains(cveID) {
            guard CVEID.isValid(cveID) else {
                failedThisSession.insert(cveID)
                continue
            }
            do {
                let url = URL(
                    string: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=\(cveID)")!
                let (data, _) = try await URLSession.shared.data(from: url)
                guard data.count <= Self.responseByteCap else {
                    failedThisSession.insert(cveID)
                    continue
                }
                ranges[cveID] = try Self.extractRanges(from: data)
                persist()
            } catch {
                failedThisSession.insert(cveID)
            }
            try? await Task.sleep(for: Self.requestSpacing)
        }
    }

    /// Pulls every vulnerable version constraint out of an NVD CVE response.
    static func extractRanges(from data: Data) throws -> [CPEVersionRange] {
        let response = try JSONDecoder().decode(NVDResponse.self, from: data)
        return response.vulnerabilities.flatMap { vulnerability in
            (vulnerability.cve.configurations ?? []).flatMap { configuration in
                configuration.nodes.flatMap { node in
                    node.cpeMatch.compactMap { match -> CPEVersionRange? in
                        guard match.vulnerable else { return nil }
                        var range = CPEVersionRange(
                            startIncluding: match.versionStartIncluding,
                            startExcluding: match.versionStartExcluding,
                            endIncluding: match.versionEndIncluding,
                            endExcluding: match.versionEndExcluding)
                        if range == CPEVersionRange() {
                            // No explicit bounds: the CPE's own version field
                            // (index 5 of cpe:2.3:a:vendor:product:version:…)
                            // is the constraint; "*"/"-" mean "unbounded",
                            // which we skip rather than flag every version.
                            let fields = match.criteria.split(
                                separator: ":", omittingEmptySubsequences: false)
                            guard fields.count > 5 else { return nil }
                            let version = String(fields[5])
                            guard version != "*", version != "-" else { return nil }
                            range.exact = version
                        }
                        return range
                    }
                }
            }
        }
    }

    private func persist() {
        do {
            try AppSupport.writePrivately(try JSONEncoder().encode(ranges), to: cacheURL)
        } catch {
            // Best-effort; a failed save costs a refetch next launch.
        }
    }
}

/// The slice of NVD's CVE API response we consume.
private struct NVDResponse: Codable {
    struct Vulnerability: Codable {
        let cve: CVE
    }

    struct CVE: Codable {
        let configurations: [Configuration]?
    }

    struct Configuration: Codable {
        let nodes: [Node]
    }

    struct Node: Codable {
        let cpeMatch: [CPEMatch]
    }

    struct CPEMatch: Codable {
        let vulnerable: Bool
        let criteria: String
        let versionStartIncluding: String?
        let versionStartExcluding: String?
        let versionEndIncluding: String?
        let versionEndExcluding: String?
    }

    let vulnerabilities: [Vulnerability]
}
