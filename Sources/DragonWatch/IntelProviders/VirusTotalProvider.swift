import Foundation

/// The slice of a VirusTotal file report we use.
struct VTFileReport: Codable, Sendable {
    struct Data_: Codable, Sendable {
        let attributes: Attributes
    }

    struct Attributes: Codable, Sendable {
        let lastAnalysisStats: Stats

        enum CodingKeys: String, CodingKey {
            case lastAnalysisStats = "last_analysis_stats"
        }
    }

    struct Stats: Codable, Sendable {
        let malicious: Int
        let suspicious: Int
        let undetected: Int
        let harmless: Int

        var totalEngines: Int { malicious + suspicious + undetected + harmless }
    }

    let data: Data_

    /// Verdict mapping, shared with tests: any "malicious" engine is critical,
    /// "suspicious"-only is a warning, otherwise informational.
    static func severity(for stats: Stats) -> IntelSeverity {
        if stats.malicious > 0 { return .critical }
        if stats.suspicious > 0 { return .warning }
        return .informational
    }
}

/// Looks up an executable's SHA-256 on VirusTotal — the hash (and only the
/// hash) leaves the machine, which still reveals *what* you run. User-supplied
/// API key; free-tier keys are limited to 4 lookups/min, one more reason
/// checks are on-demand.
struct VirusTotalProvider: IntelProvider {
    let name = "VirusTotal"
    let privacyDisclosure =
        "Sends the executable's SHA-256 hash to VirusTotal — this reveals what you run to a third party."

    enum LookupError: Error {
        case missingKey
        case invalidKey
        case rateLimited
    }

    let apiKey: String

    /// Ephemeral: `URLSession.shared` writes responses to a disk cache, which
    /// would leave a record of exactly which file hashes you looked up. This
    /// is the one lookup that reveals your software to a third party — it must
    /// not also leave that record on disk. Nothing needs HTTP caching here;
    /// results are held in memory for the session.
    private static let session = URLSession(configuration: .ephemeral)

    func findings(for subject: IntelSubject) async throws -> [IntelFinding] {
        guard !apiKey.isEmpty else { throw LookupError.missingKey }
        guard let hash = subject.sha256 else { return [] }

        var request = URLRequest(
            url: URL(string: "https://www.virustotal.com/api/v3/files/\(hash)")!)
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        let (data, response) = try await Self.session.data(for: request)

        switch (response as? HTTPURLResponse)?.statusCode {
        case 404:
            return [
                IntelFinding(
                    providerName: name,
                    severity: .informational,
                    summary: "Unknown to VirusTotal",
                    detail:
                        "No engine has seen this hash — common for niche or freshly-built binaries; not a verdict either way."
                )
            ]
        case 401, 403:
            throw LookupError.invalidKey
        case 429:
            throw LookupError.rateLimited
        default:
            break
        }

        let stats = try JSONDecoder().decode(VTFileReport.self, from: data)
            .data.attributes.lastAnalysisStats
        return [
            IntelFinding(
                providerName: name,
                severity: VTFileReport.severity(for: stats),
                summary: stats.malicious > 0
                    ? "Flagged malicious by \(stats.malicious)/\(stats.totalEngines) engines"
                    : stats.suspicious > 0
                        ? "Flagged suspicious by \(stats.suspicious)/\(stats.totalEngines) engines"
                        : "Clean across \(stats.totalEngines) engines",
                detail:
                    "\(stats.malicious) malicious, \(stats.suspicious) suspicious, \(stats.harmless) harmless, \(stats.undetected) undetected."
            )
        ]
    }
}
