import Foundation

/// What a provider gets to look at. Built locally and matched locally: no
/// provider sends any of it off the machine, and each one's disclosure says
/// what it downloads instead.
struct IntelSubject: Sendable {
    let executablePath: String
    let appName: String?
    let appVersion: String?
}

enum IntelSeverity: Int, Comparable, Sendable {
    case informational = 0
    case warning = 1
    case critical = 2

    static func < (lhs: IntelSeverity, rhs: IntelSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

struct IntelFinding: Identifiable, Sendable {
    let id = UUID()
    let providerName: String
    let severity: IntelSeverity
    let summary: String
    let detail: String
}

/// Guardrail shared by feed consumers: identifiers from untrusted feeds are
/// validated before use, never interpolated as-is.
enum CVEID {
    static func isValid(_ id: String) -> Bool {
        let parts = id.split(separator: "-", omittingEmptySubsequences: false)
        return parts.count == 3 && parts[0] == "CVE"
            && parts[1].count == 4 && parts[1].allSatisfy(\.isNumber)
            && parts[2].count >= 4 && parts[2].allSatisfy(\.isNumber)
    }
}

/// A source of external intelligence. Providers run only when the user has
/// explicitly enabled them in Settings, and only on demand — never as part of
/// the passive monitoring loop. Matching is local: a provider may download a
/// public feed, but nothing about this Mac goes the other way.
protocol IntelProvider: Sendable {
    var name: String { get }
    /// One honest line about exactly what network traffic this causes.
    var privacyDisclosure: String { get }
    func findings(for subject: IntelSubject) async throws -> [IntelFinding]
}
