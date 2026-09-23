import Foundation

/// How strongly a finding argues that a file is not what it claims to be.
/// Deliberately *not* a malware scale: the strongest thing DragonWatch can
/// honestly assert about a file at rest is that its contents contradict its
/// name, which is what `.inconsistent` means.
enum FindingSeverity: Int, Comparable, Codable, Sendable {
    /// Worth telling the user, argues nothing on its own.
    case info = 0
    /// Unusual. Legitimate files do this, but rarely and for a reason.
    case caution = 1
    /// The file's contents contradict what it presents itself as.
    case inconsistent = 2

    static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// The headline verdict for one inspected file. Ordering is "how much does
/// this want your attention", not "how bad" — `.unreadable` sits low because
/// it is an absence of evidence, but keeps its own label so "we could not
/// look" never reads as "we looked and it was fine".
enum InspectionVerdict: Int, Comparable, Codable, Sendable, CaseIterable {
    case consistent = 0
    case unreadable = 1
    case caution = 2
    case inconsistent = 3

    static func < (lhs: InspectionVerdict, rhs: InspectionVerdict) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .consistent: "Consistent"
        case .unreadable: "Unreadable"
        case .caution: "Caution"
        case .inconsistent: "Inconsistent"
        }
    }

    /// A shape as well as a colour — same reasoning as `TrustBadge.symbolName`.
    /// Roughly 8% of men cannot separate the red/green pair, and the verdict is
    /// the whole point of the view.
    var symbolName: String {
        switch self {
        case .consistent: "checkmark.circle.fill"
        case .unreadable: "questionmark.circle.fill"
        case .caution: "exclamationmark.triangle.fill"
        case .inconsistent: "exclamationmark.octagon.fill"
        }
    }

    /// One line the report and the UI both use, so they cannot drift apart.
    var summary: String {
        switch self {
        case .consistent: "Contents match what the file claims to be."
        case .unreadable: "Could not be read, so nothing was verified."
        case .caution: "Readable and identified, with traits worth a look."
        case .inconsistent: "Contents contradict what the file claims to be."
        }
    }
}

/// One rule's observation about one file.
struct Finding: Codable, Sendable, Hashable {
    /// Stable rule identifier, e.g. `magic.mismatch`. Tests assert on this
    /// rather than on prose, and `CriteriaView` keys its rulebook entries to
    /// it — so wording can be improved without breaking either.
    let rule: String
    let severity: FindingSeverity
    let title: String
    let detail: String
}

/// A neutral fact worth surfacing that argues nothing either way. Separate
/// from `Finding` so that provenance — where a file came from, that it carries
/// AI-generation metadata — does not inflate the finding count and train
/// people to ignore it.
struct Disclosure: Codable, Sendable, Hashable {
    let title: String
    let detail: String
}

/// Everything learned about one file.
struct FileInspection: Codable, Sendable, Identifiable {
    let path: String
    let displayName: String
    let byteSize: Int64
    let sha256: String?
    /// Lowercased, without the dot. Empty when the file has no extension.
    let declaredExtension: String
    /// `nil` when no signature in the table matched — the unclassified case.
    let identifiedFormat: String?
    /// First bytes as hex, set only when nothing matched. Optional so an
    /// exported report written before this field existed still decodes.
    var magicPrefix: String?
    let findings: [Finding]
    let disclosures: [Disclosure]
    /// What was examined, so "no findings" can be read as a result rather
    /// than an absence. Optional so a report exported before this existed
    /// still decodes.
    var checksRun: [String]?
    let verdict: InspectionVerdict

    var id: String { path }

    /// Pure, so the verdict can never disagree with the findings that produced
    /// it. `TrustExplanation` learned this the hard way: an explanation that
    /// contradicts its score is worse than no explanation.
    static func verdict(readable: Bool, findings: [Finding]) -> InspectionVerdict {
        guard readable else { return .unreadable }
        switch findings.map(\.severity).max() ?? .info {
        case .info: return .consistent
        case .caution: return .caution
        case .inconsistent: return .inconsistent
        }
    }
}

/// Why a run stopped short of everything the user selected.
enum InspectionLimit: String, Codable, Sendable {
    case cancelled
    case fileCountCap
    case byteCap
    case depthCap
    case timeCap

    var explanation: String {
        switch self {
        case .cancelled: "Stopped at your request."
        case .fileCountCap: "Hit the file-count limit; some files were not inspected."
        case .byteCap: "Hit the total-size limit; some files were not inspected."
        case .depthCap: "Hit the folder-depth limit; some folders were not entered."
        case .timeCap: "Hit the time limit; some files were not inspected."
        }
    }
}

/// The result of one inspection run, and the thing every report renders from.
struct InspectionReport: Codable, Sendable {
    let generated: Date
    /// What the user actually selected, before any folder expansion.
    let roots: [String]
    /// Mutable so a renderer can emit the sorted view without rebuilding the
    /// report field by field — which is how JSON export lost two fields.
    var files: [FileInspection]
    let limitHit: InspectionLimit?
    /// How long the run took and how many folders it entered — the scope of
    /// the answer, which the verdict alone does not convey.
    var durationSeconds: Double?
    var folderCount: Int?

    /// Not optional or configurable: a tool that reports on files is read as
    /// an antivirus unless it says plainly that it is not one.
    static let disclaimer =
        "Not a malware scan. This checks whether a file's contents match what it "
        + "claims to be. XProtect and Gatekeeper remain your antivirus."

    var worstVerdict: InspectionVerdict {
        files.map(\.verdict).max() ?? .consistent
    }

    var findingCount: Int { files.reduce(0) { $0 + $1.findings.count } }
    var disclosureCount: Int { files.reduce(0) { $0 + $1.disclosures.count } }

    func count(of verdict: InspectionVerdict) -> Int {
        files.filter { $0.verdict == verdict }.count
    }

    /// Worst first, then by path. The tiebreak is not cosmetic: results are
    /// assembled concurrently and `Dictionary` iteration order varies between
    /// runs of the same binary, so without a total ordering two runs over the
    /// same input render different reports.
    /// Worst first, then by the name the list shows, compared without
    /// regard to case so `dark_soul.png` sits beside `Dark_Souls.jpg` rather
    /// than after every capitalised name; the exact path breaks ties. Every
    /// comparison is locale-independent, which is what keeps two exports of
    /// one run byte-identical.
    var sortedFiles: [FileInspection] {
        files.sorted { lhs, rhs in
            guard lhs.verdict == rhs.verdict else { return lhs.verdict > rhs.verdict }
            switch lhs.displayName.caseInsensitiveCompare(rhs.displayName) {
            case .orderedSame: return lhs.path < rhs.path
            case let order: return order == .orderedAscending
            }
        }
    }
}
