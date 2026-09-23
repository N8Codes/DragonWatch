import XCTest

@testable import DragonWatch

/// The rulebook ships in the app, so it has to keep up with the code. These
/// drive a battery of crafted inputs through every inspector, collect the
/// rule ids actually emitted, and assert each one is documented — a new rule
/// added without a rulebook entry fails here rather than shipping as an
/// unexplained finding.
final class InspectionRulebookTests: XCTestCase {

    // MARK: - The rulebook itself

    func testRuleIDsAreUniqueAndDescribed() {
        let all = InspectionRulebook.groups.flatMap(\.rules)
        XCTAssertEqual(Set(all.map(\.id)).count, all.count, "duplicate rule id")
        for rule in all {
            XCTAssertFalse(rule.id.isEmpty)
            XCTAssertFalse(rule.title.isEmpty, "\(rule.id) has no title")
            XCTAssertGreaterThan(
                rule.rationale.count, 30,
                "\(rule.id) needs a rationale a user can judge, not a restatement")
        }
        XCTAssertEqual(
            Set(InspectionRulebook.groups.map(\.id)).count,
            InspectionRulebook.groups.count, "duplicate group")
    }

    /// The limits section is the honesty of the feature; losing a line there
    /// is how a verification tool starts reading as an antivirus.
    func testLimitsNameWhatTheAppWillNotConclude() {
        let text = InspectionRulebook.limits.joined(separator: " ")
        XCTAssertTrue(text.contains("not a malware scan"))
        XCTAssertTrue(text.contains("XProtect"))
        XCTAssertTrue(text.contains("never executed") || text.contains("ever executed"))
        XCTAssertTrue(text.contains("read, not verified"))
    }

    // MARK: - Drift

    /// Every rule the inspectors emit must be documented.
    func testEveryEmittedRuleIsDocumented() throws {
        let emitted = try Self.exerciseEveryInspector()
        XCTAssertGreaterThan(emitted.count, 25, "the battery should trip most of the rulebook")

        let undocumented = emitted.subtracting(InspectionRulebook.allRuleIDs)
        XCTAssertTrue(
            undocumented.isEmpty,
            "these rules are reported but not in the rulebook: \(undocumented.sorted())")
    }

    /// And the reverse, for the rules the battery reaches: a documented rule
    /// whose id no longer matches what the code emits is equally misleading.
    func testDocumentedRulesStillMatchWhatIsEmitted() throws {
        let emitted = try Self.exerciseEveryInspector()
        // Rules the battery cannot reach here are named, so the gap is
        // visible rather than silently tolerated.
        let notExercised: Set<String> = [
            "bundle.signatureInvalid", "bundle.unsigned", "bundle.adHoc",
            "file.partialRead", "file.unreadable", "container.shortFile",
            "zip.indexTruncated", "ogg.noTrailingPage", "id3.dominantTag",
        ]
        let expected = InspectionRulebook.allRuleIDs.subtracting(notExercised)
        let missing = expected.subtracting(emitted)
        XCTAssertTrue(
            missing.isEmpty,
            "documented but never emitted by the battery: \(missing.sorted()) — either the "
                + "rule id changed or the rule is gone")
    }

    /// A rule's severity in the Criteria tab must be the severity the row
    /// shows. `pdf.activeContent` was listed as Caution while a launch action
    /// was reported Inconsistent under the same id.
    func testEmittedSeverityMatchesTheRulebook() throws {
        let documented = Dictionary(
            InspectionRulebook.groups.flatMap(\.rules).map { ($0.id, $0.severity) },
            uniquingKeysWith: { first, _ in first })
        let drift = try Self.exerciseEveryInspectorFindings()
            .filter { documented[$0.rule] != nil && documented[$0.rule] != $0.severity }
            .map { "\($0.rule): emitted \($0.severity), documented \(documented[$0.rule]!)" }
        XCTAssertTrue(Set(drift).isEmpty, "severity drift: \(Set(drift).sorted())")
    }

    // MARK: - The battery

    private static func probe(
        _ data: Data, name: String, permissions: Int = 0o644, size: Int64? = nil
    ) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: size ?? Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: permissions, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    private static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }
    private static func be64(_ v: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(v >> (8 * UInt64($0)) & 0xFF) }
    }
    private static func le16(_ v: Int) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF)] }
    private static func le32(_ v: Int) -> [UInt8] {
        [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 24 & 0xFF)]
    }

    private static func zip(entries: [(name: String, compressed: Int, uncompressed: Int)]) -> Data {
        var local: [UInt8] = [0x50, 0x4B, 0x03, 0x04] + [UInt8](repeating: 0, count: 26)
        var central: [UInt8] = []
        for entry in entries {
            central += [0x50, 0x4B, 0x01, 0x02] + [UInt8](repeating: 0, count: 16)
            central += le32(entry.compressed) + le32(entry.uncompressed)
            central += le16(entry.name.utf8.count) + le16(0) + le16(0)
            central += [UInt8](repeating: 0, count: 12) + Array(entry.name.utf8)
        }
        let offset = local.count
        var eocd: [UInt8] = [0x50, 0x4B, 0x05, 0x06] + le16(0) + le16(0)
        eocd += le16(entries.count) + le16(entries.count)
        eocd += le32(central.count) + le32(offset) + le16(0)
        return Data(local + central + eocd)
    }

    /// Drives one crafted input per rule and returns every rule id produced.
    static func exerciseEveryInspector() throws -> Set<String> {
        Set(try exerciseEveryInspectorFindings().map(\.rule))
    }

    /// The findings themselves, for checks that need more than the id.
    static func exerciseEveryInspectorFindings() throws -> [Finding] {
        var emitted: [Finding] = []
        func collect(_ findings: [Finding]) { emitted.append(contentsOf: findings) }
        func collect(_ output: InspectorOutput) { collect(output.findings) }

        let jpegHead = Data([0xFF, 0xD8, 0xFF, 0xE0])
        let image = ImageInspector()
        let document = DocumentInspector()
        let media = MediaInspector()

        // Naming and type consistency.
        collect(
            UniversalChecks.typeConsistency(
                probe: probe(Data([0xCF, 0xFA, 0xED, 0xFE]), name: "a.png"),
                identified: MagicBytes.machO))
        collect(
            UniversalChecks.typeConsistency(
                probe: probe(Data("GIF89a".utf8), name: "a.png"), identified: MagicBytes.gif))
        collect(
            UniversalChecks.typeConsistency(
                probe: probe(Data([1, 2, 3, 4]), name: "a.jpg"), identified: nil))
        collect(
            UniversalChecks.typeConsistency(
                probe: probe(Data([1, 2, 3, 4]), name: "a.zzz"), identified: nil))
        collect(UniversalChecks.filename("r\u{202E}fdp.exe"))
        collect(UniversalChecks.filename("in\u{200B}voice.pdf"))
        collect(UniversalChecks.filename("photo.jpg.exe"))

        // File traits.
        collect(
            UniversalChecks.fileTraits(
                probe: probe(jpegHead, name: "w.png", permissions: 0o666)))
        collect(UniversalChecks.fileTraits(probe: probe(Data(), name: "e.jpg")))
        collect(
            UniversalChecks.fileTraits(
                probe: FileProbe(
                    path: "/tmp/d", displayName: "d", size: 0, head: Data(), tail: Data(),
                    tailOffset: 0, isDirectory: true, isSymbolicLink: false,
                    posixPermissions: 0o755,
                    quarantine: nil, whereFrom: [], readError: nil, partialRead: false)))
        collect(
            UniversalChecks.fileTraits(
                probe: FileProbe(
                    path: "/tmp/l", displayName: "l", size: 0, head: Data(), tail: Data(),
                    tailOffset: 0, isDirectory: false, isSymbolicLink: true,
                    posixPermissions: 0o755,
                    quarantine: nil, whereFrom: [], readError: nil, partialRead: false)))

        // Embedded signature and trailing data.
        let polyglot =
            jpegHead + Data(repeating: 0x20, count: 32)
            + Data([0x50, 0x4B, 0x03, 0x04]) + Data([0xFF, 0xD9])
        collect(
            UniversalChecks.embeddedSignatures(
                probe: probe(polyglot, name: "p.jpg"), identified: MagicBytes.jpeg))
        collect(
            image.jpeg(
                probe(
                    jpegHead + Data([0xFF, 0xD9]) + Data(repeating: 0x41, count: 500), name: "t.jpg"
                )))

        // Container ends.
        collect(image.jpeg(probe(jpegHead + Data(repeating: 0x11, count: 8), name: "n.jpg")))
        collect(
            image.png(
                probe(
                    Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), name: "n.png")))
        collect(image.gif(probe(Data("GIF89a".utf8) + Data([0x00]), name: "n.gif")))
        var badChunk = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        badChunk += Data([0x7F, 0xFF, 0xFF, 0xFF]) + Data("IDAT".utf8)
        badChunk += Data(repeating: 0, count: 16) + Data("IEND".utf8) + Data(repeating: 0, count: 4)
        collect(image.png(probe(badChunk, name: "bad.png")))
        collect(
            image.riff(
                probe(
                    Data("RIFF".utf8) + Data([0xFF, 0xFF, 0, 0]) + Data("WEBP".utf8),
                    name: "s.webp"), name: "WebP"))

        // SVG.
        collect(image.svg(probe(Data("<svg><script>x()</script></svg>".utf8), name: "a.svg")))
        collect(
            image.svg(
                probe(
                    Data("<!DOCTYPE s [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><svg/>".utf8),
                    name: "b.svg")))

        // Mach-O.
        var fat: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBF] + be32(1)
        fat += be32(0x0100_0007) + be32(0) + be64(4096) + be64(9_000_000) + be32(12) + be32(0)
        collect(
            ExecutableInspector().inspect(
                probe: probe(Data(fat), name: "f", size: 1000), format: MagicBytes.machOFat))

        // Documents.
        collect(document.pdf(probe(Data("%PDF-1.7\n/Launch (x)\n%%EOF".utf8), name: "a.pdf")))
        collect(document.pdf(probe(Data("%PDF-1.7\n/JavaScript\n%%EOF".utf8), name: "j.pdf")))
        collect(document.pdf(probe(Data("%PDF-1.7\nno end".utf8), name: "b.pdf")))
        collect(
            document.pdf(
                probe(
                    Data("%PDF-1.7\n%%EOF".utf8) + Data(repeating: 0x41, count: 400), name: "c.pdf")
            ))
        collect(
            document.zipContainer(
                probe(
                    zip(entries: [("word/document.xml", 1, 1), ("word/vbaProject.bin", 1, 1)]),
                    name: "a.docx")))

        // Archives.
        collect(
            ArchiveInspector.inspect(
                probe: probe(zip(entries: [("../../etc/x", 1, 1)]), name: "a.zip")))
        collect(
            ArchiveInspector.inspect(
                probe: probe(zip(entries: [("big", 1_000_000, 400_000_000)]), name: "b.zip")))
        collect(
            ArchiveInspector.inspect(
                probe: probe(
                    Data([0x50, 0x4B, 0x03, 0x04]) + Data(repeating: 0, count: 40),
                    name: "c.zip")))
        let prepended = Data(repeating: 0x41, count: 64) + zip(entries: [("a", 1, 1)])
        collect(ArchiveInspector.inspect(probe: probe(prepended, name: "d.zip")))

        // Media.
        var id3 = Data("ID3".utf8) + Data([0x04, 0x00, 0x00])
        id3 += Data([0x7F, 0x7F, 0x7F, 0x7F])  // an enormous synchsafe size
        collect(media.mp3(probe(id3 + Data(repeating: 0, count: 64), name: "a.mp3")))

        // Source.
        collect(
            SourceInspector.inspect(
                probe: probe(Data("if (x) {\u{202E}}\n".utf8), name: "a.swift")))
        collect(
            SourceInspector.inspect(
                probe: probe(Data([0xFF, 0xFE, 0x00, 0x80]), name: "b.py")))
        collect(
            SourceInspector.inspect(
                probe: probe(
                    Data(("x = \"" + String(repeating: "QUJD", count: 800) + "\"").utf8),
                    name: "c.py")))
        collect(
            SourceInspector.inspect(
                probe: probe(Data("exec(base64.b64decode(p))".utf8), name: "d.py")))
        collect(
            SourceInspector.inspect(
                probe: probe(Data(String(repeating: "a", count: 6000).utf8), name: "e.txt")))

        return emitted
    }
}
