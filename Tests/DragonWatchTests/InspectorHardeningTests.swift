import XCTest

@testable import DragonWatch

/// Wrong answers and one hang found by reviewing the inspector against
/// hostile and merely unusual input.
final class InspectorHardeningTests: XCTestCase {

    private func probe(_ data: Data, name: String, size: Int64? = nil) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: size ?? Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    private func le16(_ value: Int) -> [UInt8] { [UInt8(value & 0xFF), UInt8(value >> 8 & 0xFF)] }
    private func le32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(value >> (8 * $0) & 0xFF) }
    }

    /// Opening a FIFO blocks until a writer appears, and nothing cancels a
    /// thread parked in `open`. The test hangs if the probe ever opens one.
    func testNamedPipeIsReportedNotOpened() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("Pipe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pipe = directory.appendingPathComponent("queue")
        XCTAssertEqual(mkfifo(pipe.path, 0o600), 0)

        let probe = FileProbe.read(path: pipe.path)
        XCTAssertNotNil(probe.readError)
        XCTAssertFalse(probe.isReadable)
    }

    func testExecutableUnderATextExtensionIsAMismatch() {
        let machO = Data([0xCF, 0xFA, 0xED, 0xFE] + [UInt8](repeating: 0, count: 60))
        let format = MagicBytes.identify(head: machO)
        XCTAssertEqual(format, MagicBytes.machO)
        for name in ["readme.txt", "page.html", "notes.md"] {
            let findings = UniversalChecks.typeConsistency(
                probe: probe(machO, name: name), identified: format)
            XCTAssertEqual(findings.map(\.rule), ["magic.mismatch"], name)
            XCTAssertEqual(findings.first?.severity, .inconsistent, name)
        }
        // Extensionless and unknown extensions stay quiet, as before.
        XCTAssertTrue(
            UniversalChecks.typeConsistency(probe: probe(machO, name: "tool"), identified: format)
                .isEmpty)
    }

    /// PE is identified by the letters "MZ" alone, which a text file can
    /// start with.
    func testTextStartingWithMZIsNotCalledAWindowsExecutable() {
        let text = Data("MZ is the abbreviation used throughout.\n".utf8)
        XCTAssertTrue(
            UniversalChecks.typeConsistency(
                probe: probe(text, name: "notes.txt"), identified: MagicBytes.identify(head: text)
            ).isEmpty)
    }

    private func zip(name: [UInt8], count: Int? = nil, offset: UInt32? = nil) -> Data {
        var bytes: [UInt8] = [0x50, 0x4B, 0x03, 0x04] + [UInt8](repeating: 0, count: 26)
        let centralOffset = bytes.count
        var central: [UInt8] = [0x50, 0x4B, 0x01, 0x02] + [UInt8](repeating: 0, count: 16)
        central += le32(1) + le32(1) + le16(name.count) + le16(0) + le16(0)
        central += [UInt8](repeating: 0, count: 12) + name
        bytes += central
        bytes += [0x50, 0x4B, 0x05, 0x06] + le16(0) + le16(0)
        bytes += le16(count ?? 1) + le16(count ?? 1)
        bytes += le32(UInt32(central.count)) + le32(offset ?? UInt32(centralOffset)) + le16(0)
        return Data(bytes)
    }

    /// A strict decode turned the name into "", which contains no `../`.
    func testTraversalSurvivesAnInvalidByteInTheEntryName() {
        let name = Array("../../evil".utf8) + [0xFF] + Array(".sh".utf8)
        let output = ArchiveInspector.inspect(probe: probe(zip(name: name), name: "a.zip"))
        XCTAssertTrue(output.findings.map(\.rule).contains("zip.pathTraversal"))
    }

    func testZip64PlaceholdersAreNotReportedAsATruncatedIndex() {
        let data = zip(name: Array("a.txt".utf8), count: 0xFFFF, offset: .max)
        let output = ArchiveInspector.inspect(probe: probe(data, name: "big.zip"))
        XCTAssertTrue(output.findings.isEmpty, "\(output.findings.map(\.rule))")
        XCTAssertEqual(output.disclosures.map(\.title), ["Index not examined"])
    }

    /// The 64 KiB window can end inside a multi-byte character.
    func testValidUTF8CutAtTheWindowEdgeIsStillText() {
        var head = Data(String(repeating: "あ", count: 100).utf8)
        head.removeLast()  // mid-character, as a window boundary leaves it
        let cut = probe(head, name: "notes.md", size: 1 << 20)
        XCTAssertFalse(
            SourceInspector.inspect(probe: cut).findings.map(\.rule).contains("source.notText"))
        // A whole file that ends mid-character really is malformed.
        XCTAssertTrue(
            SourceInspector.inspect(probe: probe(head, name: "notes.md")).findings.map(\.rule)
                .contains("source.notText"))
    }

    func testAnyFtypBrandIsRecognisedAsISOMedia() {
        for brand in ["mp41", "iso5", "M4V ", "3gp4"] {
            let head = Data(
                [0, 0, 0, 0x18] + Array("ftyp".utf8) + Array(brand.utf8) + [0, 0, 0, 0])
            let format = MagicBytes.identify(head: head)
            XCTAssertEqual(format, MagicBytes.isoMedia, brand)
            XCTAssertTrue(
                UniversalChecks.typeConsistency(
                    probe: probe(head, name: "clip.mp4"), identified: format
                ).isEmpty, brand)
        }
        // A brand the table names still wins.
        let heic = Data([0, 0, 0, 0x18] + Array("ftypheic".utf8))
        XCTAssertEqual(MagicBytes.identify(head: heic), MagicBytes.heic)
    }

    func testSVGRootBehindALongCommentIsStillAnSVG() {
        let text =
            "<?xml version=\"1.0\"?><!-- " + String(repeating: "x", count: 6000)
            + " --><svg><script>alert(1)</script></svg>"
        XCTAssertEqual(MagicBytes.identify(head: Data(text.utf8)), MagicBytes.svg)
    }

    /// Not control characters, but text layout breaks the line on them.
    func testLineSafeRemovesUnicodeLineSeparators() {
        XCTAssertEqual(UniversalChecks.lineSafe("Finder\u{2028}evil\u{2029}x\ny"), "Finderevilxy")
    }
}
