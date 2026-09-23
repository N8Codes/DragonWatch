import XCTest

@testable import DragonWatch

/// "0 findings" has to mean "looked and found nothing", not "barely looked".
/// These pin that every inspected file says what was examined.
final class ExaminedChecksTests: XCTestCase {

    private func tempDir(_ label: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testACleanFileStillReportsWhatWasExamined() async throws {
        let dir = try tempDir("Clean")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("photo.jpg")
        try
            (Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + Data(repeating: 0x11, count: 14)
            + Data([0xFF, 0xD9])).write(to: file)

        let inspection = await InspectionEngine().inspect(paths: [file.path]).files[0]
        XCTAssertEqual(inspection.verdict, .consistent)
        XCTAssertTrue(inspection.findings.isEmpty)

        let checks = try XCTUnwrap(inspection.checksRun)
        XCTAssertTrue(checks.contains("Extension against actual contents"))
        XCTAssertTrue(checks.contains("Filename characters"))
        XCTAssertTrue(checks.contains("File type and permissions"))
        XCTAssertTrue(checks.contains { $0.contains("JPEG structure") })
        XCTAssertTrue(checks.contains { $0.contains("SHA-256") })
    }

    /// The wording has to distinguish a complete scan from a sampled one,
    /// because the difference is what the result is worth.
    func testCoverageWordingReflectsWhetherTheWholeFileWasSeen() async throws {
        let dir = try tempDir("Coverage")
        defer { try? FileManager.default.removeItem(at: dir) }

        let small = dir.appendingPathComponent("small.jpg")
        try (Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data([0xFF, 0xD9])).write(to: small)
        let large = dir.appendingPathComponent("large.jpg")
        try
            (Data([0xFF, 0xD8, 0xFF, 0xE0])
            + Data(repeating: 0x5A, count: FileProbe.windowSize * 3)
            + Data([0xFF, 0xD9])).write(to: large)

        let report = await InspectionEngine().inspect(paths: [small.path, large.path])
        let byName = Dictionary(uniqueKeysWithValues: report.files.map { ($0.displayName, $0) })

        XCTAssertTrue(
            (byName["small.jpg"]?.checksRun ?? []).contains { $0.contains("whole file") })
        XCTAssertTrue(
            (byName["large.jpg"]?.checksRun ?? []).contains { $0.contains("64 KB") })
    }

    /// Saying "none present" is different from not having looked.
    func testProvenanceIsReportedAsExaminedEvenWhenAbsent() async throws {
        let dir = try tempDir("Prov")
        defer { try? FileManager.default.removeItem(at: dir) }
        let plain = dir.appendingPathComponent("plain.jpg")
        try
            (Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + Data(repeating: 0x11, count: 14)
            + Data([0xFF, 0xD9])).write(to: plain)

        let report = await InspectionEngine().inspect(paths: [plain.path])
        let checks = try XCTUnwrap(report.files[0].checksRun)
        XCTAssertTrue(checks.contains("Content Credentials (none present)"))
    }

    func testUnreadableFileDoesNotClaimContentChecks() async throws {
        let report = await InspectionEngine().inspect(paths: ["/nonexistent/thing.jpg"])
        let checks = report.files[0].checksRun ?? []
        XCTAssertFalse(
            checks.contains("Extension against actual contents"),
            "nothing was read, so nothing about contents was examined")
        XCTAssertTrue(checks.contains("Filename characters"), "the name was still readable")
    }

    // MARK: - Run scope

    func testRunRecordsItsDurationAndFolderCount() async throws {
        let dir = try tempDir("Scope")
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data([0xFF, 0xD8, 0xFF, 0xD9]).write(to: dir.appendingPathComponent("a.jpg"))
        try FileManager.default.createDirectory(
            at: dir.appendingPathComponent("sub"), withIntermediateDirectories: true)
        try Data([0xFF, 0xD8, 0xFF, 0xD9]).write(to: dir.appendingPathComponent("sub/b.jpg"))

        let walk = FolderWalker.walk(roots: [dir], limits: .default)
        let report = await InspectionEngine().inspect(
            paths: walk.files, roots: [dir.path], folderCount: walk.folderCount)

        XCTAssertEqual(report.folderCount, 2)
        XCTAssertNotNil(report.durationSeconds)
        XCTAssertGreaterThanOrEqual(report.durationSeconds ?? -1, 0)
    }

    // MARK: - Reports

    func testExportedReportsCarryWhatWasExamined() {
        let inspection = FileInspection(
            path: "/tmp/a.jpg", displayName: "a.jpg", byteSize: 10, sha256: nil,
            declaredExtension: "jpg", identifiedFormat: "JPEG", findings: [],
            disclosures: [], checksRun: ["Extension against actual contents", "JPEG structure"],
            verdict: .consistent)
        let report = InspectionReport(
            generated: Date(timeIntervalSince1970: 1_700_000_000), roots: ["/tmp"],
            files: [inspection], limitHit: nil, durationSeconds: 2.5, folderCount: 3)

        let markdown = ReportRenderer.markdown(report)
        XCTAssertTrue(markdown.contains("**Examined**"))
        XCTAssertTrue(markdown.contains("JPEG structure"))
        XCTAssertTrue(markdown.contains("Folders searched:** 3"))
        XCTAssertTrue(markdown.contains("Took:** 2.5s"))

        let text = ReportRenderer.plainText(report)
        XCTAssertTrue(text.contains("examined: JPEG structure"))
        XCTAssertTrue(text.contains("Folders:     3 searched"))
    }

    /// A report exported before these fields existed must still decode.
    func testOlderReportJSONWithoutTheNewFieldsStillDecodes() throws {
        let legacy = """
            {
              "generated": "2026-01-01T00:00:00Z",
              "roots": ["/tmp"],
              "files": [
                {"path": "/tmp/a.jpg", "displayName": "a.jpg", "byteSize": 10,
                 "declaredExtension": "jpg", "findings": [], "disclosures": [],
                 "verdict": 0}
              ]
            }
            """
        let report = try ReportRenderer.jsonDecoder.decode(
            InspectionReport.self, from: Data(legacy.utf8))
        XCTAssertEqual(report.files.count, 1)
        XCTAssertNil(report.files[0].checksRun)
        XCTAssertNil(report.durationSeconds)
        XCTAssertNil(report.folderCount)
    }
}
