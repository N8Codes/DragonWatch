import XCTest

@testable import DragonWatch

/// Adding files to a run that already has results: you check one file, then
/// another, and having to Clear first threw away the comparison.
final class MergeReportTests: XCTestCase {

    private func file(_ path: String, _ verdict: InspectionVerdict = .consistent)
        -> FileInspection
    {
        FileInspection(
            path: path, displayName: (path as NSString).lastPathComponent, byteSize: 1,
            sha256: nil, declaredExtension: "jpg", identifiedFormat: "JPEG",
            findings: verdict == .consistent
                ? []
                : [
                    Finding(
                        rule: "magic.mismatch", severity: .inconsistent, title: "t", detail: "d")
                ],
            disclosures: [], checksRun: ["Extension against actual contents"], verdict: verdict)
    }

    private func report(
        _ files: [FileInspection], roots: [String], seconds: Double = 1, folders: Int = 1
    ) -> InspectionReport {
        InspectionReport(
            generated: Date(), roots: roots, files: files, limitHit: nil,
            durationSeconds: seconds, folderCount: folders)
    }

    func testFilesFromBothRunsAppear() {
        let merged = AppModel.merge(
            report([file("/a.jpg")], roots: ["/a.jpg"]),
            report([file("/b.jpg")], roots: ["/b.jpg"]))
        XCTAssertEqual(Set(merged.files.map(\.path)), ["/a.jpg", "/b.jpg"])
        XCTAssertEqual(merged.roots, ["/a.jpg", "/b.jpg"])
    }

    /// A second look at the same file is an update, not a duplicate row.
    func testReinspectingAPathReplacesItRatherThanDuplicating() {
        let merged = AppModel.merge(
            report([file("/a.jpg", .consistent)], roots: ["/a.jpg"]),
            report([file("/a.jpg", .inconsistent)], roots: ["/a.jpg"]))
        XCTAssertEqual(merged.files.count, 1)
        XCTAssertEqual(merged.files[0].verdict, .inconsistent, "the newer result wins")
        XCTAssertEqual(merged.roots, ["/a.jpg"], "a repeated root is not listed twice")
    }

    func testScopeFiguresAccumulate() {
        let merged = AppModel.merge(
            report([file("/a.jpg")], roots: ["/x"], seconds: 2, folders: 3),
            report([file("/b.jpg")], roots: ["/y"], seconds: 5, folders: 4))
        XCTAssertEqual(merged.durationSeconds, 7)
        XCTAssertEqual(merged.folderCount, 7)
    }

    /// The worst verdict across everything on screen is what the headline
    /// must show, whichever run produced it.
    func testWorstVerdictSurvivesFromEitherRun() {
        let merged = AppModel.merge(
            report([file("/bad.jpg", .inconsistent)], roots: ["/bad.jpg"]),
            report([file("/good.jpg", .consistent)], roots: ["/good.jpg"]))
        XCTAssertEqual(merged.worstVerdict, .inconsistent)
        XCTAssertEqual(merged.sortedFiles.first?.displayName, "bad.jpg", "worst first")
    }

    func testALimitFromEitherRunIsCarried() {
        let capped = InspectionReport(
            generated: Date(), roots: ["/x"], files: [], limitHit: .fileCountCap,
            durationSeconds: 1, folderCount: 1)
        let clean = report([file("/b.jpg")], roots: ["/y"])
        XCTAssertEqual(AppModel.merge(capped, clean).limitHit, .fileCountCap)
        XCTAssertEqual(AppModel.merge(clean, capped).limitHit, .fileCountCap)
    }
}
