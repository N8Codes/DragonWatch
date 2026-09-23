import XCTest

@testable import DragonWatch

/// Data past the end of a container is the highest-value signal this feature
/// has — and it fired on every photo taken with a Samsung phone, because
/// those append a 98-byte SEF trailer after the JPEG's end marker. A rule
/// that flags every photo someone owns is a rule they turn off.
///
/// These pin both halves: a recognised trailer is disclosed by name, and an
/// unrecognised one is still a finding.
final class TrailingDataTests: XCTestCase {

    private let jpegEnd = Data([0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9])

    /// Whole file in one window, which is how the classifier reads the tail.
    private func probe(_ data: Data) -> FileProbe {
        FileProbe(
            path: "/tmp/photo.jpg", displayName: "photo.jpg", size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    private func outcome(_ trailer: Data) -> InspectorOutput {
        let data = jpegEnd + trailer
        let extent = ContainerExtent(
            logicalEnd: Int64(jpegEnd.count), evidence: "JPEG image")
        return TrailingData.outcome(probe: probe(data), extent: extent)
    }

    // MARK: - Recognised trailers are disclosed, not flagged

    /// The exact shape found on real photos: an SEF block list ending "SEFT".
    func testSamsungTrailerIsDisclosedNotFlagged() {
        var trailer = Data([0x00, 0x00, 0x01, 0x0A, 0x0E, 0x00, 0x00, 0x00])
        trailer += Data("Image_UTC_Data1745547058262".utf8)
        trailer += Data([0x00, 0x00, 0xA1, 0x0A]) + Data("MCC_Data311SEFH".utf8)
        trailer += Data(repeating: 0x00, count: 20) + Data("SEFT".utf8)

        let result = outcome(trailer)
        XCTAssertTrue(result.findings.isEmpty, "a camera trailer must not read as a payload")
        XCTAssertEqual(result.disclosures.count, 1)
        let detail = result.disclosures[0].detail
        XCTAssertTrue(detail.contains("Samsung"))
        XCTAssertTrue(detail.contains("\(trailer.count) bytes"), "the size is still reported")
        XCTAssertTrue(
            detail.contains("not that it is harmless"),
            "recognising a trailer names it; it does not vouch for it")
    }

    func testSecondEmbeddedImageIsDisclosed() {
        let result = outcome(Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data(repeating: 0x11, count: 40))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertTrue(result.disclosures.first?.detail.contains("second embedded image") ?? false)
    }

    func testMotionPhotoVideoIsDisclosed() {
        let result = outcome(
            Data([0x00, 0x00, 0x00, 0x18]) + Data("ftypmp42".utf8)
                + Data(repeating: 0x00, count: 40))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertTrue(result.disclosures.first?.detail.contains("motion photo") ?? false)
    }

    func testPaddingIsDisclosed() {
        let result = outcome(Data(repeating: 0x00, count: 256))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertTrue(result.disclosures.first?.detail.contains("padding") ?? false)
    }

    // MARK: - Unrecognised trailers are still findings

    /// The check must not have been blinded by the fix.
    func testAppendedArchiveIsStillAFinding() {
        let result = outcome(
            Data([0x50, 0x4B, 0x03, 0x04]) + Data(repeating: 0x41, count: 500))
        XCTAssertEqual(result.findings.map(\.rule), ["container.trailingData"])
        XCTAssertEqual(result.findings[0].severity, .caution)
        XCTAssertTrue(result.findings[0].title.contains("Unexplained"))
    }

    func testArbitraryBytesAreStillAFinding() {
        let result = outcome(Data((0..<400).map { UInt8($0 % 251 &+ 1) }))
        XCTAssertEqual(result.findings.map(\.rule), ["container.trailingData"])
    }

    /// A trailer that merely ends in the right four bytes but is otherwise
    /// arbitrary is still recognised — the footer is the format's own marker.
    /// What must not happen is the reverse: arbitrary bytes being excused.
    func testRecognitionRequiresTheActualMarker() {
        let almost = Data("SEFX".utf8)
        let result = outcome(Data(repeating: 0x37, count: 100) + almost)
        XCTAssertFalse(result.findings.isEmpty, "a near-miss marker must not be excused")
    }

    func testSlackBytesAreIgnoredEntirely() {
        XCTAssertTrue(outcome(Data([0x00, 0x00])).findings.isEmpty)
        XCTAssertTrue(outcome(Data([0x00, 0x00])).disclosures.isEmpty)
    }

    // MARK: - Against a real photo, when one is offered

    /// The regression in its original form, against a real camera file.
    ///
    /// The path comes from the environment rather than being hardcoded: this
    /// repository is public, and a developer's own photo library is not
    /// something to publish in a test. Point it at any Samsung-camera JPEG:
    ///
    ///     DW_SAMPLE_SAMSUNG_JPEG=/path/to/photo.jpg swift test
    func testRealSamsungPhotoIsConsistentButStillDiscloses() async throws {
        // `XCTSkip`, not `XCTUnwrap`: an unset variable means "no sample
        // offered", which is the normal case on CI and on every machine but
        // the author's. Unwrapping would fail the suite everywhere instead.
        guard let path = ProcessInfo.processInfo.environment["DW_SAMPLE_SAMSUNG_JPEG"] else {
            throw XCTSkip("set DW_SAMPLE_SAMSUNG_JPEG to run this against a real Samsung photo")
        }
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "sample not found")

        let report = await InspectionEngine().inspect(paths: [path], hashFiles: false)
        let file = report.files[0]
        XCTAssertEqual(file.verdict, .consistent, "a phone photo must not be flagged")
        XCTAssertFalse(file.findings.contains { $0.rule == "container.trailingData" })
        XCTAssertTrue(
            file.disclosures.contains { $0.detail.contains("Samsung") },
            "the trailing bytes are still reported, just identified")
    }

    // MARK: - Trailers longer than the tail window

    /// A motion photo's video runs to megabytes. The classifier used to read
    /// only from the tail window, so anything longer than 64 KB was "unknown"
    /// and a recognised trailer became a finding.
    func testMotionPhotoLongerThanTheTailWindowIsStillRecognised() {
        let video = Data([0x00, 0x00, 0x00, 0x18]) + Data("ftypmp42".utf8)
        let head = jpegEnd + video + Data(repeating: 0x33, count: 1000)
        let size = Int64(jpegEnd.count) + 200_000
        let tail = Data(repeating: 0x33, count: 4096)
        let probe = FileProbe(
            path: "/tmp/motion.jpg", displayName: "motion.jpg", size: size,
            head: head, tail: tail, tailOffset: size - Int64(tail.count), isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644, quarantine: nil, whereFrom: [],
            readError: nil, partialRead: false)
        let extent = ContainerExtent(logicalEnd: Int64(jpegEnd.count), evidence: "JPEG image")

        XCTAssertEqual(
            TrailingData.classify(probe: probe, logicalEnd: extent.logicalEnd), .motionPhoto)
        let output = TrailingData.outcome(probe: probe, extent: extent)
        XCTAssertTrue(output.findings.isEmpty)
        XCTAssertEqual(output.disclosures.count, 1)
    }

    /// A trailer that begins in the unread gap between the windows was never
    /// seen, so nothing can vouch for it.
    func testTrailerBeginningInTheUnreadGapStaysAFinding() {
        let head = Data(repeating: 0x11, count: 64)
        let tail = Data(repeating: 0x00, count: 64)  // would read as padding if judged
        let probe = FileProbe(
            path: "/tmp/gap.jpg", displayName: "gap.jpg", size: 10_000,
            head: head, tail: tail, tailOffset: 10_000 - 64, isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644, quarantine: nil, whereFrom: [],
            readError: nil, partialRead: false)
        XCTAssertEqual(TrailingData.classify(probe: probe, logicalEnd: 5_000), .unknown)
        let output = TrailingData.outcome(
            probe: probe, extent: ContainerExtent(logicalEnd: 5_000, evidence: "JPEG image"))
        XCTAssertEqual(output.findings.map(\.rule), ["container.trailingData"])
    }
}
