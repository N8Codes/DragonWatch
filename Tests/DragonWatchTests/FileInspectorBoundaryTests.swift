import XCTest

@testable import DragonWatch

/// Boundaries, limits, error paths and serialisation — the cases the first
/// round of tests asserted nothing about.
final class FileInspectorBoundaryTests: XCTestCase {

    private let jpegHeader = Data([0xFF, 0xD8, 0xFF, 0xE0])
    private let zipMagic: [UInt8] = [0x50, 0x4B, 0x03, 0x04]

    private func tempDir(_ label: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func rules(_ findings: [Finding]) -> [String] { findings.map(\.rule) }

    // MARK: - A file that reports bytes but yields none

    /// `FileHasher` already carries this lesson: "A read error partway through
    /// must not finalize the digest... a well-formed, wrong answer."
    ///
    /// The same trap exists here. `lstat` says the file has 5,000 bytes, the
    /// read returns nothing, and the pipeline concluded "Format not recognised"
    /// at `.info` severity — verdict **Consistent**. A file that could not be
    /// read must never render as one that was read and found fine.
    func testFileThatReportsBytesButYieldsNoneIsUnreadable() {
        let blind = FileProbe(
            path: "/tmp/truncated.jpg", displayName: "truncated.jpg", size: 5000,
            head: Data(), tail: Data(), tailOffset: 0, isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: false)

        XCTAssertFalse(
            blind.isReadable,
            "a non-empty file that produced no bytes was not read")
        XCTAssertEqual(
            FileInspection.verdict(readable: blind.isReadable, findings: []), .unreadable)
    }

    /// The honest case: a genuinely empty file really was read.
    func testGenuinelyEmptyFileIsStillReadable() {
        let empty = FileProbe(
            path: "/tmp/empty.jpg", displayName: "empty.jpg", size: 0,
            head: Data(), tail: Data(), tailOffset: 0, isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: false)

        XCTAssertTrue(empty.isReadable)
        XCTAssertTrue(rules(UniversalChecks.fileTraits(probe: empty)).contains("file.empty"))
    }

    func testUnreadablePermissionsAreReportedNotSwallowed() async throws {
        let dir = try tempDir("Perm")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("locked.jpg")
        try (jpegHeader + Data(repeating: 0x11, count: 64)).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: file.path)

        let report = await InspectionEngine().inspect(paths: [file.path])
        // Running as root would read it anyway and the case is untestable.
        try XCTSkipIf(report.files[0].verdict != .unreadable, "running with override privileges")
        XCTAssertTrue(rules(report.files[0].findings).contains("file.unreadable"))
        XCTAssertNil(report.files[0].sha256)
    }

    /// A tail that could not be read means the end-of-file checks did not run,
    /// which must be said rather than silently producing a clean result.
    func testPartialReadIsSurfaced() {
        let partial = FileProbe(
            path: "/tmp/partial.jpg", displayName: "partial.jpg", size: 500_000,
            head: jpegHeader, tail: Data(), tailOffset: 436_000, isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: true)

        let findings = UniversalChecks.fileTraits(probe: partial)
        XCTAssertTrue(rules(findings).contains("file.partialRead"))
        XCTAssertEqual(findings.first { $0.rule == "file.partialRead" }?.severity, .caution)
    }

    // MARK: - Window arithmetic

    /// The head and tail windows are 64 KiB each. Every offset the report
    /// prints is computed from `tailOffset`, so an off-by-one here mislabels
    /// the byte position of every finding in the back half of a large file.
    func testSignatureAtTheVeryEndIsFoundAtTheRightOffsetAcrossWindowBoundaries() throws {
        let dir = try tempDir("Window")
        defer { try? FileManager.default.removeItem(at: dir) }

        // Exactly the window, one past it, exactly both windows, one past both.
        for size in [
            FileProbe.windowSize,
            FileProbe.windowSize + 1,
            FileProbe.windowSize * 2,
            FileProbe.windowSize * 2 + 1,
        ] {
            let file = dir.appendingPathComponent("w\(size).jpg")
            var blob = jpegHeader + Data(repeating: 0x5A, count: size - 4 - zipMagic.count)
            blob.append(contentsOf: zipMagic)
            XCTAssertEqual(blob.count, size, "fixture must be exactly \(size) bytes")
            try blob.write(to: file)

            let probe = FileProbe.read(path: file.path)
            XCTAssertEqual(probe.size, Int64(size))
            XCTAssertEqual(
                probe.offsets(of: zipMagic), [Int64(size - zipMagic.count)],
                "a signature at the very end of a \(size)-byte file must be found once, "
                    + "at its true offset")
        }
    }

    func testIsFullyWindowedBoundary() throws {
        let dir = try tempDir("FullWindow")
        defer { try? FileManager.default.removeItem(at: dir) }

        for (size, expected) in [
            (FileProbe.windowSize * 2, true), (FileProbe.windowSize * 2 + 1, false),
        ] {
            let file = dir.appendingPathComponent("f\(size).bin")
            try Data(repeating: 0x00, count: size).write(to: file)
            XCTAssertEqual(FileProbe.read(path: file.path).isFullyWindowed, expected)
        }
    }

    /// Between 64 KiB and 128 KiB the two windows overlap. A signature in the
    /// overlap must be reported once, not twice.
    func testOverlappingWindowsDoNotDoubleReport() throws {
        let dir = try tempDir("Overlap")
        defer { try? FileManager.default.removeItem(at: dir) }

        let size = FileProbe.windowSize + 1024
        var blob = Data(repeating: 0x5A, count: size)
        let position = FileProbe.windowSize - 512  // inside both windows
        blob.replaceSubrange(position..<(position + zipMagic.count), with: zipMagic)

        let file = dir.appendingPathComponent("overlap.bin")
        try blob.write(to: file)

        XCTAssertEqual(FileProbe.read(path: file.path).offsets(of: zipMagic), [Int64(position)])
    }

    /// A payload buried in the middle of a large file is outside both windows.
    /// The scan must miss it *and* say that it only sampled.
    func testMiddleOfLargeFileIsOutsideBothWindowsAndSaysSo() throws {
        let dir = try tempDir("Middle")
        defer { try? FileManager.default.removeItem(at: dir) }

        let size = FileProbe.windowSize * 4
        var blob = jpegHeader + Data(repeating: 0x5A, count: size - 4)
        blob.replaceSubrange((size / 2)..<(size / 2 + zipMagic.count), with: zipMagic)

        let file = dir.appendingPathComponent("middle.jpg")
        try blob.write(to: file)
        let probe = FileProbe.read(path: file.path)

        XCTAssertTrue(probe.offsets(of: zipMagic).isEmpty)
        XCTAssertFalse(probe.isFullyWindowed)

        // With nothing found there is no finding to carry the caveat, so the
        // honesty has to come from `isFullyWindowed` being false. Pin that a
        // caller can tell a complete scan from a sampled one.
        let small = dir.appendingPathComponent("small.jpg")
        try (jpegHeader + Data(repeating: 0x5A, count: 128)).write(to: small)
        XCTAssertTrue(FileProbe.read(path: small.path).isFullyWindowed)
    }

    // MARK: - Engine limits

    func testHashCeilingSkipsLargeFilesAtTheBoundary() async throws {
        let dir = try tempDir("HashCap")
        defer { try? FileManager.default.removeItem(at: dir) }

        let atLimit = dir.appendingPathComponent("at.bin")
        try Data(repeating: 0x41, count: 100).write(to: atLimit)
        let overLimit = dir.appendingPathComponent("over.bin")
        try Data(repeating: 0x41, count: 101).write(to: overLimit)

        var limits = InspectionEngine.Limits.default
        limits.maxHashBytes = 100
        let report = await InspectionEngine(limits: limits)
            .inspect(paths: [atLimit.path, overLimit.path])

        let byName = Dictionary(uniqueKeysWithValues: report.files.map { ($0.displayName, $0) })
        XCTAssertNotNil(byName["at.bin"]?.sha256, "a file exactly at the ceiling is hashed")
        XCTAssertNil(byName["over.bin"]?.sha256, "one byte over the ceiling is not")
    }

    func testHashingCanBeDisabledEntirely() async throws {
        let dir = try tempDir("NoHash")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("a.jpg")
        try jpegHeader.write(to: file)

        let report = await InspectionEngine().inspect(paths: [file.path], hashFiles: false)
        XCTAssertNil(report.files[0].sha256)
    }

    /// Cancellation must stop the run and say why. Spinning until the flag is
    /// observed makes this deterministic rather than a race with the scheduler.
    func testCancellationStopsTheRunAndIsReported() async throws {
        let dir = try tempDir("Cancel")
        defer { try? FileManager.default.removeItem(at: dir) }

        var paths: [String] = []
        for index in 0..<20 {
            let file = dir.appendingPathComponent("c\(index).jpg")
            try jpegHeader.write(to: file)
            paths.append(file.path)
        }

        let engine = InspectionEngine()
        let task = Task { () -> InspectionReport in
            while !Task.isCancelled { await Task.yield() }
            return await engine.inspect(paths: paths)
        }
        task.cancel()
        let report = await task.value

        XCTAssertEqual(report.limitHit, .cancelled)
        XCTAssertTrue(report.files.isEmpty)
        XCTAssertEqual(report.roots, paths, "roots record what was asked for, not what was done")
    }

    func testEmptySelectionProducesAnEmptyReportNotACrash() async {
        let report = await InspectionEngine().inspect(paths: [])
        XCTAssertTrue(report.files.isEmpty)
        XCTAssertNil(report.limitHit)
        XCTAssertEqual(report.worstVerdict, .consistent)
        XCTAssertEqual(report.findingCount, 0)
    }

    /// More files than one concurrency batch: every one must come back exactly
    /// once. Results are collected from a task group, where a dropped or
    /// duplicated element would otherwise go unnoticed.
    func testEveryFileIsReportedExactlyOnceAcrossConcurrentBatches() async throws {
        let dir = try tempDir("Batch")
        defer { try? FileManager.default.removeItem(at: dir) }

        var paths: [String] = []
        for index in 0..<37 {  // not a multiple of the batch size
            let file = dir.appendingPathComponent("b\(index).jpg")
            try (jpegHeader + Data(repeating: UInt8(index % 251), count: 32)).write(to: file)
            paths.append(file.path)
        }

        let report = await InspectionEngine().inspect(paths: paths)
        XCTAssertEqual(report.files.count, 37)
        XCTAssertEqual(Set(report.files.map(\.path)), Set(paths))
    }

    // MARK: - Serialisation

    /// The JSON report format encodes these types. A round trip pins that the
    /// synthesised conformances survive — and adding a non-optional field later
    /// breaks decoding of anything already written, which this catches.
    func testReportSurvivesAJSONRoundTrip() throws {
        let original = InspectionReport(
            generated: Date(timeIntervalSince1970: 1_700_000_000),
            roots: ["/tmp/a", "/tmp/b"],
            files: [
                FileInspection(
                    path: "/tmp/a", displayName: "a.jpg", byteSize: 12, sha256: "abc",
                    declaredExtension: "jpg", identifiedFormat: "JPEG",
                    findings: [
                        Finding(
                            rule: "magic.mismatch", severity: .inconsistent, title: "t",
                            detail: "d")
                    ],
                    disclosures: [Disclosure(title: "Came from", detail: "https://x")],
                    verdict: .inconsistent)
            ],
            limitHit: .fileCountCap)

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(InspectionReport.self, from: encoded)

        XCTAssertEqual(decoded.roots, original.roots)
        XCTAssertEqual(decoded.limitHit, .fileCountCap)
        XCTAssertEqual(decoded.files.count, 1)
        XCTAssertEqual(decoded.files[0].verdict, .inconsistent)
        XCTAssertEqual(decoded.files[0].findings[0].rule, "magic.mismatch")
        XCTAssertEqual(decoded.files[0].findings[0].severity, .inconsistent)
        XCTAssertEqual(decoded.files[0].disclosures[0].detail, "https://x")
        XCTAssertEqual(decoded.worstVerdict, .inconsistent)
    }

    // MARK: - Extended attributes

    func testWhereFromPlistIsParsed() throws {
        let dir = try tempDir("WhereFrom")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("dl.jpg")
        try jpegHeader.write(to: file)

        let origins = ["https://example.com/dl.jpg", "https://example.com/page"]
        let plist = try PropertyListSerialization.data(
            fromPropertyList: origins, format: .binary, options: 0)
        let set = plist.withUnsafeBytes {
            setxattr(
                file.path, "com.apple.metadata:kMDItemWhereFroms", $0.baseAddress, plist.count,
                0, 0)
        }
        try XCTSkipIf(set != 0, "filesystem refused the xattr")

        XCTAssertEqual(FileProbe.read(path: file.path).whereFrom, origins)
    }

    /// Malformed attribute data must produce no origins rather than throwing.
    func testMalformedWhereFromIsIgnored() throws {
        let dir = try tempDir("BadWhereFrom")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("bad.jpg")
        try jpegHeader.write(to: file)

        let junk = [UInt8](repeating: 0xFF, count: 64)
        let set = junk.withUnsafeBufferPointer {
            setxattr(
                file.path, "com.apple.metadata:kMDItemWhereFroms", $0.baseAddress, junk.count,
                0, 0)
        }
        try XCTSkipIf(set != 0, "filesystem refused the xattr")

        XCTAssertTrue(FileProbe.read(path: file.path).whereFrom.isEmpty)
    }

    /// Long origin lists are truncated for display; the report must say so
    /// rather than quietly dropping entries.
    func testTruncatedOriginListSaysItWasTruncated() {
        let many = (0..<9).map { "https://example.com/\($0)" }
        let probe = FileProbe(
            path: "/tmp/m.jpg", displayName: "m.jpg", size: 4, head: Data(), tail: Data(),
            tailOffset: 0, isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: many, readError: nil, partialRead: false)

        let disclosures = UniversalChecks.disclosures(probe: probe)
        let shown = disclosures.filter { $0.title == "Came from" }.count
        XCTAssertLessThan(shown, many.count)
        XCTAssertTrue(
            disclosures.contains { $0.detail.contains("\(many.count - shown) more") },
            "dropped origins must be accounted for")
    }

    // MARK: - User-facing strings

    func testEveryVerdictAndLimitHasDistinctProse() {
        let summaries = InspectionVerdict.allCases.map(\.summary)
        XCTAssertEqual(Set(summaries).count, summaries.count)
        XCTAssertFalse(
            summaries.contains { $0.localizedCaseInsensitiveContains("safe") },
            "the verdict vocabulary must never claim a file is safe")

        let limits: [InspectionLimit] = [
            .cancelled, .fileCountCap, .byteCap, .timeCap,
        ]
        let explanations = limits.map(\.explanation)
        XCTAssertEqual(Set(explanations).count, explanations.count)
    }

    // MARK: - Attacker-controlled strings in report prose

    /// Filenames, extensions, symlink targets and download URLs all reach a
    /// `detail` string. Raw, a name can forge report lines with newlines,
    /// reverse the surrounding sentence with a direction override, or bury
    /// every other finding under thousands of characters.
    func testDisplaySafeStripsAndBounds() {
        XCTAssertEqual(UniversalChecks.displaySafe("plain.jpg"), "plain.jpg")

        // Newlines and control characters cannot forge structure.
        XCTAssertEqual(
            UniversalChecks.displaySafe("a\nb\rc\td\u{0}e"), "abcde")

        // Direction overrides and zero-width characters are removed.
        XCTAssertEqual(UniversalChecks.displaySafe("a\u{202E}b\u{200B}c"), "abc")

        // Overlong input is truncated and says how long it really was.
        let long = String(repeating: "x", count: 5000)
        let bounded = UniversalChecks.displaySafe(long, limit: 20)
        XCTAssertLessThan(bounded.count, 60)
        XCTAssertTrue(bounded.contains("5000 characters"))

        XCTAssertEqual(UniversalChecks.displaySafe(""), "(empty)")
        XCTAssertEqual(UniversalChecks.displaySafe("\u{202E}\u{200B}"), "(empty)")
    }

    /// End to end: a hostile extension must not escape into the finding text.
    func testHostileExtensionIsNeutralisedInFindingProse() {
        let name = "photo.j\npg\u{202E}" + String(repeating: "A", count: 400)
        let subject = FileProbe(
            path: "/tmp/\(name)", displayName: name, size: 4,
            head: Data([0xFF, 0xD8, 0xFF, 0xE0]), tail: Data([0xFF, 0xD8, 0xFF, 0xE0]),
            tailOffset: 0, isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: false)

        for finding in UniversalChecks.run(probe: subject, identified: MagicBytes.jpeg) {
            XCTAssertFalse(finding.detail.contains("\n"), "no forged report lines")
            XCTAssertFalse(finding.detail.contains("\u{202E}"), "no direction overrides")
            XCTAssertLessThan(finding.detail.count, 600, "no burying other findings")
        }
    }

    func testHostileDownloadOriginIsNeutralised() {
        let subject = FileProbe(
            path: "/tmp/d.jpg", displayName: "d.jpg", size: 4, head: Data(), tail: Data(),
            tailOffset: 0, isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: "0281;6aaf0929;Ch\nrome\u{202E};ABC",
            whereFrom: ["https://x.example/\nInjected: line"], readError: nil,
            partialRead: false)

        for disclosure in UniversalChecks.disclosures(probe: subject) {
            XCTAssertFalse(disclosure.detail.contains("\n"))
            XCTAssertFalse(disclosure.detail.contains("\u{202E}"))
        }
    }

    func testDisclaimerNamesWhatItIsNot() {
        XCTAssertTrue(InspectionReport.disclaimer.contains("Not a malware scan"))
        XCTAssertTrue(InspectionReport.disclaimer.contains("XProtect"))
    }
}
