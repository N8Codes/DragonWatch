import XCTest

@testable import DragonWatch

final class FileInspectorTests: XCTestCase {

    // MARK: - Helpers

    /// Builds a probe from bytes, so the rules can be tested without putting
    /// hostile files on the machine running the tests.
    private func probe(
        name: String,
        bytes: Data,
        permissions: Int = 0o644,
        quarantine: String? = nil,
        whereFrom: [String] = [],
        symlink: Bool = false,
        readError: String? = nil
    ) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: Int64(bytes.count),
            head: bytes, tail: bytes, tailOffset: 0, isDirectory: false,
            isSymbolicLink: symlink, posixPermissions: permissions,
            quarantine: quarantine, whereFrom: whereFrom, readError: readError,
            partialRead: false)
    }

    private let jpegHeader = Data([0xFF, 0xD8, 0xFF, 0xE0])
    private let pngHeader = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    private let machOHeader = Data([0xCF, 0xFA, 0xED, 0xFE])

    private func rules(_ findings: [Finding]) -> [String] { findings.map(\.rule) }

    // MARK: - Extension versus contents

    func testMatchingExtensionAndContentsProducesNoFinding() {
        let subject = probe(name: "photo.jpg", bytes: jpegHeader)
        let findings = UniversalChecks.typeConsistency(probe: subject, identified: MagicBytes.jpeg)
        XCTAssertTrue(findings.isEmpty)
    }

    /// The headline case: a Mach-O wearing a .png extension.
    func testExecutableRenamedAsImageIsInconsistent() {
        let subject = probe(name: "kitten.png", bytes: machOHeader)
        let findings = UniversalChecks.typeConsistency(
            probe: subject, identified: MagicBytes.machO)
        XCTAssertEqual(rules(findings), ["magic.mismatch"])
        XCTAssertEqual(findings.first?.severity, .inconsistent)
        XCTAssertTrue(findings[0].detail.contains("Mach-O"))
    }

    func testKnownExtensionWithUnrecognisedBytesIsCaution() {
        let subject = probe(name: "photo.jpg", bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let findings = UniversalChecks.typeConsistency(probe: subject, identified: nil)
        XCTAssertEqual(rules(findings), ["magic.unconfirmed"])
        XCTAssertEqual(findings.first?.severity, .caution)
    }

    func testUnknownExtensionAndUnknownBytesIsMerelyInformational() {
        let subject = probe(name: "blob.zzz", bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let findings = UniversalChecks.typeConsistency(probe: subject, identified: nil)
        XCTAssertEqual(rules(findings), ["magic.unclassified"])
        XCTAssertEqual(findings.first?.severity, .info)
    }

    /// A `.docx` is a ZIP. Treating the container as a mismatch would flag
    /// every Office document on the machine.
    func testContainerFormatsAreNotAMismatch() {
        let subject = probe(name: "report.docx", bytes: Data([0x50, 0x4B, 0x03, 0x04]))
        let findings = UniversalChecks.typeConsistency(probe: subject, identified: MagicBytes.zip)
        XCTAssertTrue(findings.isEmpty)
    }

    func testExtensionlessBinaryIsNotFlagged() {
        let subject = probe(name: "somebinary", bytes: machOHeader)
        let findings = UniversalChecks.typeConsistency(
            probe: subject, identified: MagicBytes.machO)
        XCTAssertTrue(findings.isEmpty)
    }

    // MARK: - Deceptive filenames

    func testRightToLeftOverrideInNameIsInconsistent() {
        // "report\u{202E}fdp.exe" renders as "reportexe.pdf" in Finder.
        let findings = UniversalChecks.filename("report\u{202E}fdp.exe")
        XCTAssertTrue(rules(findings).contains("name.bidi"))
        let bidi = findings.first { $0.rule == "name.bidi" }
        XCTAssertEqual(bidi?.severity, .inconsistent)
        XCTAssertTrue(bidi!.detail.contains("U+202E"))
    }

    func testZeroWidthCharactersInNameAreCaution() {
        let findings = UniversalChecks.filename("invo\u{200B}ice.pdf")
        XCTAssertTrue(rules(findings).contains("name.invisible"))
    }

    func testOrdinaryNameProducesNothing() {
        XCTAssertTrue(UniversalChecks.filename("Quarterly Report 2026.pdf").isEmpty)
    }

    /// The double-extension rule needs both halves to mean something, or it
    /// flags every shell script and every tarball.
    func testDoubleExtensionRuleDiscriminates() {
        XCTAssertNotNil(UniversalChecks.doubleExtension("photo.jpg.exe"))
        XCTAssertNotNil(UniversalChecks.doubleExtension("invoice.pdf.app"))

        XCTAssertNil(UniversalChecks.doubleExtension("archive.tar.gz"))
        XCTAssertNil(UniversalChecks.doubleExtension("deploy.test.sh"))
        XCTAssertNil(UniversalChecks.doubleExtension("photo.jpg"))
        XCTAssertNil(UniversalChecks.doubleExtension("noextension"))
        XCTAssertNil(UniversalChecks.doubleExtension(""))
    }

    func testDoubleExtensionReportsBothHalves() {
        let findings = UniversalChecks.filename("photo.jpg.exe")
        let double = findings.first { $0.rule == "name.doubleExtension" }
        XCTAssertEqual(double?.severity, .caution)
        XCTAssertTrue(double!.detail.contains("jpg"))
        XCTAssertTrue(double!.detail.contains("exe"))
    }

    // MARK: - Embedded payloads

    /// The polyglot case: a real JPEG with a ZIP appended.
    func testAppendedArchiveInsideAnImageIsFound() {
        let payload =
            jpegHeader + Data(repeating: 0x20, count: 64)
            + Data([0x50, 0x4B, 0x03, 0x04]) + Data(repeating: 0x00, count: 16)
        let subject = probe(name: "innocent.jpg", bytes: payload)
        let findings = UniversalChecks.embeddedSignatures(
            probe: subject, identified: MagicBytes.jpeg)
        XCTAssertEqual(rules(findings), ["embedded.signature"])
        XCTAssertTrue(findings[0].title.contains("ZIP"))
        XCTAssertTrue(findings[0].detail.contains("68"), "should report the byte offset")
    }

    /// Containing other files is what an archive is for; scanning one for
    /// embedded signatures would flag every ZIP ever made.
    func testArchivesAreExemptFromTheEmbeddedScan() {
        let payload =
            Data([0x50, 0x4B, 0x03, 0x04]) + Data(repeating: 0x20, count: 32)
            + Data([0x50, 0x4B, 0x03, 0x04])
        let subject = probe(name: "bundle.zip", bytes: payload)
        XCTAssertTrue(
            UniversalChecks.embeddedSignatures(probe: subject, identified: MagicBytes.zip).isEmpty)
    }

    /// A signature at offset 0 is the file's own identity, not a passenger.
    func testOwnSignatureAtOffsetZeroIsNotReported() {
        let subject = probe(name: "tool", bytes: machOHeader + Data(repeating: 0, count: 32))
        XCTAssertTrue(
            UniversalChecks.embeddedSignatures(probe: subject, identified: MagicBytes.machO)
                .isEmpty)
    }

    // MARK: - File traits and disclosures

    func testWorldWritableFileIsCaution() {
        let subject = probe(name: "shared.png", bytes: pngHeader, permissions: 0o666)
        XCTAssertTrue(
            rules(UniversalChecks.fileTraits(probe: subject)).contains("perm.worldWritable"))
    }

    func testNormalPermissionsProduceNoTraitFinding() {
        let subject = probe(name: "fine.png", bytes: pngHeader, permissions: 0o644)
        XCTAssertTrue(UniversalChecks.fileTraits(probe: subject).isEmpty)
    }

    /// Quarantine on a downloaded file is the normal state, not a finding —
    /// the same conclusion `TrustScoring.applies` reached for processes.
    func testQuarantineIsADisclosureNotAFinding() {
        let subject = probe(
            name: "download.jpg", bytes: jpegHeader,
            quarantine: "0281;6aaf0929;Chrome;43C710CF",
            whereFrom: ["https://example.com/download.jpg"])

        XCTAssertTrue(UniversalChecks.fileTraits(probe: subject).isEmpty)

        let disclosures = UniversalChecks.disclosures(probe: subject)
        XCTAssertEqual(disclosures.count, 2)
        XCTAssertTrue(disclosures[0].detail.contains("Chrome"))
        XCTAssertTrue(disclosures[1].detail.contains("example.com"))
    }

    func testQuarantineAgentParsing() {
        XCTAssertEqual(
            UniversalChecks.quarantineAgent("0281;6aaf0929;Chrome;43C710CF"), "Chrome")
        XCTAssertNil(UniversalChecks.quarantineAgent(nil))
        XCTAssertNil(UniversalChecks.quarantineAgent("too;short"))
        XCTAssertNil(UniversalChecks.quarantineAgent("0281;6aaf0929;;43C710CF"))
    }

    // MARK: - Verdict

    /// The verdict must be derivable from the findings alone. An explanation
    /// that disagrees with its score is worse than no explanation.
    func testVerdictFollowsTheWorstFinding() {
        func finding(_ severity: FindingSeverity) -> Finding {
            Finding(rule: "t", severity: severity, title: "t", detail: "d")
        }
        XCTAssertEqual(FileInspection.verdict(readable: true, findings: []), .consistent)
        XCTAssertEqual(
            FileInspection.verdict(readable: true, findings: [finding(.info)]), .consistent)
        XCTAssertEqual(
            FileInspection.verdict(readable: true, findings: [finding(.caution)]), .caution)
        XCTAssertEqual(
            FileInspection.verdict(
                readable: true,
                findings: [finding(.info), finding(.inconsistent), finding(.caution)]
            ), .inconsistent)
    }

    /// "Could not read" must never render as a pass.
    func testUnreadableOverridesEverything() {
        XCTAssertEqual(FileInspection.verdict(readable: false, findings: []), .unreadable)
        XCTAssertEqual(
            FileInspection.verdict(
                readable: false,
                findings: [Finding(rule: "t", severity: .inconsistent, title: "t", detail: "d")]),
            .unreadable)
    }

    func testEveryVerdictHasItsOwnSymbol() {
        let symbols = InspectionVerdict.allCases.map(\.symbolName)
        XCTAssertEqual(Set(symbols).count, symbols.count, "colour alone must not carry meaning")
    }

    // MARK: - Report assembly

    func testReportSortsWorstFirstWithAStableTiebreak() {
        func inspection(_ path: String, _ verdict: InspectionVerdict) -> FileInspection {
            FileInspection(
                path: path, displayName: path, byteSize: 1, sha256: nil, declaredExtension: "",
                identifiedFormat: nil, findings: [], disclosures: [], verdict: verdict)
        }
        let report = InspectionReport(
            generated: Date(),
            roots: [],
            files: [
                inspection("/c", .consistent), inspection("/a", .inconsistent),
                inspection("/b", .inconsistent), inspection("/d", .caution),
            ],
            limitHit: nil)

        // Worst first, then path — and identical across repeated evaluation,
        // which is the property that keeps two exports of one run byte-equal.
        let expected = ["/a", "/b", "/d", "/c"]
        for _ in 0..<8 {
            XCTAssertEqual(report.sortedFiles.map(\.path), expected)
        }
        XCTAssertEqual(report.worstVerdict, .inconsistent)
        XCTAssertEqual(report.count(of: .inconsistent), 2)
    }

    // MARK: - End to end, against real files

    func testEngineInspectsRealFilesOnDisk() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Inspector-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // A structurally complete JPEG, EOI marker included. The first
        // version of this fixture was a header plus filler, which the segment
        // walk added in Phase 2 correctly called truncated — a fixture that
        // was never a shape production produces.
        let honest = dir.appendingPathComponent("real.jpg")
        try (jpegHeader + Data(repeating: 0x11, count: 512) + Data([0xFF, 0xD9]))
            .write(to: honest)

        let liar = dir.appendingPathComponent("fake.png")
        try (machOHeader + Data(repeating: 0x22, count: 512)).write(to: liar)

        let report = await InspectionEngine().inspect(
            paths: [honest.path, liar.path])

        XCTAssertEqual(report.files.count, 2)
        let byName = Dictionary(uniqueKeysWithValues: report.files.map { ($0.displayName, $0) })

        XCTAssertEqual(byName["real.jpg"]?.verdict, .consistent)
        XCTAssertEqual(byName["real.jpg"]?.identifiedFormat, "JPEG")
        XCTAssertNotNil(byName["real.jpg"]?.sha256, "readable files should be hashed")

        XCTAssertEqual(byName["fake.png"]?.verdict, .inconsistent)
        XCTAssertEqual(byName["fake.png"]?.identifiedFormat, "Mach-O executable")
        XCTAssertEqual(report.worstVerdict, .inconsistent)
    }

    func testMissingFileIsReportedNotSkipped() async {
        let report = await InspectionEngine().inspect(paths: ["/nonexistent/thing.jpg"])
        XCTAssertEqual(report.files.count, 1)
        XCTAssertEqual(report.files[0].verdict, .unreadable)
        XCTAssertNil(report.files[0].sha256)
    }

    func testFileCountCapIsReported() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("InspectorCap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        var paths: [String] = []
        for index in 0..<5 {
            let file = dir.appendingPathComponent("f\(index).jpg")
            try jpegHeader.write(to: file)
            paths.append(file.path)
        }

        var limits = InspectionEngine.Limits.default
        limits.maxFiles = 3
        let report = await InspectionEngine(limits: limits).inspect(paths: paths)

        XCTAssertEqual(report.files.count, 3)
        XCTAssertEqual(report.limitHit, .fileCountCap)
    }

    // MARK: - The fuzz gate

    /// Malformed input must be a *finding*, never a crash. These are the
    /// shapes that break hand-written parsers: empty, one byte, truncated
    /// mid-signature, all zeroes, and random noise.
    ///
    /// The assertion is simply that every call returns. A trap, an unwrap of
    /// nil, or an unbounded loop fails this test by killing the process.
    func testHostileBytesNeverCrashTheParsers() {
        var inputs: [Data] = [
            Data(),
            Data([0x00]),
            Data([0xFF]),
            Data([0xFF, 0xD8]),
            Data([0x50, 0x4B]),
            Data(repeating: 0x00, count: 4096),
            Data(repeating: 0xFF, count: 4096),
            Data("RIFF".utf8),
            Data([0xCA, 0xFE, 0xBA, 0xBE]),
            Data([0, 0, 0, 0x20]) + Data("ftyp".utf8),
        ]
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<64 {
            let count = Int.random(in: 0...2048, using: &generator)
            inputs.append(
                Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }))
        }

        let names = [
            "", ".", "..", "a", "a.b", "....", "x.jpg.exe", "\u{202E}\u{200B}.pdf",
            String(repeating: "a", count: 4096) + ".png",
        ]

        for data in inputs {
            let format = MagicBytes.identify(head: data)
            for name in names {
                let subject = probe(name: name, bytes: data)
                _ = UniversalChecks.run(probe: subject, identified: format)
                _ = UniversalChecks.disclosures(probe: subject)
                _ = FileInspection.verdict(readable: true, findings: [])
            }
        }
    }

    /// Slices again, this time through the whole pipeline rather than just
    /// the matcher.
    func testSlicedBuffersSurviveTheWholePipeline() {
        let padded = Data([0xAA, 0xBB, 0xCC]) + jpegHeader + Data(repeating: 0x10, count: 128)
        let slice = padded.dropFirst(3)
        let subject = probe(name: "sliced.jpg", bytes: slice)
        let findings = UniversalChecks.run(
            probe: subject, identified: MagicBytes.identify(head: slice))
        XCTAssertFalse(rules(findings).contains("magic.mismatch"))
    }

    // MARK: - Things that were never opened

    /// A symlink is inspected with `lstat` and never followed, so its `head`
    /// is empty. Running the content checks against that empty buffer reported
    /// a symlink pointing at a perfectly good JPEG as Caution, "contents could
    /// not be confirmed" — a claim about bytes nobody read.
    func testSymlinkIsNotJudgedOnContentsItNeverRead() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Symlink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let real = dir.appendingPathComponent("real.jpg")
        try (jpegHeader + Data(repeating: 0x11, count: 512)).write(to: real)
        let link = dir.appendingPathComponent("link.jpg")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        let report = await InspectionEngine().inspect(paths: [link.path])
        let file = report.files[0]

        XCTAssertFalse(rules(file.findings).contains("magic.unconfirmed"))
        XCTAssertFalse(rules(file.findings).contains("magic.mismatch"))
        XCTAssertTrue(rules(file.findings).contains("file.symlink"))
        XCTAssertEqual(file.verdict, .unreadable)
        // The target belongs in the report, so the user can follow it.
        XCTAssertTrue(
            file.findings.first { $0.rule == "file.symlink" }!.detail.contains("real.jpg"))
    }

    /// A folder reached the type check as "no signature matched, first bytes:
    /// (empty)", which reads as a malformed file rather than a directory.
    func testFolderIsReportedAsAFolder() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Folder-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let report = await InspectionEngine().inspect(paths: [dir.path])
        let file = report.files[0]

        XCTAssertTrue(rules(file.findings).contains("file.directory"))
        XCTAssertFalse(rules(file.findings).contains("magic.unclassified"))
        XCTAssertNil(file.sha256, "a folder must not be hashed")
    }

    // MARK: - Substring search

    func testSearchFindsEveryOccurrenceIncludingOverlaps() {
        let haystack = Data([0, 1, 2, 1, 2, 1, 2, 9])
        XCTAssertEqual(FileProbe.search([1, 2], in: haystack), [1, 3, 5])

        // Overlapping: resuming past the whole match would miss the second.
        let repeated = Data([0xAA, 0xAA, 0xAA])
        XCTAssertEqual(FileProbe.search([0xAA, 0xAA], in: repeated), [0, 1])
    }

    func testSearchEdgeCases() {
        XCTAssertEqual(FileProbe.search([], in: Data([1, 2, 3])), [])
        XCTAssertEqual(FileProbe.search([1], in: Data()), [])
        XCTAssertEqual(FileProbe.search([1, 2, 3, 4], in: Data([1, 2, 3])), [])
        XCTAssertEqual(FileProbe.search([3], in: Data([1, 2, 3])), [2])
    }

    /// Offsets must be relative to the start of the file, not the buffer, or a
    /// reported byte position points at the wrong place in a sliced window.
    func testSearchReportsSliceRelativeOffsets() {
        let padded = Data([0xFF, 0xFF]) + Data([0xAB, 0xCD])
        XCTAssertEqual(FileProbe.search([0xAB, 0xCD], in: padded.dropFirst(2)), [0])
    }

    /// An oversized extended attribute is refused rather than allocated.
    func testOversizedExtendedAttributeIsRefused() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Xattr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let file = dir.appendingPathComponent("big-xattr.jpg")
        try jpegHeader.write(to: file)

        let huge = [UInt8](repeating: 0x41, count: FileProbe.maxXattrBytes + 1024)
        let set = huge.withUnsafeBufferPointer {
            setxattr(file.path, "com.apple.quarantine", $0.baseAddress, huge.count, 0, 0)
        }
        try XCTSkipIf(set != 0, "filesystem refused an oversized xattr; cap path untestable here")

        XCTAssertNil(FileProbe.readXattrData(path: file.path, name: "com.apple.quarantine"))

        // A normal-sized value on the same attribute still reads.
        let small = Array("0281;6aaf0929;Chrome;ABC".utf8)
        _ = small.withUnsafeBufferPointer {
            setxattr(file.path, "com.apple.quarantine", $0.baseAddress, small.count, 0, 0)
        }
        XCTAssertEqual(
            UniversalChecks.quarantineAgent(
                FileProbe.readXattrString(path: file.path, name: "com.apple.quarantine")),
            "Chrome")
    }

    /// The row shows `displayName`; the rules flag a direction override in
    /// the name; the row must not then display the spoof. The path stays
    /// exact so exports and re-inspection refer to the real file.
    func testDisplayNameIsSanitisedWhilePathStaysExact() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Spoof-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let spoofed = dir.appendingPathComponent("report\u{202E}fdp.exe")
        try Data("hello".utf8).write(to: spoofed)

        let report = await InspectionEngine().inspect(paths: [spoofed.path], hashFiles: false)
        let file = try XCTUnwrap(report.files.first)
        XCTAssertEqual(file.displayName, "reportfdp.exe")
        XCTAssertEqual(file.path, spoofed.path)
        XCTAssertTrue(file.findings.contains { $0.rule == "name.bidi" })
    }

    /// Text has no signature. A `.txt` or `.py` with unrecognised bytes is
    /// the normal case, not an unknown format to report or to learn.
    func testTextAndSourceWithoutASignatureAreNotUnclassified() async throws {
        for name in ["notes.txt", "tool.py", "README.md"] {
            let findings = UniversalChecks.typeConsistency(
                probe: probe(name: name, bytes: Data("plain words\n".utf8)), identified: nil)
            XCTAssertTrue(findings.isEmpty, "\(name): \(rules(findings))")
        }

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Text-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let script = dir.appendingPathComponent("tool.py")
        try Data("import os\n".utf8).write(to: script)
        let report = await InspectionEngine().inspect(paths: [script.path], hashFiles: false)
        XCTAssertNil(report.files.first?.magicPrefix, "nothing to learn from text")
        XCTAssertEqual(report.files.first?.verdict, .consistent)
    }

    // MARK: - Graded mismatch

    /// A GIF saved as .png is the commonest mislabel on the web. It is still a
    /// finding, but orange: nothing in it can run, and red for every one of
    /// these taught users that red means nothing.
    func testImageUnderAnotherImagesNameIsCautionNotInconsistent() {
        let cases: [(String, Data, FileFormat)] = [
            ("photo.png", Data("GIF89a".utf8), MagicBytes.gif),
            ("photo.jpg", Data("RIFF....WEBP".utf8), MagicBytes.webp),
            ("song.mp3", Data("fLaC".utf8), MagicBytes.flac),
            ("bundle.zip", Data([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), MagicBytes.sevenZip),
        ]
        for (name, bytes, found) in cases {
            let findings = UniversalChecks.typeConsistency(
                probe: probe(name: name, bytes: bytes), identified: found)
            XCTAssertEqual(rules(findings), ["magic.mislabelled"], name)
            XCTAssertEqual(findings.first?.severity, .caution, name)
            XCTAssertTrue(findings.first!.detail.contains("still wrong"), name)
        }
    }

    /// Different family, or anything runnable on either side, stays red.
    func testCrossFamilyOrRunnableMismatchStaysInconsistent() {
        let cases: [(String, Data, FileFormat)] = [
            ("photo.png", machOHeader, MagicBytes.machO),  // the headline case
            ("archive.zip", Data("koly".utf8), MagicBytes.dmg),  // disk image under .zip
            ("report.docx", Data("%PDF-".utf8), MagicBytes.pdf),  // document as archive
            ("clip.mp3", Data("....ftypmp42".utf8), MagicBytes.mp4),  // video as audio
            ("tool.dmg", Data("GIF89a".utf8), MagicBytes.gif),  // runnable name on an image
        ]
        for (name, bytes, found) in cases {
            let findings = UniversalChecks.typeConsistency(
                probe: probe(name: name, bytes: bytes), identified: found)
            XCTAssertEqual(rules(findings), ["magic.mismatch"], name)
            XCTAssertEqual(findings.first?.severity, .inconsistent, name)
        }
    }

    /// End to end: the verdict on a real GIF named .png is Caution.
    func testGIFNamedPNGOnDiskIsCaution() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Mislabel-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("USS.png")
        try (Data("GIF89a".utf8) + Data(repeating: 0, count: 64) + Data([0x3B])).write(to: file)

        let report = await InspectionEngine().inspect(paths: [file.path], hashFiles: false)
        XCTAssertEqual(report.files.first?.verdict, .caution)
        XCTAssertEqual(report.files.first?.identifiedFormat, "GIF")
    }

    /// A direct download records the same URL as both source and referrer.
    func testRepeatedOriginURLIsDisclosedOnce() {
        let url = "https://example.com/proxy/abc"
        let subject = probe(
            name: "a.jpg", bytes: jpegHeader, quarantine: "0081;0;Chrome;X",
            whereFrom: [url, url, "https://example.com/"])
        let origins = UniversalChecks.disclosures(probe: subject).filter { $0.title == "Came from" }
        XCTAssertEqual(origins.map(\.detail), [url, "https://example.com/"])
    }
}
