import XCTest

@testable import DragonWatch

final class FolderWalkerTests: XCTestCase {

    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("Walk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    @discardableResult
    private func file(_ relative: String, bytes: Int = 8) throws -> URL {
        let url = root.appendingPathComponent(relative)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(repeating: 0x41, count: bytes).write(to: url)
        return url
    }

    private func names(_ result: FolderWalker.Result) -> [String] {
        result.files.map { ($0 as NSString).lastPathComponent }.sorted()
    }

    // MARK: - Basic walking

    func testWalksNestedFoldersAndReturnsEveryFile() throws {
        try file("a.jpg")
        try file("sub/b.png")
        try file("sub/deeper/c.pdf")

        let result = FolderWalker.walk(roots: [root], limits: .default)
        XCTAssertEqual(names(result), ["a.jpg", "b.png", "c.pdf"])
        XCTAssertEqual(result.folderCount, 3)
        XCTAssertNil(result.limitHit)
    }

    func testFileSelectedDirectlyIsReturnedAsItself() throws {
        let one = try file("only.jpg")
        let result = FolderWalker.walk(roots: [one], limits: .default)
        XCTAssertEqual(result.files, [one.path])
        XCTAssertEqual(result.folderCount, 0)
    }

    /// `contentsOfDirectory` returns filesystem order, which is not stable
    /// between machines or after a rename. Two walks of one folder must
    /// produce the same list or two exports of one run differ.
    func testOrderingIsStable() throws {
        for name in ["z.jpg", "a.jpg", "m.jpg", "b.png"] { try file(name) }
        let first = FolderWalker.walk(roots: [root], limits: .default).files
        for _ in 0..<5 {
            XCTAssertEqual(FolderWalker.walk(roots: [root], limits: .default).files, first)
        }
    }

    func testMissingSelectionIsReportedRatherThanDropped() {
        let ghost = root.appendingPathComponent("not-there.jpg")
        let result = FolderWalker.walk(roots: [ghost], limits: .default)
        XCTAssertEqual(result.files, [ghost.path])
    }

    // MARK: - Bundles

    /// Descending into an `.app` turns one selection into thousands of files
    /// and buries the question the user asked.
    func testAppBundleIsOneItemNotItsContents() throws {
        try file("Thing.app/Contents/MacOS/Thing")
        try file("Thing.app/Contents/Info.plist")
        try file("beside.jpg")

        let result = FolderWalker.walk(roots: [root], limits: .default)
        XCTAssertEqual(names(result), ["Thing.app", "beside.jpg"])
    }

    func testBundleSelectedDirectlyIsStillOneItem() throws {
        try file("Thing.app/Contents/MacOS/Thing")
        let bundle = root.appendingPathComponent("Thing.app")
        let result = FolderWalker.walk(roots: [bundle], limits: .default)
        XCTAssertEqual(result.files, [bundle.path])
    }

    // MARK: - Symlinks and loops

    /// A link pointing at its own ancestor is the classic way to make a
    /// walker run forever.
    func testDirectorySymlinkLoopTerminates() throws {
        try file("sub/a.jpg")
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("sub/loop"), withDestinationURL: root)

        let result = FolderWalker.walk(roots: [root], limits: .default)
        XCTAssertEqual(names(result), ["a.jpg", "loop"])
        XCTAssertNil(result.limitHit, "the loop must be avoided, not hit a cap")
    }

    func testSymlinkIsRecordedButNotFollowed() throws {
        let target = try file("real.jpg")
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("link.jpg"), withDestinationURL: target)

        let result = FolderWalker.walk(roots: [root], limits: .default)
        XCTAssertEqual(names(result), ["link.jpg", "real.jpg"])
    }

    // MARK: - Caps

    func testDepthCapStopsDescentAndSaysSo() throws {
        try file("one/two/three/four/deep.jpg")
        var limits = InspectionEngine.Limits.default
        limits.maxDepth = 2

        let result = FolderWalker.walk(roots: [root], limits: limits)
        XCTAssertEqual(result.limitHit, .depthCap)
        XCTAssertFalse(names(result).contains("deep.jpg"))
    }

    func testFileCountCapStopsAndSaysSo() throws {
        for index in 0..<10 { try file("f\(index).jpg") }
        var limits = InspectionEngine.Limits.default
        limits.maxFiles = 4

        let result = FolderWalker.walk(roots: [root], limits: limits)
        XCTAssertEqual(result.files.count, 4)
        XCTAssertEqual(result.limitHit, .fileCountCap)
    }

    func testByteCapStopsAndSaysSo() throws {
        for index in 0..<10 { try file("big\(index).bin", bytes: 1024) }
        var limits = InspectionEngine.Limits.default
        limits.maxTotalBytes = 3000

        let result = FolderWalker.walk(roots: [root], limits: limits)
        XCTAssertEqual(result.limitHit, .byteCap)
        XCTAssertLessThan(result.files.count, 10)
    }

    func testCancellationStopsTheWalk() async throws {
        for index in 0..<200 { try file("sub\(index % 8)/f\(index).jpg") }
        let target = root!

        let task = Task { () -> FolderWalker.Result in
            while !Task.isCancelled { await Task.yield() }
            return FolderWalker.walk(roots: [target], limits: .default)
        }
        task.cancel()
        let result = await task.value
        XCTAssertEqual(result.limitHit, .cancelled)
    }

    func testEmptySelectionWalksToNothing() {
        let result = FolderWalker.walk(roots: [], limits: .default)
        XCTAssertTrue(result.files.isEmpty)
        XCTAssertNil(result.limitHit)
    }

    // MARK: - End to end through the engine

    func testFolderScanProducesOneInspectionPerFile() async throws {
        try file("good.jpg", bytes: 0)
        let jpeg = root.appendingPathComponent("good.jpg")
        try (Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data(repeating: 0x11, count: 64)).write(to: jpeg)
        try file("nested/plain.txt")

        let walk = FolderWalker.walk(roots: [root], limits: .default)
        let report = await InspectionEngine().inspect(
            paths: walk.files, roots: [root.path], limitAlreadyHit: walk.limitHit)

        XCTAssertEqual(report.files.count, 2)
        XCTAssertEqual(report.roots, [root.path])
        XCTAssertEqual(
            report.files.first { $0.displayName == "good.jpg" }?.identifiedFormat, "JPEG")
    }

    /// A bundle must not fall through to "Unreadable" just because no bytes
    /// were read from the directory itself.
    func testBundleIsInspectedBySignatureNotTreatedAsAFolder() async throws {
        let app = "/System/Applications/Calculator.app"
        try XCTSkipUnless(FileManager.default.fileExists(atPath: app), "no Calculator.app")

        let report = await InspectionEngine().inspect(paths: [app])
        let file = report.files[0]

        XCTAssertNotEqual(file.verdict, .unreadable)
        XCTAssertFalse(file.findings.map(\.rule).contains("file.directory"))
        XCTAssertTrue(
            file.disclosures.contains { $0.detail.contains("Apple") },
            "an Apple-signed bundle should disclose its tier, got: "
                + file.disclosures.map(\.title).joined(separator: "; "))
    }

    // MARK: - Cancellation must not publish results

    /// The engine returns a partial report when cancelled mid-run. Publishing
    /// it put results on screen 1.5 s after the user pressed Cancel, and let
    /// an abandoned run overwrite a newer one's results.
    @MainActor
    func testCancelledRunPublishesNoReport() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CancelPublish-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        for index in 0..<3000 {
            try Data(repeating: 0x41, count: 2048)
                .write(to: dir.appendingPathComponent("s\(index).bin"))
        }

        let model = AppModel()
        model.inspect(urls: [dir])
        // Cancel only once the walk is done and the engine is actually running,
        // which is the path that used to publish.
        for _ in 0..<400 {
            if case .inspecting = model.inspectionPhase { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        guard case .inspecting = model.inspectionPhase else {
            throw XCTSkip("run finished before it could be cancelled mid-engine")
        }
        model.cancelInspection()

        try? await Task.sleep(for: .milliseconds(1500))
        XCTAssertNil(model.inspectionReport, "a cancelled run must not publish results")
        XCTAssertFalse(model.isInspecting)
    }

    // MARK: - Duplicates and unreadable folders

    /// Choosing a folder and one of its own files in the same selection
    /// reached the file twice, and the report listed it twice.
    func testFolderAndOneOfItsFilesSelectedTogetherListOnce() throws {
        let inner = try file("a.jpg")
        try file("b.jpg")
        let result = FolderWalker.walk(roots: [root, inner], limits: .default)
        XCTAssertEqual(names(result), ["a.jpg", "b.jpg"])
    }

    /// A folder the app cannot list used to vanish: the run said "2 folders
    /// searched, all consistent" about contents it never saw.
    func testUnreadableFolderIsReportedNotSkipped() async throws {
        try file("locked/secret.txt")
        let locked = root.appendingPathComponent("locked")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked.path)
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755], ofItemAtPath: locked.path)
        }
        guard FileManager.default.isReadableFile(atPath: locked.path) == false else {
            throw XCTSkip("running with privileges that ignore file modes")
        }

        let result = FolderWalker.walk(roots: [root], limits: .default)
        XCTAssertEqual(
            result.files.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path },
            [locked.resolvingSymlinksInPath().path])

        let report = await InspectionEngine().inspect(paths: result.files, hashFiles: false)
        XCTAssertEqual(report.files.first?.verdict, .unreadable)
        XCTAssertNotNil(FileProbe.read(path: locked.path).readError)
    }
}
