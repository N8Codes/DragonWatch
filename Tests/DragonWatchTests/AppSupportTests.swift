import XCTest

@testable import DragonWatch

/// Everything DragonWatch stores describes this machine. 0600 files inside a
/// 0755 directory still leak — anyone can list the names and learn which
/// features are on — so the directory is owner-only too. Both halves shipped
/// wrong once and were caught by inspecting a live install, not by a test.
final class AppSupportTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppSupportTests-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func mode(_ path: String) throws -> Int {
        try XCTUnwrap(
            FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int)
    }

    func testDirectoryIsCreatedOwnerOnly() throws {
        let dir = AppSupport.directory(override: root)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path))
        XCTAssertEqual(try mode(dir.path), 0o700)
    }

    /// createDirectory applies attributes only when it creates the directory,
    /// so an install that predates the fix must still be tightened.
    func testExistingWorldReadableDirectoryIsTightened() throws {
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        XCTAssertEqual(try mode(root.path), 0o755)

        _ = AppSupport.directory(override: root)
        XCTAssertEqual(try mode(root.path), 0o700, "must repair an existing directory")
    }

    /// A removed feature's ~32 MB index must not sit in Application Support
    /// forever; only the retired names go, and everything else stays.
    func testRetiredFilesAreRemovedAndLiveFilesKept() throws {
        let dir = AppSupport.directory(override: root)
        for name in AppSupport.retiredFileNames + ["observations.json"] {
            try Data("x".utf8).write(to: dir.appendingPathComponent(name))
        }

        AppSupport.removeRetiredFiles(in: root)

        for name in AppSupport.retiredFileNames {
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: dir.appendingPathComponent(name).path),
                "\(name) should be gone")
        }
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: dir.appendingPathComponent("observations.json").path))
        // Idempotent: a second launch with nothing to remove is not an error.
        AppSupport.removeRetiredFiles(in: root)
    }

    func testPrivateWriteIsOwnerOnlyAndStaysSoOnRewrite() throws {
        let dir = AppSupport.directory(override: root)
        let file = dir.appendingPathComponent("secret.json")

        try AppSupport.writePrivately(Data("first".utf8), to: file)
        XCTAssertEqual(try mode(file.path), 0o600)

        // An atomic write replaces the file, so the mode must be re-applied.
        try AppSupport.writePrivately(Data("second".utf8), to: file)
        XCTAssertEqual(try mode(file.path), 0o600)
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "second")
    }
}
