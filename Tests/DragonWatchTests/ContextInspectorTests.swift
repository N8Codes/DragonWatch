import XCTest

@testable import DragonWatch

final class ContextInspectorTests: XCTestCase {

    /// `$TMPDIR` on macOS is `/var/folders/<xx>/<yyy>/T/`, not `/tmp`. Matching
    /// only the static prefixes meant a payload staged in the directory the OS
    /// actually hands out lost the signal this modifier exists for.
    func testPerUserTemporaryDirectoryCountsAsSuspicious() {
        XCTAssertTrue(
            ContextInspector.isSuspiciousLocation("/var/folders/3h/abc123/T/stage1"))
        XCTAssertTrue(
            ContextInspector.isSuspiciousLocation(
                "/private/var/folders/3h/abc123/T/nested/stage1"))
        // The real one this machine hands out, whatever it happens to be.
        let real = NSTemporaryDirectory() + "planted"
        XCTAssertTrue(
            ContextInspector.isSuspiciousLocation(real),
            "NSTemporaryDirectory() must match: \(real)")
    }

    func testStaticTemporaryPrefixesStillCount() {
        for path in [
            "/tmp/x", "/private/tmp/x", "/var/tmp/x", "/private/var/tmp/x",
        ] {
            XCTAssertTrue(ContextInspector.isSuspiciousLocation(path), path)
        }
    }

    func testDownloadsCountsAndIsAskedOfTheSystem() throws {
        let downloads = try XCTUnwrap(
            FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first)
        XCTAssertTrue(
            ContextInspector.isSuspiciousLocation(downloads.path + "/installer"))
        // A sibling directory whose name merely starts the same way must not.
        XCTAssertFalse(
            ContextInspector.isSuspiciousLocation(downloads.path + "-old/installer"))
    }

    /// App Translocation (`…/d/Wrapper/`) is deliberately excluded: it is
    /// Gatekeeper working correctly on a downloaded bundle, and `.quarantined`
    /// already covers that case.
    func testOrdinaryAndTranslocatedLocationsAreNotSuspicious() {
        for path in [
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "/usr/bin/ssh",
            "/var/folders/3h/abc123/C/com.apple.something",  // caches, not temp
            "/private/var/folders/3h/abc123/d/Wrapper/App.app/Contents/MacOS/App",
        ] {
            XCTAssertFalse(ContextInspector.isSuspiciousLocation(path), path)
        }
    }

    func testShortAndMalformedPathsAreHandled() {
        for path in ["", "/", "/var", "/var/folders", "/var/folders/3h/abc/T"] {
            XCTAssertFalse(
                ContextInspector.isPerUserTemporaryDirectory(path),
                "\(path) has no file inside a temp dir")
        }
    }

    func testHiddenDirectoryIsFlaggedButDotSegmentsAreNot() {
        XCTAssertTrue(
            ContextInspector.modifiers(forPath: "/opt/.hidden/tool")
                .contains(.hiddenPath))
        XCTAssertFalse(
            ContextInspector.modifiers(forPath: "/opt/visible/tool")
                .contains(.hiddenPath))
    }
}

/// "Cannot read" and "unsigned" are different claims, and conflating them
/// accused stock macOS daemons of being unsigned.
final class UnreadableBinaryTests: XCTestCase {

    /// /usr/sbin/cupsd ships mode 0500 root-only. It became visible once the
    /// sampler stopped dropping processes whose metrics we cannot read, and
    /// was promptly rated Unsigned -> Suspicious, which raised an alert
    /// naming a component of macOS.
    func testUnreadableSystemDaemonIsNotCalledUnsigned() throws {
        let path = "/usr/sbin/cupsd"
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "no cupsd")
        try XCTSkipIf(
            FileManager.default.isReadableFile(atPath: path),
            "cupsd is readable here, so this machine cannot exercise the case")

        let info = SignatureInspector.inspect(path: path)
        XCTAssertEqual(info.tier, .osManagedUnreadable)
        XCTAssertNotEqual(info.tier, .unsigned, "it is signed; we simply cannot look")
        XCTAssertEqual(
            TrustScoring.badge(tier: info.tier, modifiers: []), .trusted,
            "a SIP-protected OS file must not raise an alert")
    }

    /// The same unreadability outside an OS-managed location is genuinely
    /// evasive and must still be flagged.
    func testUnreadableFileOutsideTheOSIsStillSuspicious() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("Unreadable-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let hidden = directory.appendingPathComponent("payload")
        try Data("binary".utf8).write(to: hidden)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o000], ofItemAtPath: hidden.path)
        try XCTSkipIf(
            FileManager.default.isReadableFile(atPath: hidden.path),
            "running as root, so unreadable cannot be simulated")

        let info = SignatureInspector.inspect(path: hidden.path)
        XCTAssertEqual(info.tier, .unreadable)
        XCTAssertEqual(TrustScoring.badge(tier: info.tier, modifiers: []), .suspicious)
    }

    /// A file inside a folder we may not even search fails `stat` with
    /// EACCES, and `FileManager.fileExists` reports it missing — which rated
    /// Xcode's staged Instruments services Unsigned -> Suspicious.
    func testFileInsideUnsearchableFolderIsUnreadableNotUnsigned() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("Unsearchable-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let payload = directory.appendingPathComponent("payload")
        try Data("binary".utf8).write(to: payload)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o000], ofItemAtPath: directory.path)
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: directory.path)
            try? FileManager.default.removeItem(at: directory)
        }
        try XCTSkipIf(
            FileManager.default.isReadableFile(atPath: payload.path),
            "running as root, so unsearchable cannot be simulated")

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: payload.path),
            "precondition: the old check saw this file as missing")
        XCTAssertTrue(SignatureInspector.existsButUnreadable(payload.path))
        XCTAssertEqual(SignatureInspector.inspect(path: payload.path).tier, .unreadable)
    }

    /// The live case: macOS stages Xcode's XPC services in a root-only,
    /// SIP-restricted folder. When one is present, it must not read Unsigned.
    func testStagedXPCServiceIsNotCalledUnsigned() throws {
        let staging = "/private/var/db/com.apple.xpc.roleaccountd.staging/exec"
        let probe = staging + "/does-not-matter/Contents/MacOS/x"
        var info = stat()
        try XCTSkipUnless(
            stat(probe, &info) != 0 && errno == EACCES,
            "staging folder is searchable here (or absent)")
        XCTAssertEqual(SignatureInspector.inspect(path: probe).tier, .osManagedUnreadable)
    }

    func testMissingFileIsNotUnreadable() {
        XCTAssertFalse(
            SignatureInspector.existsButUnreadable("/nonexistent-\(UUID().uuidString)"))
    }

    func testXPCStagingFolderIsOSManaged() {
        XCTAssertTrue(
            ContextInspector.isOSManagedLocation(
                "/private/var/db/com.apple.xpc.roleaccountd.staging/exec/1.2.xpc/Contents/MacOS/x"))
        XCTAssertFalse(ContextInspector.isOSManagedLocation("/private/var/db/other/x"))
    }

    func testOSManagedLocationsExcludeUsrLocal() {
        XCTAssertTrue(ContextInspector.isOSManagedLocation("/usr/sbin/cupsd"))
        XCTAssertTrue(ContextInspector.isOSManagedLocation("/System/Library/x"))
        XCTAssertTrue(ContextInspector.isOSManagedLocation("/bin/zsh"))
        // SIP leaves /usr/local writable, so it is not OS-managed.
        XCTAssertFalse(ContextInspector.isOSManagedLocation("/usr/local/bin/tool"))
        XCTAssertFalse(ContextInspector.isOSManagedLocation("/opt/homebrew/bin/tool"))
        XCTAssertFalse(ContextInspector.isOSManagedLocation("/Users/x/tool"))
    }
}
