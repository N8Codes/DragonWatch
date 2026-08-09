import XCTest

@testable import DragonWatch

/// Signature checking against real signed code. These build and sign a
/// fixture with the system toolchain, so a failure means the Security
/// framework contract changed (or we broke our use of it), not that a pure
/// function has a bug.
final class SignatureInspectorTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SignatureInspectorTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// The defect this test exists for: `kSecCSBasicValidateOnly` is
    /// `DoNotValidateExecutable | DoNotValidateResources`, so it checks the
    /// signature blob and certificate chain but never the code pages. Under
    /// it, a binary patched in place validated clean and was handed whatever
    /// tier its untouched signature claimed — making `.invalid` unreachable
    /// for precisely the tampering this app exists to detect.
    func testPatchedExecutableRatesInvalid() throws {
        let pristine = try adHocSignedFixture(named: "tool")
        XCTAssertEqual(
            SignatureInspector.inspect(path: pristine.path).tier, .adHoc,
            "the untampered fixture must validate, or the test proves nothing")

        let patched = directory.appendingPathComponent("tool_patched")
        var bytes = try Data(contentsOf: pristine)
        let marker = try XCTUnwrap(
            bytes.range(of: Data(Self.marker.utf8)), "marker string not found in __TEXT")
        bytes[marker.lowerBound] = UInt8(ascii: "X")
        try bytes.write(to: patched)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: patched.path)

        XCTAssertEqual(
            SignatureInspector.inspect(path: patched.path).tier, .invalid,
            "a modified code page must invalidate the signature")
    }

    /// Ground truth comes from `codesign`, not from an assumption about what
    /// the linker emits. On Apple Silicon every binary is ad-hoc signed at
    /// link time, so a freshly compiled fixture is `.adHoc` there and
    /// `.unsigned` on Intel — asserting one of those pinned the test to one
    /// architecture.
    func testUnsignedBinaryRatesUnsigned() throws {
        let binary = try compileFixture(named: "unsigned")
        // Best effort: on arm64 the linker signed it, so strip that back off.
        _ = try? runAllowingFailure(
            "/usr/bin/codesign", ["--remove-signature", binary.path])
        try XCTSkipUnless(
            systemReportsUnsigned(binary),
            "this platform will not leave a Mach-O unsigned")

        XCTAssertEqual(SignatureInspector.inspect(path: binary.path).tier, .unsigned)
    }

    /// Whatever the architecture, our tier must agree with `codesign` about
    /// whether a signature is present at all.
    func testTierAgreesWithCodesignAboutSignaturePresence() throws {
        let signed = try adHocSignedFixture(named: "agree")
        XCTAssertFalse(systemReportsUnsigned(signed))
        XCTAssertNotEqual(SignatureInspector.inspect(path: signed.path).tier, .unsigned)
    }

    /// `codesign -dv` exits non-zero with "not signed at all" when there is no
    /// signature.
    private func systemReportsUnsigned(_ binary: URL) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["-dv", binary.path]
        let pipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = pipe
        guard (try? process.run()) != nil else { return false }
        let output =
            String(
                data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        return output.contains("not signed at all")
    }

    func testApplePlatformBinaryRatesApplePlatform() {
        XCTAssertEqual(SignatureInspector.inspect(path: "/bin/zsh").tier, .applePlatform)
    }

    func testMissingFileRatesUnsigned() {
        XCTAssertEqual(
            SignatureInspector.inspect(path: directory.appendingPathComponent("nope").path)
                .tier, .unsigned)
    }

    private static let marker = "dragonwatch fixture marker padding padding"

    private func compileFixture(named name: String) throws -> URL {
        let source = directory.appendingPathComponent("\(name).c")
        try #"""
        #include <stdio.h>
        int main(void) { printf("\#(Self.marker)\n"); return 0; }
        """#
        .data(using: .utf8)!.write(to: source)

        let binary = directory.appendingPathComponent(name)
        try run("/usr/bin/clang", ["-o", binary.path, source.path])
        return binary
    }

    private func adHocSignedFixture(named name: String) throws -> URL {
        let binary = try compileFixture(named: name)
        try run("/usr/bin/codesign", ["-s", "-", "-f", binary.path])
        return binary
    }

    @discardableResult
    private func runAllowingFailure(_ tool: String, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    private func run(_ tool: String, _ arguments: [String]) throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: tool), "no \(tool)")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        try XCTSkipUnless(
            process.terminationStatus == 0,
            "\(tool) failed (\(process.terminationStatus)) — toolchain unavailable")
    }
}
