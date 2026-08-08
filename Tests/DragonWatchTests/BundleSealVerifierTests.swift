import XCTest

@testable import DragonWatch

final class BundleSealVerifierTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("BundleSealVerifierTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// Live check against a small Apple-signed bundle — full validation of
    /// Calculator takes well under a test timeout and proves the plumbing.
    func testGenuineAppleBundleVouchesNamedBinary() async throws {
        let calculator = "/System/Applications/Calculator.app"
        let binary = calculator + "/Contents/MacOS/Calculator"
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: binary), "no Calculator.app")

        let verifier = BundleSealVerifier(cacheDirectory: directory)
        let verified = await verifier.verify(
            bundlePath: calculator, vouching: [binary])
        XCTAssertTrue(verified)
        let vouches = await verifier.validVouches()
        XCTAssertEqual(vouches[binary], calculator)
    }

    /// The hiding-spot guard: a path that was not vouched at verification
    /// time is never vouched, even though it lives inside a verified bundle.
    func testPlantedPathInsideVerifiedBundleIsNotVouched() async throws {
        let calculator = "/System/Applications/Calculator.app"
        let binary = calculator + "/Contents/MacOS/Calculator"
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: binary), "no Calculator.app")

        let verifier = BundleSealVerifier(cacheDirectory: directory)
        _ = await verifier.verify(bundlePath: calculator, vouching: [binary])
        let vouches = await verifier.validVouches()
        XCTAssertNil(vouches[calculator + "/Contents/MacOS/planted"])
    }

    /// A vouched binary swapped at the same path loses its vouch: the
    /// recorded mtime/size no longer match.
    func testVouchLapsesWhenTheFileChanges() async throws {
        let bundle = directory.appendingPathComponent("Fixture.app")
        let binary = bundle.appendingPathComponent("Contents/MacOS/tool")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "original".data(using: .utf8)!.write(to: binary)

        // Record a vouch directly (no real seal to verify on a fixture).
        let identity = BundleSealVerifier.BinaryIdentity(path: binary.path)
        XCTAssertNotNil(identity)
        try "replaced-with-different-length".data(using: .utf8)!.write(to: binary)
        let after = BundleSealVerifier.BinaryIdentity(path: binary.path)
        XCTAssertNotEqual(identity, after, "changed file must not match its vouch")
    }

    func testFakeBundleFailsVerification() async throws {
        let fake = directory.appendingPathComponent("Fake.app")
        try FileManager.default.createDirectory(
            at: fake.appendingPathComponent("Contents/MacOS"),
            withIntermediateDirectories: true)
        try "not a real binary".data(using: .utf8)!
            .write(to: fake.appendingPathComponent("Contents/MacOS/Fake"))
        try "<plist/>".data(using: .utf8)!
            .write(to: fake.appendingPathComponent("Contents/Info.plist"))

        let verifier = BundleSealVerifier(cacheDirectory: directory)
        let verified = await verifier.verify(
            bundlePath: fake.path,
            vouching: [fake.appendingPathComponent("Contents/MacOS/Fake").path])
        XCTAssertFalse(verified)
        let vouches = await verifier.validVouches()
        XCTAssertTrue(vouches.isEmpty)
    }
}
