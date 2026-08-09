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
        let vouches = await verifier.vouches().mapValues(\.bundle)
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
        let vouches = await verifier.vouches().mapValues(\.bundle)
        XCTAssertNil(vouches[calculator + "/Contents/MacOS/planted"])
    }

    /// A vouched binary swapped at the same path loses its vouch, checked
    /// through the engine that actually consults it rather than by comparing
    /// two identity values.
    func testVouchLapsesWhenTheFileChanges() async throws {
        let binary = try makeFixtureBinary(contents: "original")
        let engine = TrustEngine()
        await engine.setVouchedBinaries(try vouch(for: binary))

        var assessment = await engine.assess(path: binary.path)
        XCTAssertEqual(
            assessment.vouchedByBundle, "/Fixture.app",
            "a file matching its recorded fingerprint keeps its vouch")

        try "replaced".data(using: .utf8)!.write(to: binary)
        assessment = await engine.assess(path: binary.path)
        XCTAssertNil(assessment.vouchedByBundle, "changed file must lose its vouch")
        XCTAssertNotEqual(assessment.badge, .trusted)
    }

    /// The vouch survives neither a same-size replacement nor a restored
    /// mtime. Identifying a binary by `(path, mtime, size)` meant anyone who
    /// could write the file could keep its Trusted badge, because both halves
    /// of that tuple are theirs to set.
    func testVouchLapsesWhenTheFileIsSwappedForOneOfIdenticalSizeAndMtime() async throws {
        let binary = try makeFixtureBinary(contents: "aaaaaaaa")
        let engine = TrustEngine()
        await engine.setVouchedBinaries(try vouch(for: binary))
        let originalMtime = try XCTUnwrap(
            FileManager.default.attributesOfItem(atPath: binary.path)[.modificationDate]
                as? Date)

        try "bbbbbbbb".data(using: .utf8)!.write(to: binary)  // same length
        try FileManager.default.setAttributes(
            [.modificationDate: originalMtime], ofItemAtPath: binary.path)

        // Confirm the forgery actually reproduces the old identity tuple —
        // otherwise the assertion below would pass for the wrong reason.
        // `setAttributes` stores whole seconds, so compare at that resolution.
        let attributes = try FileManager.default.attributesOfItem(atPath: binary.path)
        let restored = try XCTUnwrap(attributes[.modificationDate] as? Date)
        XCTAssertEqual(
            restored.timeIntervalSince(originalMtime), 0, accuracy: 1,
            "the forged mtime must match the original")
        XCTAssertEqual(attributes[.size] as? Int64, 8, "the forged size must match")

        let assessment = await engine.assess(path: binary.path)
        XCTAssertNil(
            assessment.vouchedByBundle,
            "identity must come from the file's contents, not from metadata the "
                + "attacker controls")
    }

    /// The vouch map is built once at launch. Checking freshness only when it
    /// is built let a file replaced later keep a vouch for the whole session.
    func testVouchIsRecheckedOnEveryAssessmentNotOnlyWhenTheMapIsBuilt() async throws {
        let binary = try makeFixtureBinary(contents: "original")
        let engine = TrustEngine()
        await engine.setVouchedBinaries(try vouch(for: binary))
        _ = await engine.assess(path: binary.path)  // warms the signature cache

        try "planted".data(using: .utf8)!.write(to: binary)
        let assessment = await engine.assess(path: binary.path)
        XCTAssertNil(assessment.vouchedByBundle)
    }

    private func makeFixtureBinary(contents: String) throws -> URL {
        let binary =
            directory
            .appendingPathComponent("Fixture.app/Contents/MacOS/tool")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(), withIntermediateDirectories: true)
        try contents.data(using: .utf8)!.write(to: binary)
        return binary
    }

    private func vouch(for binary: URL) throws -> [String: (bundle: String, fingerprint: Data)] {
        let fingerprint = try XCTUnwrap(CodeIdentity.fingerprint(path: binary.path))
        return [binary.path: ("/Fixture.app", fingerprint)]
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
        let vouches = await verifier.vouches().mapValues(\.bundle)
        XCTAssertTrue(vouches.isEmpty)
    }
}
