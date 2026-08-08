import XCTest

@testable import DragonWatch

final class BaselineStoreTests: XCTestCase {
    private var directory: URL!
    private let now = Date(timeIntervalSinceReferenceDate: 0)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("BaselineStoreTests-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func assessment(tier: SignatureTier) -> TrustAssessment {
        TrustAssessment(tier: tier, modifiers: [], teamID: nil, signingID: nil)
    }

    func testFirstBatchIsSeedingPassAndSecondIsNot() async {
        let store = BaselineStore(directory: directory)
        let first = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        XCTAssertTrue(first.wasSeedingPass)
        XCTAssertEqual(first.observations["/tmp/tool"], .addedForReview)

        let second = await store.observeBatch(
            [("/tmp/other", assessment(tier: .unsigned))],
            now: now.addingTimeInterval(25))
        XCTAssertFalse(second.wasSeedingPass)
        XCTAssertEqual(second.observations["/tmp/other"], .addedForReview)
    }

    /// The baseline lists every executable seen on this machine — the same
    /// sensitivity as the observation ledger, so it gets the same permissions.
    /// It shipped world-readable until a live check caught the mismatch.
    func testFileIsOwnerOnly() async throws {
        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        let path = directory.appendingPathComponent("baseline.json").path
        let permissions =
            try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions]
            as? Int
        XCTAssertEqual(permissions, 0o600)
    }

    func testLedgerSurvivesReload() async {
        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [("/usr/bin/true", assessment(tier: .applePlatform))], now: now)
        _ = await store.observePersistenceItems(["/Library/LaunchAgents/a.plist"])

        let reloaded = BaselineStore(directory: directory)
        let batch = await reloaded.observeBatch(
            [("/usr/bin/true", assessment(tier: .applePlatform))], now: now)
        // A reloaded ledger is not first-run: known items stay known, silently.
        XCTAssertFalse(batch.wasSeedingPass)
        XCTAssertEqual(batch.observations["/usr/bin/true"], .known)
        let fresh = await reloaded.observePersistenceItems(
            ["/Library/LaunchAgents/a.plist"])
        XCTAssertTrue(fresh.isEmpty)
    }

    func testResetReturnsToSeeding() async {
        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        await store.reset()
        let pending = await store.pendingReview()
        XCTAssertTrue(pending.isEmpty)
        let batch = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))],
            now: now.addingTimeInterval(60))
        XCTAssertTrue(batch.wasSeedingPass)
        XCTAssertEqual(batch.observations["/tmp/tool"], .addedForReview)
    }

    func testVerdictPersistsAcrossReload() async {
        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        await store.recordVerdict(path: "/tmp/tool", verdict: .expected)

        let reloaded = BaselineStore(directory: directory)
        let pending = await reloaded.pendingReview()
        XCTAssertTrue(pending.isEmpty)
        let entry = await reloaded.ledger.executables["/tmp/tool"]
        XCTAssertEqual(entry?.verdict, .expected)
    }
}
