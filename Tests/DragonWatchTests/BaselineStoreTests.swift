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

    /// Every baseline written before `schemaVersion` existed has no such key.
    /// Swift's synthesized `Decodable` throws on a missing key even when the
    /// property has a default, so a non-optional field would have failed to
    /// decode on upgrade, moved the file aside, and thrown away every verdict
    /// the user had recorded.
    func testBaselineWrittenBeforeSchemaVersioningStillLoads() async throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let legacy = """
            {"executables":{"/tmp/tool":{"tier":"Unsigned","verdict":"expected",\
            "firstSeen":0}},"persistenceItems":[]}
            """
        try legacy.data(using: .utf8)!
            .write(to: directory.appendingPathComponent("baseline.json"))

        let store = BaselineStore(directory: directory)
        let ledger = await store.ledger
        XCTAssertEqual(
            ledger.executables["/tmp/tool"]?.verdict, .expected,
            "an existing user's verdicts must survive the upgrade")
        XCTAssertEqual(ledger.effectiveSchemaVersion, 1)

        // And it must not be treated as a first run, which would re-ask about
        // the whole machine.
        let batch = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        XCTAssertFalse(batch.wasSeedingPass)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: directory.appendingPathComponent("baseline.json.bak").path),
            "a readable baseline must not be moved aside")
    }

    /// An unreadable baseline is preserved, not overwritten by the next save.
    func testUnreadableBaselineIsMovedAsideRatherThanLost() async throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let corrupt = directory.appendingPathComponent("baseline.json")
        try "{not json at all".data(using: .utf8)!.write(to: corrupt)

        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)

        let backup = directory.appendingPathComponent("baseline.json.bak")
        XCTAssertTrue(FileManager.default.fileExists(atPath: backup.path))
        XCTAssertEqual(try String(contentsOf: backup, encoding: .utf8), "{not json at all")
    }

    /// The seeding pass is the one chance to record existing state quietly.
    /// An empty first batch used to consume it, so the first real batch was
    /// treated as news and every program on the machine alerted at once.
    func testAnEmptyFirstBatchDoesNotConsumeTheSeedingPass() async {
        let store = BaselineStore(directory: directory)
        let empty = await store.observeBatch([], now: now)
        XCTAssertFalse(empty.wasSeedingPass)

        let real = await store.observeBatch(
            [("/tmp/tool", assessment(tier: .unsigned))], now: now)
        XCTAssertTrue(real.wasSeedingPass, "the first real batch is still the seeding pass")
    }

    /// "Not expected" has to be distinguishable from "expected", or the two
    /// buttons do the same thing. Both used to simply remove the row.
    func testNotExpectedItemsStayListedSeparatelyFromExpectedOnes() async {
        let store = BaselineStore(directory: directory)
        _ = await store.observeBatch(
            [
                ("/tmp/keep", assessment(tier: .unsigned)),
                ("/tmp/fine", assessment(tier: .unsigned)),
            ], now: now)

        await store.recordVerdict(path: "/tmp/keep", verdict: .keepFlagging)
        await store.recordVerdict(path: "/tmp/fine", verdict: .expected)

        let flagged = await store.markedUnexpected().map(\.path)
        let pending = await store.pendingReview().map(\.path)
        XCTAssertEqual(flagged, ["/tmp/keep"])
        XCTAssertTrue(pending.isEmpty, "both answers clear the pending queue")
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
