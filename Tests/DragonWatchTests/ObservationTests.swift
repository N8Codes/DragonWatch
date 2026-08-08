import XCTest

@testable import DragonWatch

final class ObservationLedgerTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 0)
    private var later: Date { now.addingTimeInterval(3600) }

    func testFirstSightingIsNewThenKnown() {
        var ledger = ObservationLedger()
        XCTAssertEqual(
            ledger.observe(path: "/usr/bin/true", tier: .applePlatform, now: now), .new)
        XCTAssertEqual(
            ledger.observe(path: "/usr/bin/true", tier: .applePlatform, now: later),
            .known)
        XCTAssertEqual(ledger.identities["/usr/bin/true"]?.firstSeen, now)
        XCTAssertEqual(ledger.identities["/usr/bin/true"]?.lastSeen, later)
        XCTAssertEqual(ledger.identities["/usr/bin/true"]?.transitions, [])
    }

    /// The masquerade case: a Developer ID binary replaced by an ad-hoc one.
    func testTierDowngradeIsFlagged() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/Applications/A.app/x", tier: .developerID, now: now)
        XCTAssertEqual(
            ledger.observe(path: "/Applications/A.app/x", tier: .adHoc, now: later),
            .tierDowngraded(from: .developerID, to: .adHoc))
        XCTAssertEqual(
            ledger.identities["/Applications/A.app/x"]?.transitions.last?.field, "tier")
    }

    /// Routine updates must stay quiet: equal-badge tier changes and upgrades
    /// record a transition but do not flag.
    func testEqualOrBetterTierChangeIsQuiet() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/a", tier: .appStore, now: now)
        XCTAssertEqual(
            ledger.observe(path: "/a", tier: .developerID, now: later), .known)
        _ = ledger.observe(path: "/b", tier: .adHoc, now: now)
        XCTAssertEqual(
            ledger.observe(path: "/b", tier: .developerID, now: later), .known)
        XCTAssertEqual(ledger.identities["/b"]?.transitions.count, 1)
    }

    func testHashRecordingAndChange() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/a", tier: .adHoc, now: now)
        XCTAssertFalse(ledger.recordHash(path: "/a", sha256: "aaa", now: now))
        XCTAssertFalse(ledger.recordHash(path: "/a", sha256: "aaa", now: later))
        XCTAssertTrue(ledger.recordHash(path: "/a", sha256: "bbb", now: later))
        XCTAssertEqual(ledger.identities["/a"]?.sha256, "bbb")
        XCTAssertEqual(ledger.identities["/a"]?.transitions.last?.field, "hash")
        // Hash for an unknown path is dropped, not invented.
        XCTAssertFalse(ledger.recordHash(path: "/nope", sha256: "ccc", now: now))
    }

    func testTransitionsAreCapped() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/a", tier: .adHoc, now: now)
        _ = ledger.recordHash(path: "/a", sha256: "h0", now: now)
        for i in 1...(ObservationLedger.transitionCap + 10) {
            _ = ledger.recordHash(path: "/a", sha256: "h\(i)", now: later)
        }
        XCTAssertEqual(
            ledger.identities["/a"]?.transitions.count, ObservationLedger.transitionCap)
    }

    func testUnhashedQueueRespectsOrderAndLimit() {
        var ledger = ObservationLedger()
        for path in ["/a", "/b", "/c"] {
            _ = ledger.observe(path: path, tier: .adHoc, now: now)
        }
        _ = ledger.recordHash(path: "/b", sha256: "x", now: now)
        XCTAssertEqual(
            ledger.unhashedPaths(among: ["/c", "/b", "/a", "/unknown"], limit: 1),
            ["/c"])
        XCTAssertEqual(
            ledger.unhashedPaths(among: ["/c", "/b", "/a"], limit: 5), ["/c", "/a"])
    }

    func testEventPruningByAgeAndCap() {
        var ledger = ObservationLedger()
        ledger.record(
            event: .init(
                date: now.addingTimeInterval(-100 * 86400),
                kind: "sustainedCPU", title: "old", detail: ""))
        ledger.record(event: .init(date: now, kind: "sustainedCPU", title: "new", detail: ""))
        ledger.prune(now: now, eventRetention: 90 * 86400)
        XCTAssertEqual(ledger.events.map(\.title), ["new"])
    }
}

final class ObservationStoreTests: XCTestCase {
    private var directory: URL!
    private let now = Date(timeIntervalSinceReferenceDate: 0)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ObservationStoreTests-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testLedgerSurvivesReload() async {
        let store = ObservationStore(directory: directory)
        _ = await store.observeBatch(
            [("/a", .adHoc)], now: now, eventRetention: 90 * 86400)
        await store.record(
            event: .init(date: now, kind: "sustainedCPU", title: "t", detail: "d"))

        let reloaded = ObservationStore(directory: directory)
        let identity = await reloaded.identity(for: "/a")
        XCTAssertEqual(identity?.tier, .adHoc)
        let events = await reloaded.events()
        XCTAssertEqual(events.map(\.title), ["t"])
    }

    func testFileIsOwnerOnly() async throws {
        let store = ObservationStore(directory: directory)
        _ = await store.observeBatch(
            [("/a", .adHoc)], now: now, eventRetention: 90 * 86400)
        let path = directory.appendingPathComponent("observations.json").path
        let permissions =
            try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions]
            as? Int
        XCTAssertEqual(permissions, 0o600)
    }

    func testUnknownSchemaMovesAsideInsteadOfDestroying() async throws {
        let fileURL = directory.appendingPathComponent("observations.json")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let future = #"{"schemaVersion":99,"identities":{},"events":[]}"#
        try future.data(using: .utf8)!.write(to: fileURL)

        let store = ObservationStore(directory: directory)
        let identity = await store.identity(for: "/anything")
        XCTAssertNil(identity)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: fileURL.appendingPathExtension("bak").path),
            "future-schema file should be preserved as .bak")
    }

    func testWipeForgetsEverything() async {
        let store = ObservationStore(directory: directory)
        _ = await store.observeBatch(
            [("/a", .adHoc)], now: now, eventRetention: 90 * 86400)
        await store.wipe()
        let identity = await store.identity(for: "/a")
        XCTAssertNil(identity)
        let reloaded = ObservationStore(directory: directory)
        let after = await reloaded.identity(for: "/a")
        XCTAssertNil(after)
    }
}
