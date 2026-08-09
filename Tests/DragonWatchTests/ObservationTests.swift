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
        XCTAssertFalse(ledger.recordHash(path: "/a", sha256: "aaa", stamp: nil, now: now))
        XCTAssertFalse(ledger.recordHash(path: "/a", sha256: "aaa", stamp: nil, now: later))
        XCTAssertTrue(ledger.recordHash(path: "/a", sha256: "bbb", stamp: nil, now: later))
        XCTAssertEqual(ledger.identities["/a"]?.sha256, "bbb")
        XCTAssertEqual(ledger.identities["/a"]?.transitions.last?.field, "hash")
        // Hash for an unknown path is dropped, not invented.
        XCTAssertFalse(ledger.recordHash(path: "/nope", sha256: "ccc", stamp: nil, now: now))
    }

    func testTransitionsAreCapped() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/a", tier: .adHoc, now: now)
        _ = ledger.recordHash(path: "/a", sha256: "h0", stamp: nil, now: now)
        for i in 1...(ObservationLedger.transitionCap + 10) {
            _ = ledger.recordHash(path: "/a", sha256: "h\(i)", stamp: nil, now: later)
        }
        XCTAssertEqual(
            ledger.identities["/a"]?.transitions.count, ObservationLedger.transitionCap)
    }

    func testHashQueueRespectsOrderAndLimit() {
        var ledger = ObservationLedger()
        for path in ["/a", "/b", "/c"] {
            _ = ledger.observe(path: path, tier: .adHoc, now: now)
        }
        let stamp = ObservationLedger.FileStamp(mtime: now, size: 1)
        _ = ledger.recordHash(path: "/b", sha256: "x", stamp: stamp, now: now)
        XCTAssertEqual(
            ledger.pathsNeedingHash(
                among: ["/c", "/b", "/a", "/unknown"], limit: 1, now: now
            ) { _ in stamp },
            ["/c"])
        XCTAssertEqual(
            ledger.pathsNeedingHash(among: ["/c", "/b", "/a"], limit: 5, now: now) {
                _ in stamp
            },
            ["/c", "/a"])
    }

    /// A hash that is never refreshed cannot detect anything. The queue only
    /// returned paths with no hash at all, so `recordHash`'s change branch was
    /// unreachable and a binary swapped on disk kept its original hash for
    /// good.
    func testAChangedFileIsQueuedForRehashing() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/a", tier: .adHoc, now: now)
        let original = ObservationLedger.FileStamp(mtime: now, size: 10)
        _ = ledger.recordHash(path: "/a", sha256: "aaa", stamp: original, now: now)

        XCTAssertEqual(
            ledger.pathsNeedingHash(among: ["/a"], limit: 5, now: later) { _ in original },
            [], "an unchanged file must not be re-hashed")

        let replaced = ObservationLedger.FileStamp(mtime: later, size: 99)
        XCTAssertEqual(
            ledger.pathsNeedingHash(among: ["/a"], limit: 5, now: later) { _ in replaced },
            ["/a"], "a changed file must be re-queued")

        XCTAssertTrue(
            ledger.recordHash(path: "/a", sha256: "bbb", stamp: replaced, now: later),
            "the re-hash must be reported as a change")
    }

    /// A Mac runs many root-owned binaries we cannot read. Without recording
    /// the failed attempt they stayed at the head of the three-per-tick queue
    /// permanently and nothing behind them was ever hashed.
    func testAnUnreadableFileDoesNotBlockTheQueueForever() {
        var ledger = ObservationLedger()
        for path in ["/unreadable", "/b"] {
            _ = ledger.observe(path: path, tier: .adHoc, now: now)
        }
        XCTAssertEqual(
            ledger.pathsNeedingHash(among: ["/unreadable", "/b"], limit: 1, now: now) {
                _ in nil
            },
            ["/unreadable"])

        ledger.recordHashAttemptFailed(path: "/unreadable", now: now)
        XCTAssertEqual(
            ledger.pathsNeedingHash(among: ["/unreadable", "/b"], limit: 1, now: now) {
                _ in nil
            },
            ["/b"], "the queue must move past a file it cannot read")

        let afterBackoff = now.addingTimeInterval(ObservationLedger.hashRetryInterval + 1)
        XCTAssertEqual(
            ledger.pathsNeedingHash(
                among: ["/unreadable"], limit: 1, now: afterBackoff
            ) { _ in nil },
            ["/unreadable"], "it is retried later, not abandoned")
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

/// The durable side of the alert record.
final class ObservationStoreEventTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ObservationStoreEventTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// "Clear" has to reach disk. Clearing only the in-memory list left the
    /// events in the ledger, and the next launch re-seeded the list from them
    /// — so the button appeared to work until you relaunched.
    func testClearingEventsSurvivesARelaunch() async {
        let store = ObservationStore(directory: directory)
        await store.record(
            event: .init(date: Date(), kind: "k", title: "t", detail: "d"))
        var events = await store.events()
        XCTAssertEqual(events.count, 1)

        await store.clearEvents()
        events = await store.events()
        XCTAssertTrue(events.isEmpty)

        let reloaded = ObservationStore(directory: directory)
        let afterRelaunch = await reloaded.events()
        XCTAssertTrue(afterRelaunch.isEmpty, "cleared history must stay cleared")
    }

    /// Clearing alerts must not discard the provenance record, which is a
    /// separate thing the user did not ask to delete.
    func testClearingEventsKeepsIdentities() async {
        let store = ObservationStore(directory: directory)
        _ = await store.observeBatch(
            [(path: "/tmp/a", tier: SignatureTier.adHoc)], now: Date(),
            eventRetention: 86400)
        await store.clearEvents()
        let identity = await store.identity(for: "/tmp/a")
        XCTAssertNotNil(identity, "provenance is not alert history")
    }
}
