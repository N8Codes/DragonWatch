import XCTest

@testable import DragonWatch

final class UnclassifiedFormatTests: XCTestCase {

    // MARK: - Backward compatibility

    /// The field added in this phase must be optional.
    ///
    /// Synthesised `Decodable` throws `keyNotFound` for a missing
    /// non-optional key even when the property has a default, and
    /// `ObservationStore` treats a decode failure as an unknown schema and
    /// moves the file aside. A required field here would have discarded every
    /// existing user's history on first launch after the update.
    func testLedgerWrittenBeforeThisFieldExistedStillDecodes() throws {
        let legacy = """
            {
              "schemaVersion": 1,
              "identities": {},
              "events": []
            }
            """
        let ledger = try JSONDecoder().decode(
            ObservationLedger.self, from: Data(legacy.utf8))
        XCTAssertEqual(ledger.schemaVersion, ObservationLedger.currentSchemaVersion)
        XCTAssertNil(ledger.unclassified)
    }

    /// End to end through the store, which is where the history would be lost.
    func testStoreKeepsHistoryFromALedgerWithoutTheNewField() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Legacy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let legacy = """
            {
              "schemaVersion": 1,
              "identities": {},
              "events": [
                {"date": 750000000, "kind": "newUntrustedProcess",
                 "title": "old event", "detail": "from before the update"}
              ]
            }
            """
        try Data(legacy.utf8).write(
            to: dir.appendingPathComponent("observations.json"))

        let store = ObservationStore(directory: dir)
        let events = await store.events()
        XCTAssertEqual(events.count, 1, "the pre-existing history must survive")
        XCTAssertEqual(events.first?.title, "old event")
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: dir.appendingPathComponent("observations.json.bak").path),
            "the ledger must not have been moved aside as an unknown schema")
    }

    // MARK: - Recording

    func testRepeatSightingsCountUpRatherThanDuplicate() {
        var ledger = ObservationLedger()
        let now = Date()
        for index in 0..<3 {
            ledger.observeUnclassified(
                magicPrefix: "deadbeef", fileExtension: "xyz",
                now: now.addingTimeInterval(Double(index)))
        }
        XCTAssertEqual(ledger.unclassified?.count, 1)
        XCTAssertEqual(ledger.unclassified?.first?.timesSeen, 3)
        XCTAssertEqual(ledger.unclassified?.first?.firstSeen, now)
        XCTAssertEqual(ledger.unclassified?.first?.lastSeen, now.addingTimeInterval(2))
    }

    /// The same bytes under a different extension is a different thing to
    /// have seen, so the key is both.
    func testSameBytesUnderADifferentExtensionIsASeparateEntry() {
        var ledger = ObservationLedger()
        ledger.observeUnclassified(magicPrefix: "aabb", fileExtension: "foo", now: Date())
        ledger.observeUnclassified(magicPrefix: "aabb", fileExtension: "bar", now: Date())
        XCTAssertEqual(ledger.unclassified?.count, 2)
    }

    func testTheListIsCapped() {
        var ledger = ObservationLedger()
        let now = Date()
        for index in 0..<(ObservationLedger.unclassifiedCap + 50) {
            ledger.observeUnclassified(
                magicPrefix: String(format: "%08x", index), fileExtension: "x", now: now)
        }
        XCTAssertEqual(ledger.unclassified?.count, ObservationLedger.unclassifiedCap)
    }

    // MARK: - Labelling

    func testLabellingStoresAndClears() throws {
        var ledger = ObservationLedger()
        ledger.observeUnclassified(magicPrefix: "aabb", fileExtension: "foo", now: Date())
        let id = try XCTUnwrap(ledger.unclassified?.first?.id)

        XCTAssertTrue(ledger.labelUnclassified(id: id, label: "Blender project"))
        XCTAssertEqual(ledger.unclassified?.first?.label, "Blender project")

        // No change means no write.
        XCTAssertFalse(ledger.labelUnclassified(id: id, label: "Blender project"))

        // Whitespace-only clears rather than storing a blank.
        XCTAssertTrue(ledger.labelUnclassified(id: id, label: "   "))
        XCTAssertNil(ledger.unclassified?.first?.label)

        XCTAssertFalse(ledger.labelUnclassified(id: "no-such-id", label: "x"))
    }

    /// A label says what a format is. It must not silence anything — the
    /// baseline's "expected" verdict hides a path forever, and that would be
    /// exactly the wrong behaviour here.
    func testALabelDoesNotSuppressFindings() {
        var ledger = ObservationLedger()
        ledger.observeUnclassified(magicPrefix: "0102", fileExtension: "zzz", now: Date())
        ledger.labelUnclassified(
            id: ledger.unclassified!.first!.id, label: "My tool's project file")

        // The rule that produced the entry still fires for such a file.
        let subject = FileProbe(
            path: "/tmp/a.zzz", displayName: "a.zzz", size: 4,
            head: Data([0x01, 0x02, 0x03, 0x04]), tail: Data([0x01, 0x02, 0x03, 0x04]),
            tailOffset: 0, isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: false)
        let findings = UniversalChecks.run(probe: subject, identified: nil)
        XCTAssertTrue(findings.map(\.rule).contains("magic.unclassified"))
    }

    // MARK: - Ordering

    func testStoreReturnsAStableOrder() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Order-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = ObservationStore(directory: dir)
        let now = Date()
        // Same timestamp, so only the id tiebreak makes the order total.
        await store.observeUnclassified(
            [("cccc", "a"), ("aaaa", "b"), ("bbbb", "c")], now: now)

        let first = await store.unclassifiedFormats().map(\.id)
        for _ in 0..<8 {
            let repeated = await store.unclassifiedFormats().map(\.id)
            XCTAssertEqual(repeated, first)
        }
        XCTAssertEqual(first.count, 3)
    }

    // MARK: - The engine records the bytes, not prose

    func testEngineAttachesTheMagicPrefixForUnidentifiedFiles() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Prefix-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let unknown = dir.appendingPathComponent("thing.zzz")
        try Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]).write(to: unknown)
        let jpeg = dir.appendingPathComponent("real.jpg")
        try (Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data([0xFF, 0xD9])).write(to: jpeg)

        let report = await InspectionEngine().inspect(paths: [unknown.path, jpeg.path])
        let byName = Dictionary(uniqueKeysWithValues: report.files.map { ($0.displayName, $0) })

        XCTAssertEqual(byName["thing.zzz"]?.magicPrefix, "deadbeef0102")
        XCTAssertNil(
            byName["real.jpg"]?.magicPrefix, "an identified file needs no magic recorded")
    }

    /// The whole path a real run takes: engine identifies nothing, the bytes
    /// reach the ledger, and a second run counts up rather than duplicating.
    ///
    /// Driven through the engine and a store in a temp directory rather than
    /// through `AppModel`, which has no directory override and would write to
    /// the real Application Support ledger.
    func testEngineResultsReachTheLedger() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("E2E-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let unknown = dir.appendingPathComponent("project.zzz")
        try Data([0x5A, 0x5A, 0x01, 0x00, 0xFE]).write(to: unknown)

        let store = ObservationStore(directory: dir)
        for _ in 0..<2 {
            let report = await InspectionEngine().inspect(paths: [unknown.path])
            let unrecognised = report.files.compactMap { file -> (String, String)? in
                guard let prefix = file.magicPrefix else { return nil }
                return (prefix, file.declaredExtension)
            }
            await store.observeUnclassified(unrecognised)
        }

        let learned = await store.unclassifiedFormats()
        XCTAssertEqual(learned.count, 1)
        XCTAssertEqual(learned[0].magicPrefix, "5a5a0100fe")
        XCTAssertEqual(learned[0].fileExtension, "zzz")
        XCTAssertEqual(learned[0].timesSeen, 2, "a repeat sighting counts up")
        XCTAssertNil(learned[0].label)
    }
}
