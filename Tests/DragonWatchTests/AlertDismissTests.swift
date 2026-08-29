import XCTest

@testable import DragonWatch

final class AlertDismissTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 0)

    private func event(_ title: String) -> ObservationLedger.Event {
        .init(date: now, kind: "newUntrustedProcess", title: title, detail: "d")
    }

    func testLedgerRemovesExactlyTheMatchingEvent() {
        var ledger = ObservationLedger()
        ledger.record(event: event("a"))
        ledger.record(event: event("b"))
        XCTAssertTrue(ledger.remove(event: event("a")))
        XCTAssertEqual(ledger.events.map(\.title), ["b"])
        // A near miss — same title, different date — is a different alert.
        let other = ObservationLedger.Event(
            date: now.addingTimeInterval(1), kind: "newUntrustedProcess", title: "b", detail: "d")
        XCTAssertFalse(ledger.remove(event: other))
        XCTAssertEqual(ledger.events.count, 1)
    }

    func testStoreDismissalSurvivesRelaunch() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dw-dismiss-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ObservationStore(directory: directory)
        await store.record(event: event("keep"))
        await store.record(event: event("drop"))
        await store.remove(event: event("drop"))
        let reloaded = ObservationStore(directory: directory)
        let titles = await reloaded.events().map(\.title)
        XCTAssertEqual(titles, ["keep"], "a dismissed alert must not come back on relaunch")
    }

    @MainActor
    func testAlertCenterDismissRemovesOnlyThatAlert() {
        let center = AlertCenter(canNotify: false)
        center.raise(
            .newUntrustedProcess, key: "/a", cooldown: 60, title: "a", detail: "", now: now)
        center.raise(
            .newUntrustedProcess, key: "/b", cooldown: 60, title: "b", detail: "", now: now)
        XCTAssertEqual(center.unreadCount, 2)
        let first = center.history[0]
        center.dismiss(first.id)
        XCTAssertEqual(center.history.map(\.title), ["a"])
        XCTAssertEqual(center.unreadCount, 2, "dismissing does not mark the rest read")
        center.dismiss(center.history[0].id)
        XCTAssertTrue(center.history.isEmpty)
        XCTAssertEqual(center.unreadCount, 0, "an empty list has nothing unread")
    }
}
