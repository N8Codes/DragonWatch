import XCTest

@testable import DragonWatch

/// The privacy contract: with the popover closed, DragonWatch makes no
/// network requests at all (intel aside). These pin the gate that guarantees
/// it — a regression here would resume ~1,400 background requests a day.
@MainActor
final class LatencyProbeGatingTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 10_000)

    private func shouldProbe(
        open: Bool, up: Bool = true, secondsSinceLast: TimeInterval = 120
    ) -> Bool {
        AppModel.shouldProbeLatency(
            popoverOpen: open, networkUp: up,
            lastProbe: now.addingTimeInterval(-secondsSinceLast), now: now,
            interval: 60)
    }

    func testNeverProbesWhileThePopoverIsClosed() {
        XCTAssertFalse(shouldProbe(open: false))
        XCTAssertFalse(shouldProbe(open: false, secondsSinceLast: 86_400))
    }

    func testProbesWhenOpenAndTheIntervalHasElapsed() {
        XCTAssertTrue(shouldProbe(open: true))
    }

    func testWaitsOutTheIntervalWhileOpen() {
        XCTAssertFalse(shouldProbe(open: true, secondsSinceLast: 59))
        XCTAssertTrue(shouldProbe(open: true, secondsSinceLast: 60))
    }

    func testNeverProbesWhileOffline() {
        XCTAssertFalse(shouldProbe(open: true, up: false))
    }
}
