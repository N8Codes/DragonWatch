import XCTest

@testable import DragonWatch

final class RingBufferTests: XCTestCase {

    func testAppendBelowCapacityKeepsOrder() {
        var buffer = RingBuffer<Int>(capacity: 4)
        buffer.append(1)
        buffer.append(2)
        XCTAssertEqual(buffer.elements, [1, 2])
        XCTAssertFalse(buffer.isFull)
    }

    func testOverflowEvictsOldestFirst() {
        var buffer = RingBuffer<Int>(capacity: 3)
        for value in 1...5 { buffer.append(value) }
        XCTAssertEqual(buffer.elements, [3, 4, 5])
        XCTAssertEqual(buffer.count, 3)
        XCTAssertTrue(buffer.isFull)
    }
}

final class CPUTickDeltaTests: XCTestCase {

    func testNormalDelta() {
        let percent = VitalsSampler.cpuPercent(
            current: (user: 150, system: 75, idle: 750, nice: 25),
            previous: (user: 100, system: 50, idle: 500, nice: 0))
        // busy 100 of total 350
        XCTAssertEqual(percent, 100.0 / 350.0 * 100.0, accuracy: 0.001)
    }

    /// The counters are cumulative UInt32s that wrap after weeks of uptime —
    /// this input crashed the naive UInt64 subtraction (underflow trap).
    func testCounterWrapDoesNotTrapAndStaysSane() {
        let percent = VitalsSampler.cpuPercent(
            current: (user: 40, system: 20, idle: 240, nice: 0),
            previous: (
                user: UInt32.max - 60, system: UInt32.max - 80,
                idle: UInt32.max - 60, nice: 0
            ))
        // deltas: user 101, system 101, idle 301 → busy 202 of 503
        XCTAssertEqual(percent, 202.0 / 503.0 * 100.0, accuracy: 0.001)
    }

    func testNoElapsedTicksReadsAsZero() {
        let ticks: VitalsSampler.CPUTicks = (user: 5, system: 5, idle: 5, nice: 5)
        XCTAssertEqual(VitalsSampler.cpuPercent(current: ticks, previous: ticks), 0)
    }
}

final class ThroughputRateTests: XCTestCase {

    func testSimpleRate() {
        let rate = ThroughputSampler.rate(
            current: ["en0": (rx: 3_000_000, tx: 500_000)],
            previous: ["en0": (rx: 1_000_000, tx: 250_000)],
            seconds: 2)
        XCTAssertEqual(rate.rxPerSec, 1_000_000, accuracy: 0.1)
        XCTAssertEqual(rate.txPerSec, 125_000, accuracy: 0.1)
    }

    func testTrafficIsSummedAcrossInterfaces() {
        let rate = ThroughputSampler.rate(
            current: ["en0": (rx: 300, tx: 30), "en1": (rx: 700, tx: 70)],
            previous: ["en0": (rx: 100, tx: 10), "en1": (rx: 200, tx: 20)],
            seconds: 1)
        XCTAssertEqual(rate.rxPerSec, 700, accuracy: 0.1)
        XCTAssertEqual(rate.txPerSec, 70, accuracy: 0.1)
    }

    /// A VPN coming up mid-session brings a counter holding its whole
    /// lifetime. With the totals summed before differencing, that entire
    /// figure landed in one tick and the readout claimed hundreds of MB/s.
    func testAnInterfaceAppearingContributesNothingUntilItHasABaseline() {
        let previous = ["en0": (rx: UInt32(1000), tx: UInt32(100))]
        let appeared = [
            "en0": (rx: UInt32(1200), tx: UInt32(120)),
            "utun4": (rx: UInt32(900_000_000), tx: UInt32(900_000_000)),
        ]
        let rate = ThroughputSampler.rate(
            current: appeared, previous: previous, seconds: 1)
        XCTAssertEqual(rate.rxPerSec, 200, accuracy: 0.1, "only en0's real delta counts")
        XCTAssertEqual(rate.txPerSec, 20, accuracy: 0.1)

        // On the following tick it has a baseline and counts normally.
        let next = ThroughputSampler.rate(
            current: ["en0": (rx: 1200, tx: 120), "utun4": (rx: 900_000_500, tx: 900_000_000)],
            previous: appeared, seconds: 1)
        XCTAssertEqual(next.rxPerSec, 500, accuracy: 0.1)
    }

    func testAnInterfaceDisappearingDoesNotProduceANegativeOrHugeRate() {
        let rate = ThroughputSampler.rate(
            current: ["en0": (rx: 1200, tx: 120)],
            previous: ["en0": (rx: 1000, tx: 100), "utun4": (rx: 5_000_000, tx: 5_000_000)],
            seconds: 1)
        XCTAssertEqual(rate.rxPerSec, 200, accuracy: 0.1)
        XCTAssertEqual(rate.txPerSec, 20, accuracy: 0.1)
    }

    /// A counter that went backwards is either a `UInt32` wrap or an interface
    /// recreated under the same name (a VPN reconnecting). They cannot be told
    /// apart from the counter, so the sample is skipped — a momentarily low
    /// reading beats inventing a multi-gigabyte spike.
    func testABackwardsCounterIsSkippedNotWrapped() {
        let rate = ThroughputSampler.rate(
            current: ["utun4": (rx: 1000, tx: 0)],
            previous: ["utun4": (rx: UInt32.max - 999, tx: 0)],
            seconds: 1)
        XCTAssertEqual(rate.rxPerSec, 0, accuracy: 0.1)
        XCTAssertGreaterThanOrEqual(rate.rxPerSec, 0, "a rate is never negative")
    }
}

final class AlertThrottleTests: XCTestCase {
    private let epoch = Date(timeIntervalSinceReferenceDate: 0)

    func testFirstFireAlwaysPasses() {
        var throttle = AlertThrottle()
        XCTAssertTrue(throttle.shouldFire(key: "cpu", cooldown: 60, now: epoch))
    }

    func testRefiresOnlyAfterCooldown() {
        var throttle = AlertThrottle()
        _ = throttle.shouldFire(key: "cpu", cooldown: 60, now: epoch)
        XCTAssertFalse(
            throttle.shouldFire(key: "cpu", cooldown: 60, now: epoch.addingTimeInterval(59)))
        XCTAssertTrue(
            throttle.shouldFire(key: "cpu", cooldown: 60, now: epoch.addingTimeInterval(61)))
    }

    func testKeysAreIndependent() {
        var throttle = AlertThrottle()
        _ = throttle.shouldFire(key: "cpu", cooldown: 60, now: epoch)
        XCTAssertTrue(throttle.shouldFire(key: "net", cooldown: 60, now: epoch))
    }
}

final class SustainedSpikeRuleTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 1000)

    private func samples(
        _ values: [Double], spacing: TimeInterval, endingAt end: Date
    ) -> [(date: Date, value: Double)] {
        values.enumerated().map { index, value in
            (
                date: end.addingTimeInterval(
                    -Double(values.count - 1 - index) * spacing), value: value
            )
        }
    }

    func testSustainedLoadFires() {
        let history = samples(
            Array(repeating: 90.0, count: 8), spacing: 25, endingAt: now)
        XCTAssertTrue(
            SustainedSpikeRule.isSpiking(
                samples: history, threshold: 85, window: 180, now: now))
    }

    func testBriefBurstNeverFires() {
        // Idle machine with two hot samples at the end.
        let history = samples(
            [5, 5, 5, 5, 5, 5, 95, 95], spacing: 25, endingAt: now)
        XCTAssertFalse(
            SustainedSpikeRule.isSpiking(
                samples: history, threshold: 85, window: 180, now: now))
    }

    func testInsufficientCoverageNeverFires() {
        // Hot, but the samples only span ~50 s of a 180 s window (just launched).
        let history = samples(
            Array(repeating: 95.0, count: 3), spacing: 25, endingAt: now)
        XCTAssertFalse(
            SustainedSpikeRule.isSpiking(
                samples: history, threshold: 85, window: 180, now: now))
    }

    func testDipInsideWindowResets() {
        let history = samples(
            [90, 90, 90, 40, 90, 90, 90, 90], spacing: 25, endingAt: now)
        XCTAssertFalse(
            SustainedSpikeRule.isSpiking(
                samples: history, threshold: 85, window: 180, now: now))
    }

    func testOldSamplesOutsideWindowAreIgnored() {
        // A dip 10 minutes ago must not block a genuinely sustained spike now.
        let old = [(date: now.addingTimeInterval(-600), value: 5.0)]
        let recent = samples(
            Array(repeating: 90.0, count: 8), spacing: 25, endingAt: now)
        XCTAssertTrue(
            SustainedSpikeRule.isSpiking(
                samples: old + recent, threshold: 85, window: 180, now: now))
    }
}
