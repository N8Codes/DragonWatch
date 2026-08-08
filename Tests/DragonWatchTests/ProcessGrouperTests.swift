import XCTest

@testable import DragonWatch

/// The per-process CPU maths, exercised deterministically — the live probe in
/// SystemProbeTests can only smoke-test it, and timing-based assertions are
/// the wrong place to pin arithmetic.
final class ProcessCPUAccountingTests: XCTestCase {

    func testOneFullyBusyCoreReadsOneHundredPercent() {
        let percent = ProcessSampler.cpuPercent(
            cpuTimeNs: 1_000_000_000, previousCPUTimeNs: 0,
            wallDeltaNs: 1_000_000_000)
        XCTAssertEqual(percent, 100, accuracy: 0.001)
    }

    func testMulticoreWorkCanExceedOneHundredPercent() {
        // Four cores busy for a one-second wall interval.
        let percent = ProcessSampler.cpuPercent(
            cpuTimeNs: 4_000_000_000, previousCPUTimeNs: 0,
            wallDeltaNs: 1_000_000_000)
        XCTAssertEqual(percent, 400, accuracy: 0.001)
    }

    func testFirstSightingOfAProcessReadsZero() {
        XCTAssertEqual(
            ProcessSampler.cpuPercent(
                cpuTimeNs: 5_000_000, previousCPUTimeNs: nil,
                wallDeltaNs: 1_000_000_000),
            0)
    }

    /// A recycled pid can present a *smaller* counter than the previous
    /// sample; that must read as zero, not as a negative or absurd spike.
    func testCounterMovingBackwardsReadsZero() {
        XCTAssertEqual(
            ProcessSampler.cpuPercent(
                cpuTimeNs: 10, previousCPUTimeNs: 5_000_000_000,
                wallDeltaNs: 1_000_000_000),
            0)
    }

    func testZeroWallDeltaCannotDivideByZero() {
        XCTAssertEqual(
            ProcessSampler.cpuPercent(
                cpuTimeNs: 5_000_000_000, previousCPUTimeNs: 0, wallDeltaNs: 0),
            0)
    }
}

final class ProcessGrouperTests: XCTestCase {

    private func process(
        pid: pid_t, path: String, cpu: Double, tier: SignatureTier
    ) -> MonitoredProcess {
        MonitoredProcess(
            record: ProcessRecord(
                pid: pid, path: path,
                name: (path as NSString).lastPathComponent,
                cpuPercent: cpu, residentBytes: 1 << 20),
            trust: TrustAssessment(
                tier: tier, modifiers: [], teamID: nil, signingID: nil))
    }

    func testWorstBadgeFirstThenAlphabetical() {
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/zsh", cpu: 90, tier: .applePlatform),
            process(pid: 2, path: "/usr/bin/awk", cpu: 0, tier: .applePlatform),
            process(pid: 3, path: "/tmp/evil", cpu: 0, tier: .unsigned),
        ])
        XCTAssertEqual(groups.map(\.name), ["evil", "awk", "zsh"])
    }

    /// The anti-jump guarantee: CPU changes between samples must never
    /// reorder rows — the numbers update in place instead.
    func testOrderIsStableAcrossCPUChanges() {
        let first = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/alpha", cpu: 5, tier: .applePlatform),
            process(pid: 2, path: "/usr/bin/beta", cpu: 95, tier: .applePlatform),
        ])
        let second = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/alpha", cpu: 95, tier: .applePlatform),
            process(pid: 2, path: "/usr/bin/beta", cpu: 5, tier: .applePlatform),
        ])
        XCTAssertEqual(first.map(\.name), second.map(\.name))
        XCTAssertEqual(first.map(\.name), ["alpha", "beta"])
    }

    func testNameSortModesIgnoreBadges() {
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/zsh", cpu: 0, tier: .applePlatform),
            process(pid: 2, path: "/tmp/evil", cpu: 0, tier: .unsigned),
            process(pid: 3, path: "/usr/bin/awk", cpu: 0, tier: .applePlatform),
        ])
        XCTAssertEqual(
            ProcessListSort.riskFirst.apply(groups).map(\.name), ["evil", "awk", "zsh"])
        XCTAssertEqual(
            ProcessListSort.nameAscending.apply(groups).map(\.name),
            ["awk", "evil", "zsh"])
        XCTAssertEqual(
            ProcessListSort.nameDescending.apply(groups).map(\.name),
            ["zsh", "evil", "awk"])
    }

    func testAmbiguousBareBinaryGetsContextHint() {
        let groups = ProcessGrouper.group([
            process(
                pid: 1, path: NSHomeDirectory() + "/.local/share/toolkit/versions/2.1.222",
                cpu: 0, tier: .developerID),
            process(pid: 2, path: "/usr/bin/zsh", cpu: 0, tier: .applePlatform),
        ])
        let versioned = groups.first { $0.name == "2.1.222" }
        let zsh = groups.first { $0.name == "zsh" }
        XCTAssertEqual(versioned?.contextHint, "toolkit")
        XCTAssertNil(zsh?.contextHint)
    }

    func testFilterMatchesNameHintPathAndMembers() {
        let groups = ProcessGrouper.group([
            process(
                pid: 1, path: NSHomeDirectory() + "/.local/share/toolkit/versions/2.1.222",
                cpu: 0, tier: .developerID),
            process(pid: 2, path: "/tmp/evil", cpu: 0, tier: .unsigned),
            process(
                pid: 3, path: "/Applications/Safari.app/Contents/MacOS/Safari",
                cpu: 0, tier: .appStore),
            process(
                pid: 4, path: "/Applications/Safari.app/Contents/MacOS/SafariHelper",
                cpu: 0, tier: .appStore),
        ])
        // by group name
        XCTAssertEqual(ProcessFilter.apply("safari", to: groups).map(\.name), ["Safari"])
        // by context hint
        XCTAssertEqual(ProcessFilter.apply("toolkit", to: groups).map(\.name), ["2.1.222"])
        // by path fragment
        XCTAssertEqual(ProcessFilter.apply("/tmp", to: groups).map(\.name), ["evil"])
        // by a member process's name
        XCTAssertEqual(
            ProcessFilter.apply("safarihelper", to: groups).map(\.name), ["Safari"])
    }

    func testFilterIsCaseInsensitiveAndEmptyQueryPassesEverything() {
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/ZSH", cpu: 0, tier: .applePlatform)
        ])
        XCTAssertEqual(ProcessFilter.apply("zsh", to: groups).count, 1)
        XCTAssertEqual(ProcessFilter.apply("   ", to: groups).count, 1)
        XCTAssertEqual(ProcessFilter.apply("", to: groups).count, 1)
        XCTAssertTrue(ProcessFilter.apply("nomatch", to: groups).isEmpty)
    }

    func testHelpersGroupUnderAppAndSortByName() {
        let groups = ProcessGrouper.group([
            process(
                pid: 10, path: "/Applications/A.app/Contents/MacOS/Zed",
                cpu: 50, tier: .developerID),
            process(
                pid: 11, path: "/Applications/A.app/Contents/MacOS/Aid",
                cpu: 1, tier: .developerID),
        ])
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups[0].members.map(\.record.name), ["Aid", "Zed"])
    }
}
