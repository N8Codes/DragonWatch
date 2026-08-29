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
            process(pid: 1, path: "/usr/bin/zsh", cpu: 90, tier: .developerID),
            process(pid: 2, path: "/usr/bin/awk", cpu: 0, tier: .developerID),
            process(pid: 3, path: "/tmp/evil", cpu: 0, tier: .unsigned),
        ])
        XCTAssertEqual(groups.map(\.name), ["evil", "awk", "zsh"])
    }

    /// The anti-jump guarantee: CPU changes between samples must never
    /// reorder rows — the numbers update in place instead.
    func testOrderIsStableAcrossCPUChanges() {
        let first = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/alpha", cpu: 5, tier: .developerID),
            process(pid: 2, path: "/usr/bin/beta", cpu: 95, tier: .developerID),
        ])
        let second = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/alpha", cpu: 95, tier: .developerID),
            process(pid: 2, path: "/usr/bin/beta", cpu: 5, tier: .developerID),
        ])
        XCTAssertEqual(first.map(\.name), second.map(\.name))
        XCTAssertEqual(first.map(\.name), ["alpha", "beta"])
    }

    func testNameSortModesIgnoreBadges() {
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/usr/bin/zsh", cpu: 0, tier: .developerID),
            process(pid: 2, path: "/tmp/evil", cpu: 0, tier: .unsigned),
            process(pid: 3, path: "/usr/bin/awk", cpu: 0, tier: .developerID),
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
        let versioned = groups.first { $0.name == "toolkit" }
        let zsh = groups.first { $0.name == "zsh" }
        XCTAssertEqual(versioned?.contextHint, "2.1.222", "one version: say which")
        XCTAssertEqual(versioned?.members.map(\.record.name), ["2.1.222"])
        XCTAssertNil(zsh?.contextHint)
    }

    /// Three sessions on three versions are one product. The folder names
    /// it; a known agent gets its product name and no per-version noise.
    func testVersionedBinariesFoldByOriginAndAgentsGetTheirProductName() {
        let home = NSHomeDirectory()
        let groups = ProcessGrouper.group([
            process(
                pid: 1, path: home + "/.local/share/claude/versions/2.1.246", cpu: 0,
                tier: .developerID),
            process(
                pid: 2, path: home + "/.local/share/claude/versions/2.1.248", cpu: 0,
                tier: .developerID),
            process(
                pid: 3, path: home + "/.local/share/claude/versions/2.1.251", cpu: 0,
                tier: .developerID),
            process(
                pid: 4, path: home + "/.local/share/toolkit/versions/1.0", cpu: 0,
                tier: .developerID),
        ])
        let claude = groups.first { $0.name == "Claude Code" }
        XCTAssertEqual(claude?.members.map(\.record.name), ["2.1.246", "2.1.248", "2.1.251"])
        XCTAssertNil(claude?.contextHint, "several versions: the expanded rows say which")
        XCTAssertTrue(ProcessGrouper.isAgentGroup(claude!))
        let toolkit = groups.first { $0.name == "toolkit" }
        XCTAssertEqual(toolkit?.members.count, 1)
        XCTAssertFalse(ProcessGrouper.isAgentGroup(toolkit!))
        XCTAssertTrue(
            ProcessFilter.apply("claude", to: groups).contains { $0.name == "Claude Code" },
            "searching the folder name still finds the product")
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
        XCTAssertEqual(ProcessFilter.apply("toolkit", to: groups).map(\.name), ["toolkit"])
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

    /// Apple's bare daemons fold into one row; everything else keeps its own.
    func testAppleDaemonsCollapseIntoTheSystemGroup() {
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/sbin/launchd", cpu: 0, tier: .applePlatform),
            process(pid: 2, path: "/usr/libexec/trustd", cpu: 0, tier: .applePlatform),
            process(pid: 3, path: "/usr/sbin/root-only", cpu: 0, tier: .osManagedUnreadable),
            process(pid: 4, path: "/usr/local/bin/node", cpu: 0, tier: .unsigned),
            process(
                pid: 5, path: "/System/Applications/Mail.app/Contents/MacOS/Mail", cpu: 0,
                tier: .applePlatform),
        ])
        let system = groups.first { $0.key == ProcessGrouper.systemGroupKey }
        XCTAssertEqual(system?.name, ProcessGrouper.systemGroupName)
        XCTAssertEqual(system?.members.map(\.record.pid), [1, 3, 2], "name order inside the group")
        XCTAssertNil(system?.appBundlePath)
        XCTAssertEqual(
            groups.first { $0.name == "node" }?.members.count, 1, "non-Apple stays alone")
        XCTAssertEqual(
            groups.first { $0.name == "Mail" }?.appBundlePath, "/System/Applications/Mail.app",
            "Apple *apps* stay apps")
    }

    /// The fold can never hide a bad member because nothing non-trusted can
    /// get in: only Apple-platform and OS-managed tiers qualify, both rate
    /// Trusted, and Apple platform binaries are exempt from context demotion.
    func testNothingNonTrustedEntersTheSystemGroup() {
        for tier in [
            SignatureTier.developerID, .appStore, .validSigned, .adHoc, .unsigned, .invalid,
            .unreadable,
        ] {
            XCTAssertFalse(
                ProcessGrouper.isSystemDaemon(
                    process(pid: 9, path: "/usr/libexec/x", cpu: 0, tier: tier)),
                "\(tier) must not fold into the system group")
        }
        var me = process(pid: 10, path: "/usr/libexec/dw", cpu: 0, tier: .applePlatform)
        me = MonitoredProcess(
            record: me.record,
            trust: {
                var t = me.trust
                t.isSelf = true
                return t
            }())
        XCTAssertFalse(ProcessGrouper.isSystemDaemon(me), "DragonWatch itself keeps its own row")
        let groups = ProcessGrouper.group([
            process(pid: 1, path: "/sbin/launchd", cpu: 0, tier: .applePlatform),
            process(pid: 2, path: "/usr/libexec/trustd", cpu: 0, tier: .applePlatform),
        ])
        XCTAssertEqual(
            groups.first { $0.key == ProcessGrouper.systemGroupKey }?.worstBadge, .trusted)
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
