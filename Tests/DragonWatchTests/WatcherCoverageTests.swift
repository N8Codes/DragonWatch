import XCTest

@testable import DragonWatch

/// Gaps in what the watcher could see or remember.
final class WatcherCoverageTests: XCTestCase {
    private var directory: URL!
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("WatcherCoverage-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func assessment(_ tier: SignatureTier) -> TrustAssessment {
        TrustAssessment(tier: tier, modifiers: [], teamID: nil, signingID: nil)
    }

    // MARK: - A process whose executable is gone

    func testDeletedExecutableStandInPath() {
        XCTAssertEqual(
            ProcessSampler.deletedExecutablePath(executedAs: "/tmp/x/tool", commandName: "tool"),
            "/tmp/x/tool (deleted)")
        // A relative path cannot be resolved afterwards; the name is kept.
        XCTAssertEqual(
            ProcessSampler.deletedExecutablePath(executedAs: "./tool", commandName: "tool"),
            "tool (deleted)")
        XCTAssertEqual(
            ProcessSampler.deletedExecutablePath(executedAs: nil, commandName: "rootd"),
            "rootd (deleted)")
        XCTAssertNil(ProcessSampler.deletedExecutablePath(executedAs: nil, commandName: ""))
    }

    func testMissingExecutableRatesCautionAndInspectsNothing() async {
        // A real, strongly signed file sits at the path — as after an app
        // update. It must not lend its rating to the process that is running.
        let assessment = await TrustEngine().assess(
            path: "/bin/ls", pid: 1, executableMissing: true)
        XCTAssertEqual(assessment.tier, .executableMissing)
        XCTAssertEqual(assessment.badge, .caution)
        XCTAssertTrue(assessment.modifiers.isEmpty)
        XCTAssertFalse(TrustExplanation.signatureExplanation(.executableMissing).isEmpty)
    }

    /// Live: a program that deletes its own file used to vanish from the
    /// sample, because the kernel no longer has a path for it.
    func testProcessThatDeletedItsExecutableIsStillSampled() async throws {
        let source = directory.appendingPathComponent("sleeper.c")
        try "#include <unistd.h>\nint main(void){sleep(30);return 0;}\n"
            .write(to: source, atomically: true, encoding: .utf8)
        let binary = directory.appendingPathComponent("sleeper")
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
        compiler.arguments = ["-o", binary.path, source.path]
        compiler.standardError = FileHandle.nullDevice
        do { try compiler.run() } catch { throw XCTSkip("no C compiler") }
        compiler.waitUntilExit()
        try XCTSkipUnless(compiler.terminationStatus == 0, "no C compiler")

        let sleeper = Process()
        sleeper.executableURL = binary
        try sleeper.run()
        defer { sleeper.terminate() }
        // Let the child finish exec before its file goes; deleting earlier
        // races the launch itself.
        try await Task.sleep(for: .milliseconds(400))
        try FileManager.default.removeItem(at: binary)

        let records = await ProcessSampler().sample()
        let record = try XCTUnwrap(
            records.first { $0.pid == sleeper.processIdentifier },
            "the process must not disappear with its file")
        XCTAssertTrue(record.executableMissing)
        XCTAssertTrue(record.path.hasSuffix("/sleeper" + ProcessSampler.deletedMarker), record.path)
    }

    /// Launch checks every running program's signature; done one at a time
    /// that took half a minute. The parallel pass must give the same answers.
    func testParallelWarmUpMatchesSerialAssessment() async {
        let paths = ["/bin/ls", "/bin/zsh", "/usr/bin/true", "/usr/bin/env", "/nonexistent-x"]
        let serial = TrustEngine()
        let warmed = TrustEngine()
        await warmed.warm(paths: paths + paths)
        for path in paths {
            let expected = await serial.assess(path: path)
            let actual = await warmed.assess(path: path)
            XCTAssertEqual(actual.tier, expected.tier, path)
            XCTAssertEqual(actual.modifiers, expected.modifiers, path)
        }
    }

    /// App memory is anonymous pages less purgeable ones; wired and
    /// compressed are added. Purgeable can never push the figure negative.
    func testMemoryUsedFollowsActivityMonitorsDefinition() {
        XCTAssertEqual(
            VitalsSampler.memoryUsed(
                anonymous: 100, purgeable: 10, wired: 20, compressed: 5, pageSize: 4096),
            115 * 4096)
        XCTAssertEqual(
            VitalsSampler.memoryUsed(
                anonymous: 5, purgeable: 50, wired: 1, compressed: 1, pageSize: 4096),
            2 * 4096)
    }

    // MARK: - Persistence items that change

    func testRewrittenPersistenceItemIsReportedOncePerContents() {
        var ledger = BaselineLedger()
        let item = "/Library/LaunchAgents/a.plist"
        XCTAssertTrue(ledger.observePersistenceItem(item))
        XCTAssertFalse(
            ledger.observePersistenceFingerprint(path: item, fingerprint: "aaa"),
            "the first reading is recorded, not reported")
        XCTAssertFalse(ledger.observePersistenceFingerprint(path: item, fingerprint: "aaa"))
        XCTAssertTrue(ledger.observePersistenceFingerprint(path: item, fingerprint: "bbb"))
        XCTAssertFalse(ledger.observePersistenceFingerprint(path: item, fingerprint: "bbb"))
    }

    func testLedgerWithoutFingerprintsStillDecodes() throws {
        let old = Data(#"{"executables":{},"persistenceItems":["/a.plist"]}"#.utf8)
        var ledger = try JSONDecoder().decode(BaselineLedger.self, from: old)
        XCTAssertFalse(ledger.observePersistenceFingerprint(path: "/a.plist", fingerprint: "x"))
    }

    /// An edit that restores the modification time is still seen: the
    /// status-change time moves and cannot be set back.
    func testContentChangeIsSeenEvenWithTheModificationTimeRestored() async throws {
        let plist = directory.appendingPathComponent("agent.plist")
        try Data("<plist>/usr/bin/true</plist>".utf8).write(to: plist)
        let original = try XCTUnwrap(
            FileManager.default.attributesOfItem(atPath: plist.path)[.modificationDate] as? Date)
        let contents = PersistenceContents()
        let before = await contents.fingerprints(of: [plist.path])[plist.path]
        XCTAssertNotNil(before)

        let handle = try FileHandle(forWritingTo: plist)  // same inode, same length
        try handle.write(contentsOf: Data("<plist>/usr/bin/evil</plist>".utf8))
        try handle.close()
        try FileManager.default.setAttributes(
            [.modificationDate: original], ofItemAtPath: plist.path)

        let after = await contents.fingerprints(of: [plist.path])[plist.path]
        XCTAssertNotEqual(before, after)
    }

    // MARK: - Ledgers that stop growing

    func testUnansweredEntriesExpireButVerdictsAreKept() {
        var ledger = BaselineLedger()
        for path in ["/pending", "/trusted", "/expected", "/flagged", "/ignored", "/running"] {
            _ = ledger.observe(
                path: path, assessment: assessment(path == "/trusted" ? .developerID : .adHoc),
                now: now)
        }
        ledger.recordVerdict(path: "/expected", verdict: .expected)
        ledger.recordVerdict(path: "/flagged", verdict: .keepFlagging)
        ledger.recordVerdict(path: "/ignored", verdict: .ignored)

        let later = now.addingTimeInterval(40 * 86400)
        XCTAssertTrue(ledger.refreshLastSeen(["/running"], now: later))
        XCTAssertEqual(ledger.prune(now: later, unseenFor: 30 * 86400), 2)
        XCTAssertEqual(
            Set(ledger.executables.keys), ["/expected", "/flagged", "/ignored", "/running"])
    }

    func testLastSeenIsRewrittenAtMostOnceADay() {
        var ledger = BaselineLedger()
        _ = ledger.observe(path: "/x", assessment: assessment(.adHoc), now: now)
        XCTAssertFalse(ledger.refreshLastSeen(["/x"], now: now.addingTimeInterval(3600)))
        XCTAssertTrue(ledger.refreshLastSeen(["/x"], now: now.addingTimeInterval(86400)))
    }

    func testObservationIdentitiesExpireWithTheRetention() {
        var ledger = ObservationLedger()
        _ = ledger.observe(path: "/old", tier: .adHoc, now: now)
        let later = now.addingTimeInterval(40 * 86400)
        _ = ledger.observe(path: "/current", tier: .adHoc, now: later)
        ledger.prune(now: later, eventRetention: 30 * 86400)
        XCTAssertEqual(Set(ledger.identities.keys), ["/current"])
    }

    // MARK: - An agent's name is not its identity

    func testUnsignedBinaryInAnAgentNamedFolderGetsNoProductIdentity() {
        func process(_ pid: pid_t, _ path: String, _ tier: SignatureTier) -> MonitoredProcess {
            MonitoredProcess(
                record: ProcessRecord(
                    pid: pid, path: path, name: (path as NSString).lastPathComponent,
                    cpuPercent: 0, residentBytes: 0),
                trust: assessment(tier))
        }
        let groups = ProcessGrouper.group([
            process(1, "/Users/me/.local/share/claude/versions/1.0.8", .developerID),
            process(2, "/tmp/claude/helper", .unsigned),
        ])
        let real = groups.first { $0.name == "Claude Code" }
        XCTAssertEqual(real?.members.map(\.id), [1], "the impostor must not join the real row")
        let impostor = groups.first { $0.members.contains { $0.id == 2 } }
        XCTAssertEqual(impostor?.name, "claude")
        XCTAssertFalse(ProcessGrouper.isAgentGroup(impostor!))
    }
}
