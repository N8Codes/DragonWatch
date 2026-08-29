import XCTest

@testable import DragonWatch

final class LaunchContextTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 0)

    private func record(pid: pid_t, parent: pid_t?, path: String = "/x") -> ProcessRecord {
        ProcessRecord(
            pid: pid, path: path, name: (path as NSString).lastPathComponent,
            parentPID: parent, startedAt: now)
    }

    func testParentResolvesFromTheSameBatchFirst() {
        let context = LaunchContext.resolve(
            for: record(pid: 42, parent: 7), pathsByPID: [7: "/bin/zsh"],
            lookup: { _ in
                XCTFail("batch had the parent; no lookup needed"); return nil
            })
        XCTAssertEqual(context?.parentPID, 7)
        XCTAssertEqual(context?.parentPath, "/bin/zsh")
        XCTAssertEqual(context?.parentName, "zsh")
        XCTAssertEqual(context?.startedAt, now)
    }

    func testParentMissingFromBatchFallsBackToLookup() {
        let context = LaunchContext.resolve(
            for: record(pid: 42, parent: 7), pathsByPID: [:],
            lookup: { $0 == 7 ? "/sbin/launchd" : nil })
        XCTAssertEqual(context?.parentPath, "/sbin/launchd")
    }

    /// A parent that exited is still a fact worth keeping: the pid and the
    /// start time survive, and the summary says the parent is gone rather
    /// than inventing a name.
    func testExitedParentKeepsPIDAndSaysSo() {
        let context = LaunchContext.resolve(
            for: record(pid: 42, parent: 7), pathsByPID: [:], lookup: { _ in nil })
        XCTAssertEqual(context?.parentPath, nil)
        XCTAssertEqual(context?.summary, "exited process (pid 7)")
    }

    /// No BSD info record means unknown, not "launched by pid 0".
    func testNoParentInfoResolvesToNil() {
        XCTAssertNil(
            LaunchContext.resolve(
                for: record(pid: 42, parent: nil), pathsByPID: [:], lookup: { _ in "/never" }))
    }

    /// The chain is what tells a person an AI agent — not they — started it.
    func testAncestryWalksTheListingAndNamesTheAgentSession() throws {
        let paths: [pid_t: String] = [
            7083: "/bin/zsh", 6645: "/Users/me/.local/share/claude/versions/2.1.248",
            500: "/bin/zsh",
            400: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            1: "/sbin/launchd",
        ]
        let parents: [pid_t: pid_t] = [7083: 6645, 6645: 500, 500: 400, 400: 1, 1: 0]
        let context = try XCTUnwrap(
            LaunchContext.resolve(
                for: record(pid: 42, parent: 7083), pathsByPID: paths, parentsByPID: parents,
                lookup: { _ in nil }))
        XCTAssertEqual(
            context.ancestryDescription, "zsh ← 2.1.248 · claude ← zsh ← Terminal ← launchd")
        XCTAssertEqual(context.agentSession?.product, "Claude Code")
        XCTAssertEqual(context.agentSession?.pid, 6645)
        XCTAssertTrue(
            ProvenanceNote.suffix(launch: context, keg: nil).contains(
                "Inside a Claude Code session (pid 6645) — an AI agent, not you, started it."))
    }

    func testAncestryWithoutAnAgentIsQuiet() throws {
        let context = try XCTUnwrap(
            LaunchContext.resolve(
                for: record(pid: 42, parent: 500),
                pathsByPID: [
                    500: "/bin/zsh", 400: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
                    1: "/sbin/launchd",
                ],
                parentsByPID: [500: 400, 400: 1, 1: 0], lookup: { _ in nil }))
        XCTAssertNil(context.agentSession)
        XCTAssertEqual(context.ancestryDescription, "zsh ← iTerm2 ← launchd")
        XCTAssertFalse(ProvenanceNote.suffix(launch: context, keg: nil).contains("AI agent"))
    }

    /// A reused pid can make the parent chain loop; the walk must terminate.
    func testAncestryStopsOnACycleAndAtDepth() throws {
        let cyclic = try XCTUnwrap(
            LaunchContext.resolve(
                for: record(pid: 42, parent: 10), pathsByPID: [10: "/a", 11: "/b"],
                parentsByPID: [10: 11, 11: 10], lookup: { _ in nil }))
        XCTAssertEqual(cyclic.ancestors?.map(\.pid), [10, 11])
        // A plainly named agent binary matches on the name itself.
        let plain = LaunchContext(
            parentPID: 9, parentPath: "/bin/zsh", startedAt: nil,
            ancestors: [.init(pid: 9, name: "zsh"), .init(pid: 8, name: "codex")])
        XCTAssertEqual(plain.agentSession?.product, "Codex CLI")

        var paths: [pid_t: String] = [:]
        var parents: [pid_t: pid_t] = [:]
        for pid in pid_t(1)...pid_t(30) {
            paths[pid] = "/p\(pid)"
            parents[pid] = pid + 1
        }
        let deep = try XCTUnwrap(
            LaunchContext.resolve(
                for: record(pid: 42, parent: 1), pathsByPID: paths, parentsByPID: parents,
                lookup: { _ in nil }))
        XCTAssertEqual(deep.ancestors?.count, LaunchContext.ancestryDepth)
    }

    /// Ledgers written with the first shape of `launchedBy` (no ancestors)
    /// must still decode.
    func testLaunchContextWithoutAncestorsDecodes() throws {
        let json = #"{"parentPID":1,"parentPath":"/sbin/launchd","startedAt":0}"#
        let decoded = try JSONDecoder().decode(LaunchContext.self, from: Data(json.utf8))
        XCTAssertNil(decoded.ancestors)
        XCTAssertNil(decoded.agentSession)
        XCTAssertNil(decoded.ancestryDescription)
    }

    func testSummaryNamesTheParent() {
        let context = LaunchContext(parentPID: 7083, parentPath: "/bin/zsh", startedAt: nil)
        XCTAssertEqual(context.summary, "zsh (pid 7083)")
    }

    func testProvenanceNoteIsEmptyWithNothingToSay() {
        XCTAssertEqual(ProvenanceNote.suffix(launch: nil, keg: nil), "")
    }

    func testProvenanceNoteReadsAsSentencesAfterThePath() {
        let launch = LaunchContext(parentPID: 7083, parentPath: "/bin/zsh", startedAt: nil)
        let keg = HomebrewKeg(
            formula: "node", version: "25.9.0_3", installedAt: nil, pouredFromBottle: true)
        XCTAssertEqual(
            ProvenanceNote.suffix(launch: launch, keg: keg),
            " Launched by zsh (pid 7083) — /bin/zsh. Homebrew receipt: node 25.9.0_3, poured from bottle."
        )
        XCTAssertEqual(
            ProvenanceNote.suffix(launch: launch, keg: nil),
            " Launched by zsh (pid 7083) — /bin/zsh.")
    }

    // MARK: ledger

    func testLedgerRecordsLaunchOnFirstSightingOnly() {
        var ledger = ObservationLedger()
        let first = LaunchContext(parentPID: 1, parentPath: "/sbin/launchd", startedAt: now)
        let second = LaunchContext(parentPID: 9, parentPath: "/bin/zsh", startedAt: now)
        XCTAssertEqual(ledger.observe(path: "/a", tier: .unsigned, now: now, launch: first), .new)
        XCTAssertEqual(
            ledger.observe(path: "/a", tier: .unsigned, now: now, launch: second), .known)
        XCTAssertEqual(
            ledger.identities["/a"]?.launchedBy, first,
            "first launch is the one the alert was about")
    }

    func testLedgerWithoutLaunchStillWorks() {
        var ledger = ObservationLedger()
        XCTAssertEqual(ledger.observe(path: "/a", tier: .unsigned, now: now), .new)
        XCTAssertNil(ledger.identities["/a"]?.launchedBy)
    }

    /// Ledgers written before `launchedBy` existed must still decode — a
    /// schema bump would have thrown away every user's history for one
    /// optional field.
    func testOldLedgerJSONDecodesWithoutLaunchField() throws {
        let json = """
            {"schemaVersion":1,"events":[],"identities":{"/a":{"firstSeen":0,"lastSeen":0,"tier":"Unsigned","transitions":[]}}}
            """
        let ledger = try JSONDecoder().decode(ObservationLedger.self, from: Data(json.utf8))
        XCTAssertNil(ledger.identities["/a"]?.launchedBy)
        XCTAssertEqual(ledger.identities["/a"]?.tier, .unsigned)
    }

    func testLaunchContextRoundTripsThroughTheLedger() throws {
        var ledger = ObservationLedger()
        let launch = LaunchContext(parentPID: 7083, parentPath: "/bin/zsh", startedAt: now)
        _ = ledger.observe(path: "/a", tier: .unsigned, now: now, launch: launch)
        let data = try JSONEncoder().encode(ledger)
        let decoded = try JSONDecoder().decode(ObservationLedger.self, from: data)
        XCTAssertEqual(decoded.identities["/a"]?.launchedBy, launch)
    }

    // MARK: live

    /// The C shim against reality: the test runner's parent must be a real,
    /// visible process, and its start time must be in the past but recent.
    func testSamplerReportsOurRealParent() async throws {
        let records = await ProcessSampler().sample()
        let me = try XCTUnwrap(records.first { $0.pid == getpid() })
        XCTAssertEqual(me.parentPID, getppid())
        let started = try XCTUnwrap(me.startedAt)
        XCTAssertLessThan(started, Date())
        XCTAssertGreaterThan(started, Date().addingTimeInterval(-86400))
        XCTAssertEqual(ProcessSampler.path(forPID: getpid()), me.path)
        XCTAssertNil(ProcessSampler.path(forPID: 0))
    }

    /// Parentage must come back for processes we do not own — launchd is
    /// root's, and the persistence items worth watching are its children.
    /// `proc_pidinfo(PROC_PIDTBSDINFO)` fails this test; the sysctl passes.
    func testSamplerReportsParentageForRootProcesses() async throws {
        let records = await ProcessSampler().sample()
        let launchd = try XCTUnwrap(records.first { $0.pid == 1 })
        XCTAssertEqual(launchd.parentPID, 0, "launchd's parent is the kernel")
        XCTAssertNotNil(launchd.startedAt)
        let unknown = records.filter { $0.parentPID == nil }
        XCTAssertLessThan(
            unknown.count, max(1, records.count / 10),
            "parentage should be known for nearly every process, not just our own")
    }

    func testStorePersistsLaunchContextAcrossReload() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dw-launch-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let launch = LaunchContext(parentPID: 7083, parentPath: "/bin/zsh", startedAt: now)
        let store = ObservationStore(directory: directory)
        _ = await store.observeBatch([("/a", .unsigned, launch)], now: now, eventRetention: 86400)
        let reloaded = ObservationStore(directory: directory)
        let identity = await reloaded.identity(for: "/a")
        XCTAssertEqual(identity?.launchedBy, launch)
    }
}

final class HomebrewKegTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dw-keg-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testKegRootFromCellarPaths() {
        XCTAssertEqual(
            HomebrewKeg.kegRoot(of: "/usr/local/Cellar/node/25.9.0_3/bin/node"),
            "/usr/local/Cellar/node/25.9.0_3")
        XCTAssertEqual(
            HomebrewKeg.kegRoot(
                of:
                    "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python"
            ),
            "/opt/homebrew/Cellar/python@3.13/3.13.2")
    }

    /// A receipt outside Homebrew's own prefixes is a file anything could
    /// write; it must not lend a dropped binary a package-manager origin.
    func testCellarOutsideHomebrewPrefixesDoesNotCount() {
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/Users/me/Downloads/x/Cellar/tool/1.0/bin/tool"))
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/tmp/Cellar/tool/1.0/bin/tool"))
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/usr/local/Cellar//1.0/bin/tool"), "empty formula")
    }

    func testNonKegPathsHaveNoRoot() {
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/usr/bin/true"))
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/usr/local/bin/node"), "opt symlink, not the keg")
        XCTAssertNil(HomebrewKeg.kegRoot(of: "/usr/local/Cellar/node"), "formula dir, no version")
        XCTAssertNil(
            HomebrewKeg.kegRoot(of: "/usr/local/Cellar/node/25.9.0_3"),
            "the keg itself, not a file in it")
    }

    func testParseReadsTheReceiptFields() throws {
        let receipt = """
            {"time":1777775528,"poured_from_bottle":true,"installed_on_request":true,
             "source":{"tap":"homebrew/core","spec":"stable"}}
            """
        let keg = try XCTUnwrap(
            HomebrewKeg.parse(
                receipt: Data(receipt.utf8), kegRoot: "/usr/local/Cellar/node/25.9.0_3"))
        XCTAssertEqual(keg.formula, "node")
        XCTAssertEqual(keg.version, "25.9.0_3")
        XCTAssertEqual(keg.installedAt, Date(timeIntervalSince1970: 1_777_775_528))
        XCTAssertEqual(keg.pouredFromBottle, true)
        XCTAssertTrue(
            keg.summary.hasPrefix(
                "Homebrew receipt: node 25.9.0_3, poured from bottle, installed "))
    }

    func testParseToleratesMissingFields() throws {
        let keg = try XCTUnwrap(
            HomebrewKeg.parse(receipt: Data("{}".utf8), kegRoot: "/usr/local/Cellar/x/1.0"))
        XCTAssertNil(keg.installedAt)
        XCTAssertNil(keg.pouredFromBottle)
        XCTAssertEqual(keg.summary, "Homebrew receipt: x 1.0")
        XCTAssertNil(
            HomebrewKeg.parse(receipt: Data("not json".utf8), kegRoot: "/usr/local/Cellar/x/1.0"))
    }

    /// `locate` reads only inside Homebrew's prefixes, which tests cannot
    /// write to, so the read is exercised against a keg with no receipt and
    /// against a receipt outside the prefixes, which must be ignored even
    /// though it parses.
    func testLocateNeedsAReceiptInsideARealPrefix() throws {
        XCTAssertNil(
            HomebrewKeg.locate(path: "/usr/local/Cellar/definitely-not-a-formula/1.0/bin/x"),
            "no keg, no receipt, no provenance")
        let keg = directory.appendingPathComponent("Cellar/tool/2.0")
        try FileManager.default.createDirectory(
            at: keg.appendingPathComponent("bin"), withIntermediateDirectories: true)
        try Data(#"{"time":1700000000,"poured_from_bottle":false}"#.utf8)
            .write(to: keg.appendingPathComponent("INSTALL_RECEIPT.json"))
        XCTAssertNil(HomebrewKeg.locate(path: keg.appendingPathComponent("bin/tool").path))
    }

    func testSummaryDistinguishesBottleFromSource() {
        let source = HomebrewKeg(
            formula: "tool", version: "2.0", installedAt: nil, pouredFromBottle: false)
        XCTAssertEqual(source.summary, "Homebrew receipt: tool 2.0, built from source")
    }
}
