import XCTest

@testable import DragonWatch

/// Probes against the live system — these validate our C-interop plumbing
/// (units, buffer handling) against reality, not just our own logic.
final class SystemProbeTests: XCTestCase {

    func testSamplerReportsOwnProcessWithItsRealPath() async throws {
        let sampler = ProcessSampler()
        let records = await sampler.sample()
        XCTAssertGreaterThan(
            records.count, 20, "a running Mac has many more processes than this")

        let me = try XCTUnwrap(
            records.first { $0.pid == getpid() },
            "sampler should see the test runner itself")
        // The path must be a real, complete executable path — truncation or a
        // garbage buffer is what proc_pidpath handling gets wrong. (It reports
        // the *resolved* binary, which is not always argv[0]: here argv[0] is
        // /usr/bin/xctest while the real executable lives under Agents/.)
        XCTAssertTrue(me.path.hasPrefix("/"), "path must be absolute")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: me.path),
            "reported path must exist on disk: \(me.path)")
        XCTAssertTrue(me.path.hasSuffix("xctest"), "should be the test runner binary")
        XCTAssertEqual(me.name, (me.path as NSString).lastPathComponent)
        XCTAssertGreaterThan(
            try XCTUnwrap(me.residentBytes), 1 << 20, "resident size should exceed 1 MB")
    }

    /// Smoke test for the mach-timebase conversion against a real workload —
    /// a missing conversion would inflate CPU% ~42x on Apple Silicon. The
    /// arithmetic itself is pinned deterministically in
    /// ProcessCPUAccountingTests; the bounds here are deliberately loose so a
    /// loaded CI machine cannot make this flake.
    func testBusyThreadRegistersPlausibleCPUAgainstLiveSystem() async throws {
        let sampler = ProcessSampler()
        _ = await sampler.sample()

        let deadline = Date().addingTimeInterval(0.6)
        let burner = Thread {
            var x = 0.0
            while Date() < deadline { x += 1 }
            _ = x
        }
        burner.start()
        try await Task.sleep(for: .seconds(0.7))

        let records = await sampler.sample()
        let me = records.first { $0.pid == getpid() }
        let sample = try XCTUnwrap(me)
        let cpu = try XCTUnwrap(sample.cpuPercent, "we own this process, so rusage must succeed")
        XCTAssertGreaterThan(cpu, 1, "busy loop should register at all")
        XCTAssertLessThan(
            cpu, Double(ProcessInfo.processInfo.activeProcessorCount) * 150,
            "CPU% far above core count implies a unit-conversion bug")
    }

    /// Processes we do not own are reported with unknown metrics, never
    /// dropped. Skipping them made ~40% of a running Mac — every root-only
    /// daemon, including the persistence this tool exists to notice —
    /// invisible to trust assessment and every alert rule.
    func testProcessesWeDoNotOwnAreStillReported() async {
        let records = await ProcessSampler().sample()
        let withoutMetrics = records.filter { !$0.hasMetrics }
        XCTAssertFalse(
            withoutMetrics.isEmpty,
            "a real Mac runs root daemons whose rusage we cannot read; if none "
                + "appear here the sampler is dropping them again")
        XCTAssertTrue(
            withoutMetrics.allSatisfy { !$0.path.isEmpty && $0.pid > 0 },
            "a metric-less record must still carry the identity trust needs")
    }

    func testAppleBinaryRatesAsApplePlatform() async {
        let engine = TrustEngine()
        let assessment = await engine.assess(path: "/bin/ls")
        XCTAssertEqual(assessment.tier, .applePlatform)
        XCTAssertEqual(assessment.badge, .trusted)
    }

    func testVitalsSamplerReturnsSaneValues() async {
        let sampler = VitalsSampler()
        _ = await sampler.sampleCPUAndMemory()
        try? await Task.sleep(for: .milliseconds(300))
        let (cpu, memUsed) = await sampler.sampleCPUAndMemory()
        XCTAssertGreaterThanOrEqual(cpu, 0)
        XCTAssertLessThanOrEqual(cpu, 100)
        XCTAssertGreaterThan(memUsed, 1 << 30, "a running Mac uses more than 1 GB")
        XCTAssertLessThan(memUsed, ProcessInfo.processInfo.physicalMemory)
    }

    func testBundleRootExtraction() {
        XCTAssertEqual(
            ContextInspector.bundleRoot(
                of: "/Applications/Safari.app/Contents/MacOS/Safari"),
            "/Applications/Safari.app")
        // Helpers nested inside frameworks group under the outermost app.
        XCTAssertEqual(
            ContextInspector.bundleRoot(
                of: "/Applications/X.app/Contents/Frameworks/Y.app/Contents/MacOS/Y"),
            "/Applications/X.app")
        XCTAssertNil(ContextInspector.bundleRoot(of: "/usr/bin/ssh"))
    }
}
