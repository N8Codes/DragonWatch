import XCTest

@testable import DragonWatch

final class BaselineLedgerTests: XCTestCase {
    private let now = Date(timeIntervalSinceReferenceDate: 0)

    private func assessment(
        tier: SignatureTier, modifiers: [RiskModifier] = []
    ) -> TrustAssessment {
        TrustAssessment(tier: tier, modifiers: modifiers, teamID: nil, signingID: nil)
    }

    func testTrustedBinaryJoinsSilently() {
        var ledger = BaselineLedger()
        let observation = ledger.observe(
            path: "/usr/bin/true", assessment: assessment(tier: .applePlatform), now: now)
        XCTAssertEqual(observation, .addedTrusted)
        XCTAssertEqual(ledger.executables["/usr/bin/true"]?.verdict, .autoTrusted)
        XCTAssertTrue(ledger.pendingReview.isEmpty)
    }

    func testUntrustedBinaryQueuesForReview() {
        var ledger = BaselineLedger()
        let observation = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned), now: now)
        XCTAssertEqual(observation, .addedForReview)
        XCTAssertEqual(ledger.pendingReview.map(\.path), ["/tmp/tool"])
    }

    func testDemotedTrustedTierQueuesForReview() {
        // Developer ID is a trusted *tier*, but a modifier can demote the badge —
        // the ledger must follow the badge, not the tier.
        var ledger = BaselineLedger()
        let observation = ledger.observe(
            path: NSHomeDirectory() + "/Downloads/tool",
            assessment: assessment(tier: .developerID, modifiers: [.suspiciousLocation]),
            now: now)
        XCTAssertEqual(observation, .addedForReview)
    }

    func testSecondSightingIsKnown() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned), now: now)
        let again = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned),
            now: now.addingTimeInterval(60))
        XCTAssertEqual(again, .known)
        XCTAssertEqual(ledger.pendingReview.count, 1)
    }

    func testVerdictIsAskedExactlyOnce() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned), now: now)
        ledger.recordVerdict(path: "/tmp/tool", verdict: .expected)
        XCTAssertTrue(ledger.pendingReview.isEmpty)
        // Re-observing after a verdict must not re-queue it.
        let again = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned),
            now: now.addingTimeInterval(60))
        XCTAssertEqual(again, .known)
        XCTAssertTrue(ledger.pendingReview.isEmpty)
    }

    func testKeepFlaggingAlsoLeavesReviewQueue() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .unsigned), now: now)
        ledger.recordVerdict(path: "/tmp/tool", verdict: .keepFlagging)
        XCTAssertTrue(ledger.pendingReview.isEmpty)
        XCTAssertEqual(ledger.executables["/tmp/tool"]?.verdict, .keepFlagging)
    }

    /// A trust-model improvement (or self exemption) can turn a queued item
    /// green — the pending question is then moot and resolves itself. A
    /// verdict the user already gave is never overwritten.
    func testPendingReviewAutoResolvesWhenAssessmentTurnsTrusted() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .adHoc), now: now)
        XCTAssertEqual(ledger.pendingReview.count, 1)

        var selfAssessment = assessment(tier: .adHoc)
        selfAssessment.isSelf = true
        let again = ledger.observe(
            path: "/tmp/tool", assessment: selfAssessment,
            now: now.addingTimeInterval(60))
        XCTAssertEqual(again, .known)
        XCTAssertTrue(ledger.pendingReview.isEmpty)
        XCTAssertEqual(ledger.executables["/tmp/tool"]?.verdict, .autoTrusted)
    }

    func testUserVerdictSurvivesTrustedAssessment() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .adHoc), now: now)
        ledger.recordVerdict(path: "/tmp/tool", verdict: .keepFlagging)
        var trusted = assessment(tier: .adHoc)
        trusted.isSelf = true
        _ = ledger.observe(
            path: "/tmp/tool", assessment: trusted, now: now.addingTimeInterval(60))
        XCTAssertEqual(ledger.executables["/tmp/tool"]?.verdict, .keepFlagging)
    }

    /// The realistic case the ordering test above misses: the first-run sweep
    /// observes every item with the same timestamp, so firstSeen ties and the
    /// remaining order comes from Dictionary iteration — which varies between
    /// runs and after mutations, making the review list reshuffle under the
    /// user. Order must be total, not partial.
    func testPendingReviewOrderIsStableWhenFirstSeenTies() {
        let paths = (1...12).map { "/tmp/tool\($0)" }
        func queue() -> [String] {
            var ledger = BaselineLedger()
            for path in paths.shuffled() {
                _ = ledger.observe(
                    path: path, assessment: assessment(tier: .unsigned), now: now)
            }
            return ledger.pendingReview.map(\.path)
        }
        let first = queue()
        for _ in 0..<8 {
            XCTAssertEqual(queue(), first, "review order must not depend on insertion")
        }
    }

    func testPendingReviewOrderedByFirstSeen() {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/tmp/b", assessment: assessment(tier: .unsigned),
            now: now.addingTimeInterval(60))
        _ = ledger.observe(
            path: "/tmp/a", assessment: assessment(tier: .unsigned), now: now)
        XCTAssertEqual(ledger.pendingReview.map(\.path), ["/tmp/a", "/tmp/b"])
    }

    func testPersistenceItemNewThenKnown() {
        var ledger = BaselineLedger()
        XCTAssertTrue(ledger.observePersistenceItem("/Library/LaunchAgents/a.plist"))
        XCTAssertFalse(ledger.observePersistenceItem("/Library/LaunchAgents/a.plist"))
    }

    func testLedgerRoundTripsThroughJSON() throws {
        var ledger = BaselineLedger()
        _ = ledger.observe(
            path: "/usr/bin/true", assessment: assessment(tier: .applePlatform), now: now)
        _ = ledger.observe(
            path: "/tmp/tool", assessment: assessment(tier: .adHoc), now: now)
        _ = ledger.observePersistenceItem("/Library/LaunchAgents/a.plist")

        let data = try JSONEncoder().encode(ledger)
        let decoded = try JSONDecoder().decode(BaselineLedger.self, from: data)
        XCTAssertEqual(decoded.executables.count, 2)
        XCTAssertEqual(decoded.executables["/tmp/tool"]?.verdict, .pendingReview)
        XCTAssertEqual(decoded.persistenceItems, ["/Library/LaunchAgents/a.plist"])
    }
}
