import XCTest

@testable import DragonWatch

/// The transparency contract: every rating explains itself, and the
/// explanation must match what the engine actually did.
final class TrustExplanationTests: XCTestCase {

    private func assessment(
        tier: SignatureTier, modifiers: [RiskModifier] = []
    ) -> TrustAssessment {
        TrustAssessment(tier: tier, modifiers: modifiers, teamID: nil, signingID: nil)
    }

    func testEverySignatureTierHasAnExplanation() {
        for tier in SignatureTier.allCases {
            XCTAssertFalse(
                TrustExplanation.signatureExplanation(tier).isEmpty,
                "\(tier) needs an explanation")
        }
    }

    func testEveryModifierHasRationaleAndExemptionText() {
        for modifier in RiskModifier.allCases {
            XCTAssertFalse(modifier.rationale.isEmpty, "\(modifier) needs a rationale")
            XCTAssertFalse(
                modifier.exemptionRationale.isEmpty, "\(modifier) needs exemption text")
        }
    }

    /// Applied modifiers must be reported as lowering, exempt ones as
    /// neutral — an explanation that disagrees with the score is worse than
    /// none.
    func testAppliedAndExemptModifiersAreDistinguished() {
        let developerID = assessment(
            tier: .developerID, modifiers: [.quarantined, .suspiciousLocation])
        let steps = TrustExplanation.steps(for: developerID)
        let lowering = steps.filter { $0.lowered == true }
        XCTAssertEqual(lowering.count, 1, "only the location signal applies here")
        XCTAssertTrue(lowering[0].text.contains("temporary or Downloads"))
        XCTAssertTrue(
            steps.contains { $0.lowered == nil && $0.text.contains("Quarantine") },
            "the exempt quarantine signal must still be shown, marked neutral")
    }

    func testResultStepNamesTheBadge() {
        let steps = TrustExplanation.steps(for: assessment(tier: .unsigned))
        XCTAssertTrue(steps.last?.text.contains("Suspicious") == true)
    }

    func testSelfExplanationStandsAlone() {
        var selfAssessment = assessment(tier: .adHoc, modifiers: [.hiddenPath])
        selfAssessment.isSelf = true
        let steps = TrustExplanation.steps(for: selfAssessment)
        XCTAssertEqual(steps.count, 1)
        XCTAssertTrue(steps[0].text.contains("DragonWatch itself"))
    }

    func testVouchedExplanationNamesTheBundleAndItsLimit() {
        var vouched = assessment(tier: .adHoc, modifiers: [.riskyEntitlements])
        vouched.vouchedByBundle = "/Applications/Xcode.app"
        let steps = TrustExplanation.steps(for: vouched)
        XCTAssertTrue(steps.contains { $0.text.contains("Xcode.app") })
        XCTAssertTrue(
            steps.contains { $0.text.contains("only this binary") },
            "the explanation must state the vouch does not cover the whole bundle")
    }

    func testCleanTrustedBinaryGetsReassuringStep() {
        let steps = TrustExplanation.steps(for: assessment(tier: .developerID))
        XCTAssertTrue(steps.contains { $0.lowered == false })
        XCTAssertFalse(steps.contains { $0.lowered == true })
    }
}
