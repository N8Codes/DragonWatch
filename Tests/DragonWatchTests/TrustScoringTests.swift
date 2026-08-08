import XCTest

@testable import DragonWatch

/// Pure scoring rules — the heart of the trust model.
final class TrustScoringTests: XCTestCase {

    func testBaseTiersWithoutModifiers() {
        XCTAssertEqual(TrustScoring.badge(tier: .applePlatform, modifiers: []), .trusted)
        XCTAssertEqual(TrustScoring.badge(tier: .appStore, modifiers: []), .trusted)
        XCTAssertEqual(TrustScoring.badge(tier: .developerID, modifiers: []), .trusted)
        XCTAssertEqual(TrustScoring.badge(tier: .validSigned, modifiers: []), .caution)
        XCTAssertEqual(TrustScoring.badge(tier: .adHoc, modifiers: []), .caution)
        XCTAssertEqual(TrustScoring.badge(tier: .unsigned, modifiers: []), .suspicious)
        XCTAssertEqual(TrustScoring.badge(tier: .invalid, modifiers: []), .suspicious)
    }

    /// Colour is not the only signal: each badge must carry a distinct shape,
    /// or the trusted/suspicious distinction vanishes for red-green colour
    /// blindness and in greyscale.
    func testEveryBadgeHasADistinctNonColourSymbol() {
        let badges: [TrustBadge] = [.trusted, .caution, .suspicious]
        let symbols = badges.map(\.symbolName)
        XCTAssertEqual(
            Set(symbols).count, badges.count,
            "badges share a symbol, so shape cannot distinguish them: \(symbols)")
        for badge in badges {
            XCTAssertFalse(badge.symbolName.isEmpty)
            XCTAssertFalse(badge.label.isEmpty, "VoiceOver label must not be empty")
        }
    }

    /// Driven off `allCases` so a modifier added later is covered automatically
    /// — listing them by hand let this test keep its name while silently
    /// missing the two most recent ones.
    func testApplePlatformIgnoresAllModifiers() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .applePlatform, modifiers: RiskModifier.allCases),
            .trusted)
        for modifier in RiskModifier.allCases {
            XCTAssertEqual(
                TrustScoring.badge(tier: .applePlatform, modifiers: [modifier]),
                .trusted, "\(modifier) must not demote an Apple platform binary")
        }
    }

    /// The Wacom rule: a strongly-identified signer in a hidden folder stays trusted.
    func testHiddenPathDoesNotDemoteDeveloperID() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .developerID, modifiers: [.hiddenPath]), .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .appStore, modifiers: [.hiddenPath]), .trusted)
    }

    func testHiddenPathDemotesWeakerSignatures() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .validSigned, modifiers: [.hiddenPath]), .suspicious)
        XCTAssertEqual(
            TrustScoring.badge(tier: .adHoc, modifiers: [.hiddenPath]), .suspicious)
    }

    func testSuspiciousLocationDemotesEvenDeveloperID() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .developerID, modifiers: [.suspiciousLocation]),
            .caution)
    }

    /// macOS never removes the quarantine xattr from downloaded apps, so it
    /// must not demote a notarized Developer ID app (every web download would
    /// read caution forever — the LibreOffice false positive). On weak
    /// signatures a running quarantined binary means Gatekeeper was bypassed.
    func testQuarantineExemptsStrongIdentities() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .developerID, modifiers: [.quarantined]), .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .appStore, modifiers: [.quarantined]), .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .adHoc, modifiers: [.quarantined]), .suspicious)
        XCTAssertEqual(
            TrustScoring.badge(tier: .validSigned, modifiers: [.quarantined]),
            .suspicious)
    }

    func testModifiersStack() {
        XCTAssertEqual(
            TrustScoring.badge(
                tier: .validSigned, modifiers: [.suspiciousLocation, .quarantined]),
            .suspicious)
    }

    /// Seal vouching is the earned path to trust: badge flips, tier stays
    /// honest so the detail view still shows what the binary really is.
    func testVouchedAssessmentReadsTrusted() {
        var assessment = TrustAssessment(
            tier: .adHoc, modifiers: [.riskyEntitlements], teamID: nil, signingID: nil)
        XCTAssertEqual(assessment.badge, .suspicious)
        assessment.vouchedByBundle = "/Applications/Xcode.app"
        XCTAssertEqual(assessment.badge, .trusted)
        XCTAssertEqual(assessment.tier, .adHoc)
    }

    /// The self exemption is pid-gated in AppModel; here we pin that the
    /// assessment's badge honors the flag without touching the tier.
    func testSelfAssessmentReadsTrustedRegardlessOfTier() {
        var assessment = TrustAssessment(
            tier: .adHoc, modifiers: [], teamID: nil, signingID: nil)
        XCTAssertEqual(assessment.badge, .caution)
        assessment.isSelf = true
        XCTAssertEqual(assessment.badge, .trusted)
        XCTAssertEqual(assessment.tier, .adHoc, "tier stays honest; only the badge")
    }

    func testDemotionFloorsAtSuspicious() {
        XCTAssertEqual(
            TrustScoring.badge(
                tier: .unsigned,
                modifiers: [.suspiciousLocation, .hiddenPath, .quarantined]),
            .suspicious)
    }

    func testDuplicateModifiersCountOnce() {
        XCTAssertEqual(
            TrustScoring.badge(
                tier: .developerID,
                modifiers: [.suspiciousLocation, .suspiciousLocation]),
            .caution)
    }

    /// Trusted apps talk to the network constantly — the modifier only means
    /// something on a weak signature.
    func testNetworkActiveAppliesOnlyToWeakSignatures() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .adHoc, modifiers: [.networkActive]), .suspicious)
        XCTAssertEqual(
            TrustScoring.badge(tier: .developerID, modifiers: [.networkActive]),
            .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .validSigned, modifiers: [.networkActive]),
            .caution)
    }

    /// The Electron rule: JIT/debug entitlements are routine for strongly
    /// identified apps, injection surface for unknown ones.
    func testRiskyEntitlementsExemptStrongIdentities() {
        XCTAssertEqual(
            TrustScoring.badge(tier: .developerID, modifiers: [.riskyEntitlements]),
            .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .appStore, modifiers: [.riskyEntitlements]),
            .trusted)
        XCTAssertEqual(
            TrustScoring.badge(tier: .validSigned, modifiers: [.riskyEntitlements]),
            .suspicious)
        XCTAssertEqual(
            TrustScoring.badge(tier: .adHoc, modifiers: [.riskyEntitlements]),
            .suspicious)
    }
}
