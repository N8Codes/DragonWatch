import Foundation

/// Where a binary's code signature places it, before context is considered.
enum SignatureTier: String, CaseIterable, Codable, Sendable {
    case applePlatform = "Apple system"
    case appStore = "App Store"
    case developerID = "Developer ID"
    case validSigned = "Signed (unknown authority)"
    case adHoc = "Ad-hoc signed"
    case unsigned = "Unsigned"
    case invalid = "Invalid signature"
    /// Part of the macOS install, in a location only root can write and
    /// System Integrity Protection guards, but not readable by us so the
    /// signature could not actually be checked.
    case osManagedUnreadable = "macOS system file (unverified)"
    /// We cannot read the file, and it is not somewhere the OS manages.
    case unreadable = "Cannot be read"
}

/// Context signals that can lower — never raise — a rating.
enum RiskModifier: String, CaseIterable, Codable, Sendable {
    case suspiciousLocation
    case hiddenPath
    case quarantined
    case riskyEntitlements
    case networkActive

    var explanation: String {
        switch self {
        case .suspiciousLocation: "Runs from a temporary or Downloads folder"
        case .hiddenPath: "Runs from a hidden directory"
        case .quarantined: "Quarantine attribute still present"
        case .riskyEntitlements: "Carries injection-friendly entitlements"
        case .networkActive: "Holds active network connections while weakly signed"
        }
    }
}

enum TrustBadge: Int, Comparable, Sendable {
    case trusted = 0
    case caution = 1
    case suspicious = 2

    static func < (lhs: TrustBadge, rhs: TrustBadge) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .trusted: "Trusted"
        case .caution: "Caution"
        case .suspicious: "Suspicious"
        }
    }

    /// A shape as well as a colour. Roughly 8% of men cannot separate the
    /// red/green pair, and this distinction is the whole product — so the
    /// badge must never rely on hue alone.
    var symbolName: String {
        switch self {
        case .trusted: "checkmark.circle.fill"
        case .caution: "exclamationmark.triangle.fill"
        case .suspicious: "exclamationmark.octagon.fill"
        }
    }
}

struct TrustAssessment: Sendable {
    let tier: SignatureTier
    var modifiers: [RiskModifier]
    let teamID: String?
    let signingID: String?
    /// True only for DragonWatch's own process, verified by pid — a
    /// compromised DragonWatch controls this display anyway, so flagging
    /// ourselves (ad-hoc in local builds) is pure noise, not security.
    var isSelf: Bool = false
    /// Set when this weakly-signed binary sits inside a strongly-signed
    /// bundle whose full signature seal has been verified — proof it is
    /// exactly what the vendor shipped. The one earned path to trust.
    var vouchedByBundle: String?

    var badge: TrustBadge {
        if isSelf || vouchedByBundle != nil { return .trusted }
        return TrustScoring.badge(tier: tier, modifiers: modifiers)
    }
}

/// Pure scoring rules: base badge from the signature tier, demoted one step per
/// applicable modifier. Signatures anchor; context can only pull downward.
enum TrustScoring {
    static func badge(tier: SignatureTier, modifiers: [RiskModifier]) -> TrustBadge {
        var badge = base(for: tier)
        for modifier in Set(modifiers) where applies(modifier, to: tier) {
            badge = demoted(badge)
        }
        return badge
    }

    static func base(for tier: SignatureTier) -> TrustBadge {
        switch tier {
        case .applePlatform, .appStore, .developerID, .osManagedUnreadable: .trusted
        case .validSigned, .adHoc: .caution
        case .unsigned, .invalid, .unreadable: .suspicious
        }
    }

    /// The single source of truth for whether a context signal counts. `badge`
    /// and `TrustExplanation` both read it, so an explanation can never list a
    /// demotion the score did not apply — they disagreed while `badge` carried
    /// its own early return for `.applePlatform`, and the UI showed stock
    /// system binaries a "lowered" step above a `Trusted` result.
    static func applies(_ modifier: RiskModifier, to tier: SignatureTier) -> Bool {
        // Apple platform binaries are the OS itself; every context signal is
        // noise there. Plenty of stock binaries genuinely carry them —
        // /usr/libexec/dspluginhelperd ships with disable-library-validation.
        guard tier != .applePlatform, tier != .osManagedUnreadable else { return false }
        return switch modifier {
        case .suspiciousLocation:
            true
        case .quarantined:
            // macOS never removes the quarantine xattr from downloaded apps —
            // it only marks it approved — so for a notarized Developer ID app
            // it is the *normal* state and Gatekeeper already ruled. On a
            // weak signature, a running quarantined binary means Gatekeeper
            // was bypassed: that one is real.
            !(tier == .appStore || tier == .developerID)
        case .hiddenPath, .riskyEntitlements:
            // A strongly-identified signer legitimately hides support binaries
            // (Wacom's .Tablet folder) and legitimately uses JIT/debug
            // entitlements (every Electron app); for unknown signers the same
            // traits are evasion and injection surface.
            !(tier == .appStore || tier == .developerID)
        case .networkActive:
            // Only meaningful when nobody identifiable is accountable for the
            // binary — trusted apps talk to the network constantly. That set
            // is exactly the non-trusted tiers, `.validSigned` (a self-issued
            // certificate) included: it was the one modifier that exempted
            // that tier while its own explanation argued for applying it.
            base(for: tier) != .trusted
        }
    }

    private static func demoted(_ badge: TrustBadge) -> TrustBadge {
        TrustBadge(rawValue: min(badge.rawValue + 1, TrustBadge.suspicious.rawValue))!
    }
}
