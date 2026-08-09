import Foundation

/// Turns an assessment into the plain-English reasoning behind its badge —
/// the app's transparency contract: every rating explains itself, in the
/// same order the engine applied it.
enum TrustExplanation {
    struct Step: Identifiable {
        let id = UUID()
        let symbol: String
        let text: String
        /// Nil for neutral/explanatory steps; true when this step lowered the
        /// rating, false when it is the reassuring baseline.
        let lowered: Bool?
    }

    static func steps(for assessment: TrustAssessment) -> [Step] {
        if assessment.isSelf {
            return [
                Step(
                    symbol: "checkmark.circle",
                    text:
                        "This is DragonWatch itself, matched by process ID. It rates its own process trusted — a compromised monitor could lie about itself anyway, so flagging it would be noise rather than protection.",
                    lowered: nil)
            ]
        }

        var steps: [Step] = [
            Step(
                symbol: "signature",
                text: signatureExplanation(assessment.tier),
                lowered: TrustScoring.base(for: assessment.tier) != .trusted)
        ]

        if let bundle = assessment.vouchedByBundle {
            steps.append(
                Step(
                    symbol: "checkmark.seal",
                    text:
                        "You verified \((bundle as NSString).lastPathComponent)'s full signature seal while this exact binary was running, and its contents still match what was there then. That overrides the weak signature — and only this binary, not anything else in the bundle.",
                    lowered: false))
            steps.append(resultStep(for: assessment))
            return steps
        }

        let applied = Set(assessment.modifiers).filter {
            TrustScoring.applies($0, to: assessment.tier)
        }
        let ignored = Set(assessment.modifiers).subtracting(applied)

        for modifier in RiskModifier.allCases where applied.contains(modifier) {
            steps.append(
                Step(
                    symbol: "arrow.down.circle",
                    text: "\(modifier.explanation). \(modifier.rationale)",
                    lowered: true))
        }
        for modifier in RiskModifier.allCases where ignored.contains(modifier) {
            let reason =
                assessment.tier == .applePlatform
                ? "Context signals describe how software was delivered and where it lives; macOS's own files are the platform, so they say nothing."
                : modifier.exemptionRationale
            steps.append(
                Step(
                    symbol: "minus.circle",
                    text:
                        "\(modifier.explanation) — not counted against a \(assessment.tier.rawValue.lowercased()) binary. \(reason)",
                    lowered: nil))
        }

        if applied.isEmpty && assessment.modifiers.isEmpty {
            steps.append(
                Step(
                    symbol: "checkmark.circle",
                    text: "Nothing unusual about where it runs from or how it behaves.",
                    lowered: false))
        }

        steps.append(resultStep(for: assessment))
        return steps
    }

    /// Every explanation ends by naming its outcome. The vouched path used to
    /// return without one, so the single rating the user had done work to
    /// change was the one that never told them what it became.
    private static func resultStep(for assessment: TrustAssessment) -> Step {
        let rule =
            assessment.vouchedByBundle != nil
            ? "A verified signature seal is the one thing that raises a rating; context can only lower it."
            : "Signatures set the starting point; context can only lower it, never raise it."
        return Step(
            symbol: "equal.circle",
            text: "Result: \(assessment.badge.label). \(rule)",
            lowered: nil)
    }

    static func signatureExplanation(_ tier: SignatureTier) -> String {
        switch tier {
        case .applePlatform:
            "Signed by Apple as part of macOS itself — the strongest identity there is."
        case .appStore:
            "Distributed through the Mac App Store: sandboxed and reviewed by Apple."
        case .developerID:
            "Signed with a Developer ID, so a named developer is accountable and Apple can revoke it."
        case .validSigned:
            "Carries a valid signature, but not from Apple, the App Store, or a Developer ID — nobody identifiable stands behind it."
        case .adHoc:
            "Ad-hoc signed: the signature proves the file hasn't changed since it was built, but says nothing about who built it."
        case .unsigned:
            "No code signature at all — nothing vouches for where this came from or whether it has been modified."
        case .invalid:
            "The signature is present but does not validate: the file has been modified since signing, or its certificate was revoked."
        case .osManagedUnreadable:
            "Part of the macOS install, in a directory that only root can write and System Integrity Protection guards. DragonWatch runs as you, so it cannot read the file to check the signature — this rating comes from where the file lives, not from verifying it."
        case .unreadable:
            "DragonWatch cannot read this file, so nothing about it can be checked — and unlike a system daemon, it is not somewhere macOS manages."
        }
    }
}

extension RiskModifier {
    /// Why this signal is treated as risk.
    var rationale: String {
        switch self {
        case .suspiciousLocation:
            "Software normally installs somewhere permanent; running from a temp or download folder is how freshly-delivered malware behaves."
        case .hiddenPath:
            "Hidden directories keep code out of sight in Finder — useful for support files, and equally useful for hiding."
        case .quarantined:
            "It arrived from the internet and Gatekeeper never cleared it, yet it is running."
        case .riskyEntitlements:
            "It requests permissions that weaken code-integrity protection — the ability to load unsigned code or be attached to by a debugger."
        case .networkActive:
            "It has held network connections, so an unidentified binary is talking to something."
        }
    }

    /// Why this signal is *not* counted for strongly-identified signers.
    var exemptionRationale: String {
        switch self {
        case .suspiciousLocation:
            "Location always counts."
        case .hiddenPath:
            "Identified developers routinely keep support binaries in hidden folders, and their identity is still accountable."
        case .quarantined:
            "macOS keeps the quarantine flag on downloads forever and only marks it approved, so for a notarized app this is the normal state — Gatekeeper has already ruled."
        case .riskyEntitlements:
            "Debug and JIT entitlements are routine for identified developers (every Electron app uses them)."
        case .networkActive:
            "Trusted software talks to the network constantly; the signal only means something when nobody is accountable for the binary."
        }
    }
}
