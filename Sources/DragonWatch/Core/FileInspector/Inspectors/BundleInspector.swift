import Foundation

/// Inspects an `.app` or other bundle, which `FolderWalker` hands over as a
/// single item rather than thousands of files.
///
/// A bundle has no magic bytes to check, so the question "is this what it
/// claims to be" is answered by its code signature — and an *invalid*
/// signature is precisely this feature's subject: the contents no longer match
/// the seal the vendor put on them.
///
/// Reuses `SignatureInspector` rather than re-deriving anything. Full seal
/// verification stays where it is, behind the deliberate button in
/// `BundleSealVerifier`: it takes minutes on a large bundle and must not run
/// inside a folder scan.
enum BundleInspector {

    static func inspect(probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("Bundle code signature")
        let info = SignatureInspector.inspect(path: probe.path)

        switch info.tier {
        case .invalid:
            output.findings.append(
                Finding(
                    rule: "bundle.signatureInvalid",
                    severity: .inconsistent,
                    title: "Code signature does not match the contents",
                    detail:
                        "Something inside this bundle changed after it was signed, or the "
                        + "certificate was revoked. It is not what its signer sealed."))
        case .unsigned:
            output.findings.append(
                Finding(
                    rule: "bundle.unsigned",
                    severity: .caution,
                    title: "No code signature",
                    detail:
                        "Nothing identifies who built this or proves it has not been altered."))
        case .adHoc:
            output.findings.append(
                Finding(
                    rule: "bundle.adHoc",
                    severity: .caution,
                    title: "Ad-hoc signed",
                    detail:
                        "Signed without an identity, so the signature proves the contents are "
                        + "intact but says nothing about who produced them."))
        case .applePlatform, .appStore, .developerID, .validSigned, .osManagedUnreadable,
            .unreadable:
            break
        }

        var detail = TrustExplanation.signatureExplanation(info.tier)
        if let team = info.teamID {
            detail += " Team ID \(UniversalChecks.displaySafe(team, limit: 24))."
        }
        output.disclosures.append(Disclosure(title: info.tier.rawValue, detail: detail))

        if !info.riskyEntitlements.isEmpty {
            output.disclosures.append(
                Disclosure(
                    title: "Entitlements",
                    detail: info.riskyEntitlements
                        .map { UniversalChecks.displaySafe($0, limit: 48) }
                        .joined(separator: ", ")))
        }

        // The seal check this does *not* do is worth naming, so nobody reads a
        // clean result as proof every file inside is untouched.
        output.disclosures.append(
            Disclosure(
                title: "Not a full seal check",
                detail:
                    "The signature was checked, not every sealed resource inside the bundle. "
                    + "Use Verify bundle seal on a running process for that."))
        return output
    }
}
