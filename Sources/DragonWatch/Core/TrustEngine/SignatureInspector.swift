import Foundation
import Security

struct SignatureInfo {
    let tier: SignatureTier
    let teamID: String?
    let signingID: String?
    var riskyEntitlements: [String] = []
}

/// Static code-signature inspection via the Security framework.
enum SignatureInspector {
    // Raw values for constants that don't import cleanly into Swift.
    private static let basicValidateOnly = SecCSFlags(rawValue: 6)  // kSecCSBasicValidateOnly
    // kSecCSSigningInformation | kSecCSRequirementInformation — the latter is
    // needed for the entitlements dictionary.
    private static let signingInformation = SecCSFlags(rawValue: 2 | 4)

    // Entitlements that weaken code-integrity protections: fine on a strongly
    // identified app (JIT, debugging), injection surface on an unknown one.
    private static let riskyEntitlementKeys = [
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.get-task-allow",
    ]
    private static let unsignedStatus: OSStatus = -67062  // errSecCSUnsigned
    private static let adhocFlag: UInt32 = 0x2  // kSecCodeSignatureAdhoc

    private static let requirementPlatform = "anchor apple"
    private static let requirementAppStore =
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9]"
    private static let requirementDeveloperID =
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]"

    static func inspect(path: String) -> SignatureInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var codeOpt: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, SecCSFlags(), &codeOpt) == errSecSuccess,
            let code = codeOpt
        else {
            return SignatureInfo(tier: .unsigned, teamID: nil, signingID: nil)
        }

        var infoOpt: CFDictionary?
        SecCodeCopySigningInformation(code, signingInformation, &infoOpt)
        let info = infoOpt as? [String: Any] ?? [:]
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let signingID = info[kSecCodeInfoIdentifier as String] as? String
        let csFlags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let entitlements =
            info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let risky = riskyEntitlementKeys.filter { (entitlements[$0] as? Bool) == true }

        // Basic validation only: checks the signature itself without hashing every
        // resource in the bundle — the honest tradeoff for a monitor that assesses
        // hundreds of binaries. (Full validation is Gatekeeper's job.)
        let validity = SecStaticCodeCheckValidity(code, basicValidateOnly, nil)

        switch validity {
        case errSecSuccess:
            break
        case unsignedStatus:
            return SignatureInfo(tier: .unsigned, teamID: nil, signingID: nil)
        default:
            return SignatureInfo(
                tier: .invalid, teamID: teamID, signingID: signingID,
                riskyEntitlements: risky)
        }

        let tier: SignatureTier =
            if satisfies(code, requirementPlatform) {
                .applePlatform
            } else if satisfies(code, requirementAppStore) {
                .appStore
            } else if satisfies(code, requirementDeveloperID) {
                .developerID
            } else if csFlags & adhocFlag != 0 { .adHoc } else { .validSigned }
        return SignatureInfo(
            tier: tier, teamID: teamID, signingID: signingID, riskyEntitlements: risky)
    }

    private static func satisfies(_ code: SecStaticCode, _ requirement: String) -> Bool {
        var reqOpt: SecRequirement?
        guard
            SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &reqOpt)
                == errSecSuccess,
            let req = reqOpt
        else { return false }
        return SecStaticCodeCheckValidity(code, basicValidateOnly, req) == errSecSuccess
    }
}
