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
    //
    // kSecCSDoNotValidateResources only. NOT kSecCSBasicValidateOnly (6),
    // which is DoNotValidateExecutable|DoNotValidateResources and therefore
    // skips the code pages: a Developer ID binary patched in place, signature
    // blob untouched, validates clean under 6 and is handed a Trusted badge.
    // Verified by execution — one byte flipped in __TEXT of an ad-hoc signed
    // binary: flags 6 returns errSecSuccess, flags 4 returns
    // errSecCSSignatureFailed, and `codesign -v` agrees with 4. Skipping the
    // executable would make `.invalid` unreachable for the exact tampering
    // this tool exists to detect. Costs 2-7 ms more per binary, paid once per
    // (path, mtime).
    private static let validateExecutableOnly = SecCSFlags(rawValue: 4)
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

    // Compiled once. Parsing these three strings costs ~54 µs per binary, and
    // they never change.
    private static let requirementPlatform = compile("anchor apple")
    private static let requirementAppStore = compile(
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9]")
    private static let requirementDeveloperID = compile(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]")

    private static func compile(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard
            SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement)
                == errSecSuccess
        else { return nil }
        return requirement
    }

    static func inspect(path: String) -> SignatureInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var codeOpt: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(url, SecCSFlags(), &codeOpt)
        guard created == errSecSuccess, let code = codeOpt else {
            // "Unreadable" is not "unsigned", and reporting one as the other
            // is a false accusation. Plenty of stock daemons are mode 0500
            // root-only — /usr/sbin/cupsd among them — so DragonWatch, running
            // as you, cannot open them at all. Calling those Unsigned rated
            // them Suspicious and fired an alert naming a component of macOS.
            if !FileManager.default.isReadableFile(atPath: path),
                FileManager.default.fileExists(atPath: path)
            {
                return SignatureInfo(
                    tier: ContextInspector.isOSManagedLocation(path)
                        ? .osManagedUnreadable : .unreadable,
                    teamID: nil, signingID: nil)
            }
            return SignatureInfo(tier: .unsigned, teamID: nil, signingID: nil)
        }

        // Fail closed: if we cannot read the signing information we cannot see
        // entitlements or the ad-hoc flag, so "no risky entitlements" would be
        // an assertion we have not earned. Report it as unreadable rather than
        // clean.
        var infoOpt: CFDictionary?
        guard
            SecCodeCopySigningInformation(code, signingInformation, &infoOpt)
                == errSecSuccess,
            let info = infoOpt as? [String: Any]
        else {
            return SignatureInfo(tier: .invalid, teamID: nil, signingID: nil)
        }
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let signingID = info[kSecCodeInfoIdentifier as String] as? String
        let csFlags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let entitlements =
            info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let risky = riskyEntitlementKeys.filter { (entitlements[$0] as? Bool) == true }

        // Validates the signature *and* the executable's code pages, skipping
        // only the sealed resource envelope — hashing every resource in a
        // large bundle takes minutes and is Gatekeeper's job. The executable
        // itself is not optional: it is the thing being assessed.
        let validity = SecStaticCodeCheckValidity(code, validateExecutableOnly, nil)

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

    private static func satisfies(_ code: SecStaticCode, _ requirement: SecRequirement?)
        -> Bool
    {
        guard let requirement else { return false }
        return SecStaticCodeCheckValidity(code, validateExecutableOnly, requirement)
            == errSecSuccess
    }
}
