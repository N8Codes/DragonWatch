import CDragonWatch
import Foundation

/// Assesses executables and caches results — signature checks are the expensive
/// part of DragonWatch, so each unique (path, mtime) is inspected exactly once.
/// The network-connections signal is checked live until it first fires, then
/// latched, and only for the weak signature tiers it can affect.
actor TrustEngine {
    private var cache: [String: (mtime: Date, assessment: TrustAssessment)] = [:]
    // Latched: "has held network connections" doesn't evaporate when a socket
    // closes — and an un-latched signal would flap the badge (and the list
    // order) every few seconds as connections come and go.
    private var everNetworkActive: Set<String> = []
    // executable path → vouching bundle, from BundleSealVerifier. Keyed by
    // the specific binary, never by bundle membership: a file planted into a
    // verified bundle was never vouched, so it stays flagged.
    private var vouchedBinaries: [String: String] = [:]

    func setVouchedBinaries(_ vouches: [String: String]) {
        vouchedBinaries = vouches
    }

    func assess(path: String, pid: pid_t = -1) -> TrustAssessment {
        var base = staticAssessment(path: path)
        if TrustScoring.base(for: base.tier) != .trusted,
            let bundle = vouchedBinaries[path]
        {
            base.vouchedByBundle = bundle
            return base
        }
        guard TrustScoring.applies(.networkActive, to: base.tier) else { return base }
        if !everNetworkActive.contains(path) {
            guard pid > 0, dw_has_active_network(pid) == 1 else { return base }
            everNetworkActive.insert(path)
        }
        // Mutate rather than rebuild, so fields added to TrustAssessment are
        // never silently dropped here.
        base.modifiers.append(.networkActive)
        return base
    }

    private func staticAssessment(path: String) -> TrustAssessment {
        let mtime =
            ((try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate]
                as? Date) ?? .distantPast
        if let hit = cache[path], hit.mtime == mtime {
            return hit.assessment
        }
        let signature = SignatureInspector.inspect(path: path)
        var modifiers = ContextInspector.modifiers(forPath: path)
        if !signature.riskyEntitlements.isEmpty {
            modifiers.append(.riskyEntitlements)
        }
        let assessment = TrustAssessment(
            tier: signature.tier,
            modifiers: modifiers,
            teamID: signature.teamID,
            signingID: signature.signingID
        )
        cache[path] = (mtime, assessment)
        return assessment
    }
}
