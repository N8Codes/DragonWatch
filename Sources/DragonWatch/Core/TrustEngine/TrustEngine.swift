import CDragonWatch
import Darwin
import Foundation

/// Assesses executables and caches results — signature checks are the expensive
/// part of DragonWatch, so each unique (path, mtime, size) is inspected exactly
/// once. The network-connections signal is checked live until it first fires,
/// then latched, and only for the weak signature tiers it can affect.
actor TrustEngine {
    private struct FileStamp: Equatable {
        let mtime: timespec
        let size: off_t
        let inode: ino_t

        static func == (lhs: FileStamp, rhs: FileStamp) -> Bool {
            lhs.mtime.tv_sec == rhs.mtime.tv_sec && lhs.mtime.tv_nsec == rhs.mtime.tv_nsec
                && lhs.size == rhs.size && lhs.inode == rhs.inode
        }
    }

    private var cache: [String: (stamp: FileStamp, assessment: TrustAssessment)] = [:]
    // Latched: "has held network connections" doesn't evaporate when a socket
    // closes — and an un-latched signal would flap the badge (and the list
    // order) every few seconds as connections come and go.
    private var everNetworkActive: Set<String> = []
    // executable path → the vouch recorded by BundleSealVerifier, carrying the
    // fingerprint the file had when its bundle was verified. Keyed by the
    // specific binary, never by bundle membership: a file planted into a
    // verified bundle was never vouched, so it stays flagged.
    private var vouchedBinaries: [String: (bundle: String, fingerprint: Data)] = [:]

    /// Drops every cached verdict so the next pass re-inspects from scratch.
    /// Backs "Full sweep": the cache is keyed on the file not having changed,
    /// so without this a forced sweep would re-report the same answers.
    func invalidateCache() {
        cache.removeAll()
        everNetworkActive.removeAll()
    }

    func setVouchedBinaries(_ vouches: [String: (bundle: String, fingerprint: Data)]) {
        vouchedBinaries = vouches
    }

    func assess(path: String, pid: pid_t = -1) -> TrustAssessment {
        var base = staticAssessment(path: path)
        if TrustScoring.base(for: base.tier) != .trusted,
            let vouch = vouchedBinaries[path],
            CodeIdentity.fingerprint(path: path) == vouch.fingerprint
        {
            // The fingerprint is re-read here, not trusted from the map. The
            // map is loaded at launch and after a verification and never
            // refreshed, so checking freshness only when it is built meant a
            // vouched file replaced at any point afterwards kept reading
            // Trusted for the rest of the session.
            base.vouchedByBundle = vouch.bundle
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
        let stamp = Self.stamp(path: path)
        if let hit = cache[path], let stamp, hit.stamp == stamp {
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
        if let stamp {
            // The file changed, so anything remembered about the *old* file at
            // this path is about a different file. The network latch is keyed
            // by path alone, so without this a short-lived build artifact that
            // once opened a socket demoted every later, unrelated binary
            // written to the same temp path.
            everNetworkActive.remove(path)
            cache[path] = (stamp, assessment)
        }
        return assessment
    }

    /// `lstat` rather than `FileManager.attributesOfItem`, measured here at
    /// 10 µs against 119 µs — this runs for every process on every tick, so
    /// the difference is ~5 ms versus ~60 ms of actor time per tick at 500
    /// processes.
    ///
    /// This is a freshness heuristic for an expensive computation, not a
    /// security boundary: mtime and size are both writable by whoever owns the
    /// file. Trust decisions that must survive a hostile file — the vouch
    /// check in `assess` — re-read the content fingerprint instead.
    private static func stamp(path: String) -> FileStamp? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return FileStamp(mtime: info.st_mtimespec, size: info.st_size, inode: info.st_ino)
    }
}
