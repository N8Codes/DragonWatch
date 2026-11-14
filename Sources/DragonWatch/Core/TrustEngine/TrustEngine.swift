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

    func assess(
        path: String, pid: pid_t = -1, executableMissing: Bool = false
    ) -> TrustAssessment {
        // Nothing at `path` is the running code, so nothing there is
        // inspected — and no context signal is added on top: the rating
        // already says the one thing that is known.
        if executableMissing {
            return TrustAssessment(
                tier: .executableMissing, modifiers: [], teamID: nil, signingID: nil)
        }
        var base = staticAssessment(path: path)
        if TrustScoring.base(for: base.tier) != .trusted,
            let vouch = vouchedBinaries[path],
            path.hasPrefix(vouch.bundle + "/"),
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

    /// The enclosing bundle when it carries a strong (trusted-tier) signature
    /// — the precondition for seal verification.
    func strongEnclosingBundle(for path: String) -> String? {
        guard let root = ContextInspector.bundleRoot(of: path), root != path else { return nil }
        return TrustScoring.base(for: assess(path: root).tier) == .trusted ? root : nil
    }

    /// How many executables are inspected at once when the cache is cold.
    /// Half the cores, at most eight: enough that a launch is not spent
    /// hashing one binary at a time, without taking the whole machine.
    static let warmConcurrency = max(2, min(8, ProcessInfo.processInfo.activeProcessorCount / 2))

    /// Inspects, in parallel, every path the cache cannot answer for.
    ///
    /// Validation hashes the whole executable, so one pass over a freshly
    /// launched Mac — 800-odd binaries, some of them hundreds of megabytes —
    /// took 27 s done one at a time on this actor, and nothing was shown
    /// until it finished. The inspection itself touches no actor state, so
    /// it runs off the actor and only the results come back.
    func warm(
        paths: some Sequence<String>, progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async {
        var pending: [(path: String, stamp: FileStamp)] = []
        for path in Set(paths) {
            guard let stamp = Self.stamp(path: path), cache[path]?.stamp != stamp else { continue }
            pending.append((path, stamp))
        }
        guard pending.count > 1 else { return }

        let inspected = await withTaskGroup(
            of: (String, FileStamp, TrustAssessment).self
        ) { group in
            var results: [(String, FileStamp, TrustAssessment)] = []
            var next = pending.makeIterator()
            func addNext() {
                guard let item = next.next() else { return }
                group.addTask { (item.path, item.stamp, Self.inspect(path: item.path)) }
            }
            for _ in 0..<Self.warmConcurrency { addNext() }
            for await result in group {
                results.append(result)
                progress?(results.count, pending.count)
                addNext()
            }
            return results
        }
        // The stamp was taken before the read, so a file replaced meanwhile
        // mismatches it and is inspected again on the next assessment.
        for (path, stamp, assessment) in inspected {
            everNetworkActive.remove(path)
            cache[path] = (stamp, assessment)
        }
    }

    /// Signature and location signals for the file at `path`. Touches no
    /// engine state, so it can run anywhere.
    nonisolated static func inspect(path: String) -> TrustAssessment {
        let signature = SignatureInspector.inspect(path: path)
        var modifiers = ContextInspector.modifiers(forPath: path)
        if !signature.riskyEntitlements.isEmpty {
            modifiers.append(.riskyEntitlements)
        }
        return TrustAssessment(
            tier: signature.tier,
            modifiers: modifiers,
            teamID: signature.teamID,
            signingID: signature.signingID
        )
    }

    private func staticAssessment(path: String) -> TrustAssessment {
        let stamp = Self.stamp(path: path)
        if let hit = cache[path], let stamp, hit.stamp == stamp {
            return hit.assessment
        }
        let assessment = Self.inspect(path: path)
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
