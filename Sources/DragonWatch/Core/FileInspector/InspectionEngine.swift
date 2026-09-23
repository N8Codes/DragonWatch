import Foundation

/// A structural inspector for one family of formats.
///
/// Implementations are pure functions over an already-read `FileProbe`: they
/// never touch disk, never decode, and never execute. Adding a format means
/// adding one of these and registering it — the engine itself does not change.
protocol FormatInspector: Sendable {
    func handles(_ format: FileFormat) -> Bool
    func inspect(probe: FileProbe, format: FileFormat) -> InspectorOutput

    /// Offsets at which this format legitimately contains another format's
    /// signature, so the generic scan does not report the file's own
    /// structure as a passenger. A universal binary's architecture slices are
    /// the motivating case.
    func knownEmbeddedOffsets(probe: FileProbe, format: FileFormat) -> Set<Int64>
}

extension FormatInspector {
    func knownEmbeddedOffsets(probe: FileProbe, format: FileFormat) -> Set<Int64> { [] }
}

struct InspectorOutput: Sendable {
    var findings: [Finding] = []
    var disclosures: [Disclosure] = []
    /// Plain-language names of the examinations performed.
    ///
    /// A verification tool that reports only what it *found* leaves "0
    /// findings" meaning either "checked thoroughly, nothing wrong" or
    /// "barely looked" — and the user cannot tell which. Each inspector
    /// states what it did, so a clean result says what it verified.
    var checks: [String] = []

    static let none = InspectorOutput()
}

/// Orchestrates one inspection run: probe, identify, check, assemble.
///
/// The engine is deliberately thin. All the judgement lives in
/// `UniversalChecks` and the registered `FormatInspector`s, which are pure and
/// therefore testable against bytes rather than against files on this machine.
actor InspectionEngine {

    /// Runtime caps. Generous enough that a normal folder never hits one, low
    /// enough that pointing this at a home directory cannot wedge the app.
    struct Limits: Sendable {
        var maxFiles = 50_000
        var maxTotalBytes: Int64 = 64 * 1024 * 1024 * 1024
        /// Deep enough for any real project tree; a loop the symlink guard
        /// misses still terminates here.
        var maxDepth = 16
        var maxDuration: TimeInterval = 600
        /// Files above this are identified and structurally checked but not
        /// hashed — a 20 GB video would otherwise dominate the whole run.
        var maxHashBytes: Int64 = 2 * 1024 * 1024 * 1024
        /// Probing is IO-bound and hashing is CPU-bound; four keeps a spinning
        /// disk busy without turning the app into the heaviest thing running,
        /// which is the footprint promise the whole project is built on.
        var concurrency = 4

        static let `default` = Limits()
    }

    private let hasher: FileHasher
    private let limits: Limits
    private let inspectors: [FormatInspector]

    init(
        hasher: FileHasher = FileHasher(),
        limits: Limits = .default,
        inspectors: [FormatInspector] = [
            ExecutableInspector(), ImageInspector(), DocumentInspector(),
            MediaInspector(),
        ]
    ) {
        self.hasher = hasher
        self.limits = limits
        self.inspectors = inspectors
    }

    /// Inspects a set of **file** paths.
    ///
    /// Directory expansion is not done here — `FolderWalker` turns a selection
    /// into a file list and owns the recursion caps. Keeping the engine over a
    /// flat list means a run is trivially cancellable and its cost is known
    /// before it starts.
    func inspect(
        paths: [String],
        roots: [String]? = nil,
        hashFiles: Bool = true,
        limitAlreadyHit: InspectionLimit? = nil,
        folderCount: Int? = nil,
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async -> InspectionReport {
        let started = Date()
        let deadline = started.addingTimeInterval(limits.maxDuration)
        var results: [FileInspection] = []
        var limitHit = limitAlreadyHit
        let capped = Array(paths.prefix(limits.maxFiles))
        if capped.count < paths.count { limitHit = limitHit ?? .fileCountCap }

        var index = 0
        while index < capped.count {
            if Task.isCancelled {
                limitHit = limitHit ?? .cancelled
                break
            }
            if Date() >= deadline {
                limitHit = limitHit ?? .timeCap
                break
            }
            let batch = Array(capped[index..<min(index + limits.concurrency, capped.count)])
            index += batch.count

            let batchResults = await withTaskGroup(of: FileInspection.self) { group in
                for path in batch {
                    group.addTask { [hasher, limits, inspectors] in
                        await Self.inspectOne(
                            path: path, hasher: hasher, limits: limits,
                            inspectors: inspectors, hashFiles: hashFiles)
                    }
                }
                var collected: [FileInspection] = []
                for await result in group { collected.append(result) }
                return collected
            }
            results.append(contentsOf: batchResults)
            progress?(results.count, capped.count)
        }

        return InspectionReport(
            generated: Date(),
            roots: roots ?? paths,
            files: results,
            limitHit: limitHit,
            durationSeconds: Date().timeIntervalSince(started),
            folderCount: folderCount)
    }

    /// One file, start to finish. `nonisolated static` so the task group can
    /// run several at once without serialising on the engine's actor.
    nonisolated static func inspectOne(
        path: String,
        hasher: FileHasher,
        limits: Limits,
        inspectors: [FormatInspector],
        hashFiles: Bool
    ) async -> FileInspection {
        let probe = FileProbe.read(path: path)
        let format =
            probe.isReadable ? MagicBytes.identify(head: probe.head, tail: probe.tail) : nil

        // Ask the format's own inspector which embedded signatures its
        // structure accounts for *before* the generic scan runs, so the scan
        // never reports the file's own layout as a passenger.
        var accountedFor: Set<Int64> = []
        if let format, probe.isReadable {
            for inspector in inspectors where inspector.handles(format) {
                accountedFor.formUnion(
                    inspector.knownEmbeddedOffsets(probe: probe, format: format))
            }
        }

        var findings = UniversalChecks.run(
            probe: probe, identified: format, accountedForOffsets: accountedFor)
        var disclosures = UniversalChecks.disclosures(probe: probe)
        var checks: [String] = ["Filename characters", "File type and permissions"]
        if probe.isReadable {
            checks.insert("Extension against actual contents", at: 0)
            if probe.size > 0 {
                checks.append(
                    probe.isFullyWindowed
                        ? "Embedded format signatures (whole file)"
                        : "Embedded format signatures (first and last 64 KB)")
            }
        }

        if let format, probe.isReadable {
            for inspector in inspectors where inspector.handles(format) {
                let output = inspector.inspect(probe: probe, format: format)
                findings.append(contentsOf: output.findings)
                disclosures.append(contentsOf: output.disclosures)
                checks.append(contentsOf: output.checks)
            }
        }

        // Source and plain text mostly carry no signature at all, so the
        // format-keyed inspectors never see them; the extension decides.
        if SourceInspector.appliesTo(probe: probe, format: format) {
            let output = SourceInspector.inspect(probe: probe)
            findings.append(contentsOf: output.findings)
            disclosures.append(contentsOf: output.disclosures)
            checks.append(contentsOf: output.checks)
        }

        // A bundle has no bytes of its own; its signature answers for it.
        if probe.isBundle {
            let output = BundleInspector.inspect(probe: probe)
            findings.append(contentsOf: output.findings)
            disclosures.append(contentsOf: output.disclosures)
            checks.append(contentsOf: output.checks)
        }

        var digest: String?
        if hashFiles, probe.isReadable, probe.size > 0, probe.size <= limits.maxHashBytes {
            digest = await hasher.sha256(ofPath: path)
            if digest != nil { checks.append("SHA-256 of the whole file") }
        }

        return FileInspection(
            path: path,
            // Sanitised for display: the name rules flag a direction override,
            // and the row must not then render the very spoof it flagged.
            // `path` stays exact so exports and merges refer to the real file.
            displayName: UniversalChecks.displaySafe(probe.displayName, limit: 255),
            byteSize: probe.size,
            sha256: digest,
            declaredExtension: probe.declaredExtension,
            identifiedFormat: format?.name,
            // Only for the unclassified case: the bytes are what identifies a
            // format nobody recognised yet. Text and source have no signature
            // to learn, so they are not "unclassified".
            magicPrefix: format == nil && probe.isReadable && probe.size > 0
                && !SourceInspector.appliesTo(probe: probe, format: nil)
                ? UniversalChecks.hexPreview(probe.head, limit: 16).replacingOccurrences(
                    of: " ", with: "")
                : nil,
            findings: findings,
            disclosures: disclosures,
            checksRun: checks,
            // A bundle was meaningfully examined even though no bytes were
            // read, so it must not fall through to "Unreadable".
            verdict: FileInspection.verdict(
                readable: probe.isReadable || probe.isBundle, findings: findings))
    }
}
