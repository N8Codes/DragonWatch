import AppKit
import Foundation

/// The Inspect window's state: one run at a time, its progress, its report,
/// and the unrecognised formats this Mac has met.
@MainActor
@Observable final class InspectionModel {
    private let observations: ObservationStore

    init(observations: ObservationStore) {
        self.observations = observations
    }

    /// What the Inspect window is doing, if anything.
    enum Phase: Equatable {
        case idle
        case walking
        case inspecting(done: Int, total: Int)
    }

    private(set) var phase: Phase = .idle
    /// Formats this Mac has seen that the signature table does not know.
    private(set) var unclassifiedFormats: [ObservationLedger.UnclassifiedFormat] = []
    private(set) var report: InspectionReport?
    private let engine = InspectionEngine()
    private var task: Task<Void, Never>?
    /// Results held aside while a run that adds to them is in progress.
    private var carriedReport: InspectionReport?
    /// Bumped by every start and cancel; a run publishes only while its
    /// generation is current.
    private var runGeneration = 0

    var isInspecting: Bool { phase != .idle }

    /// Opens the picker and inspects whatever was chosen.
    ///
    /// `runModal` on a panel opened from a menu bar popover needs the app
    /// activated first.
    func chooseFiles(addingToExisting adding: Bool = false) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.message = "Choose files or folders to check."
        panel.prompt = "Inspect"
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        inspect(urls: panel.urls, addingToExisting: adding)
    }

    /// Inspects a selection, optionally merging into what is already on
    /// screen rather than replacing it.
    ///
    /// Adding is the common case once results exist — you check one file,
    /// then another — and having to Clear first threw away the comparison
    /// you were making.
    func inspect(urls: [URL], addingToExisting adding: Bool = false) {
        guard !urls.isEmpty else { return }
        task?.cancel()
        runGeneration += 1
        let generation = runGeneration
        // Results being added to are held aside while the run is in progress,
        // so a second drop mid-run adds to them too instead of losing them.
        carriedReport = adding ? (report ?? carriedReport) : nil
        let carried = carriedReport
        report = nil
        phase = .walking

        task = Task { [weak self, engine] in
            guard let self else { return }
            // Expanding folders can itself take a while on a large tree, so it
            // gets its own phase rather than looking like a hung start. Detached
            // to leave the main actor; a detached task does not inherit
            // cancellation, so the handler forwards it — without that, Cancel
            // during "Finding files…" let the walk run to its limits.
            let walkTask = Task.detached(priority: .utility) {
                FolderWalker.walk(roots: urls, limits: .default)
            }
            let walk = await withTaskCancellationHandler {
                await walkTask.value
            } onCancel: {
                walkTask.cancel()
            }

            // Only the current run may touch the published state: a cancelled
            // run finishing late used to reset the phase of its replacement.
            guard !Task.isCancelled, self.runGeneration == generation else { return }
            self.phase = .inspecting(done: 0, total: walk.files.count)

            let report = await engine.inspect(
                paths: walk.files,
                roots: urls.map(\.path),
                limitAlreadyHit: walk.limitHit,
                folderCount: walk.folderCount,
                progress: { [weak self] done, total in
                    Task { @MainActor in
                        guard let self, self.runGeneration == generation else { return }
                        self.phase = .inspecting(done: done, total: total)
                    }
                })

            // The engine returns a partial report when cancelled mid-run.
            // Publishing it anyway put results on screen 1.5 s after the user
            // pressed Cancel, and — when a second run had been started — let
            // the abandoned run overwrite the new one's results.
            guard !Task.isCancelled, self.runGeneration == generation else { return }
            self.report = carried.map { Self.merge($0, report) } ?? report
            self.carriedReport = nil
            self.phase = .idle

            // Learn from what could not be identified. Recorded after the run
            // so a cancelled one contributes nothing.
            let unknown = report.files.compactMap { file -> (String, String)? in
                guard let prefix = file.magicPrefix else { return nil }
                return (prefix, file.declaredExtension)
            }
            await self.observations.observeUnclassified(unknown)
            self.unclassifiedFormats = await self.observations.unclassifiedFormats()
        }
    }

    /// Combines an earlier run with a new one.
    ///
    /// Re-inspecting the same path replaces the old entry rather than
    /// listing it twice — a second look at a file is an update, not another
    /// file. Roots accumulate so the report still says what was selected,
    /// and the scope figures add up.
    nonisolated static func merge(
        _ existing: InspectionReport, _ incoming: InspectionReport
    ) -> InspectionReport {
        let replaced = Set(incoming.files.map(\.path))
        let kept = existing.files.filter { !replaced.contains($0.path) }
        var roots = existing.roots
        for root in incoming.roots where !roots.contains(root) { roots.append(root) }
        return InspectionReport(
            generated: incoming.generated,
            roots: roots,
            files: kept + incoming.files,
            limitHit: incoming.limitHit ?? existing.limitHit,
            durationSeconds: (existing.durationSeconds ?? 0) + (incoming.durationSeconds ?? 0),
            folderCount: (existing.folderCount ?? 0) + (incoming.folderCount ?? 0))
    }

    func cancel() {
        task?.cancel()
        task = nil
        runGeneration += 1
        // Cancelling an "add" keeps what was on screen before it started.
        if let carriedReport { report = carriedReport }
        carriedReport = nil
        phase = .idle
    }

    /// Whether a new selection can be added to results rather than replace
    /// them: results are on screen, or an add is in progress and holding them.
    var canAdd: Bool { report != nil || carriedReport != nil }

    func clear() {
        cancel()
        report = nil
    }

    func loadUnclassifiedFormats() {
        Task { [weak self] in
            guard let self else { return }
            self.unclassifiedFormats = await self.observations.unclassifiedFormats()
        }
    }

    /// Names a format the app does not recognise. The name annotates; it
    /// never suppresses a finding about a file carrying those bytes.
    func labelUnclassifiedFormat(id: String, label: String?) {
        Task { [weak self] in
            guard let self else { return }
            await self.observations.labelUnclassified(id: id, label: label)
            self.unclassifiedFormats = await self.observations.unclassifiedFormats()
        }
    }

    /// Reset Baseline wipes the record these came from.
    func forgetUnclassifiedFormats() {
        unclassifiedFormats = []
    }

    /// Saves the current report in one format.
    func export(as format: ReportRenderer.Format) {
        guard let report else { return }
        Task {
            // Laying out a large report takes seconds; not on the main actor.
            let rendering = Task.detached(priority: .userInitiated) {
                ReportRenderer.render(report, as: format)
            }
            guard let data = await rendering.value else {
                FileExport.reportFailure("The report could not be rendered.")
                return
            }
            FileExport.save(
                data, suggestedName: ReportRenderer.suggestedFilename(for: report, format: format),
                message: "Save the inspection report.")
        }
    }
}
