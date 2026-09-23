import XCTest

@testable import DragonWatch

/// The model's inspect pipeline: starting, adding, cancelling and replacing
/// runs. Every case here was a real defect in the wiring, not the engine.
@MainActor
final class InspectionPipelineTests: XCTestCase {

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Pipeline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func file(_ name: String, bytes: Int = 16) throws -> URL {
        let url = dir.appendingPathComponent(name)
        try Data(repeating: 0x41, count: bytes).write(to: url)
        return url
    }

    private func bigFolder(_ name: String, count: Int = 3000) throws -> URL {
        let folder = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        for index in 0..<count {
            try Data(repeating: 0x41, count: 2048)
                .write(to: folder.appendingPathComponent("s\(index).bin"))
        }
        return folder
    }

    private func waitForReport(_ model: AppModel, timeout: Duration = .seconds(20)) async
        -> InspectionReport?
    {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if let report = model.inspectionReport, !model.isInspecting { return report }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return model.inspectionReport
    }

    /// Adding to results while a previous add is still running dropped the
    /// results being kept, because the view tested `inspectionReport`, which
    /// is nil for the duration of a run.
    func testAddingWhileAnAddIsInProgressKeepsTheCarriedResults() async throws {
        let a = try file("a.txt")
        let b = try file("b.txt")
        let c = try file("c.txt")
        let model = AppModel()

        model.inspect(urls: [a])
        let first = await waitForReport(model)
        XCTAssertNotNil(first)

        model.inspect(urls: [b], addingToExisting: true)
        XCTAssertNil(model.inspectionReport, "results are held aside during the run")
        XCTAssertTrue(model.canAddToInspection, "the view must still offer to add")
        model.inspect(urls: [c], addingToExisting: model.canAddToInspection)

        let merged = await waitForReport(model)
        let report = try XCTUnwrap(merged)
        let names = report.files.map(\.displayName).sorted()
        XCTAssertEqual(names, ["a.txt", "c.txt"], "a is kept, b was replaced before it ran")
        XCTAssertTrue(model.canAddToInspection)
    }

    /// Cancelling an add restores what was on screen before it started.
    func testCancellingAnAddRestoresTheKeptResults() async throws {
        let a = try file("a.txt")
        let big = try bigFolder("big")
        let model = AppModel()
        model.inspect(urls: [a])
        let published = await waitForReport(model)
        let first = try XCTUnwrap(published)

        model.inspect(urls: [big], addingToExisting: true)
        model.cancelInspection()
        XCTAssertEqual(model.inspectionReport?.files.map(\.path), first.files.map(\.path))
        XCTAssertFalse(model.isInspecting)
    }

    /// A run replaced mid-flight used to finish late and reset the phase to
    /// idle while its replacement was still working, so the window showed
    /// the empty state with no Cancel button.
    func testAbandonedRunNeverTouchesTheReplacementsState() async throws {
        let big = try bigFolder("big")
        let small = try file("small.txt")
        let model = AppModel()

        model.inspect(urls: [big])
        for _ in 0..<400 {
            if case .inspecting = model.inspectionPhase { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        guard case .inspecting = model.inspectionPhase else {
            throw XCTSkip("the big run finished before it could be replaced")
        }

        model.inspect(urls: [small])
        // While the replacement has not published, the phase must never read
        // idle — that is exactly what the abandoned run used to do to it.
        let deadline = ContinuousClock.now + .seconds(20)
        while model.inspectionReport == nil, ContinuousClock.now < deadline {
            XCTAssertNotEqual(model.inspectionPhase, .idle, "phase reset by the abandoned run")
            try? await Task.sleep(for: .milliseconds(2))
        }
        let report = try XCTUnwrap(model.inspectionReport)
        XCTAssertEqual(report.files.map(\.displayName), ["small.txt"])
        XCTAssertEqual(model.inspectionPhase, .idle)
    }

    /// Clear after an add leaves nothing behind to be "added to".
    func testClearDropsCarriedResultsToo() async throws {
        let a = try file("a.txt")
        let big = try bigFolder("big", count: 200)
        let model = AppModel()
        model.inspect(urls: [a])
        let first = await waitForReport(model)
        XCTAssertNotNil(first)
        model.inspect(urls: [big], addingToExisting: true)
        model.clearInspection()
        XCTAssertNil(model.inspectionReport)
        XCTAssertFalse(model.canAddToInspection)
    }
}
