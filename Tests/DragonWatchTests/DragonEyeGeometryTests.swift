import XCTest

@testable import DragonWatch

/// The menu bar mark and the Dock icon must be the same eye.
///
/// `Scripts/make-icon.swift` is a standalone script — it cannot import the
/// app target, so it carries its own copy of the control points. That is a
/// drift hazard: changing the shape in one place would leave the Dock and the
/// menu bar showing different marks, and nothing would fail. These read the
/// script and hold the two copies to the same numbers.
final class DragonEyeGeometryTests: XCTestCase {

    private func iconScript() throws -> String {
        // #filePath is <repo>/Tests/DragonWatchTests/<this file>
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let script = repo.appendingPathComponent("Scripts/make-icon.swift")
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: script.path),
            "icon script not present in this checkout")
        return try String(contentsOf: script, encoding: .utf8)
    }

    func testIconScriptUsesTheSameControlPoints() throws {
        let source = try iconScript()
        for corner in DragonEyeGeometry.corners {
            XCTAssertTrue(
                source.contains("(\(number(corner.x)), \(number(corner.y)))"),
                "make-icon.swift is missing corner (\(corner.x), \(corner.y)) — the "
                    + "Dock icon would no longer match the menu bar mark")
        }
        for control in DragonEyeGeometry.controls {
            XCTAssertTrue(
                source.contains("(\(number(control.x)), \(number(control.y)))"),
                "make-icon.swift is missing control (\(control.x), \(control.y))")
        }
    }

    func testIconScriptUsesTheSamePupilProportions() throws {
        let source = try iconScript()
        let pupil = DragonEyeGeometry.pupil
        for value in [pupil.x, pupil.y, pupil.width, pupil.height] {
            XCTAssertTrue(
                source.contains(String(format: "%.2f", value)),
                "make-icon.swift is missing pupil value \(value)")
        }
    }

    /// The shape itself: a wide almond with a hole in it.
    func testShapeIsAWideAlmondWithAPupil() {
        let rect = CGRect(x: 0, y: 0, width: 100, height: 70)
        let path = DragonEyeShape().path(in: rect)
        XCTAssertFalse(path.isEmpty)
        // The outline reaches the horizontal extremes and stays inside vertically.
        let bounds = path.boundingRect
        XCTAssertEqual(bounds.width, 96, accuracy: 2, "spans corner to corner")
        XCTAssertLessThanOrEqual(bounds.height, 70)
        // Sample off y=35: that is exactly the corner height, so a horizontal
        // ray there passes through both tips and containment is degenerate.
        XCTAssertTrue(
            path.contains(CGPoint(x: 20, y: 30), eoFill: true),
            "the body of the eye, left of the pupil, must be filled")
        XCTAssertTrue(
            path.contains(CGPoint(x: 80, y: 30), eoFill: true),
            "and right of the pupil")
        XCTAssertTrue(
            path.contains(CGPoint(x: 50, y: 16), eoFill: true),
            "the lid above the pupil must be filled")
        // Even-odd fill is what makes the pupil a hole rather than a disc.
        XCTAssertFalse(
            path.contains(CGPoint(x: 50, y: 30), eoFill: true),
            "the pupil must be a hole, not filled")
        XCTAssertFalse(
            path.contains(CGPoint(x: 50, y: 5), eoFill: true),
            "above the eye is outside the shape entirely")
    }

    private func number(_ value: CGFloat) -> String {
        value == value.rounded() ? String(Int(value)) : String(describing: value)
    }
}
