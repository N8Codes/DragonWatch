import XCTest

@testable import DragonWatch

final class ProcessNameContextTests: XCTestCase {

    func testVersionLikeNamesAreAmbiguous() {
        XCTAssertTrue(ProcessNameContext.isAmbiguous("2.1.222"))
        XCTAssertTrue(ProcessNameContext.isAmbiguous("v3"))
        XCTAssertTrue(ProcessNameContext.isAmbiguous("20_1_0"))
        XCTAssertFalse(ProcessNameContext.isAmbiguous("zsh"))
        XCTAssertFalse(ProcessNameContext.isAmbiguous("Safari"))
        XCTAssertFalse(ProcessNameContext.isAmbiguous("vvv"), "no digits — a name, not a version")
    }

    func testGenericAndTinyNamesAreAmbiguous() {
        XCTAssertTrue(ProcessNameContext.isAmbiguous("helper"))
        XCTAssertTrue(ProcessNameContext.isAmbiguous("Agent"))
        XCTAssertTrue(ProcessNameContext.isAmbiguous("sh"))
    }

    func testHintSkipsPlumbingDirectories() {
        XCTAssertEqual(
            ProcessNameContext.hint(
                name: "2.1.222",
                path: NSHomeDirectory() + "/.local/share/toolkit/versions/2.1.222"),
            "toolkit")
        XCTAssertEqual(
            ProcessNameContext.hint(
                name: "helper",
                path: "/Library/Application Support/FooApp/helper"),
            "FooApp")
    }

    func testNoHintWhenNothingMeaningfulRemains() {
        XCTAssertNil(ProcessNameContext.hint(name: "sh", path: "/bin/sh"))
    }

    func testUnambiguousNamesGetNoHint() {
        XCTAssertNil(
            ProcessNameContext.hint(
                name: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari"))
    }
}
