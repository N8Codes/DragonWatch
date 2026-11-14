import XCTest

@testable import DragonWatch

final class SimulatorAppTests: XCTestCase {
    private let launcher =
        "/Library/Developer/CoreSimulator/Volumes/iOS_23E254a/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.4.simruntime/Contents/Resources/RuntimeRoot/sbin/launchd_sim"
    private let testDevice =
        "/Users/someone/Library/Developer/XCTestDevices/11111111-2222-4333-8444-555555555555/data/Containers/Bundle/Application/CAA87DDF-63DD-46F4-B8EA-F3AC77BF64B6/notedUITests-Runner.app/notedUITests-Runner"
    private let simDevice =
        "/Users/someone/Library/Developer/CoreSimulator/Devices/AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE/data/Containers/Bundle/Application/4AFBCD31-9634-44FC-85A0-5E8B3DB65141/noted.app/noted"

    private func launch(_ parent: String?) -> LaunchContext {
        LaunchContext(parentPID: 62854, parentPath: parent, startedAt: nil)
    }

    /// The alert from 2026-11-13: a UI-test runner in a cloned test device.
    func testTestDeviceAppLaunchedBySimulatorMatches() {
        XCTAssertTrue(SimulatorApp.matches(path: testDevice, launch: launch(launcher)))
        XCTAssertTrue(SimulatorApp.matches(path: simDevice, launch: launch(launcher)))
    }

    func testDevicePathWithoutSimulatorParentDoesNotMatch() {
        XCTAssertFalse(SimulatorApp.matches(path: testDevice, launch: launch("/bin/zsh")))
        XCTAssertFalse(SimulatorApp.matches(path: testDevice, launch: launch(nil)))
        XCTAssertFalse(SimulatorApp.matches(path: testDevice, launch: nil))
    }

    /// A binary named launchd_sim somewhere writable is not the simulator.
    func testImpostorLauncherOutsideCoreSimulatorDoesNotMatch() {
        XCTAssertFalse(
            SimulatorApp.matches(path: testDevice, launch: launch("/Users/someone/tmp/launchd_sim"))
        )
    }

    func testSimulatorParentOutsideDeviceFolderDoesNotMatch() {
        XCTAssertFalse(
            SimulatorApp.matches(path: "/Users/someone/Downloads/x.app/x", launch: launch(launcher))
        )
        XCTAssertFalse(
            SimulatorApp.isDeviceAppPath(
                "/Users/someone/Library/Developer/XCTestDevices/not-a-uuid/data/Containers/Bundle/Application/A/x.app/x"
            ))
        XCTAssertFalse(
            SimulatorApp.isDeviceAppPath(
                "/Users/someone/Library/Developer/XCTestDevices/11111111-2222-4333-8444-555555555555/data/Library/x"
            ))
    }

    /// Every clone of one build shares a key; a different binary never does,
    /// whatever it is named.
    func testThrottleKeyIsPerBuildNotPerName() {
        let build = Data([0xab, 0x01])
        XCTAssertEqual(SimulatorApp.throttleKey(cdhash: build), "simulator:ab01")
        XCTAssertNotEqual(
            SimulatorApp.throttleKey(cdhash: build),
            SimulatorApp.throttleKey(cdhash: Data([0xab, 0x02])))
        XCTAssertNil(SimulatorApp.throttleKey(cdhash: nil), "no cdhash: per-path alert")
    }
}
