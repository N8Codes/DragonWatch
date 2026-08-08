import XCTest

@testable import DragonWatch

final class SettingsModelTests: XCTestCase {
    private var suiteName: String!
    private var defaults: UserDefaults!

    override func setUpWithError() throws {
        suiteName = "SettingsModelTests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suiteName)
    }

    @MainActor
    func testFreshInstallDefaults() {
        let settings = SettingsModel(defaults: defaults)
        XCTAssertEqual(settings.backgroundCadenceSeconds, 25)
        XCTAssertEqual(settings.cpuThresholdPercent, 85)
        for kind in AlertKind.allCases {
            XCTAssertTrue(settings.isEnabled(kind), "\(kind) should default to on")
        }
    }

    @MainActor
    func testChangesPersistAcrossReload() {
        let settings = SettingsModel(defaults: defaults)
        settings.backgroundCadenceSeconds = 60
        settings.cpuThresholdPercent = 70
        settings.setEnabled(.networkChange, false)

        let reloaded = SettingsModel(defaults: defaults)
        XCTAssertEqual(reloaded.backgroundCadenceSeconds, 60)
        XCTAssertEqual(reloaded.cpuThresholdPercent, 70)
        XCTAssertFalse(reloaded.isEnabled(.networkChange))
        XCTAssertTrue(reloaded.isEnabled(.sustainedCPU))
    }

    @MainActor
    func testIntelIsOffByDefault() {
        let settings = SettingsModel(defaults: defaults)
        XCTAssertFalse(settings.kevEnabled)
        XCTAssertFalse(settings.vtEnabled)
        XCTAssertEqual(settings.vtAPIKey, "")
    }

    @MainActor
    func testIntelOptInPersists() {
        let settings = SettingsModel(defaults: defaults)
        settings.kevEnabled = true
        settings.vtEnabled = true
        settings.vtAPIKey = "test-key"

        let reloaded = SettingsModel(defaults: defaults)
        XCTAssertTrue(reloaded.kevEnabled)
        XCTAssertTrue(reloaded.vtEnabled)
        XCTAssertEqual(reloaded.vtAPIKey, "test-key")
    }

    @MainActor
    func testReenablingARuleSticks() {
        let settings = SettingsModel(defaults: defaults)
        settings.setEnabled(.sustainedCPU, false)
        settings.setEnabled(.sustainedCPU, true)
        XCTAssertTrue(settings.isEnabled(.sustainedCPU))
        XCTAssertTrue(SettingsModel(defaults: defaults).isEnabled(.sustainedCPU))
    }

    @MainActor
    func testGarbageStoredValuesFallBackToDefaults() {
        defaults.set(7, forKey: "watcher.backgroundCadenceSeconds")
        defaults.set(999.0, forKey: "watcher.cpuThresholdPercent")
        let settings = SettingsModel(defaults: defaults)
        XCTAssertEqual(settings.backgroundCadenceSeconds, 25)
        XCTAssertEqual(settings.cpuThresholdPercent, 85)
    }
}
