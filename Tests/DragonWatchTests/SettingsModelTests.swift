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
    }

    @MainActor
    func testIntelOptInPersists() {
        let settings = SettingsModel(defaults: defaults)
        settings.kevEnabled = true

        let reloaded = SettingsModel(defaults: defaults)
        XCTAssertTrue(reloaded.kevEnabled)
    }

    /// The VirusTotal key was a credential stored in plain UserDefaults. With
    /// the feature gone nothing reads it, so the first launch of a build
    /// without the feature must scrub it — a secret should not outlive the
    /// code that needed it.
    @MainActor
    func testRetiredKeysAreScrubbedOnLoad() {
        defaults.set("test-key", forKey: "intel.vtAPIKey")
        defaults.set(true, forKey: "intel.vtEnabled")
        defaults.set(true, forKey: "intel.mbEnabled")
        defaults.set(true, forKey: "watcher.ruleDisabled.knownMalware")
        defaults.set(true, forKey: "intel.kevEnabled")

        let settings = SettingsModel(defaults: defaults)

        XCTAssertNil(defaults.object(forKey: "intel.vtAPIKey"))
        XCTAssertNil(defaults.object(forKey: "intel.vtEnabled"))
        XCTAssertNil(defaults.object(forKey: "intel.mbEnabled"))
        XCTAssertNil(defaults.object(forKey: "watcher.ruleDisabled.knownMalware"))
        XCTAssertTrue(settings.kevEnabled, "live keys are untouched")
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
