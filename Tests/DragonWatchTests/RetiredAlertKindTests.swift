import XCTest

@testable import DragonWatch

/// Retiring an alert rule leaves its events in every existing user's ledger.
/// They are read back on the next launch, so dropping a rule is only safe
/// because unknown kinds are discarded rather than mapped onto whichever rule
/// happens to be nearby.
///
/// `networkChange` was retired when wifi drops stopped counting as security
/// events, which is what made this path live rather than theoretical.
final class RetiredAlertKindTests: XCTestCase {

    private func event(_ kind: String, _ title: String, secondsAgo: TimeInterval = 0)
        -> ObservationLedger.Event
    {
        ObservationLedger.Event(
            date: Date(timeIntervalSince1970: 1_700_000_000 - secondsAgo),
            kind: kind, title: title, detail: "d")
    }

    func testRetiredKindIsGone() {
        XCTAssertNil(
            AlertKind(rawValue: "networkChange"),
            "the retired rule must not decode, or old events would resurface")
        XCTAssertNotNil(AlertKind(rawValue: "newUntrustedProcess"))
    }

    /// The case that matters on upgrade: a ledger holding both.
    func testRetiredEventsAreDroppedAndTheRestSurvive() {
        let events = [
            event("newUntrustedProcess", "kept one", secondsAgo: 30),
            event("networkChange", "Network dropped", secondsAgo: 20),
            event("invalidSignature", "kept two", secondsAgo: 10),
        ]
        let shown = AlertCenter.displayable(events)

        XCTAssertEqual(shown.map(\.title), ["kept two", "kept one"], "newest first")
        XCTAssertFalse(shown.contains { $0.title.contains("Network") })
    }

    func testALedgerOfOnlyRetiredEventsShowsNothing() {
        let shown = AlertCenter.displayable([
            event("networkChange", "a"), event("networkChange", "b"),
        ])
        XCTAssertTrue(shown.isEmpty)
    }

    /// An unrecognised kind from a *newer* build must be dropped just as
    /// safely as a retired one.
    func testUnknownFutureKindIsAlsoDropped() {
        let shown = AlertCenter.displayable([
            event("somethingFromALaterVersion", "future"),
            event("sustainedCPU", "known"),
        ])
        XCTAssertEqual(shown.map(\.title), ["known"])
    }

    /// Only the newest `limit` events are read back, and the limit is applied
    /// before the mapping so a run of retired events cannot push real ones
    /// out of the window.
    func testTheNewestEventsAreKeptWhenOverTheLimit() {
        let events = (0..<150).map {
            event("newUntrustedProcess", "e\($0)", secondsAgo: TimeInterval(150 - $0))
        }
        let shown = AlertCenter.displayable(events, limit: 10)
        XCTAssertEqual(shown.count, 10)
        XCTAssertEqual(shown.first?.title, "e149", "newest first")
        XCTAssertEqual(shown.last?.title, "e140")
    }

    func testEmptyLedgerIsEmpty() {
        XCTAssertTrue(AlertCenter.displayable([]).isEmpty)
    }

    /// Settings persists a disabled flag per rule. A flag left behind for a
    /// retired rule must not affect the rules that remain.
    @MainActor
    func testAStaleDisabledFlagForARetiredRuleIsHarmless() throws {
        let suite = "RetiredRule-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        // What 1.0.0 wrote when the rule was switched off: the key shape is
        // SettingsModel's, with the retired raw value.
        let staleKey = "watcher.ruleDisabled.networkChange"
        defaults.set(true, forKey: staleKey)

        let settings = SettingsModel(defaults: defaults)
        for kind in AlertKind.allCases {
            XCTAssertTrue(
                settings.isEnabled(kind), "\(kind.rawValue) was switched off by a stale key")
        }
        XCTAssertNil(
            defaults.object(forKey: staleKey),
            "a key nothing reads any more must not linger in the preferences file")
    }
}
