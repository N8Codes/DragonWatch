import UserNotifications
import XCTest

@testable import DragonWatch

/// The mapping from the system's answer to what Settings shows. `.failed`
/// exists because a request can error without ever prompting — observed on
/// a real install, where the only symptom had been silence.
final class NotificationPermissionTests: XCTestCase {
    private struct Refused: LocalizedError {
        var errorDescription: String? { "Notifications are not allowed for this application" }
    }

    func testGrantedStatesAreAllowed() {
        for status: UNAuthorizationStatus in [.authorized, .provisional] {
            XCTAssertEqual(
                NotificationPermission.from(status: status, requestError: nil), .allowed)
        }
    }

    func testDeniedIsDeniedEvenWithoutAnError() {
        XCTAssertEqual(NotificationPermission.from(status: .denied, requestError: nil), .denied)
    }

    func testUndeterminedWithAnErrorReportsTheSystemsReason() {
        XCTAssertEqual(
            NotificationPermission.from(status: .notDetermined, requestError: Refused()),
            .failed("Notifications are not allowed for this application"))
    }

    func testUndeterminedWithoutAnErrorIsUnknown() {
        XCTAssertEqual(
            NotificationPermission.from(status: .notDetermined, requestError: nil), .unknown)
    }
}
