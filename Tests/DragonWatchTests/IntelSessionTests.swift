import XCTest

@testable import DragonWatch

/// DragonWatch tells users that nothing about their Mac is sent to the intel
/// feeds. These pin the session properties that make that true — they are a
/// user-facing promise, not an implementation detail, so a future edit that
/// switches a provider back to `URLSession.shared` should fail here.
final class IntelSessionTests: XCTestCase {
    private var configuration: URLSessionConfiguration {
        IntelSession.shared.configuration
    }

    /// A single `Set-Cookie` from any feed would otherwise link every KEV and
    /// NVD request this machine ever makes into one persistent identity — verified previously against a local server, where
    /// `URLSession.shared` replayed a cookie across separate process launches.
    func testSessionAcceptsNoCookies() {
        XCTAssertEqual(configuration.httpCookieAcceptPolicy, .never)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertNil(configuration.httpCookieStorage)
    }

    /// Nothing about which hashes or CVEs were looked up may persist to disk.
    func testSessionKeepsNothingOnDisk() {
        XCTAssertNil(configuration.urlCache)
        XCTAssertNil(configuration.urlCredentialStorage)
    }

    /// The default agent string discloses the exact kernel build
    /// ("CFNetwork/… Darwin/25.5.0") and the locale. Ours is a constant, so
    /// every DragonWatch user looks identical to the server.
    func testUserAgentDisclosesNothingAboutThisMac() throws {
        let headers = try XCTUnwrap(configuration.httpAdditionalHeaders)
        let agent = try XCTUnwrap(headers["User-Agent"] as? String)
        XCTAssertEqual(agent, "DragonWatch")
        for leak in [ProcessInfo.processInfo.operatingSystemVersionString, "Darwin", "CFNetwork"] {
            XCTAssertFalse(agent.contains(leak), "user agent must not carry \(leak)")
        }
        XCTAssertEqual(headers["Accept-Language"] as? String, "en")
    }

    func testSharedSessionIsNotTheProcessWideOne() {
        XCTAssertFalse(IntelSession.shared === URLSession.shared)
    }
}
