import Foundation

/// The one `URLSession` every threat-intel fetch goes through.
///
/// `URLSession.shared` carries the process-wide cookie store and the default
/// header set, which quietly turns "we only ask a public feed for a public
/// file" into a tracked, fingerprintable client: a server that returns one
/// `Set-Cookie` can link every daily CISA KEV pull and every NVD lookup into
/// a single persistent identity, and the
/// default `User-Agent` discloses the exact macOS kernel build
/// (`CFNetwork/… Darwin/25.5.0`) while `Accept-Language` discloses the locale.
///
/// DragonWatch tells users that nothing about their Mac is sent to these
/// services. This is what makes that true: no cookie storage, no persistent
/// cache on disk, no credential store, and a fixed generic `User-Agent` that
/// is identical for every user.
enum IntelSession {
    static let shared: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.httpAdditionalHeaders = [
            "User-Agent": "DragonWatch",
            "Accept-Language": "en",
        ]
        return URLSession(configuration: configuration)
    }()

    /// Fetches a URL, rejecting non-200 responses and anything over `byteCap`.
    ///
    /// The status check is not decoration: an HTTP 503 error page is a
    /// perfectly valid `Data`, and without this the HTML body flows into the
    /// zip extractor or JSON decoder as if it were the feed.
    static func fetch(_ request: URLRequest, byteCap: Int) async -> Data? {
        guard let (data, response) = try? await shared.data(for: request),
            (response as? HTTPURLResponse)?.statusCode == 200,
            data.count <= byteCap
        else { return nil }
        return data
    }

    static func fetch(_ url: URL, byteCap: Int) async -> Data? {
        await fetch(URLRequest(url: url), byteCap: byteCap)
    }
}
