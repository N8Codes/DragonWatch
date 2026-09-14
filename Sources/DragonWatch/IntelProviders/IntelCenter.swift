import Foundation

/// Runs the enabled intel provider against one process, on demand — never as
/// part of the monitoring loop. Results cache by executable path for the
/// session.
@MainActor
@Observable final class IntelCenter {
    enum CheckState {
        case running
        case done([IntelFinding])
        case failed(String)
    }
    private(set) var results: [String: CheckState] = [:]

    private let settings: SettingsModel
    private let kev = KEVProvider()

    init(settings: SettingsModel) {
        self.settings = settings
    }

    var anyProviderEnabled: Bool {
        settings.kevEnabled
    }

    /// What the user is consenting to, assembled from the enabled providers'
    /// own disclosures.
    var activeDisclosures: [String] {
        settings.kevEnabled ? [kev.privacyDisclosure] : []
    }

    func check(_ process: MonitoredProcess) {
        // The button only renders while a provider is enabled; a call without
        // one is a stale view, not a user action.
        guard settings.kevEnabled else { return }
        let path = process.record.path
        if case .running = results[path] { return }
        results[path] = .running

        let app = appInfo(for: process)
        let subject = IntelSubject(
            executablePath: path, appName: app.name, appVersion: app.version)

        Task {
            do {
                let findings = try await kev.findings(for: subject)
                results[path] = .done(findings.sorted { $0.severity > $1.severity })
            } catch {
                results[path] = .failed("\(kev.name) lookup failed.")
            }
        }
    }

    private func appInfo(for process: MonitoredProcess)
        -> (name: String?, version: String?)
    {
        guard let root = ContextInspector.bundleRoot(of: process.record.path) else {
            return (nil, nil)
        }
        let name = ((root as NSString).lastPathComponent as NSString)
            .deletingPathExtension
        let version =
            Bundle(path: root)?
            .infoDictionary?["CFBundleShortVersionString"] as? String
        return (name, version)
    }
}
