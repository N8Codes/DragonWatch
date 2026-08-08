import Foundation

/// Runs the enabled intel providers against one process, on demand. The one
/// exception is MalwareBazaar: matching a hash is entirely local, so the
/// watcher may check every non-trusted process without revealing any of them.
/// It still downloads the public list on its own cadence — machine-independent
/// traffic, but traffic. Results cache by executable path for the session.
@MainActor
@Observable final class IntelCenter {
    enum CheckState {
        case running
        case done([IntelFinding])
        case failed(String)
    }
    private(set) var results: [String: CheckState] = [:]

    let malwareStore = MalwareHashStore()

    private let settings: SettingsModel
    private let hasher = FileHasher()
    private let kev = KEVProvider()

    init(settings: SettingsModel) {
        self.settings = settings
    }

    var anyProviderEnabled: Bool {
        settings.kevEnabled || settings.mbEnabled || settings.vtEnabled
    }

    /// What the user is consenting to, assembled from the enabled providers'
    /// own disclosures.
    var activeDisclosures: [String] {
        var disclosures: [String] = []
        if settings.kevEnabled { disclosures.append(kev.privacyDisclosure) }
        if settings.mbEnabled {
            disclosures.append(
                MalwareBazaarProvider(store: malwareStore).privacyDisclosure)
        }
        if settings.vtEnabled {
            disclosures.append(
                VirusTotalProvider(apiKey: settings.vtAPIKey).privacyDisclosure)
        }
        return disclosures
    }

    /// Shared cached hasher — the observation ledger's provenance queue uses
    /// this so a binary is hashed once, not once per consumer.
    func hash(ofPath path: String) async -> String? {
        await hasher.sha256(ofPath: path)
    }

    /// Background rule support: hash the given executables (cached) and return
    /// the paths whose hashes appear in the local malware list. No network.
    func knownMalwareHits(paths: [String]) async -> [String] {
        var hits: [String] = []
        for path in paths {
            if let hash = await hasher.sha256(ofPath: path),
                await malwareStore.contains(hash)
            {
                hits.append(path)
            }
        }
        return hits
    }

    func check(_ process: MonitoredProcess) {
        let path = process.record.path
        if case .running = results[path] { return }
        results[path] = .running

        let kevEnabled = settings.kevEnabled
        let mbEnabled = settings.mbEnabled
        let vtEnabled = settings.vtEnabled
        let vtKey = settings.vtAPIKey
        let app = appInfo(for: process)

        Task {
            let sha256 =
                vtEnabled || mbEnabled ? await hasher.sha256(ofPath: path) : nil
            let subject = IntelSubject(
                executablePath: path, sha256: sha256,
                appName: app.name, appVersion: app.version)

            var providers: [any IntelProvider] = []
            if kevEnabled { providers.append(kev) }
            if mbEnabled { providers.append(MalwareBazaarProvider(store: malwareStore)) }
            if vtEnabled { providers.append(VirusTotalProvider(apiKey: vtKey)) }

            var findings: [IntelFinding] = []
            for provider in providers {
                do {
                    findings += try await provider.findings(for: subject)
                } catch VirusTotalProvider.LookupError.missingKey {
                    results[path] = .failed("VirusTotal needs an API key (Settings).")
                    return
                } catch VirusTotalProvider.LookupError.invalidKey {
                    results[path] = .failed("VirusTotal rejected the API key.")
                    return
                } catch VirusTotalProvider.LookupError.rateLimited {
                    results[path] = .failed(
                        "VirusTotal rate limit hit — free keys allow 4 lookups/min.")
                    return
                } catch {
                    results[path] = .failed("\(provider.name) lookup failed.")
                    return
                }
            }
            results[path] = .done(
                findings.sorted { $0.severity > $1.severity })
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
