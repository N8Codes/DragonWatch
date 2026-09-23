import Foundation

/// User-tunable watcher knobs, persisted to UserDefaults. Everything defaults
/// to on/sensible so a fresh install needs no configuration.
@MainActor
@Observable final class SettingsModel {
    static let cadenceChoices = [15, 25, 60]
    static let retentionChoices = [30, 90, 365]

    private enum Keys {
        static let cadence = "watcher.backgroundCadenceSeconds"
        static let cpuThreshold = "watcher.cpuThresholdPercent"
        static func ruleDisabled(_ kind: AlertKind) -> String {
            "watcher.ruleDisabled.\(kind.rawValue)"
        }
        static let retentionDays = "history.retentionDays"
        static let kevEnabled = "intel.kevEnabled"
        /// Written by builds before 1.0 for features since removed. The
        /// VirusTotal key in particular is a credential that must not linger
        /// in the preferences file once nothing reads it.
        static let retired = [
            "intel.mbEnabled", "intel.vtEnabled", "intel.vtAPIKey",
            "watcher.ruleDisabled.knownMalware",
            "watcher.ruleDisabled.networkChange",
        ]
    }

    private let defaults: UserDefaults
    var backgroundCadenceSeconds: Int {
        didSet { defaults.set(backgroundCadenceSeconds, forKey: Keys.cadence) }
    }
    var cpuThresholdPercent: Double {
        didSet { defaults.set(cpuThresholdPercent, forKey: Keys.cpuThreshold) }
    }

    // Stored inverted (disabled = true) so the absent-key default reads as
    // enabled without registering defaults anywhere.
    private var disabledRules: Set<AlertKind> {
        didSet {
            for kind in AlertKind.allCases {
                defaults.set(
                    disabledRules.contains(kind),
                    forKey: Keys.ruleDisabled(kind))
            }
        }
    }

    /// How long observed alert events are kept in the local history file.
    var historyRetentionDays: Int {
        didSet { defaults.set(historyRetentionDays, forKey: Keys.retentionDays) }
    }

    // Threat intel is strictly opt-in: it defaults to off, and the absent-key
    // default reads as false with no registration needed.
    var kevEnabled: Bool {
        didSet { defaults.set(kevEnabled, forKey: Keys.kevEnabled) }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        for key in Keys.retired {
            defaults.removeObject(forKey: key)
        }
        kevEnabled = defaults.bool(forKey: Keys.kevEnabled)
        let storedCadence = defaults.integer(forKey: Keys.cadence)
        backgroundCadenceSeconds =
            Self.cadenceChoices.contains(storedCadence) ? storedCadence : 25
        let storedRetention = defaults.integer(forKey: Keys.retentionDays)
        historyRetentionDays =
            Self.retentionChoices.contains(storedRetention) ? storedRetention : 90
        let storedThreshold = defaults.double(forKey: Keys.cpuThreshold)
        cpuThresholdPercent = (50...100).contains(storedThreshold) ? storedThreshold : 85
        disabledRules = Set(
            AlertKind.allCases.filter {
                defaults.bool(forKey: Keys.ruleDisabled($0))
            })
    }

    func isEnabled(_ kind: AlertKind) -> Bool {
        !disabledRules.contains(kind)
    }

    func setEnabled(_ kind: AlertKind, _ enabled: Bool) {
        if enabled {
            disabledRules.remove(kind)
        } else {
            disabledRules.insert(kind)
        }
    }
}
