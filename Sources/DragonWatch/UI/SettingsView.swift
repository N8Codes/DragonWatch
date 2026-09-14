import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var launchAtLogin = false
    @State private var confirmingReset = false

    // SMAppService and UserNotifications both need an app bundle; a bare
    // `swift run` binary gets the explanation instead of broken toggles.
    private var isBundled: Bool { Bundle.main.bundleIdentifier != nil }

    var body: some View {
        ScrollView {
            settingsContent
        }
    }

    private var settingsContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            section("General") {
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, enabled in
                        setLaunchAtLogin(enabled)
                    }
                    .disabled(!isBundled)
                if !isBundled {
                    Text(
                        "Login item and notifications need the app bundle — build with Scripts/make-app.sh."
                    )
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                } else {
                    NotificationPermissionRow(permission: model.alerts.notificationPermission)
                }
            }

            section("Watcher") {
                WatcherSettingsSection(settings: model.settings)
            }

            section("Vulnerability catalog") {
                IntelSettingsSection(settings: model.settings)
            }

            section("History") {
                HistorySettingsSection(settings: model.settings) {
                    model.exportHistory()
                }
            }

            section("Baseline") {
                if confirmingReset {
                    HStack(spacing: 8) {
                        Text("Re-review everything running?")
                            .font(.caption)
                        Button("Reset") {
                            model.resetBaseline()
                            confirmingReset = false
                        }
                        .controlSize(.small)
                        Button("Cancel") { confirmingReset = false }
                            .controlSize(.small)
                    }
                } else {
                    Button("Reset Baseline…") { confirmingReset = true }
                        .controlSize(.small)
                }
                Text(
                    "Wipes the ledger of known processes and the observation history, then re-runs the reviewed first-run sweep — for after installing a batch of new software."
                )
                .font(.caption)
                .foregroundStyle(.tertiary)
            }

            // Which build is this? Answered here because a menu bar app has
            // no About window and the bundle's version is otherwise only
            // visible from Finder.
            Text(Self.versionLine)
                .font(.caption)
                .foregroundStyle(.tertiary)
                .accessibilityLabel("Version \(Self.versionLine)")
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .onAppear {
            launchAtLogin = isBundled && SMAppService.mainApp.status == .enabled
            model.alerts.refreshNotificationPermission()
        }
    }

    /// "DragonWatch 1.0.0 (4)", or "DragonWatch (unbundled build)" under
    /// `swift run`, where there is no Info.plist to read.
    static let versionLine: String = {
        let info = Bundle.main.infoDictionary ?? [:]
        guard let short = info["CFBundleShortVersionString"] as? String else {
            return "DragonWatch (unbundled build)"
        }
        let build = (info["CFBundleVersion"] as? String).map { " (\($0))" } ?? ""
        return "DragonWatch \(short)\(build)"
    }()

    private func section(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            content()
        }
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        guard isBundled else { return }
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }
}

/// Says whether macOS will show banners at all — the alert pipeline is silent
/// without the per-app permission, and until this row existed the only
/// symptom of a refused one was a notification that never came.
private struct NotificationPermissionRow: View {
    let permission: NotificationPermission

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(message)
                .font(.caption)
                .foregroundStyle(permission == .allowed ? .tertiary : .secondary)
                .fixedSize(horizontal: false, vertical: true)
            if permission != .allowed {
                Button("Open Notification Settings…") {
                    NSWorkspace.shared.open(
                        URL(
                            string:
                                "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
                        )!)
                }
                .controlSize(.small)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var message: String {
        switch permission {
        case .allowed:
            "Notifications: allowed."
        case .denied:
            "Notifications are turned off for DragonWatch in System Settings. Alerts still appear in the Alerts tab and on the menu bar icon."
        case .failed(let reason):
            "macOS refused the notification permission request (\(reason)). Alerts still appear in the Alerts tab and on the menu bar icon."
        case .unknown:
            "Notifications: not yet decided — macOS asks the first time an alert would show."
        }
    }
}

/// The observation ledger's knobs: how long alert events are kept, and a
/// user-directed export of the local history file.
private struct HistorySettingsSection: View {
    @Bindable var settings: SettingsModel
    let export: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Text("Keep alerts for")
                .font(.caption)
            Picker("", selection: $settings.historyRetentionDays) {
                ForEach(SettingsModel.retentionChoices, id: \.self) { days in
                    Text("\(days) d").tag(days)
                }
            }
            .pickerStyle(.segmented)
            .controlSize(.small)
            .labelsHidden()
            .accessibilityLabel("Keep alerts for")
        }
        Button("Export History…", action: export)
            .controlSize(.small)
        Text(
            "DragonWatch records what it has seen — first-seen dates, hashes, signature changes, alerts — in an owner-only file in Application Support. Local-only; export writes a JSON copy where you choose."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)
    }
}

/// The only place DragonWatch ever talks to anyone but Apple — off by
/// default, and the toggle states exactly what it downloads. Nothing about
/// this Mac goes the other way.
private struct IntelSettingsSection: View {
    @Bindable var settings: SettingsModel

    var body: some View {
        Text(
            "Off by default. Runs only when you press \"Run intel checks\" on a process; matching happens on this Mac."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)

        Toggle("CISA KEV catalog", isOn: $settings.kevEnabled)
            .font(.caption)
            .controlSize(.small)
        Text(
            "Downloads CISA's public exploited-vulnerabilities list (daily) plus NVD version data for every listed CVE. Nothing about your Mac is sent."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)
    }
}

/// Cadence, threshold, and per-rule toggles.
private struct WatcherSettingsSection: View {
    @Bindable var settings: SettingsModel

    var body: some View {
        Picker("Background refresh", selection: $settings.backgroundCadenceSeconds) {
            ForEach(SettingsModel.cadenceChoices, id: \.self) { seconds in
                Text("\(seconds) s").tag(seconds)
            }
        }
        .pickerStyle(.segmented)
        .controlSize(.small)
        .labelsHidden()
        .accessibilityLabel("Background refresh interval")

        HStack(spacing: 8) {
            Text("CPU alert above")
                .font(.caption)
            Slider(value: $settings.cpuThresholdPercent, in: 50...100, step: 5)
                .controlSize(.small)
                .accessibilityLabel("CPU alert threshold")
                .accessibilityValue(
                    String(format: "%.0f percent", settings.cpuThresholdPercent))
            Text(String(format: "%.0f%%", settings.cpuThresholdPercent))
                .font(.caption.monospacedDigit())
                .frame(width: 36, alignment: .trailing)
        }

        ForEach(AlertKind.allCases, id: \.self) { kind in
            Toggle(
                kind.displayName,
                isOn: Binding(
                    get: { settings.isEnabled(kind) },
                    set: { settings.setEnabled(kind, $0) }
                )
            )
            .font(.caption)
            .controlSize(.small)
        }
    }
}
