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
                }
            }

            section("Watcher") {
                WatcherSettingsSection(settings: model.settings)
            }

            section("Threat intel") {
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

        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .onAppear {
            launchAtLogin = isBundled && SMAppService.mainApp.status == .enabled
        }
    }

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

/// The only place DragonWatch ever talks to anyone but Apple/Cloudflare —
/// off by default, each toggle stating exactly what leaves the machine.
private struct IntelSettingsSection: View {
    @Bindable var settings: SettingsModel

    var body: some View {
        Text(
            "Off by default. Anything that sends data runs only when you press \"Run intel checks\" on a process; MalwareBazaar matching is local, so it also watches in the background."
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

        Toggle("MalwareBazaar hash list", isOn: $settings.mbEnabled)
            .font(.caption)
            .controlSize(.small)
        Text(
            "Downloads abuse.ch's public malware-hash list (~40 MB weekly); matching is local, and non-trusted processes are checked automatically. Community-sourced."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)

        Toggle("VirusTotal hash lookup", isOn: $settings.vtEnabled)
            .font(.caption)
            .controlSize(.small)
        Text(
            "Sends the executable's SHA-256 hash to VirusTotal — this reveals what you run to a third party. Needs a free API key."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)
        if settings.vtEnabled {
            SecureField("VirusTotal API key", text: $settings.vtAPIKey)
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
        }
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
