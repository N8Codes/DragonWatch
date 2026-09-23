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
        .onAppear { model.loadUnclassifiedFormats() }
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
                    .font(AppText.caption)
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

            unrecognisedFormats

            section("Baseline") {
                if confirmingReset {
                    HStack(spacing: 8) {
                        Text("Re-review everything running?")
                            .font(AppText.caption)
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
                .font(AppText.caption)
                .foregroundStyle(.tertiary)
            }

            // Which build is this? Answered here because a menu bar app has
            // no About window and the bundle's version is otherwise only
            // visible from Finder.
            Text(Self.versionLine)
                .font(AppText.caption)
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

    /// Formats this Mac has met that the signature table does not know.
    ///
    /// Naming one records what it is. It **annotates only** — the baseline's
    /// "expected" verdict silences a path forever, and that would be exactly
    /// wrong here: saying what a format is does not vouch for any file
    /// carrying it, and every structural finding still fires.
    @ViewBuilder
    private var unrecognisedFormats: some View {
        if !model.unclassifiedFormats.isEmpty {
            section("Unrecognised formats seen here") {
                Text(
                    "Naming one records what it is for next time. It does not suppress any finding about a file that carries it."
                )
                .font(AppText.caption)
                .foregroundStyle(.secondary)
                ForEach(model.unclassifiedFormats) { entry in
                    UnrecognisedFormatRow(entry: entry) { label in
                        model.labelUnclassifiedFormat(id: entry.id, label: label)
                    }
                }
            }
        }
    }

    private func section(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(AppText.caption.weight(.semibold))
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
                .font(AppText.caption)
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
                .font(AppText.caption)
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
        .font(AppText.caption)
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
        .font(AppText.caption)
        .foregroundStyle(.tertiary)

        Toggle("CISA KEV catalog", isOn: $settings.kevEnabled)
            .font(AppText.caption)
            .controlSize(.small)
        Text(
            "Downloads CISA's public exploited-vulnerabilities list (daily) plus NVD version data for every listed CVE. Nothing about your Mac is sent."
        )
        .font(AppText.caption)
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
                .font(AppText.caption)
            Slider(value: $settings.cpuThresholdPercent, in: 50...100, step: 5)
                .controlSize(.small)
                .accessibilityLabel("CPU alert threshold")
                .accessibilityValue(
                    String(format: "%.0f percent", settings.cpuThresholdPercent))
            Text(String(format: "%.0f%%", settings.cpuThresholdPercent))
                .font(AppText.caption.monospacedDigit())
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
            .font(AppText.caption)
            .controlSize(.small)
        }
    }
}

/// One unrecognised format, with a name the user can give it.
///
/// The name is held locally and written once, on Enter or when focus leaves.
/// Binding the field straight through to the model wrote the whole ledger to
/// disk on every keystroke, from an unstructured task per character — and
/// because those tasks carry no ordering guarantee, a later keystroke could
/// be persisted before an earlier one and leave a truncated name stored.
private struct UnrecognisedFormatRow: View {
    let entry: ObservationLedger.UnclassifiedFormat
    let commit: (String) -> Void

    @State private var draft = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(entry.fileExtension.isEmpty ? "no extension" : ".\(entry.fileExtension)")
                .font(AppText.callout)
            Text("\(entry.magicPrefix)  ·  seen \(entry.timesSeen)×")
                .font(AppText.caption2)
                .monospaced()
                .foregroundStyle(.tertiary)
            TextField("Name this format", text: $draft)
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
                .focused($focused)
                .onSubmit { commit(draft) }
                .onChange(of: focused) { _, isFocused in
                    if !isFocused { commit(draft) }
                }
                .accessibilityLabel(
                    "Name for the unrecognised format \(entry.magicPrefix)")
        }
        .padding(.vertical, 2)
        .onAppear { draft = entry.label ?? "" }
        // Switching tabs tears the view down without necessarily changing
        // focus, so without this a name typed and not submitted is lost.
        // Committing an unchanged value is a no-op, so the extra call is free.
        .onDisappear { commit(draft) }
    }
}
