import SwiftUI

/// Every alert the watcher has raised, newest first.
struct AlertHistoryView: View {
    @Environment(AppModel.self) private var model
    let alerts: AlertCenter

    var body: some View {
        Group {
            if alerts.history.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "bell.slash")
                        .font(.title2)
                        .foregroundStyle(.tertiary)
                    Text("No alerts — quiet is good.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Spacer()
                            // Through the model, not the AlertCenter: the
                            // durable copy has to go too, or "Clear" undoes
                            // itself on the next launch.
                            Button("Clear") { model.clearAlertHistory() }
                                .controlSize(.regular)
                                .accessibilityLabel("Clear alert history")
                        }
                        ForEach(alerts.history) { event in
                            row(event)
                        }
                    }
                    .padding(10)
                }
            }
        }
        .onAppear { alerts.markAllRead() }
    }

    private func row(_ event: AlertEvent) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: event.kind.symbolName)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(event.title)
                        .font(.callout)
                    if let technique = event.kind.attackTechnique {
                        Text(technique)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
                Text(event.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .help(event.detail)
            }
            Spacer()
            Text(event.date.formatted(date: .omitted, time: .shortened))
                .font(.caption)
                .foregroundStyle(.tertiary)
            // Per-alert dismiss. Names the alert for VoiceOver: a column of
            // identical "Dismiss, button" rows tells a screen-reader user
            // nothing about which one they are about to remove.
            Button {
                model.dismissAlert(event)
            } label: {
                Image(systemName: "xmark.circle")
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help("Dismiss this alert")
            .accessibilityLabel("Dismiss alert: \(event.title)")
        }
    }
}
