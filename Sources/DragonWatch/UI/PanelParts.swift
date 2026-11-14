import SwiftUI

/// A titled block in the Criteria and Settings panels.
struct PanelSection<Content: View>: View {
    let title: String
    var spacing: CGFloat = 5
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: spacing) {
            Text(title)
                .font(AppText.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            content
        }
    }
}

/// The ✕ that closes a detail panel. Names what it closes: a screen reader
/// otherwise hears an unnamed button.
struct CloseDetailsButton: View {
    let subject: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.secondary)
        }
        .buttonStyle(.plain)
        .help("Close details")
        .accessibilityLabel("Close details for \(subject)")
    }
}
