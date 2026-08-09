import SwiftUI

/// Shown once, on first open: what DragonWatch is (and isn't) and how to read
/// the badges — then straight into the reviewed first-run sweep.
struct OnboardingView: View {
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                DragonEyeIcon(badge: .trusted, size: 30)
                Text("Welcome to DragonWatch")
                    .font(.headline)
            }
            .frame(maxWidth: .infinity)

            Text(
                "A read-only window into what's running on your Mac, rated with macOS's own security signals. No data about your machine is sent anywhere. As it ships, every threat-intel provider is off and the only network request DragonWatch makes is a latency check while this popover is open. Turning a provider on lets it download public threat lists in the background; only VirusTotal sends anything of yours, and only a file's hash."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                badgeRow(.trusted, "Apple, App Store, or notarized Developer ID — nothing unusual.")
                badgeRow(
                    .caution, "Legitimate-looking but unverified, or trusted with an asterisk.")
                badgeRow(.suspicious, "Unsigned, invalid signature, or multiple risk signals.")
            }

            Text(
                "First, a one-time sweep: anything not clearly trusted is listed for your verdict before being accepted as normal on this Mac. After that, DragonWatch quietly watches in the background and notifies you only when something changes."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            Text(
                "The dragon eye in your menu bar is the summary — plain when all is clear, with a warning badge when something deserves a look."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            Spacer()

            Button("Start the first sweep") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .frame(maxWidth: .infinity)
        }
        .padding(16)
    }

    private func badgeRow(_ badge: TrustBadge, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            TrustDotView(badge: badge)
                .padding(.top, 3)
            VStack(alignment: .leading, spacing: 0) {
                Text(badge.label)
                    .font(.callout.weight(.medium))
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
