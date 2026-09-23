import SwiftUI

/// The reviewed sweep: each non-trusted item is asked about exactly once.
/// "Expected" accepts it as normal; "Not expected" keeps it listed below,
/// because an answer with no visible consequence is indistinguishable from no
/// answer at all; "Ignore" hides it without vouching for it.
struct ReviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.pendingReview.isEmpty && model.markedUnexpected.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "checkmark.seal")
                        .font(AppText.title2)
                        .foregroundStyle(.tertiary)
                    Text("Nothing awaiting review.")
                        .font(AppText.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        if !model.pendingReview.isEmpty {
                            Text(
                                "Are these expected on this Mac? \"Expected\" accepts it as normal and stops the question. \"Not expected\" keeps it listed below as one you have flagged. The eye-slash ignores it: hidden for good, no verdict either way."
                            )
                            .font(AppText.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            ForEach(model.pendingReview) { item in
                                row(item, answered: false)
                            }
                        }

                        if !model.markedUnexpected.isEmpty {
                            Divider()
                            Text("You marked these as not expected")
                                .font(AppText.callout.weight(.medium))
                            ForEach(model.markedUnexpected) { item in
                                row(item, answered: true)
                            }
                        }
                    }
                    .padding(10)
                }
            }
        }
    }

    private func row(_ item: ReviewItem, answered: Bool) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                TrustDotView(
                    badge: TrustScoring.base(for: item.tier))
                Text(item.name)
                    .font(AppText.callout)
                    .lineLimit(1)
                Text(item.tier.rawValue)
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                // The labels name the item: a screen reader hears "Expected,
                // button" on every row otherwise, with nothing to tell them
                // apart.
                if !answered {
                    Button("Expected") {
                        model.resolveReview(path: item.path, asExpected: true)
                    }
                    .controlSize(.regular)
                    .accessibilityLabel("Mark \(item.name) as expected")
                }
                Button(answered ? "Actually expected" : "Not expected") {
                    model.resolveReview(path: item.path, asExpected: answered)
                }
                .controlSize(.regular)
                .accessibilityLabel(
                    answered
                        ? "Change \(item.name) to expected"
                        : "Mark \(item.name) as not expected")
                // The third answer: "stop asking". Hides the row for good
                // without vouching for the binary.
                Button {
                    model.ignoreReview(path: item.path)
                } label: {
                    Image(systemName: "eye.slash")
                }
                .controlSize(.regular)
                .help(
                    "Ignore — hide this item without a verdict. It won't alert again; nothing vouches for it."
                )
                .accessibilityLabel("Ignore \(item.name)")
            }
            Text(item.path)
                .font(AppText.monoCaption)
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(item.path)
                .accessibilityLabel("Path: \(item.path)")
            // The reasoning belongs where the decision is made, not one
            // screen away.
            Text(TrustExplanation.signatureExplanation(item.tier))
                .font(AppText.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            // So does the evidence: who started it, and whether a package
            // manager put it here, are what "expected" actually turns on.
            if let launch = item.launchedBy {
                Label("Launched by \(launch.summary)", systemImage: "arrow.turn.down.right")
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                    .help(
                        launch.ancestryDescription ?? launch.parentPath ?? "parent already exited")
                if let agent = launch.agentSession {
                    Label(
                        "Started inside a \(agent.product) session (pid \(agent.pid)) — an AI agent, not you",
                        systemImage: "sparkles"
                    )
                    .font(AppText.caption)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let keg = item.keg {
                Label(keg.summary, systemImage: "shippingbox")
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
