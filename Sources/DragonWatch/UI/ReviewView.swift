import SwiftUI

/// The reviewed sweep: each non-trusted item gets an explicit verdict before
/// being accepted as normal — asked exactly once. Items answered "not
/// expected" stay listed below, because an answer with no visible consequence
/// is indistinguishable from no answer at all.
struct ReviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.pendingReview.isEmpty && model.markedUnexpected.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "checkmark.seal")
                        .font(.title2)
                        .foregroundStyle(.tertiary)
                    Text("Nothing awaiting review.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        if !model.pendingReview.isEmpty {
                            Text(
                                "Are these expected on this Mac? \"Expected\" accepts it as normal and stops the question. \"Not expected\" keeps it listed below as one you have flagged."
                            )
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            ForEach(model.pendingReview) { item in
                                row(item, answered: false)
                            }
                        }

                        if !model.markedUnexpected.isEmpty {
                            Divider()
                            Text("You marked these as not expected")
                                .font(.callout.weight(.medium))
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
                    .font(.callout)
                    .lineLimit(1)
                Text(item.tier.rawValue)
                    .font(.caption)
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
            }
            Text(item.path)
                .font(.caption.monospaced())
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(item.path)
                .accessibilityLabel("Path: \(item.path)")
            // The reasoning belongs where the decision is made, not one
            // screen away.
            Text(TrustExplanation.signatureExplanation(item.tier))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
