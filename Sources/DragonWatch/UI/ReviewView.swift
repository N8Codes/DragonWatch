import SwiftUI

/// The reviewed sweep: each non-trusted item gets an explicit verdict before
/// being accepted as normal — asked exactly once.
struct ReviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.pendingReview.isEmpty {
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
                        Text(
                            "Are these expected on this Mac? \"Expected\" means DragonWatch stops asking; \"Keep flagging\" leaves the badge in place."
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        ForEach(model.pendingReview) { item in
                            row(item)
                        }
                    }
                    .padding(10)
                }
            }
        }
    }

    private func row(_ item: ReviewItem) -> some View {
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
                Button("Expected") {
                    model.resolveReview(path: item.path, asExpected: true)
                }
                .controlSize(.regular)
                Button("Keep flagging") {
                    model.resolveReview(path: item.path, asExpected: false)
                }
                .controlSize(.regular)
            }
            Text(item.path)
                .font(.caption.monospaced())
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(item.path)
            // The reasoning belongs where the decision is made, not one
            // screen away.
            Text(TrustExplanation.signatureExplanation(item.tier))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
