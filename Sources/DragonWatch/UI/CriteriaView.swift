import SwiftUI

/// The complete rating rulebook, in the app. Everything DragonWatch uses to
/// decide a badge is listed here so a user can judge the judgements — and
/// disagree with them from an informed position.
struct CriteriaView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                intro

                section("Step 1 — the signature sets the starting point") {
                    ForEach(SignatureTier.allCases, id: \.self) { tier in
                        tierRow(tier)
                    }
                }

                section("Step 2 — context can only lower it") {
                    Text(
                        "Each signal below drops the rating one step. Several stack. None can ever raise a rating."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    ForEach(RiskModifier.allCases, id: \.self) { modifier in
                        modifierRow(modifier)
                    }
                }

                section("Exemptions — and why they exist") {
                    exemption(
                        "Apple system binaries ignore every context signal.",
                        "They are the operating system; flagging macOS's own components would bury real findings in noise."
                    )
                    exemption(
                        "DragonWatch never flags itself (matched by process ID).",
                        "A compromised monitor could lie about itself anyway, so self-flagging is noise, not protection."
                    )
                    exemption(
                        "A verified bundle seal overrides a weak signature — for that binary only.",
                        "Full validation hashes everything the bundle's signature seals, proving the binary is exactly what the vendor shipped. Only binaries running at verification time are vouched, so nothing planted afterwards inherits trust."
                    )
                }

                section("What this app deliberately does not do") {
                    bullet(
                        "It does not inspect what a file contains or watch what a program does — ratings come from signatures and context. It does read whole binaries to hash them, but only for the local malware-list check you enable."
                    )
                    bullet(
                        "It never stops, kills, quarantines, or modifies another program, and never asks for elevated privileges. The only things it acts on are its own: quitting a leftover copy of itself at launch, and its own files."
                    )
                    bullet(
                        "It does not replace XProtect or Gatekeeper; macOS already runs those underneath."
                    )
                    bullet(
                        "A green badge means \"nothing here looks wrong\", not \"proven safe\". A red badge means \"worth a look\", not \"proven malicious\"."
                    )
                }
            }
            .padding(14)
        }
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("How DragonWatch decides")
                .font(.headline)
            Text(
                "Every badge comes from these rules and nothing else — no cloud verdicts, no heuristics you can't see. Each process's detail view shows which of them applied to it."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
        }
    }

    private func tierRow(_ tier: SignatureTier) -> some View {
        HStack(alignment: .top, spacing: 8) {
            TrustDotView(badge: TrustScoring.base(for: tier))
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 1) {
                Text(tier.rawValue)
                    .font(.callout.weight(.medium))
                Text(TrustExplanation.signatureExplanation(tier))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func modifierRow(_ modifier: RiskModifier) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(modifier.explanation, systemImage: "arrow.down.circle")
                .font(.callout.weight(.medium))
            Text(modifier.rationale)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Not counted for: \(appliesNote(modifier))")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.leading, 2)
    }

    private func appliesNote(_ modifier: RiskModifier) -> String {
        let exempt = SignatureTier.allCases.filter {
            $0 != .applePlatform && !TrustScoring.applies(modifier, to: $0)
        }
        guard !exempt.isEmpty else {
            return "nothing — this one always counts (Apple system binaries aside)"
        }
        return exempt.map(\.rawValue).joined(separator: ", ")
            + " — " + modifier.exemptionRationale
    }

    private func exemption(_ title: String, _ why: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(title, systemImage: "checkmark.shield")
                .font(.callout.weight(.medium))
            Text(why)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("•")
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    private func section(
        _ title: String, @ViewBuilder content: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            content()
        }
    }
}
