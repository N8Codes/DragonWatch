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
                    .font(AppText.caption)
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

                section("Inspecting a file — what each finding means") {
                    Text(
                        "Inspecting a file answers one question: are these contents what the file claims to be? It is not a malware scan."
                    )
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                    ForEach(InspectionRulebook.groups) { group in
                        Text(group.id)
                            .font(AppText.title3)
                            .padding(.top, 4)
                        Text(group.summary)
                            .font(AppText.caption)
                            .foregroundStyle(.secondary)
                        ForEach(group.rules) { rule in
                            ruleRow(rule)
                        }
                    }
                }

                section("What inspecting a file cannot tell you") {
                    ForEach(InspectionRulebook.limits, id: \.self) { limit in
                        bullet(limit)
                    }
                }

                section("What this app deliberately does not do") {
                    bullet(
                        "Process ratings come from signatures and context, never from what a program does while running. The file inspector does read contents, but only to answer whether a file matches what it claims to be — never whether it is dangerous. Binaries are hashed a few at a time so a change on disk can be noticed; no hash ever leaves this Mac."
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
                .font(AppText.headline)
            Text(
                "Every badge comes from these rules and nothing else — no cloud verdicts, no heuristics you can't see. Each process's detail view shows which of them applied to it."
            )
            .font(AppText.callout)
            .foregroundStyle(.secondary)
        }
    }

    private func tierRow(_ tier: SignatureTier) -> some View {
        HStack(alignment: .top, spacing: 8) {
            TrustDotView(badge: TrustScoring.base(for: tier))
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 1) {
                Text(tier.rawValue)
                    .font(AppText.callout.weight(.medium))
                Text(TrustExplanation.signatureExplanation(tier))
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func modifierRow(_ modifier: RiskModifier) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(modifier.explanation, systemImage: "arrow.down.circle")
                .font(AppText.callout.weight(.medium))
            Text(modifier.rationale)
                .font(AppText.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Not counted for: \(appliesNote(modifier))")
                .font(AppText.caption)
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

    /// One inspection rule: its verdict weight, what it is, and why it counts.
    private func ruleRow(_ rule: InspectionRulebook.Rule) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol(for: rule.severity))
                .font(AppText.caption)
                .foregroundStyle(tint(for: rule.severity))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(rule.title).font(AppText.callout)
                Text(rule.rationale)
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(severityWord(rule.severity)). \(rule.title). \(rule.rationale)")
    }

    private func severityWord(_ severity: FindingSeverity) -> String {
        switch severity {
        case .info: "Informational"
        case .caution: "Caution"
        case .inconsistent: "Inconsistent"
        }
    }

    private func symbol(for severity: FindingSeverity) -> String {
        switch severity {
        case .info: "info.circle"
        case .caution: "exclamationmark.triangle.fill"
        case .inconsistent: "exclamationmark.octagon.fill"
        }
    }

    private func tint(for severity: FindingSeverity) -> Color {
        switch severity {
        case .info: .secondary
        case .caution: .orange
        case .inconsistent: .red
        }
    }

    private func exemption(_ title: String, _ why: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(title, systemImage: "checkmark.shield")
                .font(AppText.callout.weight(.medium))
            Text(why)
                .font(AppText.caption)
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
        .font(AppText.caption)
        .foregroundStyle(.secondary)
    }

    private func section(
        _ title: String, @ViewBuilder content: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(AppText.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            content()
        }
    }
}
