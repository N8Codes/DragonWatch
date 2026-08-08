import SwiftUI

/// The "why" behind a badge: signature tier, signer, and any tripped modifiers.
struct ProcessDetailView: View {
    let process: MonitoredProcess
    let dismiss: () -> Void
    @Environment(AppModel.self) private var model
    @State private var identity: ObservationLedger.Identity?
    @State private var enclosingBundle: String?
    @State private var showCriteria = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TrustDotView(badge: process.trust.badge)
                Text(process.record.name)
                    .font(.headline)
                Text(process.trust.badge.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }

            if process.trust.isSelf {
                Label(
                    "This is DragonWatch itself — verified by process ID",
                    systemImage: "checkmark.circle"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            if let bundle = process.trust.vouchedByBundle {
                Label(
                    "Matches \((bundle as NSString).lastPathComponent)'s verified signature seal — exactly what the vendor shipped",
                    systemImage: "checkmark.seal"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            row("Signature", process.trust.tier.rawValue)
            if let team = process.trust.teamID {
                row("Team ID", team)
            }
            if let signingID = process.trust.signingID {
                row("Identifier", signingID)
            }
            row("Path", process.record.path)
            if let identity {
                row(
                    "First seen",
                    identity.firstSeen.formatted(date: .abbreviated, time: .shortened))
                if let hash = identity.sha256 {
                    row("SHA-256", hash)
                }
                if let change = identity.transitions.last {
                    row(
                        "Changed",
                        "\(change.field) on \(change.date.formatted(date: .abbreviated, time: .omitted))"
                    )
                }
            }

            whySection

            if process.trust.badge != .trusted, let bundle = enclosingBundle {
                sealSection(bundle: bundle)
                    .padding(.top, 2)
            }

            IntelSectionView(
                intel: model.intel, settings: model.settings, process: process
            )
            .padding(.top, 2)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .task(id: process.record.pid) {
            identity = await model.observation(for: process.record.path)
            enclosingBundle = await model.strongEnclosingBundle(
                for: process.record.path)
        }
    }

    /// The transparency panel: why this badge, step by step, in the order
    /// the engine applied its rules.
    private var whySection: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Text("Why \(process.trust.badge.label.lowercased())?")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("All criteria") { showCriteria = true }
                    .font(.caption)
                    .buttonStyle(.plain)
                    .foregroundStyle(Color.accentColor)
            }
            ForEach(TrustExplanation.steps(for: process.trust)) { step in
                Label {
                    Text(step.text)
                        .font(.caption)
                        .foregroundStyle(step.lowered == true ? .primary : .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: step.symbol)
                        .foregroundStyle(stepColor(step.lowered))
                }
            }
        }
        .padding(.top, 2)
        .sheet(isPresented: $showCriteria) {
            VStack(spacing: 0) {
                HStack {
                    Spacer()
                    Button("Done") { showCriteria = false }
                        .controlSize(.regular)
                }
                .padding(8)
                CriteriaView()
            }
            .frame(width: 440, height: 560)
        }
    }

    private func stepColor(_ lowered: Bool?) -> Color {
        switch lowered {
        case true: process.trust.badge == .suspicious ? .red : .orange
        case false: .green
        default: .secondary
        }
    }

    @ViewBuilder
    private func sealSection(bundle: String) -> some View {
        let bundleName = (bundle as NSString).lastPathComponent
        switch model.sealStates[bundle] {
        case nil:
            VStack(alignment: .leading, spacing: 2) {
                Button("Verify \(bundleName)'s Seal…") {
                    model.verifySeal(
                        bundlePath: bundle, vouching: process.record.path)
                }
                .controlSize(.regular)
                Text(
                    "Hashes everything \(bundleName)'s signature seals — proving this binary is exactly what the vendor shipped. Vouches only the binaries running now, not the bundle as a whole. Can take minutes for large apps."
                )
                .font(.caption)
                .foregroundStyle(.tertiary)
            }
        case .running:
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.regular)
                Text("Verifying \(bundleName)'s seal — large apps take minutes…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .verified:
            Label(
                "Seal verified — contents rate as trusted on the next refresh",
                systemImage: "checkmark.seal.fill"
            )
            .font(.caption)
            .foregroundStyle(.green)
        case .failed:
            Label(
                "Seal verification FAILED — \(bundleName)'s contents don't match its signature. Treat with suspicion.",
                systemImage: "xmark.octagon.fill"
            )
            .font(.caption)
            .foregroundStyle(.red)
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 76, alignment: .trailing)
            Text(value)
                .font(.footnote.monospaced())
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .help(value)
        }
    }
}

/// The intel panel for one process: what the enabled providers found, or the
/// button that runs them.
struct IntelSectionView: View {
    let intel: IntelCenter
    let settings: SettingsModel
    let process: MonitoredProcess

    var body: some View {
        if intel.anyProviderEnabled {
            section
        }
    }

    @ViewBuilder
    private var section: some View {
        switch intel.results[process.record.path] {
        case nil:
            VStack(alignment: .leading, spacing: 2) {
                Button("Run intel checks") { intel.check(process) }
                    .controlSize(.regular)
                ForEach(intel.activeDisclosures, id: \.self) { disclosure in
                    Text(disclosure)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        case .running:
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.regular)
                Text("Checking…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .done(let findings):
            if findings.isEmpty {
                Text("No intel findings.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(findings) { finding in
                        Label {
                            VStack(alignment: .leading, spacing: 0) {
                                Text("\(finding.providerName): \(finding.summary)")
                                    .font(.caption)
                                Text(finding.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: symbolName(for: finding.severity))
                                .foregroundStyle(color(for: finding.severity))
                        }
                        .font(.caption)
                    }
                }
            }
        case .failed(let message):
            HStack(spacing: 6) {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Retry") { intel.check(process) }
                    .controlSize(.regular)
            }
        }
    }

    private func symbolName(for severity: IntelSeverity) -> String {
        switch severity {
        case .informational: "info.circle"
        case .warning: "exclamationmark.triangle"
        case .critical: "xmark.octagon.fill"
        }
    }

    private func color(for severity: IntelSeverity) -> Color {
        switch severity {
        case .informational: .secondary
        case .warning: .orange
        case .critical: .red
        }
    }
}
