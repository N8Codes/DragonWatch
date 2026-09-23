import SwiftUI
import UniformTypeIdentifiers

/// The Inspect window: pick files or folders, see whether each one is what
/// it claims to be.
///
/// The disclaimer is pinned at the top rather than tucked at the bottom. A
/// pane full of green checkmarks reads as an antivirus verdict unless it says
/// otherwise where the eye lands first.
struct InspectView: View {
    @Environment(AppModel.self) private var model
    @State private var expanded: Set<String> = []
    @State private var isDropTarget = false

    var body: some View {
        VStack(spacing: 0) {
            disclaimer
            Divider()
            if model.isInspecting {
                progress
            } else if let report = model.inspectionReport {
                summary(report)
                Divider()
                results(report)
            } else {
                emptyState
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            // Dropping while results are on screen adds to them; the first
            // drop onto an empty window starts a run.
            model.inspect(urls: urls, addingToExisting: model.canAddToInspection)
            return true
        } isTargeted: {
            isDropTarget = $0
        }
        .overlay {
            if isDropTarget {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.accentColor, lineWidth: 2)
                    .padding(4)
                    .allowsHitTesting(false)
            }
        }
    }

    private var disclaimer: some View {
        Text(InspectionReport.disclaimer)
            .font(AppText.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
    }

    // MARK: - States

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "doc.viewfinder")
                .font(AppText.icon(34))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Check what a file really is")
                .font(AppText.headline)
            Text(
                "Confirms that contents match the extension, and looks for data hidden past "
                    + "the end of a file, deceptive filenames, and payloads inside."
            )
            .font(AppText.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 24)
            Button("Choose Files or Folders…") { model.chooseFilesToInspect() }
                .controlSize(.regular)
            Text("or drag them here")
                .font(AppText.caption)
                .foregroundStyle(.tertiary)
            Spacer()
        }
    }

    private var progress: some View {
        VStack(spacing: 10) {
            Spacer()
            switch model.inspectionPhase {
            case .walking:
                ProgressView().controlSize(.small)
                Text("Finding files…").font(AppText.callout)
            case .inspecting(let done, let total):
                ProgressView(value: Double(done), total: Double(max(total, 1)))
                    .frame(width: 220)
                Text("Inspected \(done) of \(total)")
                    .font(AppText.callout)
                    .monospacedDigit()
            case .idle:
                EmptyView()
            }
            Button("Cancel") { model.cancelInspection() }
                .controlSize(.small)
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: - Results

    private func summary(_ report: InspectionReport) -> some View {
        let worst = report.worstVerdict
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: worst.symbolName)
                    .foregroundStyle(color(for: worst))
                    .accessibilityHidden(true)
                Text(headline(report))
                    .font(AppText.headline)
                Spacer()
                Button("Add Files…") { model.chooseFilesToInspect(addingToExisting: true) }
                    .controlSize(.small)
                    .help("Inspect more files and keep these results")
                Menu("Export") {
                    ForEach(ReportRenderer.Format.allCases, id: \.rawValue) { format in
                        Button("\(format.label)…") { model.exportInspection(as: format) }
                    }
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .controlSize(.small)
                .help("Save this report as Markdown, JSON, PDF or plain text")
                .accessibilityLabel("Export report")
                Button("Clear") { model.clearInspection() }
                    .controlSize(.small)
            }
            Text(countsLine(report))
                .font(AppText.callout)
                .foregroundStyle(.secondary)
            Text(scopeLine(report))
                .font(AppText.caption)
                .foregroundStyle(.tertiary)
            if let limit = report.limitHit {
                Label(limit.explanation, systemImage: "exclamationmark.circle")
                    .font(AppText.caption)
                    .foregroundStyle(.orange)
            }
        }
        // The headline already names the verdict in words, so the icon is
        // decoration; the label carries the whole state for VoiceOver.
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(headline(report)). \(countsLine(report))")
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func headline(_ report: InspectionReport) -> String {
        let count = report.files.count
        let files = "\(count) item\(count == 1 ? "" : "s")"
        switch report.worstVerdict {
        case .consistent: return "\(files) — all consistent"
        case .unreadable: return "\(files) — nothing could be read"
        case .caution: return "\(files) — worth a look"
        case .inconsistent: return "\(files) — something does not match"
        }
    }

    private func countsLine(_ report: InspectionReport) -> String {
        var parts: [String] = []
        for verdict in [
            InspectionVerdict.inconsistent, .caution, .unreadable, .consistent,
        ] where report.count(of: verdict) > 0 {
            parts.append("\(report.count(of: verdict)) \(verdict.label.lowercased())")
        }
        let findings = report.findingCount
        parts.append("\(findings) finding\(findings == 1 ? "" : "s")")
        return parts.joined(separator: " · ")
    }

    /// What the run covered, which the verdict alone does not convey.
    private func scopeLine(_ report: InspectionReport) -> String {
        var parts: [String] = []
        if let folders = report.folderCount, folders > 0 {
            parts.append("\(folders) folder\(folders == 1 ? "" : "s") searched")
        }
        if let seconds = report.durationSeconds {
            parts.append(
                seconds < 1
                    ? "took under a second"
                    : "took \(String(format: "%.1f", seconds))s")
        }
        parts.append("nothing was opened, run or extracted")
        return parts.joined(separator: " · ")
    }

    private func results(_ report: InspectionReport) -> some View {
        ScrollView {
            LazyVStack(spacing: 1) {
                ForEach(report.sortedFiles) { file in
                    row(file)
                }
            }
            .padding(6)
        }
    }

    private func row(_ file: FileInspection) -> some View {
        let isOpen = expanded.contains(file.path)
        let hasDetail =
            !file.findings.isEmpty || !file.disclosures.isEmpty
            || !(file.checksRun ?? []).isEmpty
        return VStack(alignment: .leading, spacing: 4) {
            Button {
                guard hasDetail else { return }
                if !expanded.insert(file.path).inserted { expanded.remove(file.path) }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: file.verdict.symbolName)
                        .foregroundStyle(color(for: file.verdict))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(file.displayName)
                            .font(AppText.body)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(subtitle(file))
                            .font(AppText.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if hasDetail {
                        Image(systemName: isOpen ? "chevron.down" : "chevron.right")
                            .font(AppText.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(
                "\(file.displayName), \(file.verdict.label). \(subtitle(file))"
            )
            .accessibilityHint(hasDetail ? (isOpen ? "Collapse details" : "Expand details") : "")

            if isOpen {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(file.findings, id: \.self) { finding in
                        detailBlock(
                            symbol: symbol(for: finding.severity),
                            tint: color(for: finding.severity),
                            title: finding.title,
                            detail: finding.detail)
                    }
                    ForEach(file.disclosures, id: \.self) { disclosure in
                        detailBlock(
                            symbol: "info.circle",
                            tint: .secondary,
                            title: disclosure.title,
                            detail: disclosure.detail)
                    }
                    if let checks = file.checksRun, !checks.isEmpty {
                        // The answer to "0 findings — but did you look?".
                        VStack(alignment: .leading, spacing: 1) {
                            Text("Examined")
                                .font(AppText.caption)
                                .foregroundStyle(.secondary)
                            ForEach(checks, id: \.self) { check in
                                Text("• \(check)")
                                    .font(AppText.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(.top, 2)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(
                            "Examined: \(checks.joined(separator: ", "))")
                    }
                    if let digest = file.sha256 {
                        Text("SHA-256 \(digest)")
                            .font(AppText.caption2)
                            .monospaced()
                            .foregroundStyle(.tertiary)
                            .textSelection(.enabled)
                            .lineLimit(2)
                    }
                }
                .padding(.leading, 26)
                .padding(.bottom, 4)
            }
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 4)
    }

    private func detailBlock(
        symbol: String, tint: Color, title: String, detail: String
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol)
                .font(AppText.caption)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(AppText.callout)
                Text(detail)
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title). \(detail)")
    }

    private func subtitle(_ file: FileInspection) -> String {
        var parts = [file.identifiedFormat ?? "unidentified"]
        if file.byteSize > 0 {
            parts.append(
                ByteCountFormatter.string(fromByteCount: file.byteSize, countStyle: .file))
        }
        let findings = file.findings.count
        if findings > 0 { parts.append("\(findings) finding\(findings == 1 ? "" : "s")") }
        return parts.joined(separator: " · ")
    }

    private func color(for verdict: InspectionVerdict) -> Color {
        switch verdict {
        case .consistent: .green
        case .unreadable: .secondary
        case .caution: .orange
        case .inconsistent: .red
        }
    }

    private func color(for severity: FindingSeverity) -> Color {
        switch severity {
        case .info: .secondary
        case .caution: .orange
        case .inconsistent: .red
        }
    }

    private func symbol(for severity: FindingSeverity) -> String {
        switch severity {
        case .info: "info.circle"
        case .caution: "exclamationmark.triangle.fill"
        case .inconsistent: "exclamationmark.octagon.fill"
        }
    }
}
