import SwiftUI

/// Processes nested under what started them. Expanded by default — this view
/// exists to show everything — and collapsible per node. Order is name then
/// pid, so the tree holds still while numbers update in place.
struct ProcessTreeView: View {
    let nodes: [ProcessTreeNode]
    /// The full listing, so a root whose parent is outside `nodes` (an app's
    /// helper started by launchd, say) can still name that parent.
    let allProcesses: [MonitoredProcess]
    let select: (MonitoredProcess) -> Void
    @State private var collapsed: Set<pid_t> = []

    private var pathsByPID: [pid_t: String] {
        Dictionary(
            allProcesses.map { ($0.record.pid, $0.record.path) },
            uniquingKeysWith: { first, _ in first })
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                if nodes.isEmpty {
                    Text("No processes to show.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 24)
                }
                let lookup = pathsByPID
                ForEach(nodes) { node in
                    subtree(node, depth: 0, lookup: lookup)
                }
            }
            .padding(6)
        }
    }

    @ViewBuilder
    private func subtree(_ node: ProcessTreeNode, depth: Int, lookup: [pid_t: String])
        -> some View
    {
        row(node, depth: depth, lookup: lookup)
        if let children = node.children, !collapsed.contains(node.id) {
            ForEach(children) { child in
                AnyView(subtree(child, depth: depth + 1, lookup: lookup))
            }
        }
    }

    private func row(_ node: ProcessTreeNode, depth: Int, lookup: [pid_t: String]) -> some View {
        let record = node.process.record
        return HStack(spacing: 6) {
            if node.children != nil {
                Button {
                    if !collapsed.insert(node.id).inserted { collapsed.remove(node.id) }
                } label: {
                    Image(
                        systemName: collapsed.contains(node.id) ? "chevron.right" : "chevron.down"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(width: 12)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(
                    "\(collapsed.contains(node.id) ? "Expand" : "Collapse") \(node.name), \(node.subtreeCount - 1) below"
                )
            } else {
                Spacer().frame(width: 12)
            }
            Button {
                select(node.process)
            } label: {
                HStack(spacing: 6) {
                    TrustDotView(badge: node.process.trust.badge)
                    Text(node.name)
                        .font(.callout)
                        .lineLimit(1)
                    Text("pid \(String(record.pid))")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    if depth == 0, let origin = origin(of: record, lookup: lookup) {
                        Text(origin)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                    Spacer()
                    if let started = record.startedAt {
                        Text(Self.startedLabel(started))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.tertiary)
                            .help(
                                "Started \(started.formatted(date: .abbreviated, time: .standard))")
                    }
                    MetricsView(cpu: record.cpuPercent, memory: record.residentBytes)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(record.path)
        }
        .padding(.vertical, 2)
        .padding(.leading, CGFloat(depth) * 16 + 4)
        .padding(.trailing, 4)
    }

    /// For a root: who started it, when that parent is not in this tree —
    /// "← launchd (pid 1)", or "← exited (pid 10857)" when it is gone.
    private func origin(of record: ProcessRecord, lookup: [pid_t: String]) -> String? {
        guard let parent = record.parentPID, parent > 0 else { return nil }
        let name =
            lookup[parent].map { ($0 as NSString).lastPathComponent }
            ?? ProcessSampler.path(forPID: parent).map { ($0 as NSString).lastPathComponent }
            ?? "exited"
        return "← \(name) (pid \(parent))"
    }

    /// Time of day for today's processes, the date for older ones — most of
    /// a Mac's processes started at boot, and "09:14" says nothing about
    /// them without the day.
    static func startedLabel(_ date: Date, now: Date = Date()) -> String {
        Calendar.current.isDate(date, inSameDayAs: now)
            ? date.formatted(date: .omitted, time: .shortened)
            : date.formatted(date: .abbreviated, time: .omitted)
    }
}
