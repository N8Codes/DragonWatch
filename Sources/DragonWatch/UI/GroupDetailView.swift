import SwiftUI

/// One group in full: every member as a tree — pid, badge, start time, who
/// started it, CPU and memory — with each row opening the per-process detail.
/// The list row shows the roll-up; this is where the roll-up is unpacked.
struct GroupDetailView: View {
    let group: ProcessGroup
    let allProcesses: [MonitoredProcess]
    let select: (MonitoredProcess) -> Void
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                TrustDotView(badge: group.worstBadge)
                Text(group.name)
                    .font(AppText.headline)
                Text("\(group.members.count) processes")
                    .font(AppText.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Close details")
                .accessibilityLabel("Close details for \(group.name)")
            }
            .padding(.horizontal, 10)
            .padding(.top, 8)

            Text(
                group.key == ProcessGrouper.systemGroupKey
                    ? "Apple's own daemons, rated by their platform signature. Nested under what started them; click any row for its rating and history."
                    : "Nested under what started them. A root's arrow names its parent outside this group. Click any row for its rating and history."
            )
            .font(AppText.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 10)

            ProcessTreeView(
                nodes: ProcessTree.build(group.members),
                allProcesses: allProcesses,
                select: select)
        }
        .frame(maxHeight: 320)
    }
}
