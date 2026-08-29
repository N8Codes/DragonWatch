import AppKit
import SwiftUI

/// One app (or standalone process) in the list, expandable to its helpers.
struct GroupRowView: View {
    let group: ProcessGroup
    let isExpanded: Bool
    let toggleExpanded: () -> Void
    let select: (MonitoredProcess) -> Void
    /// Opens the group's own detail: every member as a tree, with pids,
    /// start times and who started what.
    var inspect: ((ProcessGroup) -> Void)? = nil
    /// Width of the ⓘ column, reserved on every row.
    static let inspectSlotWidth: CGFloat = 16

    var body: some View {
        VStack(spacing: 1) {
            Button(action: primaryAction) {
                HStack(spacing: 8) {
                    TrustDotView(badge: group.worstBadge)
                    iconView
                    Text(group.name)
                        .lineLimit(1)
                    if let hint = group.contextHint {
                        Text("· \(hint)")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .help(
                                group.key.hasPrefix(ProcessGrouper.originKeyPrefix)
                                    ? "Version of the running binary"
                                    : "From \((group.key as NSString).deletingLastPathComponent)")
                    }
                    if group.members.count > 1 {
                        Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .help("\(group.members.count) processes — click to expand")
                    }
                    Spacer()
                    MetricsView(
                        count: group.members.count,
                        cpu: group.totalCPU,
                        memory: group.totalMemory)
                    // The slot exists on every row, button or not, so the
                    // CPU and memory columns line up down the whole list.
                    Group {
                        if group.members.count > 1, let inspect {
                            Button {
                                inspect(group)
                            } label: {
                                Image(systemName: "info.circle")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Show every process in \(group.name) as a tree")
                            .accessibilityLabel("Details for \(group.name)")
                        } else {
                            Color.clear
                        }
                    }
                    .frame(width: Self.inspectSlotWidth)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.vertical, 3)
            .padding(.horizontal, 4)

            if isExpanded {
                ForEach(group.members) { process in
                    Button {
                        select(process)
                    } label: {
                        HStack(spacing: 8) {
                            TrustDotView(badge: process.trust.badge)
                            Text(process.record.name)
                                .font(.callout)
                                .lineLimit(1)
                            Text("pid \(String(process.record.pid))")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                            Spacer()
                            MetricsView(
                                cpu: process.record.cpuPercent,
                                memory: process.record.residentBytes)
                            Color.clear.frame(width: Self.inspectSlotWidth)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 3)
                    .padding(.leading, 30)
                    .padding(.trailing, 4)
                }
            }
        }
    }

    private func primaryAction() {
        if group.members.count > 1 {
            toggleExpanded()
        } else if let only = group.members.first {
            select(only)
        }
    }

    @ViewBuilder
    private var iconView: some View {
        if let appPath = group.appBundlePath {
            Image(nsImage: IconCache.icon(forPath: appPath))
                .resizable()
                .frame(width: 22, height: 22)
        } else if group.key == ProcessGrouper.systemGroupKey {
            Image(systemName: "apple.logo")
                .font(.system(size: 15))
                .foregroundStyle(.secondary)
                .frame(width: 22, height: 22)
                .accessibilityHidden(true)
        } else if ProcessGrouper.isAgentGroup(group) {
            if let appPath = LaunchContext.agentAppBundle(for: group.name) {
                Image(nsImage: IconCache.icon(forPath: appPath))
                    .resizable()
                    .frame(width: 22, height: 22)
                    .accessibilityLabel("\(group.name) sessions")
            } else {
                // No desktop app to borrow an icon from: a terminal with a
                // spark — an agent working in a shell.
                Image(systemName: "terminal")
                    .font(.system(size: 15))
                    .foregroundStyle(.secondary)
                    .frame(width: 22, height: 22)
                    .overlay(alignment: .topTrailing) {
                        Image(systemName: "sparkle")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(Color.accentColor)
                            .offset(x: 2, y: -2)
                    }
                    .help("AI agent sessions")
                    .accessibilityLabel("\(group.name) sessions")
            }
        } else {
            Image(systemName: "gearshape")
                .font(.system(size: 15))
                .foregroundStyle(.secondary)
                .frame(width: 22, height: 22)
        }
    }
}

/// The trust badge: shape *and* colour, never colour alone, and labelled for
/// VoiceOver — `.help()` is a mouse tooltip and reaches neither screen readers
/// nor the keyboard.
struct TrustDotView: View {
    let badge: TrustBadge

    var body: some View {
        Image(systemName: badge.symbolName)
            .font(.system(size: 12))
            .foregroundStyle(badge.color)
            .frame(width: 14, height: 14)
            .help(badge.label)
            .accessibilityLabel(badge.label)
    }
}

extension TrustBadge {
    var color: Color {
        switch self {
        case .trusted: .green
        case .caution: .orange
        case .suspicious: .red
        }
    }
}

struct MetricsView: View {
    var count: Int?
    let cpu: Double?
    let memory: UInt64?

    var body: some View {
        // Member rows pass no count; the empty slot keeps the CPU and memory
        // columns aligned between group and member rows.
        Text(count.map(String.init) ?? "")
            .font(.callout.monospacedDigit())
            .foregroundStyle(.tertiary)
            .frame(width: 32, alignment: .trailing)
            .help("Processes in this group")
        Text(cpu.map { String(format: "%.1f%%", $0) } ?? "—")
            .font(.callout.monospacedDigit())
            .foregroundStyle(.secondary)
            .frame(width: 62, alignment: .trailing)
            .help(
                cpu == nil
                    ? "CPU unavailable — macOS does not report metrics for processes you do not own"
                    : "CPU — one fully busy core reads 100%, so multicore work can exceed it")
        Text(
            memory.map {
                ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .memory)
            } ?? "—"
        )
        .font(.callout.monospacedDigit())
        .foregroundStyle(.tertiary)
        .frame(width: 74, alignment: .trailing)
        .help("Memory footprint")
    }
}

enum IconCache {
    private static var cache: [String: NSImage] = [:]

    @MainActor
    static func icon(forPath path: String) -> NSImage {
        if let hit = cache[path] { return hit }
        let icon = NSWorkspace.shared.icon(forFile: path)
        cache[path] = icon
        return icon
    }
}
