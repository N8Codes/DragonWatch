import Foundation

struct MonitoredProcess: Identifiable, Sendable {
    let record: ProcessRecord
    let trust: TrustAssessment

    var id: pid_t { record.pid }
}

struct ProcessGroup: Identifiable, Sendable {
    let key: String
    let name: String
    let appBundlePath: String?
    /// Origin context shown beside uninformative names ("2.1.222 · toolkit").
    var contextHint: String?
    var members: [MonitoredProcess]

    var id: String { key }
    /// Sums only the members whose metrics the kernel let us read; a group of
    /// root-owned processes therefore totals nil rather than a misleading 0.
    var totalCPU: Double? {
        let known = members.compactMap(\.record.cpuPercent)
        return known.isEmpty ? nil : known.reduce(0, +)
    }
    var totalMemory: UInt64? {
        let known = members.compactMap(\.record.residentBytes)
        return known.isEmpty ? nil : known.reduce(0, +)
    }
    var worstBadge: TrustBadge { members.map(\.trust.badge).max() ?? .trusted }
}

/// Collapses the flat process list to the app level: everything inside an .app
/// bundle (including nested helper bundles) groups under the outermost app;
/// Apple's own bare daemons collapse into one "macOS system" group; other
/// bare binaries stand alone.
enum ProcessGrouper {
    /// Not a path, so it can never collide with a real group key.
    static let systemGroupKey = "system://macOS"
    static let systemGroupName = "macOS system"
    /// Some tools install each version as its own binary, named only by the
    /// version number, under a folder that carries the real name. Those
    /// group by that folder, so several running versions are one row — and
    /// when the folder is a known agent CLI, the row gets the product name.
    static let originKeyPrefix = "origin://"

    static func isAgentGroup(_ group: ProcessGroup) -> Bool {
        group.key.hasPrefix(originKeyPrefix) && LaunchContext.agents.values.contains(group.name)
    }

    /// The hundreds of Apple daemons that make a Mac a Mac. Nobody reads
    /// them one by one, and their badge is the OS's own — so they fold into
    /// one row whose badge still rolls up the worst member.
    static func isSystemDaemon(_ process: MonitoredProcess) -> Bool {
        switch process.trust.tier {
        case .applePlatform, .osManagedUnreadable: !process.trust.isSelf
        default: false
        }
    }

    static func group(_ processes: [MonitoredProcess]) -> [ProcessGroup] {
        var groups: [String: ProcessGroup] = [:]
        for process in processes {
            let path = process.record.path
            if ContextInspector.bundleRoot(of: path) == nil, isSystemDaemon(process) {
                groups[
                    systemGroupKey,
                    default: ProcessGroup(
                        key: systemGroupKey, name: systemGroupName, appBundlePath: nil,
                        contextHint: nil, members: []
                    )
                ].members.append(process)
            } else if let root = ContextInspector.bundleRoot(of: path) {
                let name = ((root as NSString).lastPathComponent as NSString)
                    .deletingPathExtension
                groups[
                    root,
                    default: ProcessGroup(
                        key: root, name: name, appBundlePath: root,
                        contextHint: nil, members: []
                    )
                ].members.append(process)
            } else if let hint = ProcessNameContext.hint(name: process.record.name, path: path) {
                let key = originKeyPrefix + hint.lowercased()
                groups[
                    key,
                    default: ProcessGroup(
                        key: key, name: LaunchContext.agents[hint] ?? hint, appBundlePath: nil,
                        contextHint: nil, members: []
                    )
                ].members.append(process)
            } else {
                groups[
                    path,
                    default: ProcessGroup(
                        key: path, name: process.record.name, appBundlePath: nil,
                        contextHint: nil, members: []
                    )
                ].members.append(process)
            }
        }
        // An origin group with one member still shows which version it is;
        // with several, the expanded rows do.
        for (key, group) in groups where key.hasPrefix(originKeyPrefix) && group.members.count == 1
        {
            groups[key]?.contextHint = group.members[0].record.name
        }
        // Stable ordering: badge severity, then name — never CPU, which
        // changes every sample and would make rows jump mid-read. The numbers
        // update in place instead.
        return groups.values
            .map { group in
                var sorted = group
                sorted.members.sort {
                    ($0.record.name.lowercased(), $0.record.pid)
                        < ($1.record.name.lowercased(), $1.record.pid)
                }
                return sorted
            }
            .sorted {
                if $0.worstBadge != $1.worstBadge { return $0.worstBadge > $1.worstBadge }
                return ($0.name.lowercased(), $0.key) < ($1.name.lowercased(), $1.key)
            }
    }
}

/// Free-text filtering over the grouped list. Matches an app or process name,
/// its origin hint, or any part of its path — so "chrome", "2.1.222",
/// "/tmp", and "toolkit" all find what you'd expect.
enum ProcessFilter {
    static func apply(_ query: String, to groups: [ProcessGroup]) -> [ProcessGroup] {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return groups }
        return groups.filter { group in
            if group.name.lowercased().contains(needle) { return true }
            if group.contextHint?.lowercased().contains(needle) == true { return true }
            if group.key.lowercased().contains(needle) { return true }
            return group.members.contains {
                $0.record.name.lowercased().contains(needle)
                    || $0.record.path.lowercased().contains(needle)
            }
        }
    }
}

/// User-selectable list ordering. Every mode is stable across refreshes —
/// only names and badges decide order, never per-sample numbers.
enum ProcessListSort: String, CaseIterable {
    case riskFirst
    case nameAscending
    case nameDescending

    var label: String {
        switch self {
        case .riskFirst: "Risk first"
        case .nameAscending: "Name A → Z"
        case .nameDescending: "Name Z → A"
        }
    }

    func apply(_ groups: [ProcessGroup]) -> [ProcessGroup] {
        switch self {
        case .riskFirst:
            return groups  // the grouper's default ordering
        case .nameAscending:
            return groups.sorted {
                ($0.name.lowercased(), $0.key) < ($1.name.lowercased(), $1.key)
            }
        case .nameDescending:
            return groups.sorted {
                ($0.name.lowercased(), $0.key) > ($1.name.lowercased(), $1.key)
            }
        }
    }
}
