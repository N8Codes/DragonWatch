import Foundation

/// One process and the processes it started, for the on-demand tree views.
struct ProcessTreeNode: Identifiable, Sendable {
    let process: MonitoredProcess
    /// nil for a leaf.
    var children: [ProcessTreeNode]?

    var id: pid_t { process.record.pid }
    var name: String { process.record.name }

    /// This node and everything below it — the collapse label's count, and
    /// what tests use to assert nothing was dropped.
    var subtreeCount: Int {
        1 + (children ?? []).reduce(0) { $0 + $1.subtreeCount }
    }
}

/// Builds parent → child trees from a set of processes, scoped to that set:
/// a process whose parent is outside the set is a root, so the same builder
/// serves one app's helpers and the whole machine. Live parentage only —
/// this is a picture of *now*, the ledger keeps the first launch.
enum ProcessTree {
    static func build(_ processes: [MonitoredProcess]) -> [ProcessTreeNode] {
        let byPID = Dictionary(
            processes.map { ($0.record.pid, $0) }, uniquingKeysWith: { first, _ in first })
        var childrenOf: [pid_t: [MonitoredProcess]] = [:]
        var roots: [MonitoredProcess] = []
        for process in byPID.values {
            if let parent = process.record.parentPID, parent != process.record.pid,
                byPID[parent] != nil
            {
                childrenOf[parent, default: []].append(process)
            } else {
                roots.append(process)
            }
        }

        var visited: Set<pid_t> = []
        func node(for process: MonitoredProcess) -> ProcessTreeNode? {
            guard visited.insert(process.record.pid).inserted else { return nil }
            let kids = (childrenOf[process.record.pid] ?? [])
                .sorted(by: stableOrder)
                .compactMap(node(for:))
            return ProcessTreeNode(process: process, children: kids.isEmpty ? nil : kids)
        }

        var tree = roots.sorted(by: stableOrder).compactMap(node(for:))
        // A parent cycle (pid reuse between samples can produce one) leaves
        // its members unreachable from any root. They still ran; list them.
        let orphans = byPID.values
            .filter { !visited.contains($0.record.pid) }
            .sorted(by: stableOrder)
        for orphan in orphans {
            if let extra = node(for: orphan) { tree.append(extra) }
        }
        return tree
    }

    /// Name then pid — never a per-sample number, so the tree does not
    /// reshuffle between refreshes.
    private static func stableOrder(_ lhs: MonitoredProcess, _ rhs: MonitoredProcess) -> Bool {
        (lhs.record.name.lowercased(), lhs.record.pid)
            < (rhs.record.name.lowercased(), rhs.record.pid)
    }
}
