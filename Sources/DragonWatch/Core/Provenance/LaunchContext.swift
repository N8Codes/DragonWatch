import Foundation

/// Who started a process, captured the first time DragonWatch sees it. A
/// rating says *what* ran; this says *why* — the difference between "an
/// unsigned binary appeared" and "npm, run from your shell, spawned node".
/// Recorded once and never updated: the first launch is the one the alert
/// was about.
struct LaunchContext: Codable, Equatable, Sendable {
    struct Ancestor: Codable, Equatable, Sendable {
        let pid: Int32
        let name: String
        /// Origin for a name that says nothing on its own — a binary called
        /// "1.2.3" inside `…/<tool>/versions/` is identified by `<tool>`.
        var hint: String?

        init(pid: Int32, name: String, hint: String? = nil) {
            self.pid = pid
            self.name = name
            self.hint = hint
        }

        init(pid: Int32, path: String) {
            let name = (path as NSString).lastPathComponent
            self.init(pid: pid, name: name, hint: ProcessNameContext.hint(name: name, path: path))
        }

        /// "1.2.3 · toolkit", as the process list shows it.
        var display: String { hint.map { "\(name) · \($0)" } ?? name }
    }

    /// Executable names that mean "an AI agent was driving". A flagged
    /// process spawned under one of these was not started by a person at a
    /// keyboard, and the alert should say so.
    static let agents: [String: String] = [
        "claude": "Claude Code",
        "Claude": "Claude app",
        "codex": "Codex CLI",
        "gemini": "Gemini CLI",
        "aider": "Aider",
        "copilot": "GitHub Copilot CLI",
    ]
    static let ancestryDepth = 8

    /// The desktop app that shares an agent's identity, when one is
    /// installed — its icon is the honest picture for the CLI's row. Nothing
    /// is bundled: the icon comes from the user's own copy, like any app.
    static let agentApps: [String: String] = [
        "Claude Code": "/Applications/Claude.app",
        "Claude app": "/Applications/Claude.app",
    ]

    static func agentAppBundle(
        for product: String,
        exists: (String) -> Bool = {
            FileManager.default.fileExists(atPath: $0)
        }
    ) -> String? {
        agentApps[product].flatMap { exists($0) ? $0 : nil }
    }

    let parentPID: Int32
    /// nil when the parent had already exited by the time it was looked up.
    let parentPath: String?
    /// When the process itself started, per the kernel. The sampler sees a
    /// process up to one cadence later than this.
    let startedAt: Date?
    /// Parent first, then its parent, up to `ancestryDepth` or launchd.
    /// Optional so ledgers written before this field existed still decode.
    var ancestors: [Ancestor]?

    init(
        parentPID: Int32, parentPath: String?, startedAt: Date?,
        ancestors: [Ancestor]? = nil
    ) {
        self.parentPID = parentPID
        self.parentPath = parentPath
        self.startedAt = startedAt
        self.ancestors = ancestors
    }

    /// The nearest AI-agent ancestor, if any, as (product name, pid).
    var agentSession: (product: String, pid: Int32)? {
        for ancestor in ancestors ?? [] {
            if let product = Self.agents[ancestor.name]
                ?? ancestor.hint.flatMap({ Self.agents[$0] })
            {
                return (product, ancestor.pid)
            }
        }
        return nil
    }

    /// "zsh ← 1.2.3 · toolkit ← Terminal ← launchd"
    var ancestryDescription: String? {
        guard let ancestors, !ancestors.isEmpty else { return nil }
        return ancestors.map(\.display).joined(separator: " ← ")
    }

    var parentName: String? {
        parentPath.map { ($0 as NSString).lastPathComponent }
    }

    /// One line for alerts and rows: "zsh (pid 7083)".
    var summary: String {
        let name = parentName ?? "exited process"
        return "\(name) (pid \(parentPID))"
    }

    /// Resolves the parent of `record` from the batch it was sampled with,
    /// falling back to `lookup` for a parent that left between the listing
    /// and this call. Returns nil when the kernel gave no parent at all.
    static func resolve(
        for record: ProcessRecord,
        pathsByPID: [pid_t: String],
        parentsByPID: [pid_t: pid_t] = [:],
        lookup: (pid_t) -> String?
    ) -> LaunchContext? {
        guard let parentPID = record.parentPID else { return nil }
        let parentPath = pathsByPID[parentPID] ?? lookup(parentPID)

        // Walk up while the chain is in the listing. Stops at launchd (whose
        // parent is the kernel, pid 0), at a pid the listing lacks, or on a
        // cycle — a reused pid can make the chain loop.
        var ancestors: [Ancestor] = []
        var seen: Set<pid_t> = [record.pid]
        var current = parentPID
        while current > 0, ancestors.count < ancestryDepth, seen.insert(current).inserted {
            let path = pathsByPID[current] ?? (current == parentPID ? parentPath : nil)
            guard let path else { break }
            ancestors.append(Ancestor(pid: current, path: path))
            guard let next = parentsByPID[current] else { break }
            current = next
        }
        return LaunchContext(
            parentPID: parentPID, parentPath: parentPath, startedAt: record.startedAt,
            ancestors: ancestors.isEmpty ? nil : ancestors)
    }
}

/// The sentence(s) appended to a new-process alert. Kept as plain sentences
/// after the path so the alert reads as prose and the path stays parseable.
enum ProvenanceNote {
    static func suffix(launch: LaunchContext?, keg: HomebrewKeg?) -> String {
        var note = ""
        if let launch {
            let parent = launch.parentPath.map { " — \($0)" } ?? ""
            note += " Launched by \(launch.summary)\(parent)."
            if let agent = launch.agentSession {
                note +=
                    " Inside a \(agent.product) session (pid \(agent.pid)) — an AI agent, not you, started it."
            }
        }
        if let keg {
            note += " \(keg.summary)."
        }
        return note
    }
}
