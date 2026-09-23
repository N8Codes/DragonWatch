import Foundation

/// Turns what the user selected into the flat list of files the engine
/// inspects, under caps that make pointing at a home directory safe.
///
/// Hand-rolled rather than `FileManager.enumerator` because the three things
/// that matter here — depth limiting, treating a bundle as one item, and
/// refusing to follow directory symlinks — all need per-entry decisions the
/// enumerator does not offer.
enum FolderWalker {

    struct Result: Sendable {
        var files: [String] = []
        /// Folders that were entered, for the "n files in m folders" line.
        var folderCount = 0
        var limitHit: InspectionLimit?
    }

    /// Directories macOS presents as single objects. Descending into an `.app`
    /// turns one selection into thousands of files and buries the question the
    /// user asked; the bundle is inspected as a unit instead.
    static let bundleExtensions: Set<String> = [
        "app", "bundle", "framework", "kext", "appex", "xpc", "plugin",
        "prefpane", "qlgenerator", "saver", "wdgt", "docset", "systemextension",
        "photoslibrary", "rtfd", "scptd",
    ]

    /// Walks `roots` breadth-first, newest caps first.
    ///
    /// Symlinked directories are recorded as files and never entered. A link
    /// pointing at its own ancestor is the classic way to make a walker run
    /// forever, and following one would also take the scan outside what the
    /// user actually selected.
    static func walk(roots: [URL], limits: InspectionEngine.Limits) -> Result {
        var result = Result()
        var queue: [(url: URL, depth: Int)] = roots.map { ($0.standardizedFileURL, 0) }
        var seenFolders = Set<String>()
        var totalBytes: Int64 = 0
        let deadline = Date().addingTimeInterval(limits.maxDuration)
        let manager = FileManager.default

        // Selecting a folder and one of its children reaches the same file
        // twice; the report lists it once. The key resolves the *parent* so
        // `/var/x` and `/private/var/x` are one file, while a symlink and its
        // target — different last components — stay two.
        var seenFiles = Set<String>()
        func addFile(_ path: String) {
            let url = URL(fileURLWithPath: path)
            let key = url.deletingLastPathComponent().resolvingSymlinksInPath()
                .appendingPathComponent(url.lastPathComponent).path
            if seenFiles.insert(key).inserted { result.files.append(path) }
        }

        while !queue.isEmpty {
            if Task.isCancelled {
                result.limitHit = result.limitHit ?? .cancelled
                break
            }
            if Date() >= deadline {
                result.limitHit = result.limitHit ?? .timeCap
                break
            }

            let (url, depth) = queue.removeFirst()
            var isDirectory: ObjCBool = false
            guard manager.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
                // A selection that vanished between picking and walking is
                // still worth reporting, so the engine can say so.
                addFile(url.path)
                continue
            }

            var status = stat()
            let isLink =
                lstat(url.path, &status) == 0
                && (status.st_mode & S_IFMT) == S_IFLNK

            let isUnitaryBundle =
                isDirectory.boolValue
                && bundleExtensions.contains(url.pathExtension.lowercased())

            guard isDirectory.boolValue, !isLink, !isUnitaryBundle else {
                guard result.files.count < limits.maxFiles else {
                    result.limitHit = result.limitHit ?? .fileCountCap
                    break
                }
                if !isDirectory.boolValue {
                    totalBytes +=
                        (try? url.resourceValues(forKeys: [.fileSizeKey]))?
                        .fileSize.map(Int64.init) ?? 0
                    guard totalBytes <= limits.maxTotalBytes else {
                        result.limitHit = result.limitHit ?? .byteCap
                        break
                    }
                }
                addFile(url.path)
                continue
            }

            guard depth < limits.maxDepth else {
                result.limitHit = result.limitHit ?? .depthCap
                continue
            }
            // Resolving guards against a loop built from hard-linked or
            // aliased directories that `standardizedFileURL` alone would miss.
            guard seenFolders.insert(url.resolvingSymlinksInPath().path).inserted else {
                continue
            }
            result.folderCount += 1

            let children: [URL]
            do {
                children = try manager.contentsOfDirectory(
                    at: url, includingPropertiesForKeys: [.fileSizeKey],
                    options: [.skipsPackageDescendants])
            } catch {
                // A folder that cannot be listed is a result, not a gap: left
                // out, a run over it read "all consistent". Handing the path
                // on lets the probe report it as unreadable.
                addFile(url.path)
                continue
            }
            // Sorted, so two runs over the same folder produce the same
            // report: `contentsOfDirectory` returns filesystem order.
            for child in children.sorted(by: { $0.path < $1.path }) {
                queue.append((child, depth + 1))
            }
        }

        return result
    }
}
