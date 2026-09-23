import Foundation

/// A bounded look at one file on disk: the only type here that touches the
/// filesystem, so everything downstream is a pure function over this struct.
///
/// Bounded on purpose — a head and tail window identifies a format and catches
/// data appended past a container's end, and makes a 40 GB file cost what a
/// 40 KB one does. Only hashing streams the whole file, and that is opt-in.
struct FileProbe: Sendable {
    /// 64 KiB each end. Large enough for every signature in the table, every
    /// JPEG/PNG header chain, and a ZIP end-of-central-directory record with a
    /// maximal comment; small enough that a folder of huge files stays cheap.
    static let windowSize = 64 * 1024

    let path: String
    let displayName: String
    let size: Int64
    let head: Data
    let tail: Data
    /// Byte offset in the file at which `tail` begins.
    let tailOffset: Int64
    let isDirectory: Bool
    let isSymbolicLink: Bool
    let posixPermissions: Int
    /// Raw `com.apple.quarantine` value, if present.
    let quarantine: String?
    /// URLs from `com.apple.metadata:kMDItemWhereFroms`, if present.
    let whereFrom: [String]
    /// Set when the file exists but its contents could not be obtained.
    let readError: String?
    /// The head was read but the tail was not, so end-of-file checks did not
    /// run. Reported rather than left to look like a clean result.
    let partialRead: Bool

    var declaredExtension: String {
        (path as NSString).pathExtension.lowercased()
    }

    /// Whether the contents were actually read, and so whether any statement
    /// about them is grounded. Two cases look readable but are not, and both
    /// shipped as bugs: a symlink (never followed, so `head` is empty), and a
    /// 5 GB file that returned zero bytes yet reported Consistent.
    var isReadable: Bool {
        readError == nil && !isDirectory && !isSymbolicLink && !(size > 0 && head.isEmpty)
    }

    /// A directory macOS presents as one object, such as an `.app`. It has no
    /// bytes of its own to check, so `BundleInspector` answers for it.
    var isBundle: Bool {
        isDirectory && FolderWalker.bundleExtensions.contains(declaredExtension)
    }

    /// True when head and tail cover the entire file, so a scan over both has
    /// seen every byte. Below this size, "no embedded signature found" is a
    /// complete answer rather than a sampled one.
    var isFullyWindowed: Bool { size <= Int64(Self.windowSize) * 2 }

    // MARK: - Reading

    /// Reads a bounded probe. Never throws: an unreadable file is a *result*,
    /// because "could not read" is something the report must state rather than
    /// a reason to abandon a folder scan halfway through.
    static func read(path: String) -> FileProbe {
        let name = (path as NSString).lastPathComponent
        var status = stat()
        // lstat, not stat: a symlink must be reported as itself rather than
        // silently measured as whatever it points at.
        guard lstat(path, &status) == 0 else {
            return empty(path: path, name: name, error: "File not found or not accessible")
        }

        let isDir = (status.st_mode & S_IFMT) == S_IFDIR
        let isLink = (status.st_mode & S_IFMT) == S_IFLNK
        let permissions = Int(status.st_mode & 0o777)
        let size = Int64(status.st_size)
        let quarantineValue = readXattrString(path: path, name: "com.apple.quarantine")
        let origins = readWhereFrom(path: path)

        func result(
            head: Data = Data(), tail: Data = Data(), tailOffset: Int64 = 0,
            error: String? = nil, partial: Bool = false
        ) -> FileProbe {
            FileProbe(
                path: path, displayName: name, size: size, head: head, tail: tail,
                tailOffset: tailOffset, isDirectory: isDir, isSymbolicLink: isLink,
                posixPermissions: permissions, quarantine: quarantineValue,
                whereFrom: origins, readError: error, partialRead: partial)
        }

        // A folder the walker could not list arrives here so the report can
        // say so; one that is listable is a bundle or a plain directory and
        // needs no bytes read.
        if isDir, access(path, R_OK | X_OK) != 0 {
            return result(error: "Folder could not be listed: permission denied")
        }
        guard !isDir, !isLink else { return result() }

        guard let handle = FileHandle(forReadingAtPath: path) else {
            return result(error: "Permission denied or unreadable")
        }
        defer { try? handle.close() }

        // A throw here is not end-of-file. Swallowing it yields an empty
        // buffer that every downstream check reads as "nothing recognisable"
        // — a confident answer about bytes nobody obtained.
        let head: Data
        do {
            head = try handle.read(upToCount: windowSize) ?? Data()
        } catch {
            return result(error: "Read failed: \(error.localizedDescription)")
        }
        if size > 0 && head.isEmpty {
            return result(error: "File reports \(size) bytes but returned none")
        }

        guard size > Int64(windowSize) else {
            // Head already covers the whole file; tail is the same bytes.
            return result(head: head, tail: head, tailOffset: 0)
        }

        let tailStart = size - Int64(windowSize)
        do {
            try handle.seek(toOffset: UInt64(tailStart))
            let tail = try handle.read(upToCount: windowSize) ?? Data()
            // A short tail means the end of the file was not obtained, so the
            // end-of-file checks did not really run.
            return result(
                head: head, tail: tail, tailOffset: tailStart, partial: tail.isEmpty)
        } catch {
            return result(head: head, tail: Data(), tailOffset: tailStart, partial: true)
        }
    }

    private static func empty(path: String, name: String, error: String) -> FileProbe {
        FileProbe(
            path: path, displayName: name, size: 0, head: Data(), tail: Data(), tailOffset: 0,
            isDirectory: false, isSymbolicLink: false, posixPermissions: 0,
            quarantine: nil, whereFrom: [], readError: error, partialRead: false)
    }

    // MARK: - Extended attributes

    /// `XATTR_NOFOLLOW` throughout, matching `ContextInspector`: a symlink's
    /// attributes are not its target's.
    ///
    /// Extended attributes are attacker-controlled, and `getxattr` reports
    /// whatever the filesystem holds. The two read here are a short string and
    /// a small plist, so anything past this cap is refused rather than
    /// allocated across four concurrent workers.
    static let maxXattrBytes = 1 << 20

    static func readXattrData(path: String, name: String) -> Data? {
        let length = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard length > 0, length <= maxXattrBytes else { return nil }
        var buffer = [UInt8](repeating: 0, count: length)
        guard getxattr(path, name, &buffer, length, 0, XATTR_NOFOLLOW) == length else {
            return nil
        }
        return Data(buffer)
    }

    static func readXattrString(path: String, name: String) -> String? {
        guard let data = readXattrData(path: path, name: name) else { return nil }
        return String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .controlCharacters)
    }

    /// `kMDItemWhereFroms` is a binary plist holding an array of strings —
    /// typically the download URL and the page that linked it.
    static func readWhereFrom(path: String) -> [String] {
        guard
            let data = readXattrData(path: path, name: "com.apple.metadata:kMDItemWhereFroms"),
            let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)
        else { return [] }
        guard let entries = plist as? [Any] else { return [] }
        return entries.compactMap { $0 as? String }.filter { !$0.isEmpty }
    }

    // MARK: - Searching the windows

    /// Byte offsets, relative to the start of the file, at which `pattern`
    /// occurs in the head or tail window.
    ///
    /// Overlapping windows on a small file would report the same hit twice, so
    /// results are de-duplicated and returned in ascending order.
    func offsets(of pattern: [UInt8]) -> [Int64] {
        guard !pattern.isEmpty else { return [] }
        var found = Set<Int64>()
        for (window, base) in [(head, Int64(0)), (tail, tailOffset)] {
            for local in Self.search(pattern, in: window) {
                found.insert(base + Int64(local))
            }
        }
        return found.sorted()
    }

    /// All offsets at which `pattern` occurs, overlaps included. Uses
    /// `Data.range(of:in:)`: the obvious byte-by-byte loop pays a bounds and
    /// copy-on-write check per subscript, measured 4x slower in release.
    static func search(_ pattern: [UInt8], in data: Data) -> [Int] {
        guard !pattern.isEmpty, data.count >= pattern.count else { return [] }
        let needle = Data(pattern)
        var hits: [Int] = []
        var from = data.startIndex
        while from < data.endIndex,
            let found = data.range(of: needle, in: from..<data.endIndex)
        {
            hits.append(found.lowerBound - data.startIndex)
            from = found.lowerBound + 1
        }
        return hits
    }
}
