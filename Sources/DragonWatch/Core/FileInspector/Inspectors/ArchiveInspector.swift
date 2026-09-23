import Foundation

/// Reads a ZIP's central directory — the index at the end of the file that
/// lists what it holds.
///
/// **Nothing is ever extracted.** Inflating an entry is the decompression-bomb
/// path, and writing one to disk is the path-traversal path; the whole point
/// of reading the directory is that both questions can be answered from the
/// index alone.
///
/// This also covers the ZIP-based document formats, since `.docx`, `.xlsx`,
/// `.pptx` and the iWork formats are all ZIPs — `DocumentInspector` reads the
/// entry list this produces.
enum ArchiveInspector {

    struct Entry: Sendable {
        let name: String
        let compressedSize: Int64
        let uncompressedSize: Int64
    }

    struct Directory: Sendable {
        var entries: [Entry] = []
        /// Offset of the end-of-central-directory record.
        var eocdOffset: Int64 = 0
        /// Where the archive's own data starts. Non-zero means something is
        /// prepended — a self-extracting stub, or a host file in a polyglot.
        var archiveStart: Int64 = 0
        var declaredCount: Int = 0
        /// Fewer entries were readable than the record declares, although the
        /// index itself was in view.
        var truncated = false
        /// The index begins before the sampled tail window, so no entry could
        /// be read. A limit of the sampling, not a property of the archive.
        var indexBeyondWindow = false
    }

    /// At most this many entries are read. A directory listing thousands of
    /// files is legitimate, but nothing here needs to see them all, and an
    /// unbounded loop over attacker-controlled counts is the thing to avoid.
    static let maxEntries = 2048

    // MARK: - Reading the index

    /// The end-of-central-directory record is `PK\x05\x06`, last in the file
    /// apart from an optional comment — so it lives in the tail window.
    static func readDirectory(probe: FileProbe) -> Directory? {
        let signature: [UInt8] = [0x50, 0x4B, 0x05, 0x06]
        guard let eocdAbsolute = probe.offsets(of: signature).last else { return nil }

        // Translate to an index inside whichever window holds it.
        let window: Data
        let base: Int64
        if eocdAbsolute >= probe.tailOffset, probe.tailOffset > 0 || probe.tail.count > 0 {
            window = probe.tail
            base = probe.tailOffset
        } else {
            window = probe.head
            base = 0
        }
        let eocd = Int(eocdAbsolute - base)
        guard eocd >= 0, eocd < window.count else { return nil }

        var directory = Directory()
        directory.eocdOffset = eocdAbsolute
        directory.declaredCount = Int(ByteReader.uint16LE(window, at: eocd + 10) ?? 0)

        guard let directorySize = ByteReader.uint32LE(window, at: eocd + 12),
            let directoryOffset = ByteReader.uint32LE(window, at: eocd + 16)
        else { return directory }

        // The recorded offset is relative to the start of the archive, so the
        // difference from where it actually sits is the size of anything
        // prepended ahead of it.
        let expectedStart = eocdAbsolute - Int64(directorySize) - Int64(directoryOffset)
        directory.archiveStart = max(0, expectedStart)

        var cursor = Int(Int64(directoryOffset) + directory.archiveStart - base)
        // An index larger than the window — roughly 600 entries — starts
        // before the bytes that were read. That is not truncation; half the
        // real archives on a Mac were being called "incomplete" for it.
        guard cursor >= 0 else {
            directory.indexBeyondWindow = true
            return directory
        }
        let central: [UInt8] = [0x50, 0x4B, 0x01, 0x02]
        while directory.entries.count < maxEntries {
            guard cursor >= 0, cursor + 46 <= window.count,
                MagicBytes.hasBytes(central, at: cursor, in: window)
            else {
                directory.truncated = directory.entries.count < directory.declaredCount
                break
            }
            let compressed = Int64(ByteReader.uint32LE(window, at: cursor + 20) ?? 0)
            let uncompressed = Int64(ByteReader.uint32LE(window, at: cursor + 24) ?? 0)
            let nameLength = Int(ByteReader.uint16LE(window, at: cursor + 28) ?? 0)
            let extraLength = Int(ByteReader.uint16LE(window, at: cursor + 30) ?? 0)
            let commentLength = Int(ByteReader.uint16LE(window, at: cursor + 32) ?? 0)

            var name = ""
            if nameLength > 0, cursor + 46 + nameLength <= window.count {
                let start = window.startIndex + cursor + 46
                name =
                    String(data: window[start..<(start + nameLength)], encoding: .utf8)
                    ?? ""
            }
            directory.entries.append(
                Entry(name: name, compressedSize: compressed, uncompressedSize: uncompressed))

            let advance = 46 + nameLength + extraLength + commentLength
            guard advance > 0 else { break }
            cursor += advance
        }
        return directory
    }

    // MARK: - Findings

    static func inspect(probe: FileProbe) -> InspectorOutput {
        inspect(probe: probe, directory: readDirectory(probe: probe))
    }

    /// Takes an already-parsed index so a caller that needs the entry list
    /// too — `DocumentInspector` does — pays for the parse once.
    static func inspect(probe: FileProbe, directory: Directory?) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("Archive index: entry paths, sizes and ratios")
        guard let directory else {
            output.findings.append(
                ContainerStructure.malformedChain(
                    format: "ZIP",
                    detail:
                        "No end-of-central-directory record was found, so the archive index "
                        + "could not be read. The file is truncated or not really a ZIP."))
            return output
        }

        output.disclosures.append(
            Disclosure(
                title: "Archive contents",
                detail:
                    "\(directory.declaredCount) entr"
                    + "\(directory.declaredCount == 1 ? "y" : "ies") listed in the index. "
                    + "Nothing was extracted."))
        if directory.indexBeyondWindow {
            output.disclosures.append(
                Disclosure(
                    title: "Index not examined",
                    detail:
                        "The index is larger than the \(FileProbe.windowSize / 1024) KB sampled "
                        + "from the end of the file, so entry paths, sizes and ratios were not "
                        + "checked."))
        }

        // An entry whose path escapes the extraction directory. Reading the
        // index is exactly how this is caught without creating the file.
        let traversing = directory.entries.filter {
            $0.name.hasPrefix("/") || $0.name.contains("../") || $0.name.contains("..\\")
        }
        if let first = traversing.first {
            output.findings.append(
                Finding(
                    rule: "zip.pathTraversal",
                    severity: .inconsistent,
                    title: "Entry escapes the extraction folder",
                    detail:
                        "\(traversing.count) entr\(traversing.count == 1 ? "y" : "ies") use an "
                        + "absolute or parent path, such as "
                        + "\(UniversalChecks.displaySafe(first.name, limit: 80)). Extracting "
                        + "this would write outside the folder you chose."))
        }

        // A tiny archive that expands enormously.
        let totalCompressed = directory.entries.reduce(Int64(0)) { $0 + $1.compressedSize }
        let totalUncompressed = directory.entries.reduce(Int64(0)) { $0 + $1.uncompressedSize }
        if totalCompressed > 0, totalUncompressed / max(totalCompressed, 1) >= 100,
            totalUncompressed > 100 * 1024 * 1024
        {
            output.findings.append(
                Finding(
                    rule: "zip.expansionRatio",
                    severity: .caution,
                    title: "Expands far more than its size suggests",
                    detail:
                        "The index describes \(ByteCountFormatter.string(fromByteCount: totalUncompressed, countStyle: .file)) "
                        + "of content in \(ByteCountFormatter.string(fromByteCount: totalCompressed, countStyle: .file)) "
                        + "of archive, a ratio of \(totalUncompressed / max(totalCompressed, 1)):1."
                ))
        }

        if directory.archiveStart > 0 {
            output.findings.append(
                Finding(
                    rule: "zip.prependedData",
                    severity: .caution,
                    title: "Data before the start of the archive",
                    detail:
                        "\(directory.archiveStart) bytes sit ahead of the archive's own data. "
                        + "Self-extracting archives look like this; so does a ZIP hidden inside "
                        + "another file."))
        }

        if directory.truncated {
            output.findings.append(
                Finding(
                    rule: "zip.indexTruncated",
                    severity: .caution,
                    title: "Archive index is incomplete",
                    detail:
                        "The record claims \(directory.declaredCount) entries but only "
                        + "\(directory.entries.count) could be read."))
        }

        let executables = directory.entries.filter {
            MagicBytes.executableExtensions.contains(
                ($0.name as NSString).pathExtension.lowercased())
        }
        if let first = executables.first {
            output.disclosures.append(
                Disclosure(
                    title: "Runnable entries",
                    detail:
                        "\(executables.count) entr\(executables.count == 1 ? "y" : "ies") macOS "
                        + "would treat as runnable, such as "
                        + "\(UniversalChecks.displaySafe(first.name, limit: 80))."))
        }
        return output
    }
}
