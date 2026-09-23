import Foundation

/// RIFF (WebP, WAV, AVI) and ISO base media (HEIC, AVIF, MP4, MOV, M4A),
/// shared so the image and media inspectors cannot disagree about where a
/// file ends.
enum ContainerStructure {

    // MARK: - RIFF

    /// `RIFF` + a little-endian uint32 counting everything after the first
    /// eight bytes, so the logical end is exact and free.
    static func riffExtent(head: Data) -> ContainerExtent? {
        guard MagicBytes.hasBytes(Array("RIFF".utf8), at: 0, in: head),
            let declared = ByteReader.uint32LE(head, at: 4)
        else { return nil }
        return ContainerExtent(
            logicalEnd: Int64(declared) + 8,
            evidence: "RIFF container, whose header declares \(declared) bytes of payload")
    }

    // MARK: - ISO base media

    struct Box: Sendable {
        let type: String
        let offset: Int64
        let size: Int64
    }

    /// Walks the top-level box chain, reading headers only — so a file whose
    /// big `mdat` starts early can be measured to its end without touching the
    /// payload. Returns the boxes found and whether the chain reached the end.
    /// A box that does not advance the cursor terminates the walk.
    static let maxTopLevelBoxes = 64

    static func isoBoxes(head: Data, fileSize: Int64, maxBoxes: Int = maxTopLevelBoxes)
        -> (boxes: [Box], reachedEnd: Bool)
    {
        var boxes: [Box] = []
        var cursor: Int64 = 0

        while boxes.count < maxBoxes {
            guard cursor >= 0, cursor <= Int64(Int.max),
                let declared = ByteReader.uint32BE(head, at: Int(cursor)),
                let type = ByteReader.fourCC(head, at: Int(cursor) + 4)
            else { break }

            var size = Int64(declared)
            if declared == 1 {
                // 64-bit `largesize` follows the type.
                guard let large = ByteReader.uint64BE(head, at: Int(cursor) + 8),
                    large <= UInt64(Int64.max)
                else { break }
                size = Int64(large)
            } else if declared == 0 {
                // "extends to end of file" — a legal terminator.
                boxes.append(Box(type: type, offset: cursor, size: fileSize - cursor))
                return (boxes, true)
            }

            // Must advance, and must not claim more than the file holds.
            // `cursor + size` is computed with overflow reporting: a crafted
            // 64-bit `largesize` of Int64.max traps on the addition, so the
            // bounds check has to survive the value it is checking.
            let (next, overflowed) = cursor.addingReportingOverflow(size)
            guard size >= 8, !overflowed, next <= fileSize else { break }
            boxes.append(Box(type: type, offset: cursor, size: size))
            cursor = next
            if cursor == fileSize { return (boxes, true) }
        }
        return (boxes, false)
    }

    static func isoExtent(head: Data, fileSize: Int64) -> ContainerExtent? {
        let walk = isoBoxes(head: head, fileSize: fileSize)
        guard let last = walk.boxes.last, walk.boxes.count < maxTopLevelBoxes else { return nil }
        let end = last.offset + last.size
        // Only a chain that parsed cleanly to a terminating box, or that
        // stopped *inside the window* because the bytes there are not a box
        // header, can speak to the end of the file. A walk that stopped because
        // the next header lay past the window never looked — and calling the
        // box before a 270 MB `mdat` the "end" flagged every movie on the Mac.
        let stoppedInsideWindow = end < fileSize && end + 8 <= Int64(head.count)
        guard walk.reachedEnd || stoppedInsideWindow else { return nil }
        return ContainerExtent(
            logicalEnd: end,
            evidence: "ISO base media box chain, which ends with `\(last.type)`")
    }

    // MARK: - Shared findings

    /// A box or chunk chain that does not parse is worth saying, because every
    /// other structural claim about the file rests on it.
    static func malformedChain(format: String, detail: String) -> Finding {
        Finding(
            rule: "container.malformed",
            severity: .caution,
            title: "\(format) structure does not parse cleanly",
            detail: detail)
    }
}
