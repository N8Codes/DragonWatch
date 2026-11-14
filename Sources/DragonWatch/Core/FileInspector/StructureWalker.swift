import Foundation

/// What a walk of a file's own structure established.
///
/// The two sampled windows in `FileProbe` cannot say where a JPEG or PNG
/// really ends: searching them for the *last* end marker let anyone append a
/// payload followed by a forged marker and have it read as part of the image.
/// A walk follows the format's own chain — segment lengths, chunk lengths, box
/// sizes — from the first byte, so the end it reports is the one a decoder
/// would stop at.
struct StructureScan: Sendable, Equatable {
    enum Credentials: Sendable, Equatable {
        case absent
        /// A C2PA container is there, but is larger than the walk will read.
        case unreadable
        /// The raw JUMBF bytes of the manifest store.
        case found(Data)
    }

    /// Offset just past the format's own end. `nil` when the walk never
    /// reached one.
    var logicalEnd: Int64?
    /// The first bytes after `logicalEnd`, so a trailer that begins between
    /// the two windows can still be recognised.
    var trailerPrefix = Data()
    /// Why the chain stopped parsing, when it did.
    var problem: String?
    var credentials: Credentials = .absent
}

/// Seek-based structure walks. With `FileProbe`, the only code here that
/// touches the filesystem; everything it returns is plain data for the pure
/// inspectors.
///
/// Reads headers, never payloads, with two bounded exceptions: a C2PA
/// container up to `maxCredentialBytes`, and JPEG scan data, which has no
/// length field and must be streamed to find the marker that ends it.
enum StructureWalker {
    static let maxCredentialBytes = 16 << 20
    /// Chunks, segments or boxes followed before giving up. A crafted chain
    /// of minimal elements cannot cost more than this many small reads.
    static let maxSteps = 1_000_000
    static let trailerPrefixLength = 64
    private static let scanChunk = 256 * 1024

    /// The `uuid` box extended type C2PA assigns to its manifest store
    /// (C2PA specification, "Embedding manifests into BMFF-based assets").
    static let c2paBoxUUID: [UInt8] = [
        0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
        0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
    ]

    static func supports(_ format: FileFormat) -> Bool {
        format == MagicBytes.jpeg || format == MagicBytes.png || isISOMedia(format)
    }

    static func isISOMedia(_ format: FileFormat) -> Bool {
        [
            MagicBytes.heic, MagicBytes.avif, MagicBytes.mp4, MagicBytes.mov, MagicBytes.m4a,
            MagicBytes.isoMedia,
        ].contains(format)
    }

    /// `nil` when the file cannot be opened as a regular file, the format has
    /// no walk, or the run was cancelled — callers fall back to the windows.
    static func scan(path: String, format: FileFormat) -> StructureScan? {
        guard supports(format) else { return nil }
        // Same rules as `FileProbe.read`: regular files only, never blocking,
        // never through a link swapped in after the probe.
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            return nil
        }
        let file = File(descriptor: descriptor, size: Int64(info.st_size))

        var scan: StructureScan?
        switch format {
        case MagicBytes.jpeg: scan = jpeg(file)
        case MagicBytes.png: scan = png(file)
        default: scan = isoMedia(file)
        }
        if let end = scan?.logicalEnd, end < file.size {
            scan?.trailerPrefix = Data(file.bytes(at: end, count: trailerPrefixLength))
        }
        return scan
    }

    // MARK: - Reading

    struct File {
        let descriptor: Int32
        let size: Int64

        /// Up to `count` bytes at `offset`; fewer only at the end of the file
        /// or on a read error.
        func bytes(at offset: Int64, count: Int) -> [UInt8] {
            guard offset >= 0, offset < size, count > 0 else { return [] }
            var buffer = [UInt8](repeating: 0, count: count)
            var filled = 0
            while filled < count {
                let got = buffer.withUnsafeMutableBytes { raw in
                    pread(
                        descriptor, raw.baseAddress! + filled, count - filled,
                        off_t(offset) + off_t(filled))
                }
                if got <= 0 { break }
                filled += got
            }
            buffer.removeSubrange(filled...)
            return buffer
        }
    }

    private static func uint16BE(_ bytes: [UInt8], _ at: Int) -> Int {
        Int(bytes[at]) << 8 | Int(bytes[at + 1])
    }

    private static func uint32BE(_ bytes: [UInt8], _ at: Int) -> Int64 {
        Int64(bytes[at]) << 24 | Int64(bytes[at + 1]) << 16 | Int64(bytes[at + 2]) << 8
            | Int64(bytes[at + 3])
    }

    // MARK: - JPEG

    /// Follows marker segments by their lengths, and streams each scan to the
    /// marker that ends it, until End Of Image.
    ///
    /// An EXIF thumbnail's own `FFD9` sits inside an APP segment the walk
    /// steps over, and a forged one after appended data is never reached, so
    /// the first EOI the chain arrives at is the real one.
    static func jpeg(_ file: File) -> StructureScan? {
        var scan = StructureScan()
        var segments: [JUMBF.APP11Segment] = []
        var collected = 0
        var offset: Int64 = 2  // past SOI

        for _ in 0..<maxSteps {
            let marker = file.bytes(at: offset, count: 2)
            guard marker.count == 2 else { break }
            guard marker[0] == 0xFF else {
                scan.problem = "Expected a marker at byte \(offset) and found something else."
                break
            }
            let kind = marker[1]
            if kind == 0xD9 {
                scan.logicalEnd = offset + 2
                break
            }
            if kind == 0xFF {  // fill byte before a marker
                offset += 1
                continue
            }
            if kind == 0x01 || (0xD0...0xD8).contains(kind) {  // no length
                offset += 2
                continue
            }
            let lengthBytes = file.bytes(at: offset + 2, count: 2)
            guard lengthBytes.count == 2 else { break }
            let length = uint16BE(lengthBytes, 0)
            guard length >= 2 else {
                scan.problem = "A segment at byte \(offset) declares an impossible length."
                break
            }
            let next = offset + 2 + Int64(length)

            if kind == 0xEB, scan.credentials != .unreadable {
                let content = file.bytes(at: offset + 4, count: length - 2)
                if let segment = JUMBF.APP11Segment(content: content) {
                    collected += content.count
                    if collected > maxCredentialBytes {
                        scan.credentials = .unreadable
                        segments = []
                    } else {
                        segments.append(segment)
                    }
                }
            }

            if kind == 0xDA {
                // Entropy-coded data carries no length. Inside it a literal FF
                // is written FF00 and restart markers are FFD0–FFD7; the next
                // FF followed by anything else is the marker that ends the scan.
                guard let found = nextMarker(in: file, from: next) else {
                    if Task.isCancelled { return nil }
                    break
                }
                offset = found
            } else {
                offset = next
            }
        }

        if scan.credentials != .unreadable, let payload = JUMBF.assemble(segments) {
            scan.credentials = .found(payload)
        }
        return scan
    }

    private static func nextMarker(in file: File, from start: Int64) -> Int64? {
        var position = start
        while position < file.size {
            if Task.isCancelled { return nil }
            let chunk = file.bytes(at: position, count: scanChunk)
            guard chunk.count >= 2 else { return nil }
            var index = 0
            while index < chunk.count - 1 {
                if chunk[index] == 0xFF {
                    let following = chunk[index + 1]
                    if following != 0x00, following != 0xFF, !(0xD0...0xD7).contains(following) {
                        return position + Int64(index)
                    }
                }
                index += 1
            }
            // Keep the last byte: an FF there needs the next chunk's first.
            position += Int64(chunk.count - 1)
        }
        return nil
    }

    // MARK: - PNG

    /// Follows the chunk chain to `IEND`. Each chunk is a four-byte length, a
    /// four-byte type, the data and a four-byte CRC.
    static func png(_ file: File) -> StructureScan? {
        var scan = StructureScan()
        var offset: Int64 = 8  // past the signature

        for _ in 0..<maxSteps {
            let header = file.bytes(at: offset, count: 8)
            guard header.count == 8 else { break }
            let length = uint32BE(header, 0)
            let type = Array(header[4...])
            guard type.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) })
            else {
                scan.problem = "The bytes at \(offset) are not a chunk header."
                break
            }
            let next = offset + 12 + length
            if type == Array("IEND".utf8) {
                scan.logicalEnd = offset + 12
                break
            }
            guard next <= file.size else {
                scan.problem =
                    "A chunk at byte \(offset) declares \(length) bytes, more than the file holds."
                break
            }
            if type == Array("caBX".utf8), scan.credentials == .absent {
                scan.credentials =
                    length <= Int64(maxCredentialBytes)
                    ? .found(Data(file.bytes(at: offset + 8, count: Int(length))))
                    : .unreadable
            }
            offset = next
        }
        return scan
    }

    // MARK: - ISO base media

    /// Follows the top-level box chain through the whole file. The end is
    /// where the chain reaches the end of the file, or the first offset at
    /// which the bytes are no longer a box that fits.
    static func isoMedia(_ file: File) -> StructureScan? {
        var scan = StructureScan()
        var offset: Int64 = 0

        for _ in 0..<maxSteps {
            let header = file.bytes(at: offset, count: 16)
            guard header.count >= 8 else { break }
            var size = uint32BE(header, 0)
            var headerSize: Int64 = 8
            if size == 1 {
                guard header.count == 16, header[8] & 0x80 == 0 else { break }
                size = uint32BE(header, 8) << 32 | uint32BE(header, 12)
                headerSize = 16
            } else if size == 0 {
                size = file.size - offset  // "extends to the end of the file"
            }
            let (next, overflowed) = offset.addingReportingOverflow(size)
            guard size >= headerSize, !overflowed, next <= file.size else { break }

            let type = Array(header[4..<8])
            if scan.credentials == .absent,
                type == Array("uuid".utf8) || type == Array("jumb".utf8)
            {
                scan.credentials = credentials(
                    in: file, type: type, start: offset, bodyStart: offset + headerSize, end: next)
            }
            offset = next
            if offset == file.size { break }
        }
        if offset > 0 { scan.logicalEnd = offset }
        return scan
    }

    private static func credentials(
        in file: File, type: [UInt8], start: Int64, bodyStart: Int64, end: Int64
    ) -> StructureScan.Credentials {
        if type == Array("jumb".utf8) {
            guard end - start <= Int64(maxCredentialBytes) else { return .unreadable }
            return .found(Data(file.bytes(at: start, count: Int(end - start))))
        }
        guard file.bytes(at: bodyStart, count: 16) == c2paBoxUUID else { return .absent }
        guard end - bodyStart <= Int64(maxCredentialBytes) else { return .unreadable }
        let body = file.bytes(at: bodyStart, count: Int(end - bodyStart))
        return JUMBF.manifestStore(inC2PABox: body).map { .found($0) } ?? .absent
    }
}
