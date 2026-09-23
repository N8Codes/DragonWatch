import Foundation

/// Walks the JUMBF box tree that carries a C2PA manifest.
///
/// The point of walking it, rather than searching the file for a key, is that
/// a box tree says *where* a value came from. A `digitalSourceType` inside
/// `c2pa.actions.v2` is a claim the manifest makes; the same bytes in an EXIF
/// comment are just bytes. Only the walk can tell them apart.
///
/// Boxes are ISO base media shaped: a four-byte big-endian length that counts
/// itself, a four-byte type, then the payload. A `jumb` superbox opens with a
/// `jumd` description box carrying its label.
enum JUMBF {

    /// A manifest is small; these stop a crafted tree from costing anything.
    static let maxBoxes = 512
    static let maxDepth = 12

    /// Maps a JUMBF label to the raw CBOR payload of the `cbor` box inside it,
    /// e.g. `"c2pa.actions.v2"` to the bytes of that assertion.
    static func labelledCBOR(in data: Data) -> [String: Data] {
        var found: [String: Data] = [:]
        var budget = maxBoxes
        walk(data, from: 0, to: data.count, label: nil, depth: 0, budget: &budget, into: &found)
        return found
    }

    private static func walk(
        _ data: Data, from start: Int, to end: Int, label: String?, depth: Int,
        budget: inout Int, into found: inout [String: Data]
    ) {
        guard depth <= maxDepth else { return }
        var offset = start
        // The label belongs to the superbox this level is inside; a `jumd`
        // encountered here names the boxes that follow it.
        var currentLabel = label

        while offset + 8 <= end, budget > 0 {
            budget -= 1
            guard let declared = ByteReader.uint32BE(data, at: offset),
                let type = ByteReader.fourCC(data, at: offset + 4)
            else { return }

            var size = Int64(declared)
            var headerSize = 8
            if declared == 1 {
                // 64-bit extended length, as in ISO base media.
                guard let large = ByteReader.uint64BE(data, at: offset + 8),
                    large <= UInt64(Int64.max)
                else { return }
                size = Int64(large)
                headerSize = 16
            } else if declared == 0 {
                size = Int64(end - offset)
            }

            // Must advance, and must stay inside the parent.
            guard size >= Int64(headerSize), size <= Int64(end - offset) else { return }
            let boxEnd = offset + Int(size)
            let payloadStart = offset + headerSize

            switch type {
            case "jumd":
                currentLabel = descriptionLabel(data, from: payloadStart, to: boxEnd)
            case "jumb":
                walk(
                    data, from: payloadStart, to: boxEnd, label: currentLabel,
                    depth: depth + 1, budget: &budget, into: &found)
            case "cbor":
                if let currentLabel, payloadStart < boxEnd, found[currentLabel] == nil {
                    let base = data.startIndex
                    found[currentLabel] = Data(data[(base + payloadStart)..<(base + boxEnd)])
                }
            default:
                break
            }
            offset = boxEnd
        }
    }

    /// A description box is a 16-byte UUID, a toggle byte, then — when the
    /// toggles say so — a NUL-terminated label.
    static func descriptionLabel(_ data: Data, from start: Int, to end: Int) -> String? {
        guard end - start > 17, let toggles = ByteReader.byte(data, at: start + 16),
            toggles & 0x02 != 0
        else { return nil }
        let base = data.startIndex
        var cursor = start + 17
        var bytes: [UInt8] = []
        while cursor < end, bytes.count < 256 {
            let byte = data[base + cursor]
            if byte == 0 { break }
            bytes.append(byte)
            cursor += 1
        }
        guard !bytes.isEmpty else { return nil }
        return String(bytes: bytes, encoding: .utf8)
    }

    // MARK: - Finding the JUMBF inside a container

    /// Extracts the JUMBF payload a file carries, or `nil` when it has none.
    ///
    /// Only the head window is available, so a manifest larger than that is
    /// reported as truncated by the caller rather than parsed half-way.
    static func payload(probe: FileProbe, format: FileFormat?) -> Data? {
        switch format {
        case MagicBytes.jpeg: return jpegPayload(probe.head)
        case MagicBytes.png: return pngPayload(probe.head)
        case MagicBytes.heic, MagicBytes.avif, MagicBytes.mp4, MagicBytes.mov, MagicBytes.m4a:
            return isoPayload(probe)
        default: return nil
        }
    }

    /// JPEG carries JUMBF in `APP11` segments. A manifest too large for one
    /// 64 KB segment is split across several, each repeating an eight-byte
    /// header, and the box data is the concatenation in packet order.
    static func jpegPayload(_ head: Data) -> Data? {
        var segments: [(sequence: UInt32, body: Data)] = []
        var offset = 2
        var guardCount = 0

        while guardCount < 256 {
            guardCount += 1
            guard let marker = ByteReader.byte(head, at: offset), marker == 0xFF,
                let kind = ByteReader.byte(head, at: offset + 1)
            else { break }
            if kind == 0xDA || kind == 0xD9 { break }
            if kind == 0x01 || (kind >= 0xD0 && kind <= 0xD7) {
                offset += 2
                continue
            }
            guard let length = ByteReader.uint16BE(head, at: offset + 2), length >= 2 else {
                break
            }
            let contentStart = offset + 4
            let contentEnd = offset + 2 + Int(length)

            // "JP" identifier, two-byte box instance, four-byte packet
            // sequence, then the box bytes.
            if kind == 0xEB, contentEnd <= head.count, contentEnd - contentStart > 8,
                ByteReader.byte(head, at: contentStart) == 0x4A,
                ByteReader.byte(head, at: contentStart + 1) == 0x50,
                let sequence = ByteReader.uint32BE(head, at: contentStart + 4)
            {
                let base = head.startIndex
                segments.append(
                    (sequence, Data(head[(base + contentStart + 8)..<(base + contentEnd)])))
            }
            offset = contentEnd
            if offset >= head.count { break }
        }

        guard !segments.isEmpty else { return nil }
        // Sorted by packet sequence, which is the order the writer intended
        // — segments arrive in file order today, but the field exists so that
        // is not guaranteed.
        return segments.sorted { $0.sequence < $1.sequence }
            .reduce(into: Data()) { $0.append($1.body) }
    }

    /// PNG carries JUMBF in a `caBX` chunk.
    static func pngPayload(_ head: Data) -> Data? {
        var offset = 8
        var guardCount = 0
        while guardCount < 256 {
            guardCount += 1
            guard let length = ByteReader.uint32BE(head, at: offset),
                let type = ByteReader.fourCC(head, at: offset + 4)
            else { return nil }
            if type == "IEND" { return nil }
            guard let size = Int(exactly: length), size >= 0 else { return nil }
            if type == "caBX", ByteReader.fits(size, at: offset + 8, in: head) {
                let base = head.startIndex
                return Data(head[(base + offset + 8)..<(base + offset + 8 + size)])
            }
            guard size <= head.count else { return nil }
            offset += 12 + size
            if offset >= head.count { return nil }
        }
        return nil
    }

    /// ISO base media carries it in a top-level `jumb` box, which the shared
    /// box walk already enumerates.
    static func isoPayload(_ probe: FileProbe) -> Data? {
        let walk = ContainerStructure.isoBoxes(head: probe.head, fileSize: probe.size)
        guard let box = walk.boxes.first(where: { $0.type == "jumb" }),
            box.offset >= 0, box.offset <= Int64(Int.max), box.size <= Int64(Int.max)
        else { return nil }
        let start = Int(box.offset)
        let length = Int(box.size)
        guard ByteReader.fits(length, at: start, in: probe.head) else { return nil }
        let base = probe.head.startIndex
        return Data(probe.head[(base + start)..<(base + start + length)])
    }
}
