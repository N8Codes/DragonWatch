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
                // Last wins: the active manifest is the last in the store,
                // and earlier ones describe ingredients.
                if let currentLabel, payloadStart < boxEnd {
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

    /// Whether this reader knows where the format keeps a manifest. Other
    /// formats can carry one too (GIF, TIFF, RIFF); for those nothing is
    /// looked for, and nothing is claimed.
    static func canCarry(_ format: FileFormat?) -> Bool {
        format.map(StructureWalker.supports) ?? false
    }

    /// Extracts the JUMBF payload from the head window, or `nil` when it
    /// holds none. The fallback for a probe with no structure walk: a
    /// manifest that runs past the window is not found here.
    static func payload(probe: FileProbe, format: FileFormat?) -> Data? {
        guard let format else { return nil }
        switch format {
        case MagicBytes.jpeg: return jpegPayload(probe.head)
        case MagicBytes.png: return pngPayload(probe.head)
        default: return StructureWalker.isISOMedia(format) ? isoPayload(probe) : nil
        }
    }

    /// One JPEG `APP11` segment carrying part of a JUMBF box (JPEG XT,
    /// ISO/IEC 18477-3): the identifier "JP", a two-byte box instance, a
    /// four-byte packet sequence, then the box bytes. **Every** segment
    /// repeats the box's length and type ahead of its share of the payload.
    struct APP11Segment: Sendable, Equatable {
        let instance: UInt16
        let sequence: UInt32
        /// From the box length field onward.
        let body: [UInt8]

        /// `content` is the segment after its two-byte length.
        init?(content: [UInt8]) {
            guard content.count > 16, content[0] == 0x4A, content[1] == 0x50 else { return nil }
            instance = UInt16(content[2]) << 8 | UInt16(content[3])
            sequence =
                UInt32(content[4]) << 24 | UInt32(content[5]) << 16 | UInt32(content[6]) << 8
                | UInt32(content[7])
            body = Array(content[8...])
        }
    }

    /// Reassembles the boxes split across `APP11` segments: grouped by box
    /// instance, ordered by packet sequence, with the repeated box header
    /// kept from the first packet only.
    static func assemble(_ segments: [APP11Segment]) -> Data? {
        guard !segments.isEmpty else { return nil }
        var result = Data()
        for instance in Set(segments.map(\.instance)).sorted() {
            let packets = segments.filter { $0.instance == instance }
                .sorted { $0.sequence < $1.sequence }
            for (index, packet) in packets.enumerated() {
                // LBox and TBox, plus XLBox when LBox is 1.
                let isExtended = packet.body.prefix(4) == [0, 0, 0, 1]
                let repeated = isExtended ? 16 : 8
                result.append(
                    contentsOf: index == 0 ? packet.body[...] : packet.body.dropFirst(repeated))
            }
        }
        return result
    }

    static func jpegPayload(_ head: Data) -> Data? {
        var segments: [APP11Segment] = []
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
            if kind == 0xEB, contentEnd <= head.count {
                let base = head.startIndex
                let content = [UInt8](head[(base + contentStart)..<(base + contentEnd)])
                if let segment = APP11Segment(content: content) { segments.append(segment) }
            }
            offset = contentEnd
            if offset >= head.count { break }
        }
        return assemble(segments)
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

    /// The manifest store inside a C2PA `uuid` box, given the box body from
    /// its extended type onward: the 16-byte type, a FullBox version and
    /// flags, a NUL-terminated purpose, and — for `manifest` — an eight-byte
    /// offset to any auxiliary box, then the JUMBF itself (C2PA
    /// specification, "Embedding manifests into BMFF-based assets").
    static func manifestStore(inC2PABox body: [UInt8]) -> Data? {
        guard body.count > 20, Array(body.prefix(16)) == StructureWalker.c2paBoxUUID else {
            return nil
        }
        let purposeStart = 20
        guard let terminator = body[purposeStart...].prefix(32).firstIndex(of: 0),
            Array(body[purposeStart..<terminator]) == Array("manifest".utf8),
            terminator + 9 < body.count
        else { return nil }
        return Data(body[(terminator + 9)...])
    }

    /// ISO base media carries the manifest in a top-level `uuid` box. Only a
    /// box that lies wholly inside the head window is found here.
    static func isoPayload(_ probe: FileProbe) -> Data? {
        let walk = ContainerStructure.isoBoxes(head: probe.head, fileSize: probe.size)
        for box in walk.boxes where box.type == "uuid" || box.type == "jumb" {
            guard box.offset <= Int64(Int.max), box.size <= Int64(Int.max),
                ByteReader.fits(Int(box.size), at: Int(box.offset), in: probe.head)
            else { continue }
            let base = probe.head.startIndex + Int(box.offset)
            let bytes = [UInt8](probe.head[base..<(base + Int(box.size))])
            if box.type == "jumb" { return Data(bytes) }
            if let store = manifestStore(inC2PABox: Array(bytes.dropFirst(8))) { return store }
        }
        return nil
    }
}
