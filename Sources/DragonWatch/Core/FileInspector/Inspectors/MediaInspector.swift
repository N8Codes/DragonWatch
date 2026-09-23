import Foundation

/// Audio and video containers.
///
/// Media files are large, and large files are where payloads hide comfortably
/// — the generic scan only samples two windows, so the declared length of the
/// container is the only reliable statement about the end of a video.
///
/// Never decodes. AVFoundation is out of bounds here for the same reason
/// ImageIO is.
struct MediaInspector: FormatInspector {

    func handles(_ format: FileFormat) -> Bool {
        format.family == .audio || format.family == .video
    }

    func inspect(probe: FileProbe, format: FileFormat) -> InspectorOutput {
        switch format {
        case MagicBytes.wav, MagicBytes.avi: return riff(probe, name: format.name)
        case MagicBytes.mp4, MagicBytes.mov, MagicBytes.m4a:
            return isoMedia(probe, format: format)
        case MagicBytes.mp3: return mp3(probe)
        case MagicBytes.flac: return flac(probe)
        case MagicBytes.ogg: return ogg(probe)
        default: return .none
        }
    }

    // MARK: - RIFF and ISO base media

    func riff(_ probe: FileProbe, name: String) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("\(name) declared length")
        guard let extent = ContainerStructure.riffExtent(head: probe.head) else {
            return output
        }
        let trailing = TrailingData.outcome(probe: probe, extent: extent)
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)
        return output
    }

    func isoMedia(_ probe: FileProbe, format: FileFormat) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("\(format.name) box chain and declared length")
        let walk = ContainerStructure.isoBoxes(head: probe.head, fileSize: probe.size)

        if let extent = ContainerStructure.isoExtent(head: probe.head, fileSize: probe.size) {
            let trailing = TrailingData.outcome(probe: probe, extent: extent)
            output.findings.append(contentsOf: trailing.findings)
            output.disclosures.append(contentsOf: trailing.disclosures)
        }

        // A box chain that neither reaches the end nor runs out of window has
        // a bad size field somewhere in it.
        if !walk.reachedEnd, let last = walk.boxes.last,
            last.offset + last.size < probe.size,
            Int(last.offset + last.size) < probe.head.count
        {
            output.findings.append(
                ContainerStructure.malformedChain(
                    format: "ISO base media",
                    detail:
                        "The box chain stops at byte \(last.offset + last.size) after "
                        + "`\(last.type)`, short of the \(probe.size)-byte file, and the next "
                        + "header there does not parse."))
        }

        return output
    }

    // MARK: - MP3

    /// An ID3v2 tag sits at the front and declares its own size as four
    /// "synchsafe" bytes — seven bits each, so a tag length can never contain
    /// a byte that looks like a frame sync.
    func mp3(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("ID3 tag size")
        guard MagicBytes.hasBytes(Array("ID3".utf8), at: 0, in: probe.head) else { return output }

        guard let size = synchsafe(probe.head, at: 6) else { return output }
        let tagEnd = Int64(size) + 10
        guard tagEnd < probe.size else {
            output.findings.append(
                Finding(
                    rule: "id3.oversizedTag",
                    severity: .caution,
                    title: "Tag is larger than the file",
                    detail:
                        "The ID3 header declares a \(tagEnd)-byte tag in a \(probe.size)-byte "
                        + "file. The header does not describe this file."))
            return output
        }

        // A tag that occupies most of the file is carrying something other
        // than song metadata.
        if tagEnd > probe.size / 2, tagEnd > 1 << 20 {
            output.findings.append(
                Finding(
                    rule: "id3.dominantTag",
                    severity: .caution,
                    title: "Metadata tag is most of the file",
                    detail:
                        "The ID3 tag is \(ByteCountFormatter.string(fromByteCount: tagEnd, countStyle: .file)) "
                        + "of a \(ByteCountFormatter.string(fromByteCount: probe.size, countStyle: .file)) "
                        + "file. Cover art explains some of this; not usually most of it."))
        }
        return output
    }

    /// Four bytes, seven bits each, big-endian.
    func synchsafe(_ data: Data, at offset: Int) -> UInt32? {
        var value: UInt32 = 0
        for index in 0..<4 {
            guard let byte = ByteReader.byte(data, at: offset + index), byte < 0x80 else {
                return nil
            }
            value = value << 7 | UInt32(byte)
        }
        return value
    }

    // MARK: - FLAC and Ogg

    /// FLAC metadata blocks run from byte 4: a flag byte whose top bit marks
    /// the last block, then a 24-bit big-endian length.
    func flac(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("FLAC metadata block chain")
        var cursor = 4
        var guard_ = 0
        while guard_ < 128 {
            guard_ += 1
            guard let flags = ByteReader.byte(probe.head, at: cursor),
                let high = ByteReader.byte(probe.head, at: cursor + 1),
                let mid = ByteReader.byte(probe.head, at: cursor + 2),
                let low = ByteReader.byte(probe.head, at: cursor + 3)
            else { return output }
            let length = Int(high) << 16 | Int(mid) << 8 | Int(low)
            let isLast = flags & 0x80 != 0
            cursor += 4 + length
            guard cursor > 0, Int64(cursor) <= probe.size else {
                output.findings.append(
                    ContainerStructure.malformedChain(
                        format: "FLAC",
                        detail:
                            "A metadata block declares a length that runs past the end of the "
                            + "file."))
                return output
            }
            if isLast { return output }
            if cursor >= probe.head.count { return output }
        }
        return output
    }

    /// Ogg is a chain of pages, each starting `OggS`. A complete file ends
    /// inside its last page, so the tail should contain one.
    func ogg(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("Ogg page chain")
        guard probe.size > Int64(FileProbe.windowSize) else { return output }
        if probe.offsets(of: Array("OggS".utf8)).filter({ $0 >= probe.tailOffset }).isEmpty {
            output.findings.append(
                Finding(
                    rule: "ogg.noTrailingPage",
                    severity: .caution,
                    title: "No Ogg page near the end of the file",
                    detail:
                        "An Ogg stream is a chain of pages running to the end. The last 64 KB "
                        + "contains none, so something follows the audio."))
        }
        return output
    }
}
