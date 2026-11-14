import Foundation

/// Structural reading of image containers.
///
/// Never decodes. ImageIO is the historical attack surface for malicious
/// images, so handing it a suspect file to "check" it would be the one thing
/// this feature exists to avoid. Everything here walks headers over bounded
/// reads.
///
/// Its main job is establishing where each format says it ends, which turns
/// the sampled guess in `UniversalChecks` into an exact answer: the generic
/// scan sees two 64 KB windows, a segment walk sees the declared end.
struct ImageInspector: FormatInspector {

    func handles(_ format: FileFormat) -> Bool {
        format.family == .image
    }

    func inspect(probe: FileProbe, format: FileFormat) -> InspectorOutput {
        var output = InspectorOutput()
        // Named only for the formats that have a walk: TIFF, BMP and the
        // rest are identified, and nothing more is claimed for them.
        var examined = true
        switch format {
        case MagicBytes.jpeg: output = jpeg(probe)
        case MagicBytes.png: output = png(probe)
        case MagicBytes.gif: output = gif(probe)
        case MagicBytes.webp: output = riff(probe, name: "WebP")
        case MagicBytes.heic, MagicBytes.avif: output = isoMedia(probe, name: format.name)
        case MagicBytes.svg: output = svg(probe)
        default: examined = false
        }
        if examined {
            output.checks.insert("\(format.name) structure and end marker", at: 0)
        }
        C2PAReader.append(to: &output, probe: probe, format: format)
        return output
    }

    // MARK: - JPEG

    /// A JPEG ends at its End Of Image marker, `FFD9`. Anything after it is
    /// not part of the image.
    ///
    /// The *last* `FFD9` is the real one: an EXIF thumbnail is itself a JPEG
    /// and carries its own, but it sits in an APP segment before the scan
    /// data. Within entropy-coded data a literal `FF` is stuffed as `FF00`, so
    /// a bare `FFD9` there would already be a malformed file.
    func jpeg(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        if let scan = probe.structure {
            return walked(
                probe, scan: scan, format: "JPEG",
                evidence: "JPEG image, which ends at its end-of-image marker",
                missing: Finding(
                    rule: "jpeg.noEndMarker",
                    severity: .caution,
                    title: "No end-of-image marker",
                    detail:
                        "Following the file's segments never reaches the FFD9 marker that "
                        + "ends a JPEG, so it is truncated or not really a JPEG."))
        }
        // No walk (a probe built from bytes alone): the last FFD9 in the two
        // windows is the best available answer, and a forgeable one.
        let eoiOffsets = probe.offsets(of: [0xFF, 0xD9])

        guard let end = eoiOffsets.last else {
            output.findings.append(
                Finding(
                    rule: "jpeg.noEndMarker",
                    severity: .caution,
                    title: "No end-of-image marker",
                    detail:
                        probe.isFullyWindowed
                        ? "The file never reaches the FFD9 marker that ends a JPEG, so it is "
                            + "truncated or not really a JPEG."
                        : "No FFD9 end marker in the last 64 KB, which a complete JPEG always "
                            + "has. Either the file is truncated, or enough data is "
                            + "appended after the image to push its end out of view."))
            return output
        }

        let extent = ContainerExtent(
            logicalEnd: end + 2, evidence: "JPEG image, which ends at its FFD9 marker")
        let trailing = TrailingData.outcome(probe: probe, extent: extent)
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)

        output.findings.append(contentsOf: jpegSegments(probe))
        return output
    }

    /// Walks the marker segments in the header, up to the start of scan data.
    ///
    /// Each segment is `FF`, a marker byte, then a two-byte big-endian length
    /// that includes itself. A length below two would not advance the cursor,
    /// which is the loop case.
    func jpegSegments(_ probe: FileProbe) -> [Finding] {
        var cursor = 2  // past SOI
        var guard_ = 0
        while guard_ < 256 {
            guard_ += 1
            // A marker and its length need four bytes. Fewer than that left in
            // the window means the chain ran past what was read, not that it
            // is broken.
            guard cursor + 4 <= probe.head.count else { return [] }
            guard let marker = ByteReader.byte(probe.head, at: cursor), marker == 0xFF,
                let kind = ByteReader.byte(probe.head, at: cursor + 1)
            else {
                return [
                    ContainerStructure.malformedChain(
                        format: "JPEG",
                        detail:
                            "Expected a marker at byte \(cursor) and found something else. The "
                            + "header segments do not form a valid chain.")
                ]
            }
            // Start of scan: entropy data follows, and the walk is done.
            if kind == 0xDA || kind == 0xD9 { return [] }
            // Standalone markers carry no length.
            if kind == 0x01 || (kind >= 0xD0 && kind <= 0xD7) {
                cursor += 2
                continue
            }
            guard let length = ByteReader.uint16BE(probe.head, at: cursor + 2), length >= 2
            else { return [] }
            cursor += 2 + Int(length)
        }
        return []
    }

    /// The outcome of a structure walk: trailing data measured from the end
    /// the chain reached, or the reason it never reached one.
    private func walked(
        _ probe: FileProbe, scan: StructureScan, format: String, evidence: String,
        missing: Finding
    ) -> InspectorOutput {
        var output = InspectorOutput()
        if let problem = scan.problem {
            output.findings.append(
                ContainerStructure.malformedChain(format: format, detail: problem))
        }
        guard let end = scan.logicalEnd else {
            if scan.problem == nil { output.findings.append(missing) }
            return output
        }
        let trailing = TrailingData.outcome(
            probe: probe, extent: ContainerExtent(logicalEnd: end, evidence: evidence))
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)
        return output
    }

    // MARK: - PNG

    /// A PNG ends with its `IEND` chunk: a zero length, the type, and a CRC —
    /// twelve bytes, always last.
    func png(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        if let scan = probe.structure {
            return walked(
                probe, scan: scan, format: "PNG",
                evidence: "PNG image, which ends at its IEND chunk",
                missing: Finding(
                    rule: "png.noEndChunk",
                    severity: .caution,
                    title: "No IEND chunk",
                    detail:
                        "Following the file's chunks never reaches the IEND chunk that ends "
                        + "a PNG, so it is truncated or not really a PNG."))
        }
        guard let iend = probe.offsets(of: Array("IEND".utf8)).last else {
            output.findings.append(
                Finding(
                    rule: "png.noEndChunk",
                    severity: .caution,
                    title: "No IEND chunk",
                    detail: "A complete PNG ends with an IEND chunk; this file has none."))
            return output
        }

        // IEND sits 4 bytes into its chunk and is followed by a 4-byte CRC.
        let extent = ContainerExtent(
            logicalEnd: iend + 8, evidence: "PNG image, which ends at its IEND chunk")
        let trailing = TrailingData.outcome(probe: probe, extent: extent)
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)

        output.findings.append(contentsOf: pngChunks(probe))
        return output
    }

    /// Walks the chunk chain in the header window. Each chunk is a 4-byte
    /// big-endian length, a 4-byte type, the data, and a 4-byte CRC.
    func pngChunks(_ probe: FileProbe) -> [Finding] {
        var cursor = 8  // past the signature
        var guard_ = 0
        var sawHeader = false
        while guard_ < 256 {
            guard_ += 1
            guard let length = ByteReader.uint32BE(probe.head, at: cursor),
                let type = ByteReader.fourCC(probe.head, at: cursor + 4)
            else { break }
            if type == "IHDR" { sawHeader = true }
            if type == "IEND" { break }
            // A chunk length beyond the file is a lie, and the arithmetic
            // that follows it is where a parser walks off the end.
            guard Int64(length) < probe.size else {
                return [
                    ContainerStructure.malformedChain(
                        format: "PNG",
                        detail:
                            "A `\(type)` chunk at byte \(cursor) declares \(length) bytes, more "
                            + "than the whole file holds.")
                ]
            }
            cursor += 12 + Int(length)
            if cursor >= probe.head.count { break }
        }

        guard sawHeader || cursor >= probe.head.count else {
            return [
                ContainerStructure.malformedChain(
                    format: "PNG", detail: "No IHDR header chunk, which every PNG must start with.")
            ]
        }
        return []
    }

    // MARK: - GIF, RIFF, ISO media

    func gif(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        // The trailer is a single 0x3B byte. One byte is too weak to search
        // for, so this only checks whether the file ends with one.
        guard let last = probe.tail.last else { return output }
        if last != 0x3B {
            output.findings.append(
                Finding(
                    rule: "gif.noTrailer",
                    severity: .caution,
                    title: "Does not end with a GIF trailer",
                    detail:
                        "A GIF ends with the byte 0x3B; this file ends with "
                        + "0x\(String(format: "%02X", last)). Either it is truncated or "
                        + "something was appended."))
        }
        return output
    }

    func riff(_ probe: FileProbe, name: String) -> InspectorOutput {
        var output = InspectorOutput()
        guard let extent = ContainerStructure.riffExtent(head: probe.head) else {
            output.findings.append(
                ContainerStructure.malformedChain(
                    format: name, detail: "The RIFF header does not declare a readable size."))
            return output
        }
        let trailing = TrailingData.outcome(probe: probe, extent: extent)
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)
        if extent.logicalEnd > probe.size {
            output.findings.append(
                Finding(
                    rule: "container.shortFile",
                    severity: .caution,
                    title: "File is shorter than its header declares",
                    detail:
                        "The header describes \(extent.logicalEnd) bytes but the file holds "
                        + "\(probe.size). It is truncated."))
        }
        return output
    }

    func isoMedia(_ probe: FileProbe, name: String) -> InspectorOutput {
        var output = InspectorOutput()
        guard let extent = ContainerStructure.isoExtent(probe: probe)
        else { return output }
        let trailing = TrailingData.outcome(probe: probe, extent: extent)
        output.findings.append(contentsOf: trailing.findings)
        output.disclosures.append(contentsOf: trailing.disclosures)
        return output
    }

    // MARK: - SVG

    /// SVG is the one image format that is also a document: it is XML, and a
    /// browser will run script inside it. An SVG carrying script is not
    /// malformed — it is a legal SVG doing the thing that makes SVG uploads
    /// dangerous — so this reports rather than judges.
    func svg(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        // Lossy: the needles are ASCII, and a window that ends mid-character
        // must not skip the check.
        let text = String(decoding: probe.head, as: UTF8.self).lowercased()

        var active: [String] = []
        if text.contains("<script") { active.append("a <script> element") }
        if text.contains("javascript:") { active.append("a javascript: URL") }
        if text.range(of: #"\son[a-z]+\s*="#, options: .regularExpression) != nil {
            active.append("an inline event handler")
        }
        if text.contains("<foreignobject") { active.append("a <foreignObject> element") }

        if !active.isEmpty {
            output.findings.append(
                Finding(
                    rule: "svg.activeContent",
                    severity: .caution,
                    title: "SVG contains active content",
                    detail:
                        "This image carries \(active.joined(separator: ", ")). SVG is XML, and a "
                        + "browser runs script inside it — an image viewer does not. Safe to "
                        + "look at locally; not safe to serve to other people."))
        }

        if text.contains("<!entity") {
            output.findings.append(
                Finding(
                    rule: "svg.externalEntity",
                    severity: .caution,
                    title: "SVG declares an XML entity",
                    detail:
                        "Entity declarations are how XML parsers are made to read other files "
                        + "off the machine that opens them."))
        }
        return output
    }
}
