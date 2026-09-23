import Foundation

/// Identifies what the bytes after a container's logical end actually are.
///
/// Data past the end is the feature's highest-value signal, but phone cameras
/// routinely append their own trailers — flagging every Samsung photo as
/// carrying a hidden payload is the false positive that gets a tool ignored.
/// A recognised trailer is disclosed by name; only unexplained bytes are a
/// finding. Either way the bytes and their size are reported.
enum TrailingData {

    enum Kind: Sendable, Equatable {
        /// Samsung Extended Format, appended by Samsung camera software.
        case samsungSEF
        /// A whole second image, as in a multi-picture (MPO) file.
        case secondImage
        /// An appended video, as in an Android or Samsung motion photo.
        case motionPhoto
        /// Only filler bytes.
        case padding
        case unknown

        var name: String? {
            switch self {
            case .samsungSEF: "a Samsung camera trailer (SEF)"
            case .secondImage: "a second embedded image (multi-picture format)"
            case .motionPhoto: "an appended video (motion photo)"
            case .padding: "padding"
            case .unknown: nil
            }
        }
    }

    /// Classifies the bytes between `logicalEnd` and the end of the file.
    ///
    /// The trailer's first bytes come from whichever window holds them: a
    /// trailer shorter than the tail window is read from the tail, a longer
    /// one — a motion photo's video runs to megabytes — from the head, where
    /// it begins. One that begins in the unread gap between the windows was
    /// never seen, and stays a finding.
    static func classify(probe: FileProbe, logicalEnd: Int64) -> Kind {
        guard logicalEnd >= 0, logicalEnd < probe.size else { return .unknown }
        let wholeTrailerInView = logicalEnd >= probe.tailOffset
        let bytes: Data
        if wholeTrailerInView {
            let start = Int(logicalEnd - probe.tailOffset)
            guard start < probe.tail.count else { return .unknown }
            bytes = Data(probe.tail[(probe.tail.startIndex + start)...])
        } else if logicalEnd < Int64(probe.head.count) {
            bytes = Data(probe.head[(probe.head.startIndex + Int(logicalEnd))...])
        } else {
            return .unknown
        }
        guard !bytes.isEmpty else { return .unknown }

        // Samsung writes a fixed "SEFT" footer as the very last four bytes of
        // the file, which the tail window always holds.
        if probe.tail.count >= 4, Array(probe.tail.suffix(4)) == Array("SEFT".utf8) {
            return .samsungSEF
        }
        // A second SOI immediately after the first image is a multi-picture
        // file; cameras use it for depth maps and paired exposures.
        if MagicBytes.hasBytes([0xFF, 0xD8, 0xFF], at: 0, in: bytes) {
            return .secondImage
        }
        // Motion photos append an ISO base media stream.
        let head = Data(bytes.prefix(64))
        if !FileProbe.search(Array("ftyp".utf8), in: head).isEmpty
            || !FileProbe.search(Array("mpvd".utf8), in: head).isEmpty
        {
            return .motionPhoto
        }
        // Filler only — a claim about every byte, so only when every byte
        // was read.
        if wholeTrailerInView,
            bytes.allSatisfy({ $0 == 0x00 || $0 == 0x20 || $0 == 0xFF || $0 == 0x0A })
        {
            return .padding
        }
        return .unknown
    }

    /// The finding or disclosure for data past the end. A few slack bytes are
    /// ignored: encoders pad to even boundaries, and a rule that fires on
    /// every third photo gets turned off.
    static func outcome(
        probe: FileProbe, extent: ContainerExtent, slack: Int64 = 2
    ) -> InspectorOutput {
        var output = InspectorOutput()
        let extra = extent.trailingBytes(fileSize: probe.size)
        guard extra > slack else { return output }

        let kind = classify(probe: probe, logicalEnd: extent.logicalEnd)
        if let name = kind.name {
            output.disclosures.append(
                Disclosure(
                    title: "Data after the image",
                    detail:
                        "\(extra) bytes follow the end of the \(extent.evidence), and they look "
                        + "like \(name). Recognising it says what it is, not that it is "
                        + "harmless — the bytes are still there."))
            return output
        }

        output.findings.append(
            Finding(
                rule: "container.trailingData",
                severity: .caution,
                title: "Unexplained data after the end of the file",
                detail:
                    "\(extra) bytes follow the end of the \(extent.evidence), and they match no "
                    + "trailer DragonWatch recognises. This is how a second file is carried "
                    + "inside an innocuous-looking one."))
        return output
    }
}
