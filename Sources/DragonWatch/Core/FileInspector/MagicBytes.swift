import Foundation

/// Broad category, used to route a file to its structural inspector and to
/// group results in the UI.
enum FormatFamily: String, Codable, Sendable, CaseIterable {
    case image
    case audio
    case video
    case document
    case archive
    case executable
    case text
    case data
}

/// One recognised file format: what it is called, what it belongs to, and the
/// extensions that legitimately carry it.
struct FileFormat: Sendable, Hashable {
    let name: String
    let family: FormatFamily
    /// Lowercase, no dot. First entry is the canonical one.
    let extensions: [String]
}

/// A byte pattern that identifies a format.
///
/// `secondaryOffset`/`secondaryBytes` cover container formats where the first
/// four bytes are shared: RIFF is WebP, WAV *and* AVI, and ISO-BMFF is HEIC,
/// AVIF, MP4 and MOV — the brand that separates them sits further in.
struct FormatSignature: Sendable {
    let format: FileFormat
    let offset: Int
    let bytes: [UInt8]
    let secondaryOffset: Int?
    let secondaryBytes: [UInt8]?

    init(
        _ format: FileFormat, offset: Int = 0, _ bytes: [UInt8],
        secondaryOffset: Int? = nil, secondaryBytes: [UInt8]? = nil
    ) {
        self.format = format
        self.offset = offset
        self.bytes = bytes
        self.secondaryOffset = secondaryOffset
        self.secondaryBytes = secondaryBytes
    }

    /// Total bytes that had to match, so the most specific signature can win.
    var specificity: Int { bytes.count + (secondaryBytes?.count ?? 0) }
}

/// The signature table, and the only place that decides "what is this file,
/// really".
///
/// Everything here is a pure function over bytes already in memory — no file
/// access, no decoding, no third-party parser. That is the point: identifying
/// a hostile file must not involve handing it to the library that parses it.
enum MagicBytes {

    // MARK: - Formats

    static let jpeg = FileFormat(name: "JPEG", family: .image, extensions: ["jpg", "jpeg", "jpe"])
    static let png = FileFormat(name: "PNG", family: .image, extensions: ["png"])
    static let gif = FileFormat(name: "GIF", family: .image, extensions: ["gif"])
    static let webp = FileFormat(name: "WebP", family: .image, extensions: ["webp"])
    static let tiff = FileFormat(name: "TIFF", family: .image, extensions: ["tif", "tiff"])
    static let bmp = FileFormat(name: "BMP", family: .image, extensions: ["bmp"])
    static let ico = FileFormat(name: "Windows icon", family: .image, extensions: ["ico"])
    static let icns = FileFormat(name: "Apple icon image", family: .image, extensions: ["icns"])
    static let heic = FileFormat(name: "HEIF/HEIC", family: .image, extensions: ["heic", "heif"])
    static let avif = FileFormat(name: "AVIF", family: .image, extensions: ["avif"])
    static let psd = FileFormat(name: "Photoshop document", family: .image, extensions: ["psd"])

    static let mp4 = FileFormat(name: "MPEG-4", family: .video, extensions: ["mp4", "m4v"])
    static let mov = FileFormat(name: "QuickTime movie", family: .video, extensions: ["mov", "qt"])
    static let matroska = FileFormat(
        name: "Matroska / WebM", family: .video, extensions: ["mkv", "webm"])
    static let avi = FileFormat(name: "AVI", family: .video, extensions: ["avi"])

    static let mp3 = FileFormat(name: "MP3", family: .audio, extensions: ["mp3"])
    static let flac = FileFormat(name: "FLAC", family: .audio, extensions: ["flac"])
    static let wav = FileFormat(name: "WAV", family: .audio, extensions: ["wav", "wave"])
    static let ogg = FileFormat(name: "Ogg", family: .audio, extensions: ["ogg", "oga", "opus"])
    static let aiff = FileFormat(name: "AIFF", family: .audio, extensions: ["aiff", "aif"])
    static let m4a = FileFormat(name: "MPEG-4 audio", family: .audio, extensions: ["m4a"])
    static let caf = FileFormat(name: "Core Audio Format", family: .audio, extensions: ["caf"])

    static let pdf = FileFormat(name: "PDF", family: .document, extensions: ["pdf"])
    static let rtf = FileFormat(name: "RTF", family: .document, extensions: ["rtf"])
    /// OOXML and iWork are ZIP containers; only opening the central directory
    /// tells them apart, which is `DocumentInspector`'s job, not the table's.
    static let zip = FileFormat(
        name: "ZIP archive",
        family: .archive,
        extensions: [
            "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp",
            "pages", "numbers", "key", "epub", "jar", "ipa", "aar",
        ])
    static let gzip = FileFormat(name: "gzip", family: .archive, extensions: ["gz", "tgz"])
    static let bzip2 = FileFormat(name: "bzip2", family: .archive, extensions: ["bz2", "tbz"])
    static let xz = FileFormat(name: "xz", family: .archive, extensions: ["xz"])
    static let zstd = FileFormat(name: "Zstandard", family: .archive, extensions: ["zst"])
    static let sevenZip = FileFormat(name: "7-Zip", family: .archive, extensions: ["7z"])
    static let rar = FileFormat(name: "RAR", family: .archive, extensions: ["rar"])
    static let tar = FileFormat(name: "tar", family: .archive, extensions: ["tar"])
    static let dmg = FileFormat(name: "Apple disk image", family: .archive, extensions: ["dmg"])
    static let xar = FileFormat(name: "xar / pkg", family: .archive, extensions: ["pkg", "xar"])

    static let machO = FileFormat(
        name: "Mach-O executable", family: .executable, extensions: ["", "dylib", "bundle", "o"])
    static let machOFat = FileFormat(
        name: "Mach-O universal binary", family: .executable,
        extensions: ["", "dylib", "bundle", "o"])
    static let elf = FileFormat(
        name: "ELF executable", family: .executable, extensions: ["so", ""])
    static let pe = FileFormat(
        name: "Windows executable", family: .executable, extensions: ["exe", "dll", "sys"])
    static let javaClass = FileFormat(
        name: "Java class", family: .executable, extensions: ["class"])

    static let xml = FileFormat(name: "XML", family: .text, extensions: ["xml", "plist", "svg"])
    /// An SVG is XML, and an XML file may be an SVG: both extensions accept
    /// both formats, or every `.svg` on disk is a "mismatch".
    static let svg = FileFormat(name: "SVG", family: .image, extensions: ["svg", "xml"])
    static let bplist = FileFormat(
        name: "Binary property list", family: .data, extensions: ["plist"])
    static let sqlite = FileFormat(
        name: "SQLite database", family: .data, extensions: ["sqlite", "db", "sqlite3"])
    /// No extensions on purpose. Most scripts have no `#!` line — 117 of 120
    /// real `.py` files did not — so claiming the extension made every one of
    /// them "unconfirmed". `SourceInspector` handles source by extension.
    static let shebang = FileFormat(name: "Script (shebang)", family: .text, extensions: [])

    // MARK: - Table

    /// Order does not matter; `identify` picks the most specific match.
    static let signatures: [FormatSignature] = [
        .init(jpeg, [0xFF, 0xD8, 0xFF]),
        .init(png, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        .init(gif, ascii("GIF87a")),
        .init(gif, ascii("GIF89a")),
        .init(webp, ascii("RIFF"), secondaryOffset: 8, secondaryBytes: ascii("WEBP")),
        .init(wav, ascii("RIFF"), secondaryOffset: 8, secondaryBytes: ascii("WAVE")),
        .init(avi, ascii("RIFF"), secondaryOffset: 8, secondaryBytes: ascii("AVI ")),
        .init(tiff, [0x49, 0x49, 0x2A, 0x00]),
        .init(tiff, [0x4D, 0x4D, 0x00, 0x2A]),
        .init(bmp, ascii("BM")),
        .init(ico, [0x00, 0x00, 0x01, 0x00]),
        .init(icns, ascii("icns")),
        .init(psd, ascii("8BPS")),

        // ISO base media: the brand at offset 8 is what separates these.
        .init(heic, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("heic")),
        .init(heic, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("heix")),
        .init(heic, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("mif1")),
        .init(avif, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("avif")),
        .init(mp4, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("isom")),
        .init(mp4, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("mp42")),
        .init(mov, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("qt  ")),
        .init(m4a, offset: 4, ascii("ftyp"), secondaryOffset: 8, secondaryBytes: ascii("M4A ")),
        .init(matroska, [0x1A, 0x45, 0xDF, 0xA3]),

        .init(mp3, ascii("ID3")),
        .init(mp3, [0xFF, 0xFB]),
        .init(mp3, [0xFF, 0xF3]),
        .init(mp3, [0xFF, 0xF2]),
        .init(flac, ascii("fLaC")),
        .init(ogg, ascii("OggS")),
        .init(aiff, ascii("FORM"), secondaryOffset: 8, secondaryBytes: ascii("AIFF")),
        .init(caf, ascii("caff")),

        .init(pdf, ascii("%PDF-")),
        .init(rtf, ascii("{\\rtf")),

        .init(zip, [0x50, 0x4B, 0x03, 0x04]),
        .init(zip, [0x50, 0x4B, 0x05, 0x06]),
        .init(zip, [0x50, 0x4B, 0x07, 0x08]),
        .init(gzip, [0x1F, 0x8B]),
        .init(bzip2, ascii("BZh")),
        .init(xz, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
        .init(zstd, [0x28, 0xB5, 0x2F, 0xFD]),
        .init(sevenZip, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
        .init(rar, ascii("Rar!")),
        .init(tar, offset: 257, ascii("ustar")),
        .init(xar, ascii("xar!")),

        .init(machO, [0xCF, 0xFA, 0xED, 0xFE]),
        .init(machO, [0xCE, 0xFA, 0xED, 0xFE]),
        .init(machO, [0xFE, 0xED, 0xFA, 0xCF]),
        .init(machO, [0xFE, 0xED, 0xFA, 0xCE]),
        .init(elf, [0x7F, 0x45, 0x4C, 0x46]),
        .init(pe, ascii("MZ")),

        .init(bplist, ascii("bplist00")),
        .init(sqlite, ascii("SQLite format 3")),
        .init(xml, ascii("<?xml")),
        .init(svg, ascii("<svg")),
        .init(shebang, ascii("#!")),
    ]

    /// Signatures that live at the *end* of the file, matched against the
    /// tail window. A UDIF disk image's `koly` block is its last 512 bytes;
    /// its first bytes are whatever the compressed data happens to start with
    /// — a bzip2-compressed image begins `BZh` — so the trailer is checked
    /// first, before the head can be mistaken for something else.
    static let trailerSignatures: [(format: FileFormat, fromEnd: Int, bytes: [UInt8])] = [
        (dmg, 512, ascii("koly"))
    ]

    /// Formats reached only through disambiguation, never by a table entry,
    /// which the reverse lookup would otherwise miss: a universal `.dylib`
    /// is a `.dylib` all the same.
    static let disambiguatedFormats: [FileFormat] = [machOFat, javaClass]

    // MARK: - Identification

    /// Identifies `head` against the table, most specific match first.
    ///
    /// Returns `nil` for anything the table does not know — the unclassified
    /// case, which is reported rather than guessed at.
    /// Identifies a probe: trailer signatures first, then the head.
    static func identify(head: Data, tail: Data) -> FileFormat? {
        for signature in trailerSignatures
        where hasBytes(signature.bytes, at: tail.count - signature.fromEnd, in: tail) {
            return signature.format
        }
        return identify(head: head)
    }

    static func identify(head: Data) -> FileFormat? {
        if let ambiguous = disambiguateCafebabe(head: head) { return ambiguous }

        var best: FormatSignature?
        for signature in signatures where matches(signature, head: head) {
            if best == nil || signature.specificity > best!.specificity {
                best = signature
            }
        }
        if let format = best?.format, format == xml, looksLikeSVG(head: head) {
            return svg
        }
        return best?.format
    }

    static func matches(_ signature: FormatSignature, head: Data) -> Bool {
        guard hasBytes(signature.bytes, at: signature.offset, in: head) else { return false }
        guard let secondBytes = signature.secondaryBytes,
            let secondOffset = signature.secondaryOffset
        else { return true }
        return hasBytes(secondBytes, at: secondOffset, in: head)
    }

    /// Bounds-checked comparison against a `Data` that may be a slice.
    ///
    /// A `Data` slice carries a non-zero `startIndex`, so `data[0]` traps.
    /// Every offset here is relative to the start of the *file*, and resolved
    /// against `startIndex` rather than assumed to be zero.
    static func hasBytes(_ pattern: [UInt8], at offset: Int, in data: Data) -> Bool {
        guard !pattern.isEmpty, ByteReader.fits(pattern.count, at: offset, in: data)
        else { return false }
        let base = data.startIndex + offset
        for (index, byte) in pattern.enumerated() where data[base + index] != byte {
            return false
        }
        return true
    }

    /// `CAFEBABE` is both a Mach-O universal binary and a Java class file.
    ///
    /// The next four bytes settle it: in a fat Mach-O they are the architecture
    /// count (realistically 1–16); in a Java class they are the minor and major
    /// version, and the major has been ≥ 45 since Java 1.1. The ranges do not
    /// overlap, so this is exact for every real file — but it is a heuristic,
    /// and a crafted file can sit in the gap. `ExecutableInspector` re-checks
    /// by parsing the arch table.
    static func disambiguateCafebabe(head: Data) -> FileFormat? {
        guard hasBytes([0xCA, 0xFE, 0xBA, 0xBE], at: 0, in: head), head.count >= 8 else {
            return nil
        }
        let base = head.startIndex
        let next =
            (UInt32(head[base + 4]) << 24) | (UInt32(head[base + 5]) << 16)
            | (UInt32(head[base + 6]) << 8) | UInt32(head[base + 7])
        return next <= 16 ? machOFat : javaClass
    }

    /// An SVG is XML, so the XML signature matches first. Look a little
    /// further for the root element before calling it one.
    private static func looksLikeSVG(head: Data) -> Bool {
        guard let text = String(data: head.prefix(4096), encoding: .utf8) else { return false }
        return text.contains("<svg")
    }

    // MARK: - Reverse lookup

    /// Formats that legitimately carry `ext` (lowercase, no dot).
    ///
    /// Used to answer "this says .png — could these bytes be a PNG?" without
    /// assuming a one-to-one mapping. `.svg` is both XML and SVG; `.docx` is a
    /// ZIP; a bare extensionless file may be anything.
    static func formats(forExtension ext: String) -> [FileFormat] {
        guard !ext.isEmpty else { return [] }
        let lowered = ext.lowercased()
        var seen: [FileFormat] = []
        let known =
            signatures.map(\.format) + trailerSignatures.map(\.format) + disambiguatedFormats
        for format in known where format.extensions.contains(lowered) && !seen.contains(format) {
            seen.append(format)
        }
        // Stable order: the table is a literal, but callers render this.
        return seen.sorted { $0.name < $1.name }
    }

    /// Extensions that macOS or a user would reasonably treat as runnable.
    /// Used by the double-extension rule, not for identification.
    static let executableExtensions: Set<String> = [
        "app", "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "msi", "jar", "sh", "bash", "zsh", "command", "tool", "workflow",
        "scpt", "scptd", "osascript", "pkg", "mpkg", "dmg", "action", "prefpane", "kext",
        "term", "url", "webloc", "shortcut", "applescript", "ipa", "apk",
    ]

    private static func ascii(_ text: String) -> [UInt8] { Array(text.utf8) }
}
