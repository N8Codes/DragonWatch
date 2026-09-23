import Foundation

/// Text and source files.
///
/// "Is this code malicious?" is not a question a parser answers, and this does
/// not try. What it reports is narrower and checkable: text that does not read
/// the way it renders, and shapes that mean something was deliberately made
/// hard to read. Everything here is an observation the user can confirm by
/// opening the file.
enum SourceInspector {

    /// Extensions worth treating as source even when the bytes carry no
    /// signature — which is most of them, since a `.py` or `.js` file is just
    /// text.
    static let sourceExtensions: Set<String> = [
        "swift", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rb", "pl", "php",
        "sh", "bash", "zsh", "fish", "c", "h", "cpp", "hpp", "cc", "m", "mm",
        "java", "kt", "kts", "go", "rs", "cs", "scala", "lua", "r", "sql",
        "ps1", "psm1", "bat", "cmd", "vbs", "applescript", "scpt",
        "html", "htm", "css", "json", "yaml", "yml", "toml", "xml", "md", "txt",
    ]

    static func appliesTo(probe: FileProbe, format: FileFormat?) -> Bool {
        guard probe.isReadable, probe.size > 0 else { return false }
        if let format, format.family == .text { return true }
        if format == nil, sourceExtensions.contains(probe.declaredExtension) { return true }
        return false
    }

    static func inspect(probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("Text encoding, hidden characters and obfuscation")
        guard let text = String(data: probe.head.prefix(1 << 18), encoding: .utf8) else {
            // Something with a source extension that is not UTF-8 text is
            // worth saying, since every check below assumes it is.
            output.findings.append(
                Finding(
                    rule: "source.notText",
                    severity: .caution,
                    title: "Not readable as text",
                    detail:
                        "The extension says source or text, but the contents are not valid "
                        + "UTF-8."))
            return output
        }

        output.findings.append(contentsOf: bidirectionalText(text))
        output.findings.append(contentsOf: obfuscationShapes(text, probe: probe))
        output.disclosures.append(contentsOf: interpreter(text))
        return output
    }

    // MARK: - Text that does not read the way it renders

    /// Trojan Source (CVE-2021-42574): direction-override characters reorder
    /// how a line *displays* without changing what the compiler reads, so a
    /// reviewer and the toolchain see different programs. There is no
    /// legitimate use of these in code.
    ///
    /// Only the direction controls count here. Zero-width joiners and BOMs
    /// are in the filename rule's set because a filename has no business
    /// carrying them, but in file *contents* they are ordinary: every emoji
    /// sequence, Indic and Arabic text, and any file saved by Windows carries
    /// them, and rating those Inconsistent flagged real localisation files.
    static func bidirectionalText(_ text: String) -> [Finding] {
        var findings: [Finding] = []

        // Every character of interest is at or above U+202A, and source is
        // overwhelmingly ASCII, so the cheap comparison skips the set lookup
        // for almost every scalar.
        let overrides = text.unicodeScalars.filter {
            $0.value >= 0x202A && UniversalChecks.directionControls.contains($0)
        }
        if !overrides.isEmpty {
            let codes = Set(overrides.map { String(format: "U+%04X", $0.value) })
                .sorted()
                .prefix(6)
                .joined(separator: ", ")
            findings.append(
                Finding(
                    rule: "source.bidiText",
                    severity: .inconsistent,
                    title: "Source contains direction-override characters",
                    detail:
                        "\(overrides.count) invisible control character"
                        + "\(overrides.count == 1 ? "" : "s") (\(codes)). These change how the "
                        + "text displays without changing what a compiler reads, so the code "
                        + "you review is not the code that runs. Known as Trojan Source."))
        }
        return findings
    }

    // MARK: - Shapes that mean "made hard to read"

    static func obfuscationShapes(_ text: String, probe: FileProbe) -> [Finding] {
        var findings: [Finding] = []

        // Scanned over UTF-8 rather than `Character`s. Iterating a Swift
        // String by Character does grapheme-cluster breaking for every byte:
        // measured at 178 ms for a 256 KB source file, which put a repository
        // of 10,000 files at ~30 minutes and past the run's time cap. The
        // byte scan is the same answer without the Unicode segmentation.
        var longestLine = 0
        var lineLength = 0
        var longestEncoded = 0
        var encodedRun = 0
        for byte in text.utf8 {
            if byte == 0x0A {
                if lineLength > longestLine { longestLine = lineLength }
                lineLength = 0
            } else {
                lineLength += 1
            }
            if isBase64Byte(byte) {
                encodedRun += 1
                if encodedRun > longestEncoded { longestEncoded = encodedRun }
            } else {
                encodedRun = 0
            }
        }
        if lineLength > longestLine { longestLine = lineLength }

        // One enormous line is minification, packing, or a pasted blob.
        // Bundled assets are exempt, because minification there is normal.
        if longestLine > 5000,
            !["js", "mjs", "cjs", "css", "json", "map"].contains(probe.declaredExtension)
        {
            findings.append(
                Finding(
                    rule: "source.veryLongLine",
                    severity: .caution,
                    title: "Contains a \(longestLine)-character line",
                    detail:
                        "A single line that long is packed or generated rather than written. "
                        + "Worth seeing what is in it."))
        }

        // A long unbroken run of base64 alphabet is an encoded payload. The
        // threshold is well above what a key, hash or data URI needs.
        if longestEncoded >= 2000 {
            findings.append(
                Finding(
                    rule: "source.encodedBlob",
                    severity: .caution,
                    title: "Contains a \(longestEncoded)-character encoded run",
                    detail:
                        "An unbroken base64-style run that long is carrying data, not "
                        + "configuration."))
        }

        // Decoding a string and then executing it is the shape that matters —
        // either half alone is ordinary.
        let decodeThenRun = [
            "eval(atob", "eval(base64", "eval(decode", "exec(base64", "exec(b64decode",
            "iex(", "invoke-expression", "eval(string.fromcharcode",
        ]
        // `String.contains` performs Unicode canonical-equivalence matching:
        // measured at 115 ms of this function's 140 ms for a 256 KB file, nine
        // needles over one string. The needles are pure ASCII, so folding the
        // text to lowercase bytes once and scanning those answers the same
        // question without the Unicode machinery.
        let folded: [UInt8] = text.utf8.map { $0 >= 0x41 && $0 <= 0x5A ? $0 &+ 32 : $0 }
        let hits = decodeThenRun.filter { contains(folded, Array($0.utf8)) }
        if !hits.isEmpty {
            findings.append(
                Finding(
                    rule: "source.decodeAndExecute",
                    severity: .caution,
                    title: "Decodes a string and runs it",
                    detail:
                        "Found \(hits.map { "`\($0)`" }.joined(separator: ", ")). Code that "
                        + "builds itself at runtime cannot be read by looking at it, which is "
                        + "the point of writing it that way."))
        }
        return findings
    }

    /// Naive substring search over bytes. Both sides are already
    /// lowercase ASCII, and the first-byte check makes the inner loop rare.
    static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        let first = needle[0]
        let last = haystack.count - needle.count
        var index = 0
        while index <= last {
            if haystack[index] == first {
                var matched = true
                for offset in 1..<needle.count where haystack[index + offset] != needle[offset] {
                    matched = false
                    break
                }
                if matched { return true }
            }
            index += 1
        }
        return false
    }

    /// Base64 alphabet, as raw bytes: A–Z, a–z, 0–9, `+`, `/`, `=`.
    static func isBase64Byte(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            || (byte >= 0x30 && byte <= 0x39) || byte == 0x2B || byte == 0x2F || byte == 0x3D
    }

    // MARK: - Disclosures

    /// A shebang says what will run the file if it is executed.
    static func interpreter(_ text: String) -> [Disclosure] {
        guard text.hasPrefix("#!") else { return [] }
        let line = text.prefix(while: { $0 != "\n" })
        return [
            Disclosure(
                title: "Runs with",
                detail: UniversalChecks.displaySafe(String(line.dropFirst(2)), limit: 120))
        ]
    }
}
