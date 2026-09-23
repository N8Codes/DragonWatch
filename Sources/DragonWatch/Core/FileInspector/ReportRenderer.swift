import AppKit
import CoreText
import Foundation

/// Renders an `InspectionReport` in the four formats the export offers.
///
/// Every renderer is a pure function of the report, and every one of them
/// starts from `sortedFiles` — results are assembled concurrently, so without
/// that total ordering two exports of the same run would differ.
enum ReportRenderer {

    enum Format: String, CaseIterable, Sendable {
        case markdown
        case json
        case pdf
        case plainText

        var label: String {
            switch self {
            case .markdown: "Markdown"
            case .json: "JSON"
            case .pdf: "PDF"
            case .plainText: "Plain Text"
            }
        }

        var fileExtension: String {
            switch self {
            case .markdown: "md"
            case .json: "json"
            case .pdf: "pdf"
            case .plainText: "txt"
            }
        }
    }

    static func render(_ report: InspectionReport, as format: Format) -> Data? {
        switch format {
        case .markdown: Data(markdown(report).utf8)
        case .json: json(report)
        case .plainText: Data(plainText(report).utf8)
        case .pdf: pdf(report)
        }
    }

    static func suggestedFilename(for report: InspectionReport, format: Format) -> String {
        let stamp = ISO8601DateFormatter.filenameStamp.string(from: report.generated)
        return "dragonwatch-inspection-\(stamp).\(format.fileExtension)"
    }

    // MARK: - Markdown

    /// Untrusted text is escaped here, not at construction.
    ///
    /// `UniversalChecks.displaySafe` already stripped control characters and
    /// bounded the length, but Markdown metacharacters are format-specific: a
    /// filename containing a pipe silently breaks a table, and one containing
    /// backticks or brackets changes how the rest of the line renders. Escaping
    /// belongs to whichever renderer is writing.
    static func markdownEscaped(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count + 8)
        for character in text {
            switch character {
            case "\\", "`", "*", "_", "[", "]", "<", ">", "|", "#":
                out.append("\\")
                out.append(character)
            case "\n", "\r":
                out.append(" ")
            default:
                out.append(character)
            }
        }
        return out
    }

    /// Wraps text in a code span, which is how paths should read.
    ///
    /// Markdown does **not** process escapes inside a code span, so running
    /// `markdownEscaped` first renders the backslashes literally — a path with
    /// underscores came out as `quarterly\_report\_final.jpeg`. Only a
    /// pipe needs escaping here, because a table cell is split before inline
    /// parsing runs. A backtick would end the span early, and rather than
    /// juggle fence lengths that case falls back to escaped plain text.
    static func markdownCode(_ text: String) -> String {
        let text = UniversalChecks.lineSafe(text)
        guard !text.contains("`") else { return markdownEscaped(text) }
        return "`" + text.replacingOccurrences(of: "|", with: "\\|") + "`"
    }

    static func markdown(_ report: InspectionReport) -> String {
        var lines: [String] = []
        lines.append("# DragonWatch file inspection")
        lines.append("")
        lines.append("> \(report.disclaimerLine)")
        lines.append("")
        lines.append("- **Run:** \(ISO8601DateFormatter.readable.string(from: report.generated))")
        lines.append("- **Verdict:** \(report.worstVerdict.label) — \(report.worstVerdict.summary)")
        lines.append("- **Items:** \(report.files.count)")
        lines.append("- **Findings:** \(report.findingCount)")
        lines.append("- **Disclosures:** \(report.disclosureCount)")
        if let folders = report.folderCount, folders > 0 {
            lines.append("- **Folders searched:** \(folders)")
        }
        if let seconds = report.durationSeconds {
            lines.append("- **Took:** \(durationText(seconds))")
        }
        if let limit = report.limitHit {
            lines.append("- **Incomplete:** \(limit.explanation)")
        }
        lines.append("")
        lines.append("Selected:")
        for root in report.roots {
            lines.append("- \(markdownCode(root))")
        }
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append("| Verdict | Items |")
        lines.append("| --- | ---: |")
        for verdict in [
            InspectionVerdict.inconsistent, .caution, .unreadable, .consistent,
        ] where report.count(of: verdict) > 0 {
            lines.append("| \(verdict.label) | \(report.count(of: verdict)) |")
        }
        lines.append("")

        lines.append("## Items")
        for file in report.sortedFiles {
            lines.append("")
            lines.append(
                "### \(markdownEscaped(UniversalChecks.lineSafe(file.displayName))) — "
                    + file.verdict.label)
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("| --- | --- |")
            lines.append("| Path | \(markdownCode(file.path)) |")
            lines.append("| Format | \(markdownEscaped(file.identifiedFormat ?? "unidentified")) |")
            lines.append("| Size | \(byteText(file.byteSize)) |")
            if let digest = file.sha256 {
                lines.append("| SHA-256 | `\(digest)` |")
            }
            if !file.findings.isEmpty {
                lines.append("")
                lines.append("**Findings**")
                lines.append("")
                for finding in file.findings {
                    lines.append(
                        "- **\(markdownEscaped(finding.title))** "
                            + "(`\(finding.rule)`, \(severityWord(finding.severity)))  ")
                    lines.append("  \(markdownEscaped(finding.detail))")
                }
            }
            if let checks = file.checksRun, !checks.isEmpty {
                lines.append("")
                lines.append("**Examined**")
                lines.append("")
                for check in checks { lines.append("- \(markdownEscaped(check))") }
            }
            if !file.disclosures.isEmpty {
                lines.append("")
                lines.append("**Disclosures**")
                lines.append("")
                for disclosure in file.disclosures {
                    // A URL goes in a code span: escaping its underscores for
                    // emphasis left `\_` inside the link in the raw file.
                    let detail =
                        disclosure.detail.hasPrefix("http")
                        ? markdownCode(disclosure.detail)
                        : markdownEscaped(disclosure.detail)
                    lines.append("- **\(markdownEscaped(disclosure.title))** — \(detail)")
                }
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    // MARK: - JSON

    /// Reads back JSON written by `json(_:)`.
    ///
    /// The exported dates are ISO-8601, which a default `JSONDecoder` cannot
    /// read — it expects a `Double`. Exposing the matching decoder keeps the
    /// export round-trippable instead of write-only, which is the point of
    /// offering JSON at all.
    static var jsonDecoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// Sorted keys and a fixed date strategy, so the same run exports
    /// byte-identical JSON every time.
    static func json(_ report: InspectionReport) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        // Encode the sorted view, not the assembly order.
        var ordered = report
        ordered.files = report.sortedFiles
        return try? encoder.encode(ordered)
    }

    // MARK: - Plain text

    static func plainText(_ report: InspectionReport) -> String {
        var lines: [String] = []
        lines.append("DRAGONWATCH FILE INSPECTION")
        lines.append(String(repeating: "=", count: 60))
        lines.append(report.disclaimerLine)
        lines.append("")
        lines.append("Run:         \(ISO8601DateFormatter.readable.string(from: report.generated))")
        lines.append("Verdict:     \(report.worstVerdict.label)")
        lines.append("Items:       \(report.files.count)")
        lines.append("Findings:    \(report.findingCount)")
        lines.append("Disclosures: \(report.disclosureCount)")
        if let folders = report.folderCount, folders > 0 {
            lines.append("Folders:     \(folders) searched")
        }
        if let seconds = report.durationSeconds {
            lines.append("Took:        \(durationText(seconds))")
        }
        if let limit = report.limitHit { lines.append("Incomplete:  \(limit.explanation)") }
        lines.append("")
        // Names and paths are attacker-chosen text in a line-oriented format:
        // a newline in a filename forged whole entries.
        for root in report.roots {
            lines.append("Selected:    \(UniversalChecks.lineSafe(root))")
        }
        lines.append("")

        for file in report.sortedFiles {
            lines.append(String(repeating: "-", count: 60))
            lines.append(
                "\(file.verdict.label.uppercased())  \(UniversalChecks.lineSafe(file.displayName))")
            lines.append("  path:   \(UniversalChecks.lineSafe(file.path))")
            lines.append("  format: \(file.identifiedFormat ?? "unidentified")")
            lines.append("  size:   \(byteText(file.byteSize))")
            if let digest = file.sha256 { lines.append("  sha256: \(digest)") }
            for finding in file.findings {
                lines.append("  [\(severityWord(finding.severity))] \(finding.title)")
                for wrapped in wrap(finding.detail, width: 70) {
                    lines.append("      \(wrapped)")
                }
            }
            for check in file.checksRun ?? [] {
                lines.append("  examined: \(check)")
            }
            for disclosure in file.disclosures {
                lines.append("  (i) \(disclosure.title)")
                for wrapped in wrap(disclosure.detail, width: 70) {
                    lines.append("      \(wrapped)")
                }
            }
        }
        lines.append(String(repeating: "-", count: 60))
        lines.append("")
        return lines.joined(separator: "\n")
    }

    // MARK: - PDF

    /// Paginated with CoreText into a `CGPDFContext`. No new dependency: the
    /// plain-text rendering is laid out into US Letter pages, which keeps the
    /// PDF and the text export saying exactly the same thing.
    static func pdf(_ report: InspectionReport) -> Data? {
        let page = CGRect(x: 0, y: 0, width: 612, height: 792)  // US Letter, 72 dpi
        let margin: CGFloat = 48
        let textBox = page.insetBy(dx: margin, dy: margin)

        let body = plainText(report)
        let attributed = NSAttributedString(
            string: body,
            attributes: [
                .font: NSFont.monospacedSystemFont(ofSize: 8.5, weight: .regular),
                .foregroundColor: NSColor.black,
            ])

        let data = NSMutableData()
        guard let consumer = CGDataConsumer(data: data as CFMutableData) else { return nil }
        var mediaBox = page
        guard let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            return nil
        }

        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        let path = CGPath(rect: textBox, transform: nil)
        var start = 0
        let total = attributed.length
        var pages = 0

        // A frame that consumes no characters would loop forever; the page cap
        // is the second guard in case a glyph will not fit the column at all.
        while start < total, pages < 500 {
            context.beginPDFPage(nil)
            let frame = CTFramesetterCreateFrame(
                framesetter, CFRange(location: start, length: 0), path, nil)
            CTFrameDraw(frame, context)
            let consumed = CTFrameGetVisibleStringRange(frame).length
            context.endPDFPage()
            pages += 1
            guard consumed > 0 else { break }
            start += consumed
        }
        context.closePDF()
        return data as Data
    }

    // MARK: - Shared

    /// "0.0s" for a 39 ms run read as a bug; anything under a tenth says so.
    static func durationText(_ seconds: Double) -> String {
        seconds < 0.05 ? "under 0.1s" : String(format: "%.1fs", seconds)
    }

    static func severityWord(_ severity: FindingSeverity) -> String {
        switch severity {
        case .info: "info"
        case .caution: "caution"
        case .inconsistent: "inconsistent"
        }
    }

    static func byteText(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    /// Word wrap for the fixed-width renderings. A word longer than the column
    /// is emitted on its own line rather than dropped or split.
    static func wrap(_ text: String, width: Int) -> [String] {
        var lines: [String] = []
        var current = ""
        for word in text.split(separator: " ", omittingEmptySubsequences: true) {
            if current.isEmpty {
                current = String(word)
            } else if current.count + 1 + word.count <= width {
                current += " " + word
            } else {
                lines.append(current)
                current = String(word)
            }
        }
        if !current.isEmpty { lines.append(current) }
        return lines
    }
}

extension InspectionReport {
    /// The disclaimer as one line, for renderings where a paragraph break
    /// would separate it from the results it qualifies.
    var disclaimerLine: String {
        Self.disclaimer.replacingOccurrences(of: "\n", with: " ")
    }
}

extension ISO8601DateFormatter {
    static let readable: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate, .withTime, .withColonSeparatorInTime]
        return formatter
    }()

    /// Colons are legal in a macOS filename but display as `/` in Finder.
    static let filenameStamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withYear, .withMonth, .withDay, .withTime]
        return formatter
    }()
}
