import Foundation

/// PDFs and the ZIP-based Office and iWork documents.
///
/// Both formats can carry things that run when the document opens. Reporting
/// that is not a malware verdict — plenty of legitimate documents use macros
/// and embedded files — but it is the difference between a document and a
/// program, and the user is entitled to know which one they have.
struct DocumentInspector: FormatInspector {

    func handles(_ format: FileFormat) -> Bool {
        format == MagicBytes.pdf || format == MagicBytes.zip
    }

    func inspect(probe: FileProbe, format: FileFormat) -> InspectorOutput {
        switch format {
        case MagicBytes.pdf: return pdf(probe)
        case MagicBytes.zip: return zipContainer(probe)
        default: return .none
        }
    }

    // MARK: - PDF

    /// A PDF ends with `%%EOF`. Incremental updates append whole revisions,
    /// each with its own marker, so the *last* one is the end of the document.
    func pdf(_ probe: FileProbe) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("PDF end marker and revisions")
        output.disclosures.append(contentsOf: attachments(probe))
        output.checks.append(
            probe.isFullyWindowed
                ? "PDF active content (whole file)"
                : "PDF active content (first and last 64 KB)")

        let markers = probe.offsets(of: Array("%%EOF".utf8))
        if let last = markers.last {
            // Writers commonly leave a newline after the marker.
            let extent = ContainerExtent(
                logicalEnd: last + 5,
                evidence: "PDF document, which ends at its last %%EOF marker")
            let trailing = TrailingData.outcome(probe: probe, extent: extent)
            output.findings.append(contentsOf: trailing.findings)
            output.disclosures.append(contentsOf: trailing.disclosures)
            if markers.count > 1 {
                output.disclosures.append(
                    Disclosure(
                        title: "Revised document",
                        detail:
                            "\(markers.count) end-of-file markers, so this PDF was saved "
                            + "incrementally. Earlier revisions of the content may still be "
                            + "recoverable from the file."))
            }
        } else {
            output.findings.append(
                Finding(
                    rule: "pdf.noEndMarker",
                    severity: .caution,
                    title: "No %%EOF marker",
                    detail: "A complete PDF ends with %%EOF; this file has none."))
        }

        // Active content.
        //
        // Only tokens long enough to mean something are searched. `/AA` and
        // `/JS` were tried and removed: three characters match by accident
        // constantly — `/AA` was flagging every document whose font subset
        // was named `/AAAAAA+Montserrat`, and 26 of 60 real PDFs tripped this
        // rule, including resumes and tax returns.
        output.findings.append(contentsOf: activeContent(probe))
        return output
    }

    /// What a PDF carries that can *do* something, as opposed to render.
    ///
    /// `/OpenAction` is deliberately not a signal on its own. In almost every
    /// PDF it is a view destination — `/OpenAction[1 0 R /XYZ null null 0]`
    /// means "open at page one, this zoom" — and flagging it condemns most
    /// documents ever written. It only matters when there is code for it to
    /// run, so it is reported as an amplifier, never alone.
    func activeContent(_ probe: FileProbe) -> [Finding] {
        func has(_ token: String) -> Bool {
            !probe.offsets(of: Array(token.utf8)).isEmpty
        }
        let coverage =
            probe.isFullyWindowed ? "" : " Only the first and last 64 KB were searched."

        // Starts another program. Nothing legitimate in a document needs it.
        if has("/Launch") {
            return [
                Finding(
                    rule: "pdf.launchAction",
                    severity: .inconsistent,
                    title: "PDF can launch another program",
                    detail:
                        "This document contains a /Launch action, which asks the reader to "
                        + "start a separate program when the document is opened or clicked. A "
                        + "document that displays content has no reason to do that." + coverage)
            ]
        }

        if has("/JavaScript") {
            let onOpen = has("/OpenAction")
            return [
                Finding(
                    rule: "pdf.activeContent",
                    severity: .caution,
                    title: onOpen
                        ? "PDF runs JavaScript when it opens"
                        : "PDF contains JavaScript",
                    detail:
                        "This document carries JavaScript"
                        + (onOpen
                            ? ", and an /OpenAction that runs when you open it. "
                            : ". ")
                        + "Interactive forms use it for validation and calculations, so it is "
                        + "common in anything fillable; in a document that only displays text "
                        + "it is worth asking why." + coverage)
            ]
        }

        if has("/RichMedia") {
            return [
                Finding(
                    rule: "pdf.activeContent",
                    severity: .caution,
                    title: "PDF contains embedded rich media",
                    detail:
                        "An embedded media object that the reader plays. Rare in an ordinary "
                        + "document." + coverage)
            ]
        }
        return []
    }

    /// An attachment inside the PDF. Worth saying, but routine — PDF/A and
    /// emailed invoices carry them — so it is a disclosure, not a finding.
    func attachments(_ probe: FileProbe) -> [Disclosure] {
        guard !probe.offsets(of: Array("/EmbeddedFile".utf8)).isEmpty else { return [] }
        return [
            Disclosure(
                title: "Carries an attachment",
                detail:
                    "The document embeds at least one other file. Common in archival PDFs and "
                    + "invoices; the attachment is not inspected.")
        ]
    }

    // MARK: - ZIP-based documents

    /// `.docx`, `.xlsx`, `.pptx`, `.pages` and friends are ZIPs. The archive
    /// checks apply, plus what the entry names say about the document.
    func zipContainer(_ probe: FileProbe) -> InspectorOutput {
        let parsed = ArchiveInspector.readDirectory(probe: probe)
        var output = ArchiveInspector.inspect(probe: probe, directory: parsed)
        output.checks.append("Document type, macros and external references")
        guard let directory = parsed else { return output }
        let names = directory.entries.map { $0.name.lowercased() }

        let kind = documentKind(names)
        if let kind {
            output.disclosures.append(
                Disclosure(title: "Document type", detail: "Contents look like \(kind)."))
        }

        // A macro project is the classic document-borne execution path.
        let macros = names.filter {
            $0.hasSuffix("vbaproject.bin") || $0.hasSuffix(".bin") && $0.contains("vba")
        }
        if !macros.isEmpty {
            output.findings.append(
                Finding(
                    rule: "ooxml.macros",
                    severity: .caution,
                    title: "Document contains a macro project",
                    detail:
                        "A vbaProject.bin is present, so this document carries code. Office "
                        + "will ask before running it; the document is a program as well as a "
                        + "document."))
        }
        // External relationship targets are *not* checked: the `.rels` parts
        // that would carry `TargetMode="External"` are deflated inside the
        // archive, so a byte search can never see them, and a rule that can
        // never fire is a false promise in the Criteria tab.
        return output
    }

    func documentKind(_ names: [String]) -> String? {
        if names.contains(where: { $0.hasPrefix("word/") }) { return "a Word document" }
        if names.contains(where: { $0.hasPrefix("xl/") }) { return "an Excel workbook" }
        if names.contains(where: { $0.hasPrefix("ppt/") }) { return "a PowerPoint presentation" }
        if names.contains(where: { $0.hasSuffix(".iwa") }) { return "an iWork document" }
        if names.contains("mimetype") { return "an OpenDocument or EPUB file" }
        return nil
    }
}
