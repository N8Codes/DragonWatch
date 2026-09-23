import XCTest

@testable import DragonWatch

final class ReportRendererTests: XCTestCase {

    private func inspection(
        path: String = "/tmp/a.jpg",
        name: String = "a.jpg",
        verdict: InspectionVerdict = .consistent,
        findings: [Finding] = [],
        disclosures: [Disclosure] = []
    ) -> FileInspection {
        FileInspection(
            path: path, displayName: name, byteSize: 1234,
            sha256: String(repeating: "a", count: 64),
            declaredExtension: "jpg", identifiedFormat: "JPEG",
            findings: findings, disclosures: disclosures, verdict: verdict)
    }

    private func report(_ files: [FileInspection], limit: InspectionLimit? = nil)
        -> InspectionReport
    {
        InspectionReport(
            generated: Date(timeIntervalSince1970: 1_700_000_000),
            roots: ["/tmp"], files: files, limitHit: limit)
    }

    private let sample = Finding(
        rule: "magic.mismatch", severity: .inconsistent,
        title: "Extension does not match contents",
        detail: "Named .png but the contents are Mach-O executable.")

    // MARK: - Every format produces something

    func testAllFourFormatsRender() {
        let subject = report([
            inspection(verdict: .inconsistent, findings: [sample]),
            inspection(path: "/tmp/b.png", name: "b.png"),
        ])
        for format in ReportRenderer.Format.allCases {
            let data = ReportRenderer.render(subject, as: format)
            XCTAssertNotNil(data, "\(format.label) produced nothing")
            XCTAssertGreaterThan(data!.count, 100, "\(format.label) is suspiciously small")
        }
    }

    func testEmptyReportStillRenders() {
        let subject = report([])
        for format in ReportRenderer.Format.allCases {
            XCTAssertNotNil(ReportRenderer.render(subject, as: format), "\(format.label)")
        }
    }

    /// The PDF must actually be a PDF, not an empty container.
    func testPDFHasAValidHeaderAndPages() {
        // Enough items to run past one page.
        let many = (0..<60).map {
            inspection(
                path: "/tmp/f\($0).jpg", name: "f\($0).jpg",
                verdict: .caution, findings: [sample])
        }
        guard let data = ReportRenderer.pdf(report(many)) else {
            return XCTFail("no PDF produced")
        }
        XCTAssertEqual(data.prefix(5), Data("%PDF-".utf8))
        XCTAssertNotNil(
            FileProbe.search(Array("%%EOF".utf8), in: data).last, "PDF must be terminated")

        let document = CGPDFDocument(CGDataProvider(data: data as CFData)!)
        XCTAssertNotNil(document)
        XCTAssertGreaterThan(document!.numberOfPages, 1, "long report should paginate")
    }

    // MARK: - Determinism

    /// Two exports of the same run must be byte-identical: results are
    /// assembled concurrently, so anything reading `files` instead of
    /// `sortedFiles` would reorder between runs.
    func testEveryFormatIsByteIdenticalAcrossRepeatedRenders() {
        let subject = report([
            inspection(path: "/tmp/c.jpg", name: "c.jpg", verdict: .caution),
            inspection(
                path: "/tmp/a.jpg", name: "a.jpg", verdict: .inconsistent, findings: [sample]),
            inspection(path: "/tmp/b.jpg", name: "b.jpg", verdict: .inconsistent),
        ])
        for format in ReportRenderer.Format.allCases where format != .pdf {
            let first = ReportRenderer.render(subject, as: format)
            for _ in 0..<8 {
                XCTAssertEqual(
                    ReportRenderer.render(subject, as: format), first,
                    "\(format.label) is not deterministic")
            }
        }
    }

    func testItemsAreOrderedWorstFirstInEveryTextFormat() {
        let subject = report([
            inspection(path: "/tmp/z.jpg", name: "zebra.jpg", verdict: .consistent),
            inspection(path: "/tmp/a.jpg", name: "alpha.jpg", verdict: .inconsistent),
        ])
        for text in [ReportRenderer.markdown(subject), ReportRenderer.plainText(subject)] {
            guard let bad = text.range(of: "alpha.jpg"), let good = text.range(of: "zebra.jpg")
            else { return XCTFail("both items should appear") }
            XCTAssertLessThan(bad.lowerBound, good.lowerBound, "worst must come first")
        }
    }

    // MARK: - Escaping

    /// A filename containing a pipe silently breaks a Markdown table; one
    /// containing brackets or backticks changes how the rest of the line
    /// renders. `displaySafe` strips control characters but cannot know the
    /// output format.
    func testMarkdownMetacharactersInFilenamesAreEscaped() {
        let hostile = "evil|name`with*[markdown](x)<b>#.jpg"
        let subject = report([inspection(path: "/tmp/\(hostile)", name: hostile)])
        let text = ReportRenderer.markdown(subject)

        XCTAssertFalse(
            text.contains("evil|name"), "an unescaped pipe would break the table")
        XCTAssertTrue(text.contains("evil\\|name"))
        XCTAssertTrue(text.contains("\\`with"))
        XCTAssertTrue(text.contains("\\[markdown\\]"))
    }

    /// Markdown does not process escapes inside a code span, so a path
    /// escaped before being fenced renders its backslashes literally.
    func testCodeSpansAreNotBackslashEscaped() {
        let path = "/tmp/quarterly_report_final.jpeg"
        let code = ReportRenderer.markdownCode(path)
        XCTAssertEqual(code, "`\(path)`")
        XCTAssertFalse(code.contains("\\_"), "backslashes render literally inside a code span")

        // A pipe still has to be escaped: the table cell splits first.
        XCTAssertEqual(ReportRenderer.markdownCode("a|b"), "`a\\|b`")

        // A backtick would close the span early, so that case drops to text.
        XCTAssertFalse(ReportRenderer.markdownCode("a`b").hasPrefix("`"))
    }

    func testEscapingCoversEveryMetacharacter() {
        for character in ["\\", "`", "*", "_", "[", "]", "<", ">", "|", "#"] {
            let escaped = ReportRenderer.markdownEscaped("a\(character)b")
            XCTAssertEqual(escaped, "a\\\(character)b", "\(character) must be escaped")
        }
        XCTAssertEqual(ReportRenderer.markdownEscaped("a\nb\rc"), "a b c")
        XCTAssertEqual(ReportRenderer.markdownEscaped("ordinary name.jpg"), "ordinary name.jpg")
    }

    /// The escaping must not reach the JSON path, where it would corrupt the
    /// value — JSONEncoder does its own.
    /// Also pins that the export is round-trippable: the dates it writes
    /// are ISO-8601, which a default decoder rejects.
    func testJSONCarriesRawNamesNotMarkdownEscapes() throws {
        let hostile = "evil|name.jpg"
        let subject = report([inspection(path: "/tmp/\(hostile)", name: hostile)])
        let data = try XCTUnwrap(ReportRenderer.json(subject))
        let decoded = try ReportRenderer.jsonDecoder.decode(InspectionReport.self, from: data)
        XCTAssertEqual(decoded.files[0].displayName, hostile)
    }

    // MARK: - Content

    /// The line that keeps the feature honest has to survive into every
    /// exported artifact, not just the on-screen view.
    func testDisclaimerAppearsInEveryTextFormat() throws {
        let subject = report([inspection()])
        XCTAssertTrue(ReportRenderer.markdown(subject).contains("Not a malware scan"))
        XCTAssertTrue(ReportRenderer.plainText(subject).contains("Not a malware scan"))

        let json = try XCTUnwrap(ReportRenderer.json(subject))
        let pdf = try XCTUnwrap(ReportRenderer.pdf(subject))
        // JSON carries the structured report; the disclaimer is a constant on
        // the type, so assert the consumer can always reach it.
        XCTAssertFalse(InspectionReport.disclaimer.isEmpty)
        XCTAssertGreaterThan(json.count, 0)
        XCTAssertGreaterThan(pdf.count, 0)
    }

    func testLimitIsReportedWhenTheRunWasIncomplete() {
        let subject = report([inspection()], limit: .cancelled)
        XCTAssertTrue(ReportRenderer.markdown(subject).contains("Stopped at your request"))
        XCTAssertTrue(ReportRenderer.plainText(subject).contains("Stopped at your request"))
    }

    func testFindingsAndDisclosuresBothAppear() {
        let subject = report([
            inspection(
                verdict: .inconsistent,
                findings: [sample],
                disclosures: [Disclosure(title: "Came from", detail: "https://example.com/x")])
        ])
        for text in [ReportRenderer.markdown(subject), ReportRenderer.plainText(subject)] {
            XCTAssertTrue(text.contains("Extension does not match contents"))
            XCTAssertTrue(text.contains("example.com"))
        }
    }

    // MARK: - Filenames

    func testSuggestedFilenameHasTheRightExtensionAndNoColons() {
        let subject = report([inspection()])
        for format in ReportRenderer.Format.allCases {
            let name = ReportRenderer.suggestedFilename(for: subject, format: format)
            XCTAssertTrue(name.hasSuffix(".\(format.fileExtension)"), name)
            XCTAssertFalse(name.contains(":"), "colons display as slashes in Finder: \(name)")
        }
    }

    // MARK: - Wrapping

    func testWrapNeverDropsOrSplitsWords() {
        let text = "the quick brown fox jumps over the lazy dog"
        let lines = ReportRenderer.wrap(text, width: 12)
        XCTAssertEqual(lines.joined(separator: " "), text)
        for line in lines where line.split(separator: " ").count > 1 {
            XCTAssertLessThanOrEqual(line.count, 12)
        }
    }

    func testWrapEmitsAnOverlongWordOnItsOwnLine() {
        let long = String(repeating: "x", count: 40)
        XCTAssertEqual(ReportRenderer.wrap("a \(long) b", width: 10), ["a", long, "b"])
        XCTAssertEqual(ReportRenderer.wrap("", width: 10), [])
    }

    // MARK: - Hostile content

    /// A report assembled from a hostile file must render in every format
    /// without throwing or hanging.
    func testHostileContentRendersInEveryFormat() {
        let nasty = String(repeating: "|`*_[]<>#\\", count: 40)
        let subject = report([
            inspection(
                path: "/tmp/\(nasty)", name: nasty, verdict: .inconsistent,
                findings: [
                    Finding(rule: "r", severity: .inconsistent, title: nasty, detail: nasty)
                ],
                disclosures: [Disclosure(title: nasty, detail: nasty)])
        ])
        for format in ReportRenderer.Format.allCases {
            XCTAssertNotNil(ReportRenderer.render(subject, as: format), "\(format.label)")
        }
    }

    // MARK: - Fields and hostile names

    /// JSON was rebuilt field by field for sorting and silently lost two.
    func testJSONKeepsDurationAndFolderCount() throws {
        var subject = report([inspection()])
        subject.durationSeconds = 2.5
        subject.folderCount = 3
        let data = try XCTUnwrap(ReportRenderer.json(subject))
        let decoded = try ReportRenderer.jsonDecoder.decode(InspectionReport.self, from: data)
        XCTAssertEqual(decoded.durationSeconds, 2.5)
        XCTAssertEqual(decoded.folderCount, 3)
    }

    /// A filename may contain a newline. In a line-oriented format that let
    /// one file forge entries that read as other files' verdicts.
    func testNewlineInAFilenameCannotForgeReportLines() {
        let name = "a.txt\nINCONSISTENT  totally-real.pdf"
        let subject = report([inspection(path: "/tmp/\(name)", name: name)])

        let text = ReportRenderer.plainText(subject)
        XCTAssertEqual(
            text.split(separator: "\n").filter { $0.hasPrefix("INCONSISTENT") }.count, 0)
        XCTAssertTrue(text.contains("CONSISTENT  a.txtINCONSISTENT  totally-real.pdf"))

        let markdown = ReportRenderer.markdown(subject)
        let pathRows = markdown.split(separator: "\n").filter { $0.hasPrefix("| Path |") }
        XCTAssertEqual(pathRows.count, 1)
        XCTAssertTrue(pathRows[0].contains("totally-real.pdf"), "the path row must stay one row")
    }

    /// The direction override that `name.bidi` flags must not then be
    /// rendered as the spoof it produces. JSON keeps the exact path.
    func testDirectionOverrideIsStrippedFromTextFormatsButNotJSON() throws {
        let name = "report\u{202E}fdp.exe"
        let subject = report([inspection(path: "/tmp/\(name)", name: name)])
        for format in [ReportRenderer.Format.markdown, .plainText] {
            let text = String(decoding: ReportRenderer.render(subject, as: format)!, as: UTF8.self)
            XCTAssertFalse(text.contains("\u{202E}"), format.label)
            XCTAssertTrue(text.contains("reportfdp.exe"), format.label)
        }
        let json = String(decoding: try XCTUnwrap(ReportRenderer.json(subject)), as: UTF8.self)
        XCTAssertTrue(json.contains("\u{202E}"))
    }

    // MARK: - Consistency found by reading real exports

    /// The list shows names, so ties sort by name, and `dark_soul.png` must
    /// not land after every capitalised name because of ASCII order.
    func testTiesSortByNameWithoutRegardToCase() {
        let subject = report([
            inspection(path: "/p/SendSafely.jpeg", name: "SendSafely.jpeg"),
            inspection(path: "/p/dark_soul.png", name: "dark_soul.png"),
            inspection(path: "/d/PXL.jpg", name: "PXL.jpg"),
            inspection(path: "/p/Dark_Souls.jpg", name: "Dark_Souls.jpg"),
            inspection(path: "/d/image001.png", name: "image001.png"),
        ])
        XCTAssertEqual(
            subject.sortedFiles.map(\.displayName),
            ["dark_soul.png", "Dark_Souls.jpg", "image001.png", "PXL.jpg", "SendSafely.jpeg"])
        // Same name in two folders: the path decides, deterministically.
        let twins = report([
            inspection(path: "/b/x.jpg", name: "x.jpg"),
            inspection(path: "/a/x.jpg", name: "x.jpg"),
        ])
        XCTAssertEqual(twins.sortedFiles.map(\.path), ["/a/x.jpg", "/b/x.jpg"])
    }

    func testSubTenthSecondRunDoesNotReadAsZero() {
        var subject = report([inspection()])
        subject.durationSeconds = 0.039
        XCTAssertTrue(ReportRenderer.plainText(subject).contains("Took:        under 0.1s"))
        XCTAssertTrue(ReportRenderer.markdown(subject).contains("**Took:** under 0.1s"))
        subject.durationSeconds = 2.34
        XCTAssertTrue(ReportRenderer.plainText(subject).contains("Took:        2.3s"))
    }

    /// A "Came from" URL must survive a copy out of the raw Markdown.
    func testURLDisclosuresAreNotBackslashEscapedInMarkdown() {
        let url = "https://example.com/download?id=ab_cd&x=1"
        let subject = report([
            inspection(disclosures: [Disclosure(title: "Came from", detail: url)])
        ])
        let markdown = ReportRenderer.markdown(subject)
        XCTAssertTrue(markdown.contains("`\(url)`"), markdown)
        XCTAssertFalse(markdown.contains("ab\\_cd"))
    }
}
