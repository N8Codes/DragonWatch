import XCTest

@testable import DragonWatch

final class DocumentArchiveSourceTests: XCTestCase {

    private func probe(_ data: Data, name: String) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }
    private func rules(_ output: InspectorOutput) -> [String] { output.findings.map(\.rule) }

    // MARK: - ZIP central directory

    private func le16(_ value: Int) -> [UInt8] { [UInt8(value & 0xFF), UInt8(value >> 8 & 0xFF)] }
    private func le32(_ value: Int) -> [UInt8] {
        [
            UInt8(value & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value >> 16 & 0xFF),
            UInt8(value >> 24 & 0xFF),
        ]
    }

    /// A ZIP built from its index outward: local data, then one central
    /// directory header per entry, then the end record.
    private func zip(entries: [(name: String, compressed: Int, uncompressed: Int)]) -> Data {
        var local: [UInt8] = [0x50, 0x4B, 0x03, 0x04] + [UInt8](repeating: 0, count: 26)
        var central: [UInt8] = []
        for entry in entries {
            central += [0x50, 0x4B, 0x01, 0x02]
            central += [UInt8](repeating: 0, count: 16)  // through to sizes
            central += le32(entry.compressed)
            central += le32(entry.uncompressed)
            central += le16(entry.name.utf8.count)  // name length
            central += le16(0)  // extra length
            central += le16(0)  // comment length
            central += [UInt8](repeating: 0, count: 12)  // rest of the header
            central += Array(entry.name.utf8)
        }
        let centralOffset = local.count
        var eocd: [UInt8] = [0x50, 0x4B, 0x05, 0x06]
        eocd += le16(0) + le16(0)  // disk numbers
        eocd += le16(entries.count) + le16(entries.count)
        eocd += le32(central.count)
        eocd += le32(centralOffset)
        eocd += le16(0)  // comment length
        local += central
        local += eocd
        return Data(local)
    }

    func testCentralDirectoryEntriesAreRead() {
        let data = zip(entries: [("a.txt", 10, 20), ("b/c.txt", 5, 5)])
        let directory = ArchiveInspector.readDirectory(probe: probe(data, name: "z.zip"))
        XCTAssertEqual(directory?.declaredCount, 2)
        XCTAssertEqual(directory?.entries.map(\.name), ["a.txt", "b/c.txt"])
    }

    /// Caught from the index, without creating a single file.
    func testPathTraversalEntryIsInconsistent() {
        let data = zip(entries: [("../../etc/evil", 10, 10)])
        let output = ArchiveInspector.inspect(probe: probe(data, name: "z.zip"))
        XCTAssertTrue(rules(output).contains("zip.pathTraversal"))
        XCTAssertEqual(
            output.findings.first { $0.rule == "zip.pathTraversal" }?.severity, .inconsistent)
    }

    func testAbsolutePathEntryIsCaught() {
        let data = zip(entries: [("/Users/someone/.zshrc", 10, 10)])
        XCTAssertTrue(
            rules(ArchiveInspector.inspect(probe: probe(data, name: "z.zip")))
                .contains("zip.pathTraversal"))
    }

    func testOrdinaryArchiveHasNoFindings() {
        let data = zip(entries: [("notes.txt", 100, 200), ("img/a.png", 50, 60)])
        XCTAssertTrue(rules(ArchiveInspector.inspect(probe: probe(data, name: "z.zip"))).isEmpty)
    }

    func testExpansionRatioIsReportedOnlyWhenBothLargeAndLopsided() {
        // 400:1 and well over the size floor.
        let bomb = zip(entries: [("big", 1_000_000, 400_000_000)])
        XCTAssertTrue(
            rules(ArchiveInspector.inspect(probe: probe(bomb, name: "b.zip")))
                .contains("zip.expansionRatio"))

        // A high ratio on a small file is ordinary compression.
        let small = zip(entries: [("tiny", 10, 5000)])
        XCTAssertFalse(
            rules(ArchiveInspector.inspect(probe: probe(small, name: "s.zip")))
                .contains("zip.expansionRatio"))
    }

    func testMissingEndRecordIsReported() {
        let data = Data([0x50, 0x4B, 0x03, 0x04] + [UInt8](repeating: 0, count: 64))
        XCTAssertTrue(
            rules(ArchiveInspector.inspect(probe: probe(data, name: "broken.zip")))
                .contains("container.malformed"))
    }

    func testRunnableEntriesAreDisclosedNotFlagged() {
        let data = zip(entries: [("installer.app", 10, 10)])
        let output = ArchiveInspector.inspect(probe: probe(data, name: "z.zip"))
        XCTAssertTrue(output.disclosures.contains { $0.title == "Runnable entries" })
        XCTAssertTrue(rules(output).isEmpty)
    }

    // MARK: - PDF

    func testPDFWithLaunchActionIsInconsistent() {
        let pdf = Data("%PDF-1.7\n/OpenAction /Launch (calc)\ntrailer\n%%EOF".utf8)
        let finding = DocumentInspector().pdf(probe(pdf, name: "a.pdf")).findings
            .first { $0.rule == "pdf.launchAction" }
        XCTAssertEqual(finding?.severity, .inconsistent)
        XCTAssertTrue(finding!.detail.localizedCaseInsensitiveContains("launch"))
    }

    /// `/OpenAction` alone is a *view destination* — "open at page one, this
    /// zoom" — emitted by nearly every PDF writer. Flagging it condemned 26
    /// of 60 real documents, including resumes and tax returns.
    func testBareOpenActionIsNotActiveContent() {
        let pdf = Data("%PDF-1.7\n/OpenAction[1 0 R /XYZ null null 0]\ntrailer\n%%EOF".utf8)
        XCTAssertTrue(rules(DocumentInspector().pdf(probe(pdf, name: "resume.pdf"))).isEmpty)
    }

    /// `/AA` was matching font subset names like `/AAAAAA+Montserrat-Regular`.
    /// Three characters cannot carry a security signal.
    func testFontSubsetNamesAreNotMistakenForActions() {
        let pdf = Data("%PDF-1.7\n/BaseFont/AAAAAA+Montserrat-Regular\ntrailer\n%%EOF".utf8)
        XCTAssertTrue(rules(DocumentInspector().pdf(probe(pdf, name: "b.pdf"))).isEmpty)
    }

    /// The check must still catch code, which is the whole point.
    func testJavaScriptIsStillReported() {
        let pdf = Data("%PDF-1.7\n/JavaScript (app.alert)\n%%EOF".utf8)
        let finding = DocumentInspector().pdf(probe(pdf, name: "a.pdf")).findings
            .first { $0.rule == "pdf.activeContent" }
        XCTAssertEqual(finding?.severity, .caution)
        XCTAssertTrue(finding!.title.contains("JavaScript"))
        XCTAssertFalse(finding!.title.contains("when it opens"), "no OpenAction here")
    }

    /// JavaScript plus an OpenAction is what actually runs on open.
    func testJavaScriptWithOpenActionSaysItRunsOnOpen() {
        let pdf = Data("%PDF-1.7\n/OpenAction 2 0 R\n/JavaScript (x)\n%%EOF".utf8)
        let finding = DocumentInspector().pdf(probe(pdf, name: "a.pdf")).findings
            .first { $0.rule == "pdf.activeContent" }
        XCTAssertTrue(finding!.title.contains("when it opens"))
    }

    func testRichMediaIsReported() {
        let pdf = Data("%PDF-1.7\n/RichMedia 3 0 R\n%%EOF".utf8)
        XCTAssertTrue(
            rules(DocumentInspector().pdf(probe(pdf, name: "a.pdf")))
                .contains("pdf.activeContent"))
    }

    /// An attachment is routine in archival PDFs and invoices.
    func testEmbeddedFileIsDisclosedNotFlagged() {
        let pdf = Data("%PDF-1.7\n/EmbeddedFile 4 0 R\n%%EOF".utf8)
        let output = DocumentInspector().pdf(probe(pdf, name: "a.pdf"))
        XCTAssertTrue(rules(output).isEmpty)
        XCTAssertTrue(output.disclosures.contains { $0.title == "Carries an attachment" })
    }

    func testPlainPDFProducesNothing() {
        let pdf = Data("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n".utf8)
        XCTAssertTrue(rules(DocumentInspector().pdf(probe(pdf, name: "plain.pdf"))).isEmpty)
    }

    func testDataAfterLastPDFEndMarkerIsReported() {
        let pdf = Data("%PDF-1.7\ntrailer\n%%EOF".utf8) + Data(repeating: 0x41, count: 300)
        let output = DocumentInspector().pdf(probe(pdf, name: "poly.pdf"))
        XCTAssertTrue(rules(output).contains("container.trailingData"))
    }

    func testIncrementalPDFIsDisclosedNotFlagged() {
        let pdf = Data("%PDF-1.7\ntrailer\n%%EOF\n2 0 obj\nendobj\ntrailer\n%%EOF".utf8)
        let output = DocumentInspector().pdf(probe(pdf, name: "rev.pdf"))
        XCTAssertTrue(output.disclosures.contains { $0.title == "Revised document" })
        XCTAssertFalse(rules(output).contains("container.trailingData"))
    }

    func testPDFWithoutEndMarkerIsReported() {
        let pdf = Data("%PDF-1.7\n1 0 obj\nendobj\n".utf8)
        XCTAssertTrue(
            rules(DocumentInspector().pdf(probe(pdf, name: "cut.pdf"))).contains("pdf.noEndMarker"))
    }

    // MARK: - OOXML

    func testOfficeMacroProjectIsReported() {
        let data = zip(entries: [
            ("[Content_Types].xml", 10, 10), ("word/document.xml", 10, 10),
            ("word/vbaProject.bin", 10, 10),
        ])
        let output = DocumentInspector().zipContainer(probe(data, name: "a.docx"))
        XCTAssertTrue(rules(output).contains("ooxml.macros"))
        XCTAssertTrue(output.disclosures.contains { $0.detail.contains("Word document") })
    }

    func testOfficeDocumentWithoutMacrosIsClean() {
        let data = zip(entries: [("[Content_Types].xml", 10, 10), ("word/document.xml", 10, 10)])
        XCTAssertFalse(
            rules(DocumentInspector().zipContainer(probe(data, name: "a.docx")))
                .contains("ooxml.macros"))
    }

    // MARK: - Source

    /// Trojan Source, CVE-2021-42574.
    func testBidirectionalOverrideInSourceIsInconsistent() {
        let code = "if (isAdmin) {\u{202E} // safe \u{202C}\n  grant();\n}\n"
        let output = SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.swift"))
        let finding = output.findings.first { $0.rule == "source.bidiText" }
        XCTAssertEqual(finding?.severity, .inconsistent)
        XCTAssertTrue(finding!.detail.contains("U+202E"))
    }

    func testOrdinarySourceProducesNothing() {
        let code = "import Foundation\n\nfunc greet() { print(\"hi\") }\n"
        XCTAssertTrue(
            rules(SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.swift"))).isEmpty)
    }

    func testDecodeThenExecuteIsReported() {
        let code = "import base64\nexec(base64.b64decode(payload))\n"
        XCTAssertTrue(
            rules(SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.py")))
                .contains("source.decodeAndExecute"))
    }

    func testLongEncodedRunIsReported() {
        let code = "data = \"" + String(repeating: "QUJDRA", count: 400) + "\"\n"
        XCTAssertTrue(
            rules(SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.py")))
                .contains("source.encodedBlob"))
    }

    /// A minified bundle is a normal `.js`, and flagging every one of them
    /// would make the rule useless.
    func testMinifiedJavaScriptIsNotFlaggedForLineLength() {
        let code = "var a=1;" + String(repeating: "b(); ", count: 2000)
        XCTAssertFalse(
            rules(SourceInspector.inspect(probe: probe(Data(code.utf8), name: "bundle.js")))
                .contains("source.veryLongLine"))
        XCTAssertTrue(
            rules(SourceInspector.inspect(probe: probe(Data(code.utf8), name: "notes.txt")))
                .contains("source.veryLongLine"))
    }

    func testShebangIsDisclosed() {
        let code = "#!/usr/bin/env python3\nprint(1)\n"
        let output = SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.py"))
        XCTAssertTrue(output.disclosures.contains { $0.detail.contains("python3") })
    }

    func testSourceExtensionHoldingBinaryIsReported() {
        let binary = Data([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90])
        XCTAssertTrue(
            rules(SourceInspector.inspect(probe: probe(binary, name: "a.py"))).contains(
                "source.notText"))
    }

    func testSourceInspectorAppliesOnlyWhereItShould() {
        let text = probe(Data("print(1)".utf8), name: "a.py")
        XCTAssertTrue(SourceInspector.appliesTo(probe: text, format: nil))

        let jpeg = probe(Data([0xFF, 0xD8, 0xFF, 0xE0]), name: "a.jpg")
        XCTAssertFalse(SourceInspector.appliesTo(probe: jpeg, format: MagicBytes.jpeg))
    }

    // MARK: - Hostile input

    func testHostileDocumentBytesNeverCrash() {
        var inputs: [Data] = [
            Data(), Data("%PDF-".utf8), Data([0x50, 0x4B, 0x05, 0x06]),
            Data([0x50, 0x4B, 0x05, 0x06] + [UInt8](repeating: 0xFF, count: 18)),
            Data([0x50, 0x4B, 0x01, 0x02] + [UInt8](repeating: 0xFF, count: 46)),
        ]
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<40 {
            let count = Int.random(in: 0...1024, using: &generator)
            inputs.append(
                Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }))
        }
        for data in inputs {
            let subject = probe(data, name: "fuzz.zip")
            _ = ArchiveInspector.inspect(probe: subject)
            _ = ArchiveInspector.readDirectory(probe: subject)
            _ = DocumentInspector().pdf(subject)
            _ = DocumentInspector().zipContainer(subject)
            _ = SourceInspector.inspect(probe: subject)
        }
    }

    // MARK: - Regressions from scanning real files

    /// Half the real archives on a Mac were "incomplete": an index larger than
    /// the tail window starts before the bytes that were read, which is a
    /// limit of the sampling and not a defect of the archive.
    func testIndexLargerThanTheSampledWindowIsDisclosedNotFlagged() {
        let entries = (0..<1500).map { ("folder/file-\($0).txt", 100, 200) }
        let data = zip(entries: entries)
        XCTAssertGreaterThan(data.count, FileProbe.windowSize, "the fixture must exceed the window")
        let head = data.prefix(FileProbe.windowSize)
        let tail = data.suffix(FileProbe.windowSize)
        let probe = FileProbe(
            path: "/tmp/big.zip", displayName: "big.zip", size: Int64(data.count),
            head: Data(head), tail: Data(tail), tailOffset: Int64(data.count - tail.count),
            isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644, quarantine: nil,
            whereFrom: [], readError: nil, partialRead: false)

        let output = ArchiveInspector.inspect(probe: probe)
        XCTAssertFalse(rules(output).contains("zip.indexTruncated"), "\(rules(output))")
        XCTAssertTrue(output.disclosures.contains { $0.title == "Index not examined" })
    }

    /// The rule itself still fires when the index is in view and short.
    func testIndexClaimingMoreEntriesThanPresentIsTruncated() {
        var data = zip(entries: [("a.txt", 1, 1), ("b.txt", 1, 1)])
        // EOCD: count at len-14, total at len-12 — say five, ship two.
        data[data.count - 14] = 5
        data[data.count - 12] = 5
        let output = ArchiveInspector.inspect(probe: probe(data, name: "short.zip"))
        XCTAssertTrue(rules(output).contains("zip.indexTruncated"))
    }

    /// Emoji sequences, Indic and Arabic text and a Windows BOM all carry
    /// zero-width or joining characters. They are not Trojan Source.
    func testZeroWidthJoinersAndBOMsAreNotTrojanSource() {
        let texts = [
            ("family.txt", "Family: \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\n"),
            ("ml.txt", "\u{0D28}\u{0D28}\u{0D4D}\u{200D}\u{0D26}\u{0D3F}\n"),
            ("win.py", "\u{FEFF}import os\n"),
            ("rtl.md", "\u{200F}\u{0645}\u{0631}\u{062D}\u{0628}\u{0627}\n"),
        ]
        for (name, text) in texts {
            let output = SourceInspector.inspect(probe: probe(Data(text.utf8), name: name))
            XCTAssertFalse(rules(output).contains("source.bidiText"), name)
        }
    }

    func testIsolatesAndEmbeddingsAreStillTrojanSource() {
        for scalar in ["\u{2066}", "\u{202B}", "\u{202D}"] {
            let code = "x = 1 \(scalar)// \u{2069}\n"
            let output = SourceInspector.inspect(probe: probe(Data(code.utf8), name: "a.js"))
            XCTAssertTrue(rules(output).contains("source.bidiText"), scalar)
        }
    }

    /// `fromCharCode` alone is a method name; TypeScript's own standard
    /// library declares it. Decode-then-execute needs the execute half.
    func testFromCharCodeAloneIsNotDecodeAndExecute() {
        let declaration =
            "interface StringConstructor { fromCharCode(...codes: number[]): string; }\n"
        let output = SourceInspector.inspect(probe: probe(Data(declaration.utf8), name: "lib.ts"))
        XCTAssertFalse(rules(output).contains("source.decodeAndExecute"))

        let attack = "eval(String.fromCharCode(97,108,101,114,116))\n"
        let hit = SourceInspector.inspect(probe: probe(Data(attack.utf8), name: "a.js"))
        XCTAssertTrue(rules(hit).contains("source.decodeAndExecute"))
    }

    /// The external-relationship rule could never fire — `.rels` parts are
    /// deflated — so it is gone rather than advertised.
    func testNoRuleClaimsToSeeExternalRelationshipTargets() {
        var external = zip(entries: [("word/_rels/document.xml.rels", 1, 1)])
        external += Data("TargetMode=\"External\"".utf8)
        let output = DocumentInspector().zipContainer(probe(external, name: "b.docx"))
        XCTAssertFalse(rules(output).contains("ooxml.externalTarget"))
        XCTAssertFalse(InspectionRulebook.allRuleIDs.contains("ooxml.externalTarget"))
    }
}
