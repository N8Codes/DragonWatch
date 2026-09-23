import XCTest

@testable import DragonWatch

final class MagicBytesTests: XCTestCase {

    private func bytes(_ values: [UInt8]) -> Data { Data(values) }
    private func ascii(_ text: String, padTo count: Int = 0) -> Data {
        var data = Data(text.utf8)
        while data.count < count { data.append(0) }
        return data
    }

    // MARK: - Straightforward identification

    func testIdentifiesCommonFormats() {
        XCTAssertEqual(MagicBytes.identify(head: bytes([0xFF, 0xD8, 0xFF, 0xE0]))?.name, "JPEG")
        XCTAssertEqual(
            MagicBytes.identify(head: bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))?
                .name, "PNG")
        XCTAssertEqual(MagicBytes.identify(head: ascii("GIF89a"))?.name, "GIF")
        XCTAssertEqual(MagicBytes.identify(head: ascii("%PDF-1.7"))?.name, "PDF")
        XCTAssertEqual(MagicBytes.identify(head: ascii("fLaC"))?.name, "FLAC")
        XCTAssertEqual(
            MagicBytes.identify(head: bytes([0x7F, 0x45, 0x4C, 0x46]))?.name, "ELF executable")
    }

    func testUnknownBytesIdentifyAsNil() {
        XCTAssertNil(MagicBytes.identify(head: bytes([0x01, 0x02, 0x03, 0x04, 0x05])))
        XCTAssertNil(MagicBytes.identify(head: Data()))
    }

    // MARK: - Shared container prefixes

    /// RIFF is WebP, WAV *and* AVI. Identifying on the first four bytes alone
    /// would make all three the same format.
    func testRIFFVariantsSeparateOnTheirSecondaryBrand() {
        XCTAssertEqual(
            MagicBytes.identify(head: ascii("RIFF") + ascii("....") + ascii("WEBP"))?.name, "WebP")
        XCTAssertEqual(
            MagicBytes.identify(head: ascii("RIFF") + ascii("....") + ascii("WAVE"))?.name, "WAV")
        XCTAssertEqual(
            MagicBytes.identify(head: ascii("RIFF") + ascii("....") + ascii("AVI "))?.name, "AVI")
    }

    /// Same problem one level deeper: HEIC, AVIF and MP4 are all ISO base
    /// media with `ftyp` at offset 4.
    func testISOBaseMediaVariantsSeparateOnBrand() {
        let prefix = Data([0, 0, 0, 0x20]) + ascii("ftyp")
        XCTAssertEqual(MagicBytes.identify(head: prefix + ascii("heic"))?.name, "HEIF/HEIC")
        XCTAssertEqual(MagicBytes.identify(head: prefix + ascii("avif"))?.name, "AVIF")
        XCTAssertEqual(MagicBytes.identify(head: prefix + ascii("isom"))?.name, "MPEG-4")
        XCTAssertEqual(MagicBytes.identify(head: prefix + ascii("qt  "))?.name, "QuickTime movie")
    }

    /// `CAFEBABE` is both a Mach-O universal binary and a Java class file.
    /// The arch count and the class-file version occupy the same four bytes
    /// and cannot overlap for any real file.
    func testCafebabeSplitsMachOFromJavaClass() {
        let fat = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02])
        XCTAssertEqual(MagicBytes.identify(head: fat)?.name, "Mach-O universal binary")

        // Java 8 = class file major version 52.
        let java = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34])
        XCTAssertEqual(MagicBytes.identify(head: java)?.name, "Java class")
    }

    func testSVGWinsOverBareXML() {
        let plain = ascii("<?xml version=\"1.0\"?><root/>")
        XCTAssertEqual(MagicBytes.identify(head: plain)?.name, "XML")

        let svg = ascii("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>")
        XCTAssertEqual(MagicBytes.identify(head: svg)?.name, "SVG")
    }

    /// The tar signature sits at offset 257, which is the only entry in the
    /// table that is not near the start.
    func testOffsetSignatureIsFoundAwayFromTheStart() {
        var data = Data(repeating: 0, count: 257)
        data.append(ascii("ustar"))
        XCTAssertEqual(MagicBytes.identify(head: data)?.name, "tar")
    }

    // MARK: - Slice safety

    /// A `Data` slice carries a non-zero `startIndex`, so any matcher that
    /// assumes index 0 traps. Every offset in the table is relative to the
    /// start of the file, not the start of the buffer.
    func testMatchingWorksOnASliceWithNonZeroStartIndex() {
        let padded = Data([0xAA, 0xBB]) + bytes([0xFF, 0xD8, 0xFF, 0xE0])
        let slice = padded.dropFirst(2)
        XCTAssertNotEqual(slice.startIndex, 0, "precondition: the slice must be offset")
        XCTAssertEqual(MagicBytes.identify(head: slice)?.name, "JPEG")
    }

    func testHasBytesRejectsOutOfBoundsWithoutTrapping() {
        let short = bytes([0xFF, 0xD8])
        XCTAssertFalse(MagicBytes.hasBytes([0xFF, 0xD8, 0xFF], at: 0, in: short))
        XCTAssertFalse(MagicBytes.hasBytes([0xFF], at: 99, in: short))
        XCTAssertFalse(MagicBytes.hasBytes([0xFF], at: -1, in: short))
        XCTAssertFalse(MagicBytes.hasBytes([], at: 0, in: short))
    }

    // MARK: - Reverse lookup

    func testExtensionLookupIsStableAndCoversAliases() {
        XCTAssertEqual(MagicBytes.formats(forExtension: "jpeg").map(\.name), ["JPEG"])
        XCTAssertEqual(MagicBytes.formats(forExtension: "JPG").map(\.name), ["JPEG"])
        XCTAssertTrue(MagicBytes.formats(forExtension: "docx").contains(MagicBytes.zip))
        XCTAssertTrue(MagicBytes.formats(forExtension: "zzz").isEmpty)
        XCTAssertTrue(MagicBytes.formats(forExtension: "").isEmpty)

        // `.svg` is both XML and SVG; the order must not depend on table order.
        let svg = MagicBytes.formats(forExtension: "svg").map(\.name)
        XCTAssertEqual(svg, svg.sorted())
    }

    /// The table is a literal, but `identify` iterates it and callers render
    /// the result. Repeat the lookup to pin that nothing depends on hash order.
    func testIdentificationIsStableAcrossRepeatedRuns() {
        let head = ascii("RIFF") + ascii("....") + ascii("WEBP")
        let first = MagicBytes.identify(head: head)?.name
        for _ in 0..<16 {
            XCTAssertEqual(MagicBytes.identify(head: head)?.name, first)
        }
    }

    // MARK: - Reverse lookup regressions (every one flagged real files)

    private func probe(_ data: Data, name: String) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    /// 120 of 120 real SVGs were flagged: `.svg` expected only XML while the
    /// bytes identified as SVG, and an SVG without an XML prolog matched
    /// nothing at all.
    func testSVGIsConsistentWithOrWithoutAnXMLProlog() {
        let bare = ascii("<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>")
        XCTAssertEqual(MagicBytes.identify(head: bare)?.name, "SVG")
        for head in [bare, ascii("<?xml version=\"1.0\"?><svg xmlns=\"x\"/>")] {
            let findings = UniversalChecks.typeConsistency(
                probe: probe(head, name: "icon.svg"), identified: MagicBytes.identify(head: head))
            XCTAssertTrue(findings.isEmpty, "\(findings.map(\.rule))")
        }
        // An SVG saved as .xml is still XML.
        XCTAssertTrue(
            UniversalChecks.typeConsistency(
                probe: probe(bare, name: "icon.xml"), identified: MagicBytes.svg
            ).isEmpty)
    }

    /// 83 of 120 real dylibs (Chrome, Firefox) were "Inconsistent" because the
    /// universal format is reached only by disambiguation and the reverse
    /// lookup never saw it.
    func testUniversalBinaryIsAcceptedUnderItsExtensions() {
        let fat = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2])
        XCTAssertEqual(MagicBytes.identify(head: fat), MagicBytes.machOFat)
        for name in ["libfoo.dylib", "plugin.bundle", "obj.o"] {
            XCTAssertTrue(
                UniversalChecks.typeConsistency(
                    probe: probe(fat, name: name), identified: MagicBytes.machOFat
                ).isEmpty, name)
        }
        XCTAssertTrue(MagicBytes.formats(forExtension: "class").contains(MagicBytes.javaClass))
    }

    /// 117 of 120 real `.py` files have no `#!` line. A shebang is evidence
    /// of a script, never a requirement of one.
    func testScriptExtensionsCarryNoByteExpectation() {
        for ext in ["py", "sh", "rb", "pl", "bash"] {
            XCTAssertTrue(MagicBytes.formats(forExtension: ext).isEmpty, ext)
        }
        XCTAssertTrue(
            UniversalChecks.typeConsistency(
                probe: probe(ascii("import os\n"), name: "tool.py"), identified: nil
            ).isEmpty)
        XCTAssertEqual(MagicBytes.identify(head: ascii("#!/bin/sh\n"))?.name, "Script (shebang)")
    }

    /// A UDIF image's `koly` block is its *last* 512 bytes; the old signature
    /// looked at offset 0 and so called 33 of 33 real disk images unconfirmed.
    func testDiskImageIsIdentifiedByItsTrailer() {
        var tail = Data(repeating: 0, count: 2048)
        tail.replaceSubrange((2048 - 512)..<(2048 - 508), with: ascii("koly"))
        XCTAssertEqual(
            MagicBytes.identify(head: Data(repeating: 0, count: 64), tail: tail), MagicBytes.dmg)
        // bzip2-compressed images start "BZh": the trailer must win over the head.
        XCTAssertEqual(MagicBytes.identify(head: ascii("BZh91AY&SY"), tail: tail), MagicBytes.dmg)
        // Without the trailer the head decides as before.
        XCTAssertEqual(
            MagicBytes.identify(head: ascii("BZh91AY&SY"), tail: Data(repeating: 0, count: 2048)),
            MagicBytes.bzip2)
        XCTAssertNil(MagicBytes.identify(head: Data(), tail: Data()))
        XCTAssertTrue(MagicBytes.formats(forExtension: "dmg").contains(MagicBytes.dmg))
    }
}
