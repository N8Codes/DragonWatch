import XCTest

@testable import DragonWatch

final class ImageInspectorTests: XCTestCase {

    private let soi: [UInt8] = [0xFF, 0xD8]
    private let eoi: [UInt8] = [0xFF, 0xD9]
    private let pngSignature: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]

    private func probe(_ data: Data, name: String) -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    private func rules(_ output: InspectorOutput) -> [String] { output.findings.map(\.rule) }

    /// SOI, one APP0 segment, SOS, a little entropy data, EOI.
    private func minimalJPEG(trailing: Int = 0) -> Data {
        var bytes: [UInt8] = soi
        bytes += [0xFF, 0xE0, 0x00, 0x10]  // APP0, length 16
        bytes += Array("JFIF\0".utf8) + [UInt8](repeating: 0, count: 9)
        bytes += [0xFF, 0xDA, 0x00, 0x0C]  // SOS, length 12
        bytes += [UInt8](repeating: 0x00, count: 10)
        bytes += [0x11, 0x22, 0x33, 0x44]  // entropy data
        bytes += eoi
        bytes += [UInt8](repeating: 0x41, count: trailing)
        return Data(bytes)
    }

    private func minimalPNG(trailing: Int = 0) -> Data {
        var bytes: [UInt8] = pngSignature
        // IHDR: length 13
        bytes += [0x00, 0x00, 0x00, 0x0D] + Array("IHDR".utf8)
        bytes += [UInt8](repeating: 0x01, count: 13) + [0x00, 0x00, 0x00, 0x00]
        // IEND: length 0
        bytes += [0x00, 0x00, 0x00, 0x00] + Array("IEND".utf8) + [0xAE, 0x42, 0x60, 0x82]
        bytes += [UInt8](repeating: 0x41, count: trailing)
        return Data(bytes)
    }

    // MARK: - The check the whole feature exists for

    func testCleanJPEGProducesNothing() {
        let output = ImageInspector().jpeg(probe(minimalJPEG(), name: "clean.jpg"))
        XCTAssertTrue(rules(output).isEmpty, "got \(rules(output))")
    }

    /// Exact, unlike the sampled scan in `UniversalChecks`: the segment walk
    /// knows where the image ends regardless of file size.
    func testDataAfterEndOfImageIsReportedWithItsExactSize() {
        let output = ImageInspector().jpeg(probe(minimalJPEG(trailing: 204), name: "poly.jpg"))
        XCTAssertEqual(rules(output), ["container.trailingData"])
        XCTAssertTrue(output.findings[0].detail.contains("204 bytes"))
    }

    /// Encoders pad; a rule that fires on every third photo gets ignored.
    func testATrivialAmountOfPaddingIsNotReported() {
        let output = ImageInspector().jpeg(probe(minimalJPEG(trailing: 2), name: "pad.jpg"))
        XCTAssertFalse(rules(output).contains("container.trailingData"))
    }

    func testTruncatedJPEGWithNoEndMarkerIsReported() {
        var data = minimalJPEG()
        data = data.prefix(data.count - 2)  // drop the EOI
        let output = ImageInspector().jpeg(probe(data, name: "cut.jpg"))
        XCTAssertEqual(rules(output), ["jpeg.noEndMarker"])
    }

    /// An EXIF thumbnail is itself a JPEG and carries its own FFD9, before
    /// the scan data. Taking the first marker would call every photo with a
    /// thumbnail truncated.
    func testThumbnailEndMarkerDoesNotEndTheImage() {
        var bytes: [UInt8] = soi
        bytes += [0xFF, 0xE1, 0x00, 0x0C]  // APP1 (EXIF), length 12
        bytes += Array("Exif\0\0".utf8) + eoi + [0x00, 0x00]  // thumbnail's own EOI inside
        bytes += [0xFF, 0xDA, 0x00, 0x08] + [UInt8](repeating: 0, count: 6)
        bytes += [0x99, 0x88]
        bytes += eoi
        let output = ImageInspector().jpeg(probe(Data(bytes), name: "exif.jpg"))
        XCTAssertTrue(rules(output).isEmpty, "got \(rules(output))")
    }

    // MARK: - PNG

    func testCleanPNGProducesNothing() {
        let output = ImageInspector().png(probe(minimalPNG(), name: "clean.png"))
        XCTAssertTrue(rules(output).isEmpty, "got \(rules(output))")
    }

    func testDataAfterIENDIsReported() {
        let output = ImageInspector().png(probe(minimalPNG(trailing: 512), name: "poly.png"))
        XCTAssertEqual(rules(output), ["container.trailingData"])
        XCTAssertTrue(output.findings[0].detail.contains("512 bytes"))
    }

    func testPNGWithoutIENDIsReported() {
        var bytes: [UInt8] = pngSignature
        bytes += [0x00, 0x00, 0x00, 0x0D] + Array("IHDR".utf8)
        bytes += [UInt8](repeating: 0x01, count: 13) + [0x00, 0x00, 0x00, 0x00]
        let output = ImageInspector().png(probe(Data(bytes), name: "cut.png"))
        XCTAssertEqual(rules(output), ["png.noEndChunk"])
    }

    /// A chunk length beyond the file is where a parser walks off the end.
    func testPNGChunkLengthLargerThanTheFileIsReported() {
        var bytes: [UInt8] = pngSignature
        bytes += [0x7F, 0xFF, 0xFF, 0xFF] + Array("IDAT".utf8)
        bytes += [UInt8](repeating: 0, count: 32)
        bytes += [0x00, 0x00, 0x00, 0x00] + Array("IEND".utf8) + [0xAE, 0x42, 0x60, 0x82]
        let output = ImageInspector().png(probe(Data(bytes), name: "lying.png"))
        XCTAssertTrue(rules(output).contains("container.malformed"))
    }

    // MARK: - RIFF

    func testRIFFDeclaredSizeCatchesAppendedData() {
        var bytes = Array("RIFF".utf8)
        bytes += [0x14, 0x00, 0x00, 0x00]  // 20 bytes of payload
        bytes += Array("WEBP".utf8)
        bytes += [UInt8](repeating: 0x00, count: 16)
        let clean = Data(bytes)
        XCTAssertEqual(clean.count, 28)

        XCTAssertTrue(
            ImageInspector().riff(probe(clean, name: "a.webp"), name: "WebP").findings.isEmpty)

        let padded = clean + Data(repeating: 0x41, count: 100)
        let output = ImageInspector().riff(probe(padded, name: "b.webp"), name: "WebP")
        XCTAssertEqual(rules(output), ["container.trailingData"])
        XCTAssertTrue(output.findings[0].detail.contains("100 bytes"))
    }

    func testRIFFShorterThanDeclaredIsReported() {
        var bytes = Array("RIFF".utf8)
        bytes += [0xFF, 0xFF, 0x00, 0x00]  // claims 65535 bytes
        bytes += Array("WEBP".utf8)
        let output = ImageInspector().riff(probe(Data(bytes), name: "short.webp"), name: "WebP")
        XCTAssertTrue(rules(output).contains("container.shortFile"))
    }

    // MARK: - SVG

    func testSVGWithScriptIsReported() {
        let svg = Data(
            #"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>"#
                .utf8)
        let output = ImageInspector().svg(probe(svg, name: "a.svg"))
        XCTAssertTrue(rules(output).contains("svg.activeContent"))
    }

    func testSVGWithInlineHandlerIsReported() {
        let svg = Data(#"<svg xmlns="x"><rect onload="steal()"/></svg>"#.utf8)
        XCTAssertTrue(
            rules(ImageInspector().svg(probe(svg, name: "b.svg"))).contains("svg.activeContent"))
    }

    func testPlainSVGProducesNothing() {
        let svg = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="4"/></svg>"#.utf8)
        XCTAssertTrue(ImageInspector().svg(probe(svg, name: "c.svg")).findings.isEmpty)
    }

    func testSVGEntityDeclarationIsReported() {
        let svg = Data(
            #"<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg/>"#
                .utf8)
        XCTAssertTrue(
            rules(ImageInspector().svg(probe(svg, name: "d.svg"))).contains("svg.externalEntity"))
    }

    // MARK: - Hostile input

    /// Every walk must terminate and none may trap, whatever the bytes say.
    func testMalformedImagesNeverHangOrCrash() {
        var inputs: [Data] = [
            Data(soi), Data(pngSignature), Data("RIFF".utf8),
            Data(soi + [0xFF, 0xE0, 0x00, 0x00]),  // zero-length segment: must not loop
            Data(soi + [0xFF, 0xE0, 0x00, 0x01]),  // length below the minimum
            Data(pngSignature + [0xFF, 0xFF, 0xFF, 0xFF] + Array("IDAT".utf8)),
            Data(Array("RIFF".utf8) + [0xFF, 0xFF, 0xFF, 0xFF] + Array("WEBP".utf8)),
        ]
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<40 {
            let count = Int.random(in: 0...1024, using: &generator)
            inputs.append(
                Data(soi + (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }))
        }

        let inspector = ImageInspector()
        for data in inputs {
            let subject = probe(data, name: "fuzz.jpg")
            _ = inspector.jpeg(subject)
            _ = inspector.png(subject)
            _ = inspector.gif(subject)
            _ = inspector.riff(subject, name: "WebP")
            _ = inspector.svg(subject)
            _ = inspector.isoMedia(subject, name: "HEIF")
        }
    }

    /// A segment ending one byte before the window edge left the marker byte
    /// readable but not its kind, which read as a broken chain. Running out
    /// of window is not malformation.
    func testSegmentChainReachingTheWindowEdgeIsNotMalformed() {
        var bytes: [UInt8] = soi
        bytes += [0xFF, 0xE1, 0x00, 0x10] + [UInt8](repeating: 0, count: 14)  // ends at 20
        bytes += [0xFF]  // the window ends here, mid-marker
        let head = Data(bytes)
        let probe = FileProbe(
            path: "/tmp/edge.jpg", displayName: "edge.jpg", size: 1_000_000,
            head: head, tail: Data(), tailOffset: 1_000_000, isDirectory: false,
            isSymbolicLink: false, posixPermissions: 0o644, quarantine: nil, whereFrom: [],
            readError: nil, partialRead: true)
        XCTAssertTrue(ImageInspector().jpegSegments(probe).isEmpty)
    }

    func testBrokenSegmentChainInsideTheWindowIsStillMalformed() {
        var bytes: [UInt8] = soi
        bytes += [0xFF, 0xE1, 0x00, 0x10] + [UInt8](repeating: 0, count: 14)
        bytes += [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]  // not a marker, well inside the window
        let output = ImageInspector().jpegSegments(probe(Data(bytes), name: "broken.jpg"))
        XCTAssertEqual(output.map(\.rule), ["container.malformed"])
    }
}
