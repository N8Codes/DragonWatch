import XCTest

@testable import DragonWatch

/// The end of a file is where its own structure says, not where the last
/// end-marker-shaped bytes happen to be.
final class StructureWalkerTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("StructureWalker-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func write(_ data: Data, _ name: String) throws -> String {
        let url = directory.appendingPathComponent(name)
        try data.write(to: url)
        return url.path
    }

    private func be32(_ value: Int) -> [UInt8] {
        [
            UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    private func rules(_ path: String) async -> [String] {
        let report = await InspectionEngine().inspect(paths: [path])
        return report.files.flatMap(\.findings).map(\.rule)
    }

    // MARK: - JPEG

    /// SOI, an APP1 whose payload holds a thumbnail's own EOI, a scan with a
    /// stuffed FF and a restart marker in it, then the real EOI.
    private func jpeg(scanBytes: Int = 600) -> Data {
        var data = Data([0xFF, 0xD8])
        let thumbnail: [UInt8] = [0xFF, 0xD8, 0x01, 0x02, 0xFF, 0xD9, 0x00, 0x00]
        data += Data([0xFF, 0xE1, 0x00, UInt8(2 + thumbnail.count)] + thumbnail)
        data += Data([0xFF, 0xDA, 0x00, 0x08]) + Data(repeating: 0, count: 6)
        data += Data(repeating: 0x11, count: scanBytes)
        data += Data([0xFF, 0x00, 0x22, 0xFF, 0xD3, 0x33])
        data += Data([0xFF, 0xD9])
        return data
    }

    func testJPEGEndIsTheEOITheSegmentChainReaches() throws {
        let image = jpeg()
        let scan = try XCTUnwrap(
            StructureWalker.scan(path: try write(image, "a.jpg"), format: MagicBytes.jpeg))
        XCTAssertEqual(scan.logicalEnd, Int64(image.count))
        XCTAssertNil(scan.problem)
    }

    /// The forgery: a payload with its own FFD9 after it. Searching for the
    /// last end marker read the payload as part of the image.
    func testPayloadBehindAForgedEOIIsTrailingData() async throws {
        let image = jpeg()
        let forged = image + Data(repeating: 0x5A, count: 3000) + Data([0xFF, 0xD9])
        let path = try write(forged, "photo.jpg")
        let scan = try XCTUnwrap(StructureWalker.scan(path: path, format: MagicBytes.jpeg))
        XCTAssertEqual(scan.logicalEnd, Int64(image.count))

        let found = await rules(path)
        XCTAssertTrue(found.contains("container.trailingData"), "\(found)")
        let clean = await rules(try write(image, "clean.jpg"))
        XCTAssertFalse(clean.contains("container.trailingData"), "\(clean)")
    }

    /// A second image that begins between the two sampled windows is still
    /// recognised, from the bytes the walk reads at the end it found.
    func testTrailerStartingBetweenTheWindowsIsStillClassified() throws {
        let image = jpeg(scanBytes: 200_000)
        let second = jpeg(scanBytes: 200_000)
        let path = try write(image + second, "mpf.jpg")
        var probe = FileProbe.read(path: path)
        XCTAssertFalse(probe.isFullyWindowed)
        probe.structure = StructureWalker.scan(path: path, format: MagicBytes.jpeg)
        XCTAssertEqual(probe.structure?.logicalEnd, Int64(image.count))
        XCTAssertEqual(
            TrailingData.classify(probe: probe, logicalEnd: Int64(image.count)), .secondImage)
    }

    func testJPEGThatNeverReachesAnEndSaysSo() async throws {
        var truncated = jpeg()
        truncated.removeLast(2)
        let found = await rules(try write(truncated, "cut.jpg"))
        XCTAssertTrue(found.contains("jpeg.noEndMarker"), "\(found)")
    }

    // MARK: - PNG

    private func chunk(_ type: String, _ body: [UInt8]) -> Data {
        Data(be32(body.count) + Array(type.utf8) + body + [0, 0, 0, 0])
    }

    private func png(extra: Data = Data()) -> Data {
        Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            + chunk("IHDR", [UInt8](repeating: 0, count: 13)) + extra
            + chunk("IDAT", [UInt8](repeating: 7, count: 64)) + chunk("IEND", [])
    }

    func testPayloadBehindAForgedIENDIsTrailingData() async throws {
        let image = png()
        let forged = image + Data(repeating: 0x5A, count: 3000) + chunk("IEND", [])
        let path = try write(forged, "shot.png")
        let scan = try XCTUnwrap(StructureWalker.scan(path: path, format: MagicBytes.png))
        XCTAssertEqual(scan.logicalEnd, Int64(image.count))
        let found = await rules(path)
        XCTAssertTrue(found.contains("container.trailingData"), "\(found)")
    }

    func testPNGContentCredentialsChunkIsFoundAnywhereBeforeIEND() throws {
        let store = [UInt8](repeating: 0xAB, count: 100_000)  // larger than the head window
        let path = try write(png(extra: chunk("caBX", store)), "signed.png")
        let scan = try XCTUnwrap(StructureWalker.scan(path: path, format: MagicBytes.png))
        XCTAssertEqual(scan.credentials, .found(Data(store)))
    }

    // MARK: - ISO base media

    private func box(_ type: String, _ body: [UInt8]) -> Data {
        Data(be32(8 + body.count) + Array(type.utf8) + body)
    }

    /// The layout the C2PA specification gives for BMFF: a `uuid` FullBox
    /// with the C2PA extended type, the purpose "manifest", an eight-byte
    /// auxiliary offset, then the manifest store.
    func testC2PAManifestIsReadFromItsUUIDBox() throws {
        let store = Array("pretend-jumbf-manifest-store".utf8)
        let body =
            StructureWalker.c2paBoxUUID + [0, 0, 0, 0] + Array("manifest".utf8) + [0]
            + [UInt8](repeating: 0, count: 8) + store
        let file =
            box("ftyp", Array("isom".utf8) + [0, 0, 0, 0])
            + box("mdat", [UInt8](repeating: 1, count: 90_000))  // pushes it past the window
            + box("uuid", body)
        let path = try write(file, "clip.mp4")
        let scan = try XCTUnwrap(StructureWalker.scan(path: path, format: MagicBytes.mp4))
        XCTAssertEqual(scan.credentials, .found(Data(store)))
        XCTAssertEqual(scan.logicalEnd, Int64(file.count))

        // Bytes after the last box are measured from where the chain stops.
        let padded = try write(file + Data(repeating: 0xEE, count: 500), "padded.mp4")
        XCTAssertEqual(
            StructureWalker.scan(path: padded, format: MagicBytes.mp4)?.logicalEnd,
            Int64(file.count))
    }

    func testAnotherVendorsUUIDBoxIsNotAManifest() {
        let other = [UInt8](repeating: 0x42, count: 16) + [0, 0, 0, 0] + Array("manifest".utf8)
        XCTAssertNil(JUMBF.manifestStore(inC2PABox: other + [0] + [UInt8](repeating: 0, count: 20)))
    }

    // MARK: - JUMBF

    /// Every APP11 segment repeats the box length and type; only the first
    /// copy belongs in the reassembled box.
    func testAPP11SegmentsAreJoinedWithoutTheRepeatedBoxHeader() throws {
        let header = be32(24) + Array("jumb".utf8)
        func content(sequence: UInt8, _ payload: String) -> [UInt8] {
            [0x4A, 0x50, 0x00, 0x01, 0, 0, 0, sequence] + header + Array(payload.utf8)
        }
        let second = try XCTUnwrap(JUMBF.APP11Segment(content: content(sequence: 2, "BBBBBBBB")))
        let first = try XCTUnwrap(JUMBF.APP11Segment(content: content(sequence: 1, "AAAAAAAA")))
        XCTAssertEqual(
            JUMBF.assemble([second, first]),
            Data(header + Array("AAAAAAAABBBBBBBB".utf8)))
    }

    /// The active manifest is the last in the store (C2PA 2.3.7); earlier
    /// ones describe ingredients.
    func testTheLastManifestWinsForARepeatedLabel() {
        func superbox(label: String, cbor: [UInt8]) -> Data {
            let description =
                [UInt8](repeating: 0, count: 16) + [0x03] + Array(label.utf8) + [0]
            let inner = box("jumd", description) + box("cbor", cbor)
            return box("jumb", [UInt8](inner))
        }
        let store =
            superbox(label: "c2pa.claim", cbor: [0x01])
            + superbox(label: "c2pa.claim", cbor: [0x02])
        XCTAssertEqual(JUMBF.labelledCBOR(in: store)["c2pa.claim"], Data([0x02]))
    }

    // MARK: - PDF

    private func pdfProbe(_ text: String) -> FileProbe {
        let data = Data(text.utf8)
        return FileProbe(
            path: "/tmp/doc.pdf", displayName: "doc.pdf", size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    func testBareEOFMarkerAfterAPayloadDoesNotEndThePDF() {
        let document =
            "%PDF-1.7\n1 0 obj\n<<>>\nendobj\nxref\n0 1\ntrailer\n<<>>\nstartxref\n30\n%%EOF\n"
        let honest = DocumentInspector().pdf(pdfProbe(document))
        XCTAssertFalse(honest.findings.map(\.rule).contains("container.trailingData"))

        let forged = DocumentInspector().pdf(
            pdfProbe(document + String(repeating: "Z", count: 2000) + "\n%%EOF\n"))
        XCTAssertTrue(forged.findings.map(\.rule).contains("container.trailingData"))
    }
}
