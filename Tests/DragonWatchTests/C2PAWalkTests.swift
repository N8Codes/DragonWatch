import XCTest

@testable import DragonWatch

final class C2PAWalkTests: XCTestCase {

    // MARK: - CBOR

    private func cbor(_ bytes: [UInt8]) -> CBORValue? { CBOR.decode(Data(bytes)) }

    func testDecodesTheBasicTypes() {
        XCTAssertEqual(cbor([0x00])?.unsignedValue, 0)
        XCTAssertEqual(cbor([0x17])?.unsignedValue, 23)
        XCTAssertEqual(cbor([0x18, 0x2A])?.unsignedValue, 42)
        XCTAssertEqual(cbor([0x19, 0x01, 0x00])?.unsignedValue, 256)
        XCTAssertEqual(cbor([0x1A, 0x00, 0x01, 0x00, 0x00])?.unsignedValue, 65536)
        XCTAssertEqual(cbor([0x20])?.negativeValue, -1)
        XCTAssertEqual(cbor([0x63] + Array("abc".utf8))?.textValue, "abc")
        XCTAssertEqual(cbor([0xF5])?.boolValue, true)
        XCTAssertEqual(cbor([0xF4])?.boolValue, false)
        if case .null = cbor([0xF6]) {} else { XCTFail("expected null") }
    }

    func testDecodesNestedMapsAndArrays() {
        // {"actions": [{"action": "c2pa.created"}]}
        var bytes: [UInt8] = [0xA1, 0x67] + Array("actions".utf8)
        bytes += [0x81, 0xA1, 0x66] + Array("action".utf8)
        bytes += [0x6C] + Array("c2pa.created".utf8)
        let value = cbor(bytes)
        XCTAssertEqual(value?["actions"]?.arrayValue?.first?["action"]?.textValue, "c2pa.created")
    }

    /// A key is only found in the map it belongs to, which is the entire
    /// reason for decoding rather than scanning bytes.
    func testAKeyIsScopedToItsOwnMap() {
        var bytes: [UInt8] = [0xA1, 0x65] + Array("outer".utf8)
        bytes += [0xA1, 0x65] + Array("inner".utf8) + [0x62] + Array("hi".utf8)
        let value = cbor(bytes)
        XCTAssertNil(value?["inner"], "a nested key must not surface at the top level")
        XCTAssertEqual(value?["outer"]?["inner"]?.textValue, "hi")
    }

    // MARK: - CBOR limits, because the input is untrusted

    /// A declared length is a claim. Five bytes cannot hold four billion
    /// entries, and reserving for them is the memory-exhaustion bug.
    func testAbsurdContainerLengthIsRefusedNotAllocated() {
        XCTAssertNil(cbor([0x9A, 0xFF, 0xFF, 0xFF, 0xFF]), "array of 4 billion in 5 bytes")
        XCTAssertNil(cbor([0xBA, 0xFF, 0xFF, 0xFF, 0xFF]), "map of 4 billion in 5 bytes")
        XCTAssertNil(cbor([0x5A, 0xFF, 0xFF, 0xFF, 0xFF]), "byte string of 4 GB in 5 bytes")
        XCTAssertNil(cbor([0x7B] + [UInt8](repeating: 0xFF, count: 8)), "64-bit text length")
    }

    func testDeepNestingIsRefusedRatherThanRecursing() {
        // One more array wrapper than the depth limit allows.
        let deep = [UInt8](repeating: 0x81, count: CBOR.maxDepth + 5) + [0x00]
        XCTAssertNil(cbor(deep))

        let fine = [UInt8](repeating: 0x81, count: 4) + [0x00]
        XCTAssertNotNil(cbor(fine))
    }

    func testIndefiniteLengthIsRefused() {
        // Legal CBOR, never produced by a manifest writer; refusing it keeps
        // the break-marker state machine out of the code entirely.
        XCTAssertNil(cbor([0x9F, 0x01, 0x02, 0xFF]))
        XCTAssertNil(cbor([0x7F, 0x61, 0x61, 0xFF]))
    }

    func testTruncatedInputReturnsNil() {
        XCTAssertNil(cbor([0x63, 0x61]))  // says 3 bytes, has 1
        XCTAssertNil(cbor([0x82, 0x01]))  // says 2 items, has 1
        XCTAssertNil(cbor([]))
        XCTAssertNil(cbor([0x18]))  // argument byte missing
    }

    /// The decoder must return, whatever the bytes are.
    func testHostileCBORNeverCrashesOrHangs() {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<400 {
            let count = Int.random(in: 0...400, using: &generator)
            let bytes = (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
            _ = CBOR.decode(Data(bytes))
        }
        // Shapes that specifically stress the container paths.
        for header in [UInt8(0x80), 0x9F, 0xA0, 0xBF, 0x5F, 0x7F, 0xD8, 0xFF] {
            for tail in 0..<12 {
                _ = CBOR.decode(Data([header] + [UInt8](repeating: 0xFF, count: tail)))
            }
        }
    }

    // MARK: - JUMBF

    private func box(_ type: String, payload: [UInt8]) -> [UInt8] {
        let size = 8 + payload.count
        return [
            UInt8(size >> 24 & 0xFF), UInt8(size >> 16 & 0xFF),
            UInt8(size >> 8 & 0xFF), UInt8(size & 0xFF),
        ] + Array(type.utf8) + payload
    }

    /// UUID(16) + toggles(1) + NUL-terminated label.
    private func description(_ label: String) -> [UInt8] {
        box("jumd", payload: [UInt8](repeating: 0xAA, count: 16) + [0x03] + Array(label.utf8) + [0])
    }

    func testWalkFindsCBORByItsLabel() {
        let inner = description("c2pa.actions.v2") + box("cbor", payload: [0xA0])
        let tree = box("jumb", payload: description("c2pa") + box("jumb", payload: inner))
        let found = JUMBF.labelledCBOR(in: Data(tree))
        XCTAssertEqual(found["c2pa.actions.v2"], Data([0xA0]))
    }

    func testLabelIsAbsentWhenTheTogglesSaySo() {
        var payload = [UInt8](repeating: 0xAA, count: 16) + [0x00]  // label bit clear
        payload += Array("c2pa.actions.v2".utf8) + [0]
        let tree = box(
            "jumb", payload: box("jumd", payload: payload) + box("cbor", payload: [0xA0]))
        XCTAssertTrue(JUMBF.labelledCBOR(in: Data(tree)).isEmpty)
    }

    /// A box that does not advance the cursor is the infinite-loop case.
    func testZeroAndUndersizedBoxLengthsTerminate() {
        XCTAssertTrue(JUMBF.labelledCBOR(in: Data([0, 0, 0, 0] + Array("jumb".utf8))).isEmpty)
        XCTAssertTrue(JUMBF.labelledCBOR(in: Data([0, 0, 0, 1] + Array("jumb".utf8))).isEmpty)
        XCTAssertTrue(JUMBF.labelledCBOR(in: Data([0, 0, 0, 7] + Array("jumb".utf8))).isEmpty)
    }

    func testBoxClaimingMoreThanItsParentIsRefused() {
        let liar: [UInt8] = [0x7F, 0xFF, 0xFF, 0xFF] + Array("cbor".utf8) + [0xA0]
        let tree = box("jumb", payload: description("c2pa.actions.v2") + liar)
        XCTAssertTrue(JUMBF.labelledCBOR(in: Data(tree)).isEmpty)
    }

    func testHostileJUMBFNeverCrashesOrHangs() {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<300 {
            let count = Int.random(in: 0...600, using: &generator)
            _ = JUMBF.labelledCBOR(
                in: Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }))
        }
    }

    // MARK: - The forgery this rewrite exists to stop

    /// The previous reader searched the whole head window for
    /// `digitalSourceType` and read whatever CBOR string followed it. That
    /// made provenance forgeable: a file with no manifest at all, carrying
    /// those bytes in a JPEG comment, displayed as camera-captured. The walk
    /// only reads values from inside a real box tree.
    func testPlantedKeywordsOutsideAManifestAreIgnored() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Forge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        var comment = Data("jumd".utf8) + Data("c2pa".utf8) + Data("digitalSourceType".utf8)
        comment += Data([0x78, 0x46])
        comment += Data(
            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture!!!!!!".utf8)
        comment += Data("name".utf8) + Data([0x78, 0x0C]) + Data("Nikon Camera".utf8)

        var forged = Data([0xFF, 0xD8])
        let length = comment.count + 2
        forged += Data([0xFF, 0xFE, UInt8(length >> 8), UInt8(length & 0xFF)]) + comment
        forged += Data([0xFF, 0xDA, 0x00, 0x08]) + Data(repeating: 0, count: 6)
        forged += Data([0x11, 0x22]) + Data([0xFF, 0xD9])

        let file = dir.appendingPathComponent("forged.jpg")
        try forged.write(to: file)

        let disclosures = C2PAReader.disclosures(
            probe: FileProbe.read(path: file.path), format: MagicBytes.jpeg)
        XCTAssertTrue(
            disclosures.isEmpty,
            "planted keywords must not produce provenance, got: "
                + disclosures.map(\.detail).joined(separator: " | "))
    }

    func testFileWithNoManifestProducesNothing() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Plain-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("plain.jpg")
        try
            (Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + Data(repeating: 0x11, count: 14)
            + Data([0xFF, 0xD9])).write(to: file)

        XCTAssertTrue(
            C2PAReader.disclosures(
                probe: FileProbe.read(path: file.path), format: MagicBytes.jpeg
            ).isEmpty)
    }

    // MARK: - Against a real manifest, when one is offered

    func testRealManifestIsReadFromItsOwnAssertions() throws {
        // From the environment, not hardcoded: this repository is public and
        // a developer's own files are not something to publish in a test.
        // Point it at any image carrying Content Credentials:
        //
        //     DW_SAMPLE_C2PA_JPEG=/path/to/image.jpg swift test
        // `XCTSkip`, not `XCTUnwrap`: an unset variable means "no sample
        // offered", which is the normal case on CI and on every machine but
        // the author's. Unwrapping would fail the suite everywhere instead.
        guard let path = ProcessInfo.processInfo.environment["DW_SAMPLE_C2PA_JPEG"] else {
            throw XCTSkip(
                "set DW_SAMPLE_C2PA_JPEG to run this against a real Content Credentials image")
        }
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "sample not found")

        let probe = FileProbe.read(path: path)
        let payload = try XCTUnwrap(JUMBF.payload(probe: probe, format: MagicBytes.jpeg))
        let boxes = JUMBF.labelledCBOR(in: payload)

        XCTAssertNotNil(boxes["c2pa.claim.v2"])
        XCTAssertNotNil(boxes["c2pa.actions.v2"])
        XCTAssertNotNil(boxes["c2pa.signature"])

        let claim = try XCTUnwrap(CBOR.decode(try XCTUnwrap(boxes["c2pa.claim.v2"])))
        XCTAssertEqual(
            claim["claim_generator_info"]?["name"]?.textValue,
            "Google C2PA Core Generator Library")

        let actions = CBOR.decode(try XCTUnwrap(boxes["c2pa.actions.v2"]))
        let steps = C2PAReader.declaredActions(actions)
        XCTAssertEqual(steps.first?.action, "c2pa.created")
        XCTAssertEqual(
            steps.first?.digitalSourceType,
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")

        // Ingredient assertions carry their own `description`. Reading actions
        // from their own map means those can no longer be mistaken for steps
        // the file declares — the old scanner needed a filter for exactly that.
        let descriptions = steps.compactMap(\.description)
        XCTAssertTrue(descriptions.contains("Created by Google Generative AI."))
        XCTAssertFalse(descriptions.contains { $0.lowercased().contains("ingredient") })
    }
}

// Small readers used only by these tests.
extension CBORValue {
    var unsignedValue: UInt64? {
        if case .unsigned(let value) = self { return value }
        return nil
    }
    var negativeValue: Int64? {
        if case .negative(let value) = self { return value }
        return nil
    }
    var boolValue: Bool? {
        if case .boolean(let value) = self { return value }
        return nil
    }
}
