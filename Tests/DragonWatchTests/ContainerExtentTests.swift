import XCTest

@testable import DragonWatch

/// The ISO base media extent is what decides whether an MP4 or MOV "has data
/// after its end". It was claiming the box before an unread `mdat` as the end
/// of the file, which flagged every movie on the Mac as carrying a payload.
final class ContainerExtentTests: XCTestCase {

    private func be32(_ v: UInt32) -> Data {
        Data([UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)])
    }
    private func box(_ type: String, size: UInt32) -> Data { be32(size) + Data(type.utf8) }

    private func probe(head: Data, size: Int64, name: String = "clip.mp4") -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: size,
            head: head, tail: Data(repeating: 0, count: 16), tailOffset: size - 16,
            isDirectory: false, isSymbolicLink: false, posixPermissions: 0o644,
            quarantine: nil, whereFrom: [], readError: nil, partialRead: false)
    }

    /// `ftyp` then a `moov` whose end lies past the 64 KB window: the walk
    /// stopped because it could not look, not because the chain ended.
    func testWalkThatRanOutOfWindowClaimsNoExtent() {
        let head =
            box("ftyp", size: 24) + Data(repeating: 0, count: 16) + box("moov", size: 200_000)
        XCTAssertNil(ContainerStructure.isoExtent(head: head, fileSize: 5_000_000))

        let output = MediaInspector().isoMedia(
            probe(head: head, size: 5_000_000), format: MagicBytes.mp4)
        XCTAssertFalse(output.findings.contains { $0.rule == "container.trailingData" })
        XCTAssertFalse(output.findings.contains { $0.rule == "container.malformed" })
    }

    /// The common camera layout — a huge `mdat` early, `moov` at the end —
    /// stops the walk the same way.
    func testEarlyMdatIsNotTrailingData() {
        let head =
            box("ftyp", size: 24) + Data(repeating: 0, count: 16) + box("mdat", size: 3_000_000)
        XCTAssertNil(ContainerStructure.isoExtent(head: head, fileSize: 3_100_000))
    }

    /// A chain that ends inside the window with bytes after it that are not a
    /// box header is the real signal, and must still be reported.
    func testChainEndingInsideTheWindowStillReportsTrailingData() {
        let boxes =
            box("ftyp", size: 24) + Data(repeating: 0, count: 16) + box("moov", size: 16)
            + Data(repeating: 0, count: 8)
        let trailer = Data(repeating: 0x41, count: 500)
        let head = boxes + trailer
        let extent = ContainerStructure.isoExtent(head: head, fileSize: Int64(head.count))
        XCTAssertEqual(extent?.logicalEnd, Int64(boxes.count))

        var probe = probe(head: head, size: Int64(head.count))
        probe = FileProbe(
            path: probe.path, displayName: probe.displayName, size: probe.size, head: head,
            tail: head, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
        let output = MediaInspector().isoMedia(probe, format: MagicBytes.mp4)
        XCTAssertTrue(output.findings.contains { $0.rule == "container.trailingData" })
    }

    /// A terminating `size == 0` box still speaks for the whole file.
    func testChainReachingTheEndClaimsTheWholeFile() {
        let head = box("ftyp", size: 24) + Data(repeating: 0, count: 16) + box("mdat", size: 0)
        let extent = ContainerStructure.isoExtent(head: head, fileSize: 9_999)
        XCTAssertEqual(extent?.logicalEnd, 9_999)
    }

    /// Hitting the box cap is another way of not having looked.
    func testBoxCapClaimsNoExtent() {
        var head = Data()
        for _ in 0..<ContainerStructure.maxTopLevelBoxes { head += box("free", size: 8) }
        XCTAssertNil(ContainerStructure.isoExtent(head: head, fileSize: Int64(head.count) + 4_000))
    }
}
