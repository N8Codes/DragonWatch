import XCTest

@testable import DragonWatch

/// Regressions for arithmetic that trapped on crafted input.
///
/// Swift traps on integer overflow, so an overflow in a bounds check is a
/// crash, not a wrong answer — and these parsers exist to read files nobody
/// trusts. Both cases below aborted the whole test runner with SIGILL before
/// the fix; a test that merely *returns* is therefore the assertion.
final class OverflowRegressionTests: XCTestCase {

    private func probe(_ data: Data, size: Int64) -> FileProbe {
        FileProbe(
            path: "/tmp/crafted", displayName: "crafted", size: size,
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o644, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    private func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }
    private func be64(_ v: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(v >> (8 * UInt64($0)) & 0xFF) }
    }

    // MARK: - ISO base media

    /// A 64-bit `largesize` of Int64.max, positioned after a small box so the
    /// cursor is non-zero — `cursor + size` then overflows. At cursor 0 the
    /// addition is safe, which is why the first version of this test passed
    /// while the bug was live.
    func testIsoBoxWithMaximumLargesizeIsRejectedNotFatal() {
        var bytes: [UInt8] = be32(16) + Array("ftyp".utf8) + [UInt8](repeating: 0, count: 8)
        bytes += be32(1) + Array("mdat".utf8) + be64(UInt64(Int64.max))
        bytes += [UInt8](repeating: 0, count: 32)

        let walk = ContainerStructure.isoBoxes(head: Data(bytes), fileSize: 1_000_000)
        XCTAssertEqual(walk.boxes.map(\.type), ["ftyp"], "the impossible box must be refused")
        XCTAssertFalse(walk.reachedEnd)
    }

    func testIsoBoxSizesAcrossTheWholeRangeAreSafe() {
        for size in [UInt64(0), 1, 7, 8, 16, UInt64(UInt32.max), UInt64(Int64.max)] {
            var bytes: [UInt8] = be32(16) + Array("ftyp".utf8) + [UInt8](repeating: 0, count: 8)
            bytes += be32(1) + Array("mdat".utf8) + be64(size)
            bytes += [UInt8](repeating: 0, count: 16)
            _ = ContainerStructure.isoBoxes(head: Data(bytes), fileSize: 1_000_000)
        }
    }

    // MARK: - Fat Mach-O

    /// Offset and size both Int64.max: the out-of-bounds check added the two
    /// together before comparing, and the addition was the crash.
    func testFatSliceWithMaximumOffsetAndSizeIsReportedNotFatal() {
        var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBF]  // fat_magic_64
        bytes += be32(1)
        bytes += be32(0x0100_0007) + be32(0)
        bytes += be64(UInt64(Int64.max)) + be64(UInt64(Int64.max))
        bytes += be32(12) + be32(0)

        let output = ExecutableInspector()
            .inspect(probe: probe(Data(bytes), size: 1000), format: MagicBytes.machOFat)
        XCTAssertEqual(output.findings.map(\.rule), ["macho.sliceOutOfBounds"])
    }

    func testFatSliceBoundaryValuesAreSafe() {
        for (offset, size) in [
            (UInt64(0), UInt64(0)), (0, 1000), (1000, 0), (999, 1),
            (UInt64(Int64.max), 0), (0, UInt64(Int64.max)),
            (UInt64(Int64.max), UInt64(Int64.max)), (UInt64(UInt32.max), UInt64(UInt32.max)),
        ] {
            var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBF] + be32(1)
            bytes += be32(0x0100_0007) + be32(0) + be64(offset) + be64(size) + be32(12) + be32(0)
            _ = ExecutableInspector()
                .inspect(probe: probe(Data(bytes), size: 1000), format: MagicBytes.machOFat)
        }
    }

    // MARK: - The shared bounds check

    /// `fits` exists because `offset + count <= data.count` overflows for a
    /// large offset, making the bounds check itself the crash.
    func testFitsSurvivesExtremeOffsets() {
        let data = Data(repeating: 0, count: 16)
        XCTAssertFalse(ByteReader.fits(4, at: Int.max, in: data))
        XCTAssertFalse(ByteReader.fits(Int.max, at: 0, in: data))
        XCTAssertFalse(ByteReader.fits(4, at: -1, in: data))
        XCTAssertFalse(ByteReader.fits(-1, at: 0, in: data))
        XCTAssertTrue(ByteReader.fits(4, at: 12, in: data))
        XCTAssertFalse(ByteReader.fits(5, at: 12, in: data))
        XCTAssertTrue(ByteReader.fits(0, at: 16, in: data))
    }

    func testEveryReaderRefusesExtremeOffsets() {
        let data = Data(repeating: 0xAB, count: 32)
        for offset in [Int.max, Int.max - 1, -1, 33, 1_000_000] {
            XCTAssertNil(ByteReader.uint32BE(data, at: offset))
            XCTAssertNil(ByteReader.uint32LE(data, at: offset))
            XCTAssertNil(ByteReader.uint64BE(data, at: offset))
            XCTAssertNil(ByteReader.fourCC(data, at: offset))
            XCTAssertNil(ByteReader.byte(data, at: offset))
        }
        XCTAssertFalse(MagicBytes.hasBytes([0xAB], at: Int.max, in: data))
    }
}
