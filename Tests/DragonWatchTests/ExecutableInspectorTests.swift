import XCTest

@testable import DragonWatch

final class ExecutableInspectorTests: XCTestCase {

    private let machO64: [UInt8] = [0xCF, 0xFA, 0xED, 0xFE]

    private func be32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF),
            UInt8(value & 0xFF),
        ]
    }
    private func be64(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(value >> (8 * UInt64($0)) & 0xFF) }
    }

    /// A 32-bit fat header with `slices` architectures, each pointing at a
    /// thin Mach-O placed at its declared offset.
    private func fatBinary(slices: [(cpu: UInt32, offset: UInt32, size: UInt32)]) -> Data {
        var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
        bytes += be32(UInt32(slices.count))
        for slice in slices {
            bytes += be32(slice.cpu)  // cputype
            bytes += be32(0)  // cpusubtype
            bytes += be32(slice.offset)
            bytes += be32(slice.size)
            bytes += be32(12)  // align
        }
        let total = Int(slices.map { $0.offset + $0.size }.max() ?? 0)
        var data = Data(bytes)
        data.append(Data(repeating: 0, count: max(0, total - data.count)))
        for slice in slices {
            data.replaceSubrange(
                Int(slice.offset)..<(Int(slice.offset) + machO64.count), with: machO64)
        }
        return data
    }

    private func probe(_ data: Data, name: String = "tool") -> FileProbe {
        FileProbe(
            path: "/tmp/\(name)", displayName: name, size: Int64(data.count),
            head: data, tail: data, tailOffset: 0, isDirectory: false, isSymbolicLink: false,
            posixPermissions: 0o755, quarantine: nil, whereFrom: [], readError: nil,
            partialRead: false)
    }

    // MARK: - The false positive this class exists to remove

    /// A universal binary's own slices were being reported as embedded
    /// Mach-O passengers — one bogus finding per architecture, on every fat
    /// binary on the machine.
    func testArchitectureSlicesAreNotReportedAsEmbeddedPayloads() {
        let data = fatBinary(slices: [
            (cpu: 0x0100_0007, offset: 4096, size: 1024),
            (cpu: 0x0100_000C, offset: 8192, size: 1024),
        ])
        let subject = probe(data)
        let inspector = ExecutableInspector()
        let accounted = inspector.knownEmbeddedOffsets(
            probe: subject, format: MagicBytes.machOFat)

        XCTAssertEqual(accounted, [4096, 8192])

        let withoutKnowledge = UniversalChecks.embeddedSignatures(
            probe: subject, identified: MagicBytes.machOFat)
        XCTAssertFalse(
            withoutKnowledge.isEmpty,
            "precondition: the generic scan does see the slices")

        let withKnowledge = UniversalChecks.embeddedSignatures(
            probe: subject, identified: MagicBytes.machOFat,
            accountedForOffsets: accounted)
        XCTAssertTrue(
            withKnowledge.filter { $0.title.contains("Mach-O") }.isEmpty,
            "slices listed in the file's own architecture table are not passengers")
    }

    /// The suppression must be exact. A payload at an offset the header does
    /// *not* declare is still reported.
    func testUndeclaredPayloadInAFatBinaryIsStillReported() {
        var data = fatBinary(slices: [(cpu: 0x0100_0007, offset: 4096, size: 1024)])
        data.append(Data(repeating: 0, count: 2048))
        let stowawayAt = data.count - 512
        data.replaceSubrange(
            stowawayAt..<(stowawayAt + 4), with: Data([0x50, 0x4B, 0x03, 0x04]))

        let subject = probe(data)
        let inspector = ExecutableInspector()
        let findings = UniversalChecks.embeddedSignatures(
            probe: subject, identified: MagicBytes.machOFat,
            accountedForOffsets: inspector.knownEmbeddedOffsets(
                probe: subject, format: MagicBytes.machOFat))

        XCTAssertTrue(findings.contains { $0.title.contains("ZIP") })
    }

    func testArchitecturesAreNamedInADisclosure() {
        let data = fatBinary(slices: [
            (cpu: 0x0100_0007, offset: 4096, size: 16),
            (cpu: 0x0100_000C, offset: 8192, size: 16),
        ])
        let output = ExecutableInspector().inspect(
            probe: probe(data), format: MagicBytes.machOFat)

        XCTAssertEqual(output.disclosures.count, 1)
        XCTAssertTrue(output.disclosures[0].detail.contains("x86_64"))
        XCTAssertTrue(output.disclosures[0].detail.contains("arm64"))
        XCTAssertTrue(output.findings.isEmpty)
    }

    // MARK: - Malformed headers

    func testSliceRunningPastEndOfFileIsInconsistent() {
        var data = fatBinary(slices: [(cpu: 0x0100_0007, offset: 4096, size: 16)])
        data = data.prefix(2048)  // truncate so the slice no longer fits
        let output = ExecutableInspector().inspect(
            probe: probe(data), format: MagicBytes.machOFat)

        XCTAssertEqual(output.findings.map(\.rule), ["macho.sliceOutOfBounds"])
        XCTAssertEqual(output.findings[0].severity, .inconsistent)
    }

    func testAbsurdArchitectureCountIsRefused() {
        var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
        bytes += be32(0xFFFF_FFFF)
        bytes += [UInt8](repeating: 0, count: 256)
        XCTAssertTrue(ExecutableInspector.architectures(in: probe(Data(bytes))).isEmpty)
    }

    func testTruncatedFatHeaderYieldsNoArchitectures() {
        for length in 0..<28 {
            var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
            bytes += be32(2)
            bytes += [UInt8](repeating: 0x11, count: max(0, length - 8))
            // Must not trap on any prefix length.
            _ = ExecutableInspector.architectures(in: probe(Data(bytes.prefix(length))))
        }
    }

    func testThinMachOHasNoArchitectureTable() {
        let thin = Data(machO64 + [UInt8](repeating: 0, count: 256))
        XCTAssertTrue(ExecutableInspector.architectures(in: probe(thin)).isEmpty)
        XCTAssertTrue(
            ExecutableInspector().inspect(probe: probe(thin), format: MagicBytes.machO)
                .disclosures.isEmpty)
    }

    /// A Java class file shares the `CAFEBABE` magic. Its version fields must
    /// not be read as an architecture count.
    func testJavaClassIsNotParsedAsAFatBinary() {
        let java = Data(
            [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]
                + [UInt8](repeating: 0x20, count: 256))
        XCTAssertEqual(MagicBytes.identify(head: java)?.name, "Java class")
        // 0x34 = 52 architectures, past the sanity cap.
        XCTAssertTrue(ExecutableInspector.architectures(in: probe(java)).isEmpty)
    }

    func testFat64HeaderIsParsed() {
        var bytes: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBF]
        bytes += be32(1)
        bytes += be32(0x0100_000C)  // cputype arm64
        bytes += be32(0)  // cpusubtype
        bytes += be64(16384)  // offset
        bytes += be64(512)  // size
        bytes += be32(14)  // align
        bytes += be32(0)  // reserved
        var data = Data(bytes)
        data.append(Data(repeating: 0, count: 16384 + 512 - data.count))

        let slices = ExecutableInspector.architectures(in: probe(data))
        XCTAssertEqual(slices.count, 1)
        XCTAssertEqual(slices[0].name, "arm64")
        XCTAssertEqual(slices[0].offset, 16384)
        XCTAssertEqual(slices[0].size, 512)
    }

    // MARK: - Against a real binary on this machine

    /// The regression in its original form: a real system binary inspected
    /// end to end must not report its own slices.
    func testRealSystemBinaryReportsNoEmbeddedPayloads() async throws {
        let path = "/bin/echo"
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "no /bin/echo")

        let report = await InspectionEngine().inspect(paths: [path])
        let file = report.files[0]
        try XCTSkipUnless(
            file.identifiedFormat == "Mach-O universal binary",
            "/bin/echo is thin on this machine; the fat path is untestable here")

        XCTAssertTrue(
            file.findings.filter { $0.rule == "embedded.signature" }.isEmpty,
            "a stock universal binary must produce no embedded-payload findings, got: "
                + file.findings.map(\.title).joined(separator: "; "))
        XCTAssertTrue(file.disclosures.contains { $0.title == "Universal binary" })
    }
}
