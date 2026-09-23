import Foundation

/// Structural reading of Mach-O files.
///
/// Its first job is subtractive. A universal ("fat") binary is a container of
/// thin Mach-O slices, so the generic embedded-signature scan finds a Mach-O
/// magic at every slice offset and reports each one as a passenger. Those
/// offsets are listed in the file's own architecture table, so they can be
/// recognised and excluded rather than reported — a false positive that
/// inflates the finding count is exactly what teaches people to ignore it.
///
/// Parsing only. Nothing here executes the file, and signature checking stays
/// with `SignatureInspector`, which already owns it.
struct ExecutableInspector: FormatInspector {

    /// Fat headers are always big-endian on disk, whatever the slices are.
    static let fatMagic32: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
    static let fatMagic64: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBF]

    /// A real universal binary has a handful of slices. A large count means a
    /// malformed or hostile header, and the table is not trusted past it.
    static let maxArchitectures = 32

    func handles(_ format: FileFormat) -> Bool {
        format.family == .executable
    }

    /// Offsets the generic scan should not treat as passengers, because the
    /// file's own architecture table accounts for them.
    func knownEmbeddedOffsets(probe: FileProbe, format: FileFormat) -> Set<Int64> {
        Set(Self.architectures(in: probe).map(\.offset))
    }

    func inspect(probe: FileProbe, format: FileFormat) -> InspectorOutput {
        var output = InspectorOutput()
        output.checks.append("Mach-O architecture table")
        let slices = Self.architectures(in: probe)
        guard !slices.isEmpty else { return output }

        let names = slices.map(\.name).joined(separator: ", ")
        output.disclosures.append(
            Disclosure(
                title: "Universal binary",
                detail: "Contains \(slices.count) architecture"
                    + "\(slices.count == 1 ? "" : "s"): \(names)."))

        // A slice claiming to run past the end of the file is a malformed
        // header, and the arithmetic that reads it is the arithmetic an
        // attacker would aim at.
        // Overflow-reporting: a header declaring an Int64.max offset and size
        // traps on the plain addition, crashing the app on a crafted file.
        if let bad = slices.first(where: { slice in
            let (end, overflowed) = slice.offset.addingReportingOverflow(slice.size)
            return overflowed || end > probe.size
        }) {
            output.findings.append(
                Finding(
                    rule: "macho.sliceOutOfBounds",
                    severity: .inconsistent,
                    title: "Architecture slice extends past the end of the file",
                    detail:
                        "The header describes a \(bad.name) slice of \(bad.size) bytes at byte "
                        + "\(bad.offset), but the file is only \(probe.size) bytes. The header "
                        + "does not describe this file."))
        }
        return output
    }

    // MARK: - Fat header

    struct Architecture: Sendable, Hashable {
        let name: String
        let offset: Int64
        let size: Int64
    }

    /// Parses the architecture table, or returns empty for a thin Mach-O,
    /// a Java class file, or anything malformed.
    ///
    /// Every field is bounds-checked against the head window before it is
    /// read; a truncated or lying header yields no architectures rather than
    /// a trap.
    static func architectures(in probe: FileProbe) -> [Architecture] {
        let head = probe.head
        let is64: Bool
        if MagicBytes.hasBytes(fatMagic64, at: 0, in: head) {
            is64 = true
        } else if MagicBytes.hasBytes(fatMagic32, at: 0, in: head) {
            is64 = false
        } else {
            return []
        }

        guard let count = ByteReader.uint32BE(head, at: 4), count > 0, count <= maxArchitectures
        else {
            return []
        }

        // fat_arch is 20 bytes; fat_arch_64 is 32.
        let entrySize = is64 ? 32 : 20
        var architectures: [Architecture] = []
        for index in 0..<Int(count) {
            let base = 8 + index * entrySize
            guard let cpuType = ByteReader.uint32BE(head, at: base) else { break }
            let offset: Int64
            let size: Int64
            if is64 {
                guard let rawOffset = ByteReader.uint64BE(head, at: base + 8),
                    let rawSize = ByteReader.uint64BE(head, at: base + 16),
                    rawOffset <= UInt64(Int64.max), rawSize <= UInt64(Int64.max)
                else { break }
                offset = Int64(rawOffset)
                size = Int64(rawSize)
            } else {
                guard let rawOffset = ByteReader.uint32BE(head, at: base + 8),
                    let rawSize = ByteReader.uint32BE(head, at: base + 12)
                else { break }
                offset = Int64(rawOffset)
                size = Int64(rawSize)
            }
            architectures.append(
                Architecture(name: cpuName(cpuType), offset: offset, size: size))
        }
        return architectures
    }

    /// `CPU_ARCH_ABI64` is the high bit of the cputype; the low bits are the
    /// family. Unknown families are reported by number rather than guessed at.
    static func cpuName(_ cpuType: UInt32) -> String {
        switch cpuType {
        case 0x0100_0007: return "x86_64"
        case 0x0000_0007: return "i386"
        case 0x0100_000C: return "arm64"
        case 0x0000_000C: return "arm"
        case 0x0200_000C: return "arm64_32"
        case 0x0100_0012: return "ppc64"
        case 0x0000_0012: return "ppc"
        default: return "cputype \(cpuType)"
        }
    }

}
