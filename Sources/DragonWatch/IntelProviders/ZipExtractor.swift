import Compression
import Foundation

/// Minimal single-entry ZIP reader for the MalwareBazaar full dump — one text
/// file, stored or deflated. Sizes come from the central directory and are
/// checked against the caller's cap before any allocation, so a hostile
/// archive can claim whatever it likes and still not exhaust memory.
enum ZipExtractor {
    enum ZipError: Error {
        case malformed
        case unsupported
        case tooLarge
    }

    static func extractFirstEntry(from zip: Data, decompressedByteCap: Int) throws -> Data {
        // End-of-central-directory record: scan the trailing 64 KB for its
        // signature (the spec allows a comment after it).
        let eocdSignature: UInt32 = 0x0605_4b50
        guard zip.count >= 22 else { throw ZipError.malformed }
        var eocdOffset = -1
        let scanStart = max(0, zip.count - 22 - 65_536)
        for offset in stride(from: zip.count - 22, through: scanStart, by: -1)
        where readU32(zip, offset) == eocdSignature {
            eocdOffset = offset
            break
        }
        guard eocdOffset >= 0 else { throw ZipError.malformed }

        let entryCount = Int(readU16(zip, eocdOffset + 10))
        let directoryOffset = Int(readU32(zip, eocdOffset + 16))
        guard entryCount >= 1, directoryOffset + 46 <= zip.count,
            readU32(zip, directoryOffset) == 0x0201_4b50
        else { throw ZipError.malformed }

        let method = readU16(zip, directoryOffset + 10)
        let compressedSize = Int(readU32(zip, directoryOffset + 20))
        let uncompressedSize = Int(readU32(zip, directoryOffset + 24))
        let localOffset = Int(readU32(zip, directoryOffset + 42))
        // 0xFFFFFFFF sizes mean zip64, which a ~40 MB feed never needs.
        guard compressedSize != 0xFFFF_FFFF, uncompressedSize != 0xFFFF_FFFF,
            localOffset != 0xFFFF_FFFF
        else { throw ZipError.unsupported }
        guard uncompressedSize <= decompressedByteCap else { throw ZipError.tooLarge }

        guard localOffset + 30 <= zip.count, readU32(zip, localOffset) == 0x0403_4b50
        else { throw ZipError.malformed }
        let nameLength = Int(readU16(zip, localOffset + 26))
        let extraLength = Int(readU16(zip, localOffset + 28))
        let dataStart = localOffset + 30 + nameLength + extraLength
        guard dataStart + compressedSize <= zip.count else { throw ZipError.malformed }
        // startIndex-relative, like readU16/readU32 — a Data slice carries a
        // non-zero startIndex and raw offsets would read the wrong bytes.
        let from = zip.startIndex + dataStart
        let compressed = zip.subdata(in: from..<from + compressedSize)

        switch method {
        case 0:  // stored
            guard compressed.count == uncompressedSize else { throw ZipError.malformed }
            return compressed
        case 8:  // deflate (Compression's ZLIB algorithm is raw DEFLATE)
            var output = Data(count: uncompressedSize)
            let written = output.withUnsafeMutableBytes { destination in
                compressed.withUnsafeBytes { source in
                    compression_decode_buffer(
                        destination.bindMemory(to: UInt8.self).baseAddress!,
                        uncompressedSize,
                        source.bindMemory(to: UInt8.self).baseAddress!,
                        compressed.count,
                        nil, COMPRESSION_ZLIB)
                }
            }
            guard written == uncompressedSize else { throw ZipError.malformed }
            return output
        default:
            throw ZipError.unsupported
        }
    }

    private static func readU16(_ data: Data, _ offset: Int) -> UInt16 {
        UInt16(data[data.startIndex + offset])
            | UInt16(data[data.startIndex + offset + 1]) << 8
    }

    private static func readU32(_ data: Data, _ offset: Int) -> UInt32 {
        var value: UInt32 = 0
        for i in (0..<4).reversed() {
            value = value << 8 | UInt32(data[data.startIndex + offset + i])
        }
        return value
    }
}
