import Foundation

/// Bounds-checked reads over a window of a file.
///
/// Every parser here reads attacker-controlled bytes, so there is one
/// implementation of "read an integer at an offset" and it returns `nil`
/// rather than trapping. Offsets resolve against `startIndex`, so a `Data`
/// slice works.
enum ByteReader {

    /// Whether `count` bytes are readable at `offset`. A subtraction, not
    /// `offset + count <= data.count`: that addition overflows for a large
    /// offset, making the bounds check itself the crash.
    static func fits(_ count: Int, at offset: Int, in data: Data) -> Bool {
        offset >= 0 && count >= 0 && data.count >= count && offset <= data.count - count
    }

    static func byte(_ data: Data, at offset: Int) -> UInt8? {
        guard offset >= 0, offset < data.count else { return nil }
        return data[data.startIndex + offset]
    }

    static func uint16BE(_ data: Data, at offset: Int) -> UInt16? {
        guard let high = byte(data, at: offset), let low = byte(data, at: offset + 1) else {
            return nil
        }
        return UInt16(high) << 8 | UInt16(low)
    }

    static func uint32BE(_ data: Data, at offset: Int) -> UInt32? {
        guard fits(4, at: offset, in: data) else { return nil }
        let base = data.startIndex + offset
        return UInt32(data[base]) << 24 | UInt32(data[base + 1]) << 16
            | UInt32(data[base + 2]) << 8 | UInt32(data[base + 3])
    }

    static func uint32LE(_ data: Data, at offset: Int) -> UInt32? {
        guard fits(4, at: offset, in: data) else { return nil }
        let base = data.startIndex + offset
        return UInt32(data[base]) | UInt32(data[base + 1]) << 8
            | UInt32(data[base + 2]) << 16 | UInt32(data[base + 3]) << 24
    }

    static func uint16LE(_ data: Data, at offset: Int) -> UInt16? {
        guard let low = byte(data, at: offset), let high = byte(data, at: offset + 1) else {
            return nil
        }
        return UInt16(high) << 8 | UInt16(low)
    }

    static func uint64BE(_ data: Data, at offset: Int) -> UInt64? {
        guard fits(8, at: offset, in: data) else { return nil }
        let base = data.startIndex + offset
        var value: UInt64 = 0
        for index in 0..<8 { value = value << 8 | UInt64(data[base + index]) }
        return value
    }

    /// Four-character box and chunk types, as ASCII. Returns `nil` rather than
    /// a replacement-character string when the bytes are not printable, so a
    /// caller cannot mistake binary noise for a type it recognises.
    static func fourCC(_ data: Data, at offset: Int) -> String? {
        guard fits(4, at: offset, in: data) else { return nil }
        let base = data.startIndex + offset
        var scalars = ""
        for index in 0..<4 {
            let value = data[base + index]
            guard value >= 0x20, value < 0x7F else { return nil }
            scalars.append(Character(UnicodeScalar(value)))
        }
        return scalars
    }

}

/// Where the file's own structure says it ends, and therefore whether
/// anything rides along after it. The generic scan samples two 64 KB windows;
/// a format that declares its own length answers exactly, at any size.
struct ContainerExtent: Sendable {
    /// Byte offset one past the last byte the format accounts for.
    let logicalEnd: Int64
    /// How the end was established, for the finding text.
    let evidence: String

    func trailingBytes(fileSize: Int64) -> Int64 { max(0, fileSize - logicalEnd) }

}
