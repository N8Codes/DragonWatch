import Foundation

/// A CBOR value (RFC 8949), as much of it as a manifest needs.
indirect enum CBORValue: Sendable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    /// Pairs rather than a dictionary: CBOR permits duplicate and non-text
    /// keys, and silently collapsing them would be a decision the decoder has
    /// no business making.
    case map([(key: CBORValue, value: CBORValue)])
    case tagged(UInt64, CBORValue)
    case boolean(Bool)
    case null

    /// Value for a text key, first match wins.
    subscript(key: String) -> CBORValue? {
        guard case .map(let pairs) = self else { return nil }
        for pair in pairs {
            if case .text(let name) = pair.key, name == key { return pair.value }
        }
        return nil
    }

    var textValue: String? {
        if case .text(let value) = self { return value }
        return nil
    }

    var arrayValue: [CBORValue]? {
        if case .array(let items) = self { return items }
        return nil
    }
}

/// A bounded CBOR decoder.
///
/// Written because the alternative — searching the raw bytes for a key and
/// reading whatever followed — cannot tell which map a key belonged to, and
/// worse, cannot tell a real manifest from the same bytes planted anywhere
/// else in the file. Provenance that an attacker can forge by adding a comment
/// is not provenance.
///
/// Every limit below exists because the input is a file nobody trusts:
/// a declared length is a claim, not a fact, so nothing is allocated on the
/// strength of one, and every container checks that it could not possibly fit
/// in the bytes remaining before it reserves anything.
enum CBOR {
    /// Deep enough for any real manifest; shallow enough that the recursive
    /// descent cannot exhaust the stack.
    static let maxDepth = 24
    /// Total items across the whole document, so a nest of small containers
    /// cannot multiply into a long decode.
    static let maxItems = 50_000
    /// Longest text or byte string kept. A manifest field is short; anything
    /// past this is refused rather than held in memory.
    static let maxStringBytes = 1 << 16

    struct Cursor {
        var offset: Int
        var items: Int
    }

    static func decode(_ data: Data) -> CBORValue? {
        var cursor = Cursor(offset: 0, items: 0)
        guard let value = decodeValue(data, &cursor, depth: 0) else { return nil }
        return value
    }

    // MARK: - One value

    private static func decodeValue(_ data: Data, _ cursor: inout Cursor, depth: Int)
        -> CBORValue?
    {
        guard depth <= maxDepth, cursor.items < maxItems,
            let header = ByteReader.byte(data, at: cursor.offset)
        else { return nil }
        cursor.items += 1
        cursor.offset += 1

        let major = header >> 5
        let additional = header & 0x1F

        // Indefinite-length items are legal CBOR and are not produced by any
        // manifest writer; refusing them removes the break-marker state
        // machine rather than carrying untested code.
        guard additional != 31 else { return nil }

        guard let argument = decodeArgument(data, &cursor, additional: additional) else {
            return nil
        }

        switch major {
        case 0:
            return .unsigned(argument)
        case 1:
            guard argument <= UInt64(Int64.max) else { return nil }
            return .negative(-1 - Int64(argument))
        case 2, 3:
            guard argument <= UInt64(maxStringBytes),
                let length = Int(exactly: argument),
                ByteReader.fits(length, at: cursor.offset, in: data)
            else { return nil }
            let start = data.startIndex + cursor.offset
            let slice = data[start..<(start + length)]
            cursor.offset += length
            if major == 2 { return .bytes(Data(slice)) }
            guard let text = String(data: slice, encoding: .utf8) else { return nil }
            return .text(text)
        case 4:
            guard let count = boundedCount(argument, data: data, cursor: cursor) else {
                return nil
            }
            var items: [CBORValue] = []
            items.reserveCapacity(count)
            for _ in 0..<count {
                guard let item = decodeValue(data, &cursor, depth: depth + 1) else { return nil }
                items.append(item)
            }
            return .array(items)
        case 5:
            // Each pair needs at least two bytes, so halve the headroom.
            guard let count = boundedCount(argument, data: data, cursor: cursor, bytesPerItem: 2)
            else { return nil }
            var pairs: [(key: CBORValue, value: CBORValue)] = []
            pairs.reserveCapacity(count)
            for _ in 0..<count {
                guard let key = decodeValue(data, &cursor, depth: depth + 1),
                    let value = decodeValue(data, &cursor, depth: depth + 1)
                else { return nil }
                pairs.append((key, value))
            }
            return .map(pairs)
        case 6:
            guard let inner = decodeValue(data, &cursor, depth: depth + 1) else { return nil }
            return .tagged(argument, inner)
        case 7:
            switch additional {
            case 20: return .boolean(false)
            case 21: return .boolean(true)
            case 22, 23: return .null
            // Floats carry no information this reader uses, and skipping them
            // correctly still needs their width consumed, which
            // `decodeArgument` already did.
            default: return .null
            }
        default:
            return nil
        }
    }

    /// The integer argument encoded in the header, or following it.
    private static func decodeArgument(
        _ data: Data, _ cursor: inout Cursor, additional: UInt8
    ) -> UInt64? {
        switch additional {
        case 0...23:
            return UInt64(additional)
        case 24:
            guard let value = ByteReader.byte(data, at: cursor.offset) else { return nil }
            cursor.offset += 1
            return UInt64(value)
        case 25:
            guard let value = ByteReader.uint16BE(data, at: cursor.offset) else { return nil }
            cursor.offset += 2
            return UInt64(value)
        case 26:
            guard let value = ByteReader.uint32BE(data, at: cursor.offset) else { return nil }
            cursor.offset += 4
            return UInt64(value)
        case 27:
            guard let value = ByteReader.uint64BE(data, at: cursor.offset) else { return nil }
            cursor.offset += 8
            return value
        default:
            return nil
        }
    }

    /// A container's declared length, refused when the bytes left could not
    /// possibly hold that many items.
    ///
    /// This is the memory-exhaustion guard: without it a five-byte input
    /// declaring four billion entries would reserve capacity for all of them.
    private static func boundedCount(
        _ argument: UInt64, data: Data, cursor: Cursor, bytesPerItem: Int = 1
    ) -> Int? {
        guard let count = Int(exactly: argument), count >= 0 else { return nil }
        let remaining = data.count - cursor.offset
        guard remaining >= 0, count <= remaining / bytesPerItem,
            cursor.items + count <= maxItems
        else { return nil }
        return count
    }
}
