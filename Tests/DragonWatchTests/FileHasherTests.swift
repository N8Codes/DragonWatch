import CryptoKit
import XCTest

@testable import DragonWatch

final class FileHasherTests: XCTestCase {

    func testKnownDigest() async throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("FileHasherTests-\(UUID().uuidString)")
        try "hello world".data(using: .utf8)!.write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }

        let digest = await FileHasher().sha256(ofPath: file.path)
        XCTAssertEqual(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    }

    func testMissingFileReturnsNil() async {
        let digest = await FileHasher().sha256(ofPath: "/nonexistent/binary")
        XCTAssertNil(digest)
    }

    /// Multi-chunk files exercise the streaming loop, which must release each
    /// 1 MB chunk as it goes. Without the autoreleasepool this produced a
    /// correct digest while retaining the entire file in memory — correctness
    /// alone would not have caught it, so this pins the digest across the
    /// chunk boundary.
    func testMultiChunkFileHashesCorrectly() async throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("FileHasherChunk-\(UUID().uuidString)")
        // 2.5 MB: three reads, the last one short.
        let block = Data(repeating: 0x41, count: 1 << 20)
        try (block + block + block.prefix(1 << 19)).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }

        let streamed = await FileHasher().sha256(ofPath: file.path)

        // Independent path: hash the whole buffer in one shot. A loop that
        // drops, repeats, or truncates a chunk disagrees with this.
        let contents = try Data(contentsOf: file)
        let oneShot = SHA256.hash(data: contents)
            .map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(streamed, oneShot, "streamed digest must match one-shot")
        XCTAssertEqual(streamed?.count, 64)
    }
}
