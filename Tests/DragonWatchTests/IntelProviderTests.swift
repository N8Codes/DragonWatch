import CryptoKit
import XCTest

@testable import DragonWatch

final class KEVMatcherTests: XCTestCase {

    private func entry(vendor: String, product: String, cve: String = "CVE-2024-0001")
        -> KEVCatalog.Entry
    {
        KEVCatalog.Entry(
            cveID: cve, vendorProject: vendor, product: product,
            vulnerabilityName: "Test", dateAdded: "2024-01-01",
            shortDescription: "Test")
    }

    func testExactMatchIsCaseInsensitive() {
        let entries = [entry(vendor: "Google", product: "chrome")]
        XCTAssertEqual(KEVMatcher.matches(appName: "Chrome", in: entries).count, 1)
    }

    func testProductContainedInAppName() {
        // KEV lists product "Chrome"; the app on disk is "Google Chrome.app".
        let entries = [entry(vendor: "Google", product: "Chrome")]
        XCTAssertEqual(KEVMatcher.matches(appName: "Google Chrome", in: entries).count, 1)
    }

    func testAppNameContainedInProduct() {
        let entries = [entry(vendor: "Microsoft", product: "Microsoft Word")]
        XCTAssertEqual(KEVMatcher.matches(appName: "Word", in: entries).count, 0)
        XCTAssertEqual(
            KEVMatcher.matches(appName: "Microsoft Word", in: entries).count, 1)
    }

    func testShortProductNamesNeedExactMatch() {
        // 4-char products only match exactly, never by containment — "Word"
        // must not light up "Wordle".
        let entries = [entry(vendor: "Microsoft", product: "Word")]
        XCTAssertEqual(KEVMatcher.matches(appName: "Wordle", in: entries).count, 0)
        XCTAssertEqual(KEVMatcher.matches(appName: "Word", in: entries).count, 1)
    }

    func testUnrelatedProductDoesNotMatch() {
        let entries = [entry(vendor: "Adobe", product: "ColdFusion")]
        XCTAssertTrue(KEVMatcher.matches(appName: "Safari", in: entries).isEmpty)
    }

    func testMultipleEntriesForOneProductAllReturned() {
        let entries = [
            entry(vendor: "Google", product: "Chrome", cve: "CVE-2024-0001"),
            entry(vendor: "Google", product: "Chrome", cve: "CVE-2024-0002"),
            entry(vendor: "Adobe", product: "ColdFusion", cve: "CVE-2024-0003"),
        ]
        XCTAssertEqual(
            KEVMatcher.matches(appName: "Google Chrome", in: entries).map(\.cveID),
            ["CVE-2024-0001", "CVE-2024-0002"])
    }
}

final class VirusTotalReportTests: XCTestCase {

    func testDecodesRealResponseShape() throws {
        let json = """
            {"data":{"id":"abc","type":"file","attributes":{
                "last_analysis_stats":{
                    "malicious":2,"suspicious":1,"undetected":60,"harmless":10,
                    "timeout":0,"confirmed-timeout":0,"failure":0,"type-unsupported":4}}}}
            """.data(using: .utf8)!
        let stats = try JSONDecoder().decode(VTFileReport.self, from: json)
            .data.attributes.lastAnalysisStats
        XCTAssertEqual(stats.malicious, 2)
        XCTAssertEqual(stats.totalEngines, 73)
    }

    func testSeverityMapping() {
        func stats(malicious: Int, suspicious: Int) -> VTFileReport.Stats {
            VTFileReport.Stats(
                malicious: malicious, suspicious: suspicious,
                undetected: 50, harmless: 10)
        }
        XCTAssertEqual(
            VTFileReport.severity(for: stats(malicious: 1, suspicious: 0)), .critical)
        XCTAssertEqual(
            VTFileReport.severity(for: stats(malicious: 0, suspicious: 3)), .warning)
        XCTAssertEqual(
            VTFileReport.severity(for: stats(malicious: 0, suspicious: 0)),
            .informational)
    }
}

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
