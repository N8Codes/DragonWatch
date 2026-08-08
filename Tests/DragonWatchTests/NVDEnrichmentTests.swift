import XCTest

@testable import DragonWatch

final class AppVersionTests: XCTestCase {

    func testNumericComparison() {
        // "2.10" must beat "2.9" — string comparison would get this wrong.
        XCTAssertTrue(AppVersion("2.9")! < AppVersion("2.10")!)
        XCTAssertTrue(AppVersion("1.2.3")! < AppVersion("1.3")!)
        XCTAssertEqual(AppVersion("1.2")!, AppVersion("1.2.0")!)
    }

    func testSuffixesAndGarbage() {
        XCTAssertEqual(AppVersion("1.2b3")!, AppVersion("1.2")!)
        XCTAssertNil(AppVersion("not a version"))
        XCTAssertNotNil(AppVersion("0.1"))
    }
}

final class CPEVersionRangeTests: XCTestCase {

    func testInclusiveAndExclusiveBounds() {
        let range = CPEVersionRange(
            startIncluding: "2.0", endExcluding: "3.0")
        XCTAssertTrue(range.contains(AppVersion("2.0")!))
        XCTAssertTrue(range.contains(AppVersion("2.9.9")!))
        XCTAssertFalse(range.contains(AppVersion("3.0")!))
        XCTAssertFalse(range.contains(AppVersion("1.9")!))
    }

    func testEndIncludingBoundary() {
        let range = CPEVersionRange(endIncluding: "5.1")
        XCTAssertTrue(range.contains(AppVersion("5.1")!))
        XCTAssertFalse(range.contains(AppVersion("5.1.1")!))
    }

    func testExactVersion() {
        let range = CPEVersionRange(exact: "4.2")
        XCTAssertTrue(range.contains(AppVersion("4.2")!))
        XCTAssertFalse(range.contains(AppVersion("4.2.1")!))
    }

    func testOpenEndedStart() {
        let range = CPEVersionRange(startExcluding: "1.0")
        XCTAssertFalse(range.contains(AppVersion("1.0")!))
        XCTAssertTrue(range.contains(AppVersion("99.0")!))
    }
}

final class NVDExtractionTests: XCTestCase {

    func testExtractsBoundedRangesAndSkipsNonVulnerable() throws {
        let json = """
            {"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","configurations":[
              {"nodes":[{"operator":"OR","cpeMatch":[
                {"vulnerable":true,
                 "criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                 "versionEndExcluding":"120.0.6099.109"},
                {"vulnerable":false,
                 "criteria":"cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"}
              ]}]}]}}]}
            """.data(using: .utf8)!
        let ranges = try NVDEnrichment.extractRanges(from: json)
        XCTAssertEqual(ranges, [CPEVersionRange(endExcluding: "120.0.6099.109")])
    }

    func testExactVersionFallsBackToCPEField() throws {
        let json = """
            {"vulnerabilities":[{"cve":{"id":"CVE-2024-0002","configurations":[
              {"nodes":[{"cpeMatch":[
                {"vulnerable":true,
                 "criteria":"cpe:2.3:a:vendor:tool:1.4.2:*:*:*:*:*:*:*"}
              ]}]}]}}]}
            """.data(using: .utf8)!
        let ranges = try NVDEnrichment.extractRanges(from: json)
        XCTAssertEqual(ranges, [CPEVersionRange(exact: "1.4.2")])
    }

    func testWildcardVersionWithoutBoundsProducesNoRange() throws {
        // "*" with no explicit bounds means NVD gave us nothing usable —
        // flagging every version would be dishonest.
        let json = """
            {"vulnerabilities":[{"cve":{"id":"CVE-2024-0003","configurations":[
              {"nodes":[{"cpeMatch":[
                {"vulnerable":true,
                 "criteria":"cpe:2.3:a:vendor:tool:*:*:*:*:*:*:*:*"}
              ]}]}]}}]}
            """.data(using: .utf8)!
        XCTAssertEqual(try NVDEnrichment.extractRanges(from: json), [])
    }

    func testMalformedFeedThrowsInsteadOfGuessing() {
        let garbage = "]]not json{{".data(using: .utf8)!
        XCTAssertThrowsError(try NVDEnrichment.extractRanges(from: garbage))
    }
}

final class KEVValidationTests: XCTestCase {

    private func entry(cve: String, product: String) -> KEVCatalog.Entry {
        KEVCatalog.Entry(
            cveID: cve, vendorProject: "V", product: product,
            vulnerabilityName: "N", dateAdded: "2024-01-01", shortDescription: "D")
    }

    func testDropsMalformedEntriesKeepsValid() {
        let validated = KEVCatalog.validated([
            entry(cve: "CVE-2024-1234", product: "Chrome"),
            entry(cve: "not-a-cve", product: "Chrome"),
            entry(cve: "CVE-2024-5678", product: ""),
        ])
        XCTAssertEqual(validated.map(\.cveID), ["CVE-2024-1234"])
    }
}
