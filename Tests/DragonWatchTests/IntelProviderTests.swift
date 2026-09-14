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
