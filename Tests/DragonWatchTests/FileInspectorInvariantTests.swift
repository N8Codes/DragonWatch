import XCTest

@testable import DragonWatch

/// The README promises three things about the inspector, "each enforced by
/// tests": nothing inspected is executed, nothing is handed to a system media
/// decoder, and no archive is extracted. This is that enforcement — a scan of
/// the inspector's own source for the imports and calls that would break them.
/// It is a blunt instrument on purpose: the historical attack surface for a
/// malicious image is the decoder, and the only reliable way to keep it out
/// is to fail the build the moment it appears.
final class FileInspectorInvariantTests: XCTestCase {

    private static var inspectorSources: [URL] {
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/DragonWatch/Core/FileInspector")
        let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        var files: [URL] = []
        while let url = enumerator?.nextObject() as? URL {
            if url.pathExtension == "swift" { files.append(url) }
        }
        return files.sorted { $0.path < $1.path }
    }

    private func offences(matching needles: [String], allow: (URL) -> Bool = { _ in false }) throws
        -> [String]
    {
        var found: [String] = []
        for url in Self.inspectorSources where !allow(url) {
            let text = try String(contentsOf: url, encoding: .utf8)
            for needle in needles where text.contains(needle) {
                found.append("\(url.lastPathComponent): \(needle)")
            }
        }
        return found
    }

    func testTheScanSeesTheInspectorSources() {
        let names = Self.inspectorSources.map(\.lastPathComponent)
        XCTAssertTrue(names.contains("InspectionEngine.swift"), "\(names)")
        XCTAssertGreaterThan(names.count, 15)
    }

    /// Rule 2: no system media decoder. ImageIO, AVFoundation and friends
    /// parse hostile bytes with privileged, historically exploitable code.
    func testNoMediaDecoderIsImportedOrCalled() throws {
        let imports = [
            "import ImageIO", "import AVFoundation", "import AVKit", "import PDFKit",
            "import CoreImage", "import Vision", "import QuickLook",
            "import QuickLookThumbnailing", "import WebKit",
        ]
        let calls = [
            "CGImageSource", "NSImage(", "CIImage(", "AVAsset", "AVURLAsset", "PDFDocument(",
            "NSBitmapImageRep", "QLThumbnail", "WKWebView",
        ]
        XCTAssertEqual(try offences(matching: imports + calls), [])
        // AppKit is drawing the *report*, in one file, and nowhere else.
        let appKit = try offences(matching: ["import AppKit", "import Cocoa"])
        XCTAssertEqual(appKit, ["ReportRenderer.swift: import AppKit"])
    }

    /// Rule 1: nothing inspected is executed, opened, or launched.
    func testNothingIsExecutedOrOpened() throws {
        let needles = [
            "Process(", "NSTask", "posix_spawn", "system(", "popen(", "execv", "NSWorkspace",
            "LSOpen", "NSAppleScript", "dlopen(", "Bundle(url", "Bundle(path",
        ]
        XCTAssertEqual(try offences(matching: needles), [])
    }

    /// Rule 3: no archive is extracted, and nothing is inflated or written.
    func testNothingIsExtractedInflatedOrWritten() throws {
        let needles = [
            "import Compression", "compression_decode", "compression_stream", "import zlib",
            "inflate(", "unzip", "NSFileCoordinator", ".write(to", "createFile(",
            "createDirectory(", "removeItem(", "copyItem(", "moveItem(",
        ]
        XCTAssertEqual(try offences(matching: needles), [])
    }

    /// Whole-file reads defeat the bounded-window design; only the hasher
    /// streams, and it lives outside this directory.
    func testNoWholeFileReads() throws {
        let needles = ["Data(contentsOf", "String(contentsOf", "readDataToEndOfFile", "readToEnd("]
        XCTAssertEqual(try offences(matching: needles), [])
    }
}
