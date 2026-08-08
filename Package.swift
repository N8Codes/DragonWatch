// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DragonWatch",
    platforms: [.macOS(.v14)],
    targets: [
        // C shim exposing libproc / mach APIs to Swift.
        .target(name: "CDragonWatch"),
        .executableTarget(
            name: "DragonWatch",
            dependencies: ["CDragonWatch"]
        ),
        .testTarget(
            name: "DragonWatchTests",
            dependencies: ["DragonWatch"]
        ),
    ]
)
