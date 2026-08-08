import AppKit

enum DisplayInfo {
    /// One entry per screen: pixel resolution @ current maximum refresh rate.
    /// (macOS exposes no global "system FPS" — refresh rate is the honest stat.)
    @MainActor
    static func current() -> [String] {
        NSScreen.screens.map { screen in
            let pixels = screen.convertRectToBacking(screen.frame)
            return "\(Int(pixels.width))×\(Int(pixels.height)) @ \(screen.maximumFramesPerSecond)Hz"
        }
    }
}
