import SwiftUI

/// The app's type scale, in one place.
///
/// SwiftUI's semantic fonts put most of this app's text at 10–12 pt, which is
/// hard to read in a popover you glance at. Routing every size through here
/// makes "bigger" one number instead of an edit in fifteen files. The
/// smallest sizes are lifted most: 10 pt captions carried most of the detail.
enum AppText {

    /// One knob. 1.0 reproduces the system sizes.
    static let scale: CGFloat = 1.15

    private static func sized(_ points: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: (points * scale).rounded(), weight: weight)
    }

    /// Hashes, byte counts, timestamps.
    static var caption2: Font { sized(11) }
    /// Secondary detail under a row, and rule rationales.
    static var caption: Font { sized(12) }
    static var footnote: Font { sized(12) }
    /// List rows and body copy in dense panels.
    static var callout: Font { sized(13) }
    static var body: Font { sized(14) }
    static var headline: Font { sized(14, .semibold) }
    static var title3: Font { sized(16, .semibold) }
    static var title2: Font { sized(18, .semibold) }

    /// Monospaced, for digests and magic bytes.
    static var monoCaption: Font { .system(size: (11 * scale).rounded(), design: .monospaced) }
    static var monoCaption2: Font { .system(size: (10 * scale).rounded(), design: .monospaced) }

    /// Icons that sit beside text and must grow with it.
    static func icon(_ points: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: (points * scale).rounded(), weight: weight)
    }

    /// The popover widens with the scale rather than squeezing the same
    /// words into the old frame.
    static var popoverWidth: CGFloat { (460 * scale).rounded() }
    static var popoverHeight: CGFloat { (640 * min(scale, 1.1)).rounded() }
}
