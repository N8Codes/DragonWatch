import SwiftUI

/// The DragonWatch mark: a slit-pupil dragon eye, drawn as a vector path —
/// crisp at menu bar size and tinted with the menu bar appearance. (A dragon
/// head silhouette was tried first; the eye reads far better at 18 px.)
enum DragonEyeGeometry {
    /// Control points in a 100x100 authoring space: the two corners, then the
    /// upper and lower curve controls. Scripts/make-icon.swift redraws this
    /// same outline for the app icon and DragonEyeGeometryTests pins the two
    /// copies together.
    static let corners: [(x: CGFloat, y: CGFloat)] = [(2, 50), (98, 50)]
    static let controls: [(x: CGFloat, y: CGFloat)] = [(50, -16), (50, 116)]
    /// Pupil as a fraction of the bounding rect.
    static let pupil = (x: 0.34, y: 0.30, width: 0.32, height: 0.40)
}

struct DragonEyeShape: Shape {
    func path(in rect: CGRect) -> Path {
        // Control points authored in a 100×100 space, scaled to fit.
        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(
                x: rect.minX + x / 100 * rect.width,
                y: rect.minY + y / 100 * rect.height)
        }

        var path = Path()
        // Full, round almond — sharp corners, deep curvature (Eye-of-Ra
        // proportions; texture and brow variants were tried and read worse
        // at menu bar size than this bold silhouette).
        let corners = DragonEyeGeometry.corners
        let controls = DragonEyeGeometry.controls
        path.move(to: point(corners[0].x, corners[0].y))
        path.addQuadCurve(
            to: point(corners[1].x, corners[1].y),
            control: point(controls[0].x, controls[0].y))
        path.addQuadCurve(
            to: point(corners[0].x, corners[0].y),
            control: point(controls[1].x, controls[1].y))
        path.closeSubpath()
        // Round pupil — a circular cutout via even-odd fill.
        let pupil = DragonEyeGeometry.pupil
        path.addEllipse(
            in: CGRect(
                x: rect.minX + pupil.x * rect.width,
                y: rect.minY + pupil.y * rect.height,
                width: pupil.width * rect.width,
                height: pupil.height * rect.height))
        return path
    }
}

/// Menu bar mark: the eye, plus a colored warning badge when the overall
/// state needs attention — the one deliberate splash of color in the menu bar.
/// The path is rasterized into a template Image because NSStatusItem labels
/// reliably render only Image content — a bare SwiftUI Shape draws nothing
/// in the menu bar.
struct DragonEyeIcon: View {
    let badge: TrustBadge
    var size: CGFloat = 24

    var body: some View {
        eyeImage
            .foregroundStyle(.primary)
            .overlay(alignment: .bottomTrailing) {
                if badge != .trusted {
                    // Triangle for caution, octagon for suspicious — the shape
                    // carries the severity, so the menu bar reads correctly in
                    // greyscale and for red/green colour blindness.
                    Image(systemName: badge.symbolName)
                        .font(.system(size: size * 0.5, weight: .bold))
                        .foregroundStyle(.white, badge.color)
                        .offset(x: size * 0.18, y: size * 0.1)
                }
            }
            .accessibilityLabel("DragonWatch — \(badge.label)")
    }

    private var eyeImage: Image {
        // The eye is wider than tall; keep its natural proportions.
        let dimensions = CGSize(width: size, height: size * 0.7)
        return Image(size: dimensions) { context in
            context.fill(
                DragonEyeShape().path(in: CGRect(origin: .zero, size: dimensions)),
                with: .color(.black),
                style: FillStyle(eoFill: true))
        }
        .renderingMode(.template)
    }
}
