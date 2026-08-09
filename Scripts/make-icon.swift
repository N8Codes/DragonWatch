#!/usr/bin/env swift
// Generates Resources/DragonWatch.icns — the Dock/Finder icon.
//
// The eye geometry below is a copy of `DragonEyeShape` in
// Sources/DragonWatch/UI/DragonEyeIcon.swift, which stays the source of
// truth: it is a SwiftUI Shape inside the app target and cannot be imported
// by a standalone script. `DragonEyeGeometryTests` pins the control points on
// both sides, so changing one without the other fails the suite rather than
// quietly leaving the Dock and the menu bar showing different marks.
//
// Run via Scripts/make-app.sh, or directly: swift Scripts/make-icon.swift

import AppKit
import Foundation

// Same 100x100 authoring space as DragonEyeShape.
let eyeControlPoints: [(CGFloat, CGFloat)] = [
    (2, 50), (98, 50), (50, -16), (50, 116),
]
let pupilRect = (x: 0.34, y: 0.30, width: 0.32, height: 0.40)

func eyePath(in rect: CGRect) -> NSBezierPath {
    func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
        CGPoint(x: rect.minX + x / 100 * rect.width, y: rect.minY + y / 100 * rect.height)
    }
    // NSBezierPath has no quadratic segment, so raise each quad to a cubic.
    // A quadratic (P0, Q, P2) is exactly the cubic with control points
    // P0 + 2/3(Q - P0) and P2 + 2/3(Q - P2). Reusing Q for both — the obvious
    // shortcut — is a different, flatter curve, and it turned the almond into
    // a diamond that looked nothing like the menu bar mark.
    func quadCurve(_ path: NSBezierPath, to end: CGPoint, control: CGPoint) {
        let start = path.currentPoint
        path.curve(
            to: end,
            controlPoint1: CGPoint(
                x: start.x + 2.0 / 3.0 * (control.x - start.x),
                y: start.y + 2.0 / 3.0 * (control.y - start.y)),
            controlPoint2: CGPoint(
                x: end.x + 2.0 / 3.0 * (control.x - end.x),
                y: end.y + 2.0 / 3.0 * (control.y - end.y)))
    }

    let path = NSBezierPath()
    path.move(to: point(eyeControlPoints[0].0, eyeControlPoints[0].1))
    quadCurve(
        path, to: point(eyeControlPoints[1].0, eyeControlPoints[1].1),
        control: point(eyeControlPoints[2].0, eyeControlPoints[2].1))
    quadCurve(
        path, to: point(eyeControlPoints[0].0, eyeControlPoints[0].1),
        control: point(eyeControlPoints[3].0, eyeControlPoints[3].1))
    path.close()
    path.appendOval(
        in: CGRect(
            x: rect.minX + pupilRect.x * rect.width,
            y: rect.minY + pupilRect.y * rect.height,
            width: pupilRect.width * rect.width,
            height: pupilRect.height * rect.height))
    path.windingRule = .evenOdd
    return path
}

func renderIcon(size: Int) -> Data {
    let side = CGFloat(size)
    let image = NSImage(size: NSSize(width: side, height: side))
    image.lockFocus()
    let context = NSGraphicsContext.current!.cgContext
    context.setShouldAntialias(true)

    // macOS icons sit in a rounded square with a margin, not edge to edge.
    let inset = side * 0.06
    let plate = CGRect(x: inset, y: inset, width: side - inset * 2, height: side - inset * 2)
    let corner = plate.width * 0.2237  // Apple's squircle-ish radius ratio
    let platePath = NSBezierPath(roundedRect: plate, xRadius: corner, yRadius: corner)

    // Dark slate plate so the amber eye carries the colour.
    context.saveGState()
    platePath.addClip()
    let gradient = NSGradient(
        colors: [
            NSColor(calibratedRed: 0.13, green: 0.15, blue: 0.20, alpha: 1),
            NSColor(calibratedRed: 0.05, green: 0.06, blue: 0.09, alpha: 1),
        ])!
    gradient.draw(in: plate, angle: -90)
    context.restoreGState()

    // The eye: same silhouette as the menu bar mark, proportioned 100x70.
    let eyeWidth = plate.width * 0.74
    let eyeHeight = eyeWidth * 0.7
    let eyeRect = CGRect(
        x: plate.midX - eyeWidth / 2, y: plate.midY - eyeHeight / 2,
        width: eyeWidth, height: eyeHeight)

    context.saveGState()
    let eye = eyePath(in: eyeRect)
    eye.addClip()
    NSGradient(
        colors: [
            NSColor(calibratedRed: 1.00, green: 0.78, blue: 0.30, alpha: 1),
            NSColor(calibratedRed: 0.94, green: 0.45, blue: 0.09, alpha: 1),
        ])!.draw(in: eyeRect, angle: -90)
    context.restoreGState()

    image.unlockFocus()

    guard let tiff = image.tiffRepresentation,
        let bitmap = NSBitmapImageRep(data: tiff),
        let png = bitmap.representation(using: .png, properties: [:])
    else { fatalError("could not render \(size)px") }
    return png
}

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let iconset = root.appendingPathComponent("build/DragonWatch.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

// The set macOS expects; omitting sizes makes the Dock scale a bad one.
for base in [16, 32, 128, 256, 512] {
    try renderIcon(size: base)
        .write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    try renderIcon(size: base * 2)
        .write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}

let output = root.appendingPathComponent("Resources/DragonWatch.icns")
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", output.path]
try iconutil.run()
iconutil.waitUntilExit()
guard iconutil.terminationStatus == 0 else {
    FileHandle.standardError.write(Data("iconutil failed\n".utf8))
    exit(1)
}
print("Wrote \(output.path)")
