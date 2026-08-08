import SwiftUI

/// A tiny line chart over the in-memory sample history — no axes, no labels;
/// the tile's number is the label.
struct SparklineView: View {
    let values: [Double]

    var body: some View {
        GeometryReader { geometry in
            if values.count >= 2 {
                let maxValue = max(values.max() ?? 1, 1)
                let stepX = geometry.size.width / CGFloat(values.count - 1)
                Path { path in
                    for (index, value) in values.enumerated() {
                        let point = CGPoint(
                            x: CGFloat(index) * stepX,
                            y: geometry.size.height
                                * (1 - CGFloat(value / maxValue)))
                        if index == 0 {
                            path.move(to: point)
                        } else {
                            path.addLine(to: point)
                        }
                    }
                }
                .stroke(.secondary.opacity(0.6), lineWidth: 1)
            }
        }
        .frame(height: 11)
    }
}
