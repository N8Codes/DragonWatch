import SwiftUI

struct VitalsHeaderView: View {
    let vitals: Vitals

    private let columns = [
        GridItem(.flexible(), spacing: 18),
        GridItem(.flexible(), spacing: 18),
        GridItem(.flexible(), spacing: 18),
    ]

    var body: some View {
        LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
            tile(
                icon: "cpu",
                caption: "CPU",
                value: String(format: "%.0f%%", vitals.cpuPercent),
                sparkline: vitals.cpuSparkline,
                explanation:
                    "System-wide CPU load across all cores, sampled every few seconds. The sparkline is recent history."
            )
            tile(
                icon: "memorychip",
                caption: "Memory",
                value: ByteCountFormatter.string(
                    fromByteCount: Int64(vitals.memoryUsedBytes), countStyle: .memory)
                    + " of "
                    + ByteCountFormatter.string(
                        fromByteCount: Int64(vitals.memoryTotalBytes), countStyle: .memory),
                explanation:
                    "Memory in use — apps plus wired and compressed — counted the way Activity Monitor counts it."
            )
            tile(
                icon: "internaldrive",
                caption: "Storage",
                value: ByteCountFormatter.string(
                    fromByteCount: vitals.storageFreeBytes, countStyle: .file)
                    + " free of "
                    + ByteCountFormatter.string(
                        fromByteCount: vitals.storageTotalBytes, countStyle: .file),
                explanation:
                    "Boot volume: free space (counting purgeable, like Finder) of total capacity."
            )
            tile(
                icon: vitals.networkUp ? "wifi" : "wifi.slash",
                caption: "Network",
                value: vitals.networkSummary
                    + (vitals.latencyMs.map { String(format: " · %.0f ms", $0) } ?? ""),
                sparkline: vitals.latencySparkline,
                explanation:
                    "Connection type, and round-trip latency to Apple's captive-portal server (probed every minute)."
            )
            tile(
                icon: "arrow.up.arrow.down.circle",
                caption: "Traffic",
                value: throughputText,
                explanation:
                    "Current network throughput across all interfaces — download ↓ and upload ↑ — averaged since the last sample."
            )
            tile(
                icon: "display",
                caption: vitals.displays.count > 1
                    ? "Displays (\(vitals.displays.count))" : "Display",
                value: vitals.displays.first ?? "—",
                explanation:
                    "Pixel resolution and current refresh rate. macOS has no global FPS — refresh rate is the honest stat."
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var throughputText: String {
        guard let rx = vitals.rxBytesPerSec, let tx = vitals.txBytesPerSec else {
            return "measuring…"
        }
        return "↓ \(rateText(rx))  ↑ \(rateText(tx))"
    }

    private func rateText(_ bytesPerSec: Double) -> String {
        ByteCountFormatter.string(
            fromByteCount: Int64(bytesPerSec), countStyle: .binary) + "/s"
    }

    private func tile(
        icon: String,
        caption: String,
        value: String,
        sparkline: [Double] = [],
        explanation: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(caption, systemImage: icon)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(
                    .system(.callout, design: .rounded).weight(.medium).monospacedDigit()
                )
                .lineLimit(1)
                .minimumScaleFactor(0.65)
            if sparkline.count >= 2 {
                SparklineView(values: sparkline)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(explanation)
    }
}
