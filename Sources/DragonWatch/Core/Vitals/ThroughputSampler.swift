import Darwin
import Foundation

/// Current network throughput from interface byte counters (getifaddrs),
/// summed across non-loopback interfaces and differenced between samples.
/// The kernel's if_data counters are UInt32 and wrap every ~4 GB of traffic,
/// so deltas use wrapping subtraction — same trap as the CPU tick counters.
actor ThroughputSampler {
    private var last: (rx: UInt32, tx: UInt32, at: Date)?

    /// Bytes/second since the previous call; nil on the first sample.
    func sample(now: Date = Date()) -> (rxPerSec: Double, txPerSec: Double)? {
        let totals = Self.interfaceTotals()
        defer { last = (totals.rx, totals.tx, now) }
        guard let last else { return nil }
        let seconds = now.timeIntervalSince(last.at)
        guard seconds > 0.5 else { return nil }
        return Self.rate(
            current: totals, previous: (last.rx, last.tx), seconds: seconds)
    }

    /// Pure, wrap-safe delta math — the testable core.
    static func rate(
        current: (rx: UInt32, tx: UInt32),
        previous: (rx: UInt32, tx: UInt32),
        seconds: TimeInterval
    ) -> (rxPerSec: Double, txPerSec: Double) {
        (
            Double(current.rx &- previous.rx) / seconds,
            Double(current.tx &- previous.tx) / seconds
        )
    }

    private static func interfaceTotals() -> (rx: UInt32, tx: UInt32) {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0 else { return (0, 0) }
        defer { freeifaddrs(addresses) }

        var rx: UInt32 = 0
        var tx: UInt32 = 0
        var cursor = addresses
        while let interface = cursor?.pointee {
            defer { cursor = interface.ifa_next }
            guard interface.ifa_addr?.pointee.sa_family == UInt8(AF_LINK),
                let dataPointer = interface.ifa_data,
                let name = interface.ifa_name.map({ String(cString: $0) }),
                !name.hasPrefix("lo")
            else { continue }
            let data = dataPointer.assumingMemoryBound(to: if_data.self).pointee
            rx = rx &+ data.ifi_ibytes
            tx = tx &+ data.ifi_obytes
        }
        return (rx, tx)
    }
}
