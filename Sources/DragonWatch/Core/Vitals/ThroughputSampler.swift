import Darwin
import Foundation

/// Current network throughput from interface byte counters (getifaddrs),
/// differenced per interface between samples.
///
/// Per interface, not summed. Summing first and differencing the total made
/// the set of interfaces part of the measurement: bringing up a VPN or
/// plugging in USB ethernet added that interface's *lifetime* counter to the
/// sum in one tick, and the display reported hundreds of megabytes per second
/// of traffic that never happened. Dropping an interface did the same in
/// reverse, where the wrapping subtraction turned the shortfall into a delta
/// near 4 GB.
actor ThroughputSampler {
    typealias Counters = [String: (rx: UInt32, tx: UInt32)]

    private var last: (counters: Counters, at: Date)?

    /// Bytes/second since the previous call; nil on the first sample.
    func sample(now: Date = Date()) -> (rxPerSec: Double, txPerSec: Double)? {
        let counters = Self.interfaceCounters()
        defer { last = (counters, now) }
        guard let last else { return nil }
        let seconds = now.timeIntervalSince(last.at)
        guard seconds > 0.5 else { return nil }
        return Self.rate(current: counters, previous: last.counters, seconds: seconds)
    }

    /// Pure, wrap-safe delta math — the testable core.
    ///
    /// An interface with no previous reading contributes nothing: there is no
    /// baseline to difference against, and its counter is a lifetime total,
    /// not traffic that happened in this interval.
    ///
    /// A counter that went *backwards* also contributes nothing for this one
    /// tick. That covers both a genuine `UInt32` wrap (~4 GB) and an interface
    /// torn down and recreated under the same name, which is what actually
    /// happens when a VPN reconnects. The two are indistinguishable from the
    /// counter alone, and for a live rate readout, missing one sample is a far
    /// better failure than inventing a multi-gigabyte spike.
    static func rate(
        current: Counters, previous: Counters, seconds: TimeInterval
    ) -> (rxPerSec: Double, txPerSec: Double) {
        var rx: UInt64 = 0
        var tx: UInt64 = 0
        for (name, now) in current {
            guard let before = previous[name] else { continue }
            if now.rx >= before.rx { rx += UInt64(now.rx - before.rx) }
            if now.tx >= before.tx { tx += UInt64(now.tx - before.tx) }
        }
        return (Double(rx) / seconds, Double(tx) / seconds)
    }

    private static func interfaceCounters() -> Counters {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0 else { return [:] }
        defer { freeifaddrs(addresses) }

        var counters: Counters = [:]
        var cursor = addresses
        while let interface = cursor?.pointee {
            defer { cursor = interface.ifa_next }
            guard interface.ifa_addr?.pointee.sa_family == UInt8(AF_LINK),
                let dataPointer = interface.ifa_data,
                let name = interface.ifa_name.map({ String(cString: $0) }),
                !name.hasPrefix("lo")
            else { continue }
            let data = dataPointer.assumingMemoryBound(to: if_data.self).pointee
            counters[name] = (data.ifi_ibytes, data.ifi_obytes)
        }
        return counters
    }
}
