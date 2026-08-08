import CDragonWatch
import Foundation

struct Vitals: Sendable {
    var cpuPercent: Double = 0
    var cpuSparkline: [Double] = []
    var memoryUsedBytes: UInt64 = 0
    var memoryTotalBytes: UInt64 = ProcessInfo.processInfo.physicalMemory
    var networkSummary: String = "Checking…"
    var networkUp: Bool = false
    var latencyMs: Double?
    var latencySparkline: [Double] = []
    var rxBytesPerSec: Double?
    var txBytesPerSec: Double?
    var storageFreeBytes: Int64 = 0
    var storageTotalBytes: Int64 = 0
    var displays: [String] = []
}

/// System-wide CPU and memory via mach host statistics. CPU% is computed from
/// tick deltas between consecutive samples (0–100 across all cores).
actor VitalsSampler {
    typealias CPUTicks = (user: UInt32, system: UInt32, idle: UInt32, nice: UInt32)

    private var lastTicks: CPUTicks?

    func sampleCPUAndMemory() -> (cpuPercent: Double, memoryUsedBytes: UInt64) {
        (sampleCPU(), sampleMemoryUsed())
    }

    /// Boot-volume capacity. "Available for important usage" is the number
    /// Finder shows — purgeable space counts as free.
    func sampleStorage() -> (freeBytes: Int64, totalBytes: Int64) {
        let values = try? URL(fileURLWithPath: "/").resourceValues(forKeys: [
            .volumeAvailableCapacityForImportantUsageKey, .volumeTotalCapacityKey,
        ])
        return (
            values?.volumeAvailableCapacityForImportantUsage ?? 0,
            Int64(values?.volumeTotalCapacity ?? 0)
        )
    }

    /// The tick counters are cumulative UInt32s and wrap after weeks of uptime
    /// (2³² / (100 Hz × cores) ≈ a month on 16 cores) — deltas must use
    /// wrapping subtraction or the first sample after a wrap traps.
    static func cpuPercent(current: CPUTicks, previous: CPUTicks) -> Double {
        let busy =
            UInt64(current.user &- previous.user)
            + UInt64(current.system &- previous.system)
            + UInt64(current.nice &- previous.nice)
        let total = busy + UInt64(current.idle &- previous.idle)
        guard total > 0 else { return 0 }
        return Double(busy) / Double(total) * 100.0
    }

    private func sampleCPU() -> Double {
        var load = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &load) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return 0 }

        let ticks: CPUTicks = (
            load.cpu_ticks.0, load.cpu_ticks.1, load.cpu_ticks.2, load.cpu_ticks.3
        )
        defer { lastTicks = ticks }
        guard let last = lastTicks else { return 0 }
        return Self.cpuPercent(current: ticks, previous: last)
    }

    private func sampleMemoryUsed() -> UInt64 {
        var stats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &stats) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return 0 }
        let pageSize = UInt64(vm_kernel_page_size)
        // "Used" the way Activity Monitor means it: app + wired + compressed.
        return
            (UInt64(stats.active_count) + UInt64(stats.wire_count)
            + UInt64(stats.compressor_page_count)) * pageSize
    }
}
