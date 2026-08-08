import CDragonWatch
import Foundation

struct ProcessRecord: Identifiable, Hashable, Sendable {
    let pid: pid_t
    let path: String
    let name: String
    var cpuPercent: Double
    var residentBytes: UInt64

    var id: pid_t { pid }
}

/// Enumerates all visible processes via libproc, computing CPU% from the delta
/// in accumulated CPU time between consecutive samples (like `ps`/`top`, a
/// fully-busy core reads ~100%, so multicore processes can exceed 100).
actor ProcessSampler {
    private var lastCPUTimeNs: [pid_t: UInt64] = [:]
    private var lastSampleStamp: UInt64 = 0

    private let timebase: mach_timebase_info_data_t = {
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        return tb
    }()

    func sample() -> [ProcessRecord] {
        let declaredCount = proc_listallpids(nil, 0)
        guard declaredCount > 0 else { return [] }

        // Headroom for processes spawned between the two calls.
        var pids = [pid_t](repeating: 0, count: Int(declaredCount) + 64)
        let byteCount = Int32(pids.count * MemoryLayout<pid_t>.size)
        let filled = pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, byteCount)
        }
        guard filled > 0 else { return [] }

        let now = mach_absolute_time()
        let wallDeltaNs = machToNs(now &- lastSampleStamp)

        var currentCPUTimes: [pid_t: UInt64] = [:]
        var records: [ProcessRecord] = []
        records.reserveCapacity(Int(filled))

        for pid in pids.prefix(Int(filled)) where pid > 0 {
            var pathBuffer = [CChar](repeating: 0, count: 4096)
            guard proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count)) > 0 else {
                continue  // died mid-sample, or not visible to us
            }
            let path = String(cString: pathBuffer)

            var usage = dw_rusage_info()
            guard dw_proc_pid_rusage(pid, &usage) == 0 else { continue }

            let cpuTimeNs = machToNs(usage.ri_user_time &+ usage.ri_system_time)
            currentCPUTimes[pid] = cpuTimeNs

            let cpuPercent =
                lastSampleStamp == 0
                ? 0
                : Self.cpuPercent(
                    cpuTimeNs: cpuTimeNs,
                    previousCPUTimeNs: lastCPUTimeNs[pid],
                    wallDeltaNs: wallDeltaNs)

            records.append(
                ProcessRecord(
                    pid: pid,
                    path: path,
                    name: (path as NSString).lastPathComponent,
                    cpuPercent: cpuPercent,
                    residentBytes: usage.ri_phys_footprint
                ))
        }

        lastCPUTimeNs = currentCPUTimes
        lastSampleStamp = now
        return records
    }

    /// CPU time consumed as a share of elapsed wall time, in percent — the
    /// `ps`/`top` convention, so one fully busy core reads ~100. Returns 0
    /// for a process with no previous sample, and for a counter that moved
    /// backwards (pid reused by a new process between samples).
    static func cpuPercent(
        cpuTimeNs: UInt64, previousCPUTimeNs: UInt64?, wallDeltaNs: UInt64
    ) -> Double {
        guard wallDeltaNs > 0, let previous = previousCPUTimeNs, cpuTimeNs >= previous
        else { return 0 }
        return Double(cpuTimeNs - previous) / Double(wallDeltaNs) * 100.0
    }

    private func machToNs(_ machTime: UInt64) -> UInt64 {
        machTime &* UInt64(timebase.numer) / UInt64(timebase.denom)
    }
}
