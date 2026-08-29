import CDragonWatch
import Foundation

struct ProcessRecord: Identifiable, Hashable, Sendable {
    let pid: pid_t
    let path: String
    let name: String
    /// nil when the kernel denied rusage — true for processes we do not own.
    /// The process is still reported; only its metrics are unknown, and the
    /// UI must show that rather than an implied zero.
    var cpuPercent: Double?
    var residentBytes: UInt64?
    /// nil when the kernel had no record for the pid (it exited mid-sample).
    /// Never 0: pid 0 is the kernel, and "launched by kernel_task" is a
    /// claim, not an unknown.
    var parentPID: pid_t?
    var startedAt: Date?

    var id: pid_t { pid }
    var hasMetrics: Bool { cpuPercent != nil }
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

            // rusage is denied for processes we do not own — about 40% of a
            // running Mac, every root daemon among them. Losing the *metrics*
            // is unavoidable; dropping the *process* is not. Skipping the
            // record here made root-only executables invisible to trust
            // assessment, the baseline, and every alert rule — precisely the
            // persistence this tool exists to notice. Report the process with
            // metrics marked unavailable instead.
            var usage = dw_rusage_info()
            let haveMetrics = dw_proc_pid_rusage(pid, &usage) == 0

            var cpuPercent: Double?
            var residentBytes: UInt64?
            if haveMetrics {
                let cpuTimeNs = machToNs(usage.ri_user_time &+ usage.ri_system_time)
                currentCPUTimes[pid] = cpuTimeNs
                cpuPercent =
                    lastSampleStamp == 0
                    ? 0
                    : Self.cpuPercent(
                        cpuTimeNs: cpuTimeNs,
                        previousCPUTimeNs: lastCPUTimeNs[pid],
                        wallDeltaNs: wallDeltaNs)
                residentBytes = usage.ri_phys_footprint
            }

            // Parentage and start time come from the KERN_PROC sysctl, which
            // answers for every process, root daemons included — unlike
            // rusage above and unlike proc_pidinfo's BSD-info flavor.
            var parentPID: pid_t = 0
            var startEpoch: Double = 0
            let haveParent = dw_proc_parent(pid, &parentPID, &startEpoch) == 0

            records.append(
                ProcessRecord(
                    pid: pid,
                    path: path,
                    name: (path as NSString).lastPathComponent,
                    cpuPercent: cpuPercent,
                    residentBytes: residentBytes,
                    parentPID: haveParent ? parentPID : nil,
                    startedAt: haveParent ? Date(timeIntervalSince1970: startEpoch) : nil
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

    /// Executable path of a process that may not be in the current sample —
    /// a parent that exited between the listing and the lookup, typically.
    nonisolated static func path(forPID pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }

    private func machToNs(_ machTime: UInt64) -> UInt64 {
        machTime &* UInt64(timebase.numer) / UInt64(timebase.denom)
    }
}
