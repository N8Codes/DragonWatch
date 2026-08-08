#ifndef CDRAGONWATCH_H
#define CDRAGONWATCH_H

#include <libproc.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <mach/mach_time.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

/* rusage_info_current is a moving typedef; pin v4, which has everything we need
   (ri_user_time, ri_system_time, ri_phys_footprint) and exists since 10.9. */
typedef struct rusage_info_v4 dw_rusage_info;

static inline int dw_proc_pid_rusage(pid_t pid, dw_rusage_info *ri) {
    return proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)ri);
}

/* 1 if the process holds at least one established TCP connection, else 0.
   Any error reads as 0 — absence of evidence must not look suspicious. */
static inline int dw_has_active_network(pid_t pid) {
    int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (size <= 0) return 0;
    size += 16 * (int)PROC_PIDLISTFD_SIZE; /* headroom for fds opened since sizing */
    struct proc_fdinfo *fds = malloc((size_t)size);
    if (!fds) return 0;
    int used = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, size);
    int found = 0;
    for (int i = 0; i < used / (int)PROC_PIDLISTFD_SIZE && !found; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo si;
        int n = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO,
                               &si, (int)PROC_PIDFDSOCKETINFO_SIZE);
        if (n != (int)PROC_PIDFDSOCKETINFO_SIZE) continue;
        if (si.psi.soi_kind == SOCKINFO_TCP &&
            si.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_ESTABLISHED)
            found = 1;
    }
    free(fds);
    return found;
}

#endif /* CDRAGONWATCH_H */
