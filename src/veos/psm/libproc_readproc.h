// New Interface to Process Table -- PROCTAB Stream (a la Directory streams)
// Copyright 1996 Charles L. Blake.
// Copyright 1998 Michael K. Johnson
// Copyright 1998-2003 Albert Cahalan
// May be distributed under the terms of the
// GNU Library General Public License, a copy of which is provided
// in the file COPYING
// -----------------------------------------------------
/* Changes by NEC Corporation for the VE port, 2025 */

/**
 * @file libproc_readproc.h
 * @brief definition relating process information for VE.
 * @details This file is based on readproc.h from procps-ng v3.3.15-6 in RHEL8.
 * It extracts the definitions of ns_type and proc_t required for VEOS.
 * Only the necessary variables are extracted for proc_t.
 * Therefore, the definition of proc_t differs from that in readproc.h of
 * procps-ng v3.3.15-6 in RHEL8.
 * 
 * @internal
 * @author PSMG / MPMT
 */

#ifndef __PSM_LIBPROC_READPROC_H
#define __PSM_LIBPROC_READPROC_H

// Extracted from readproc.h in procps-ng v3.3.15 of RHEL8.
enum ns_type {
    IPCNS = 0,
    MNTNS,
    NETNS,
    PIDNS,
    USERNS,
    UTSNS,
    NUM_NS         // total namespaces (fencepost)
    };

// Extracted from readproc.h in procps-ng v3.3.15 of RHEL8.
typedef struct proc_t {
    int tid;
    char
        state;          // stat,status     single-char code for process state (S=sleeping)
    int
        euid, egid,     // stat(),status   effective
        ruid, rgid,     // status          real
        suid, sgid,     // status          saved
        fuid, fgid;     // status          fs (used for file access only)
    long
        ns[NUM_NS];     // (ns subdir)     inode number of namespaces
} proc_t;
#endif