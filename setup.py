# Copyright (c) Recommenders contributors.
# Licensed under the MIT License.

from os import environ
from pathlib import Path
from setuptools import setup, find_packages
import site
import sys
import time

# Workaround for enabling editable user pip installs
site.ENABLE_USER_SITE = "--user" in sys.argv[1:]

# Version
here = Path(__file__).absolute().parent
version_data = {}
with open(here.joinpath("recommenders", "__init__.py"), "r") as f:
    exec(f.read(), version_data)
version = version_data.get("__version__", "0.0")

# Get the long description from the README file
with open(here.joinpath("recommenders", "README.md"), encoding="utf-8") as f:
    LONG_DESCRIPTION = f.read()

HASH = environ.get("HASH", None)
if HASH is not None:
    version += ".post" + str(int(time.time()))

install_requires = [
    "category-encoders>=2.6.0,<3",  # requires packaging
    "cornac>=1.15.2,<3",  # requires packaging, tqdm
    "hyperopt>=0.2.7,<1",
    "lightgbm>=4.0.0,<5",
    "locust>=2.12.2,<3",  # requires jinja2
    "memory-profiler>=0.61.0,<1",
    "nltk>=3.8.1,<4",  # requires tqdm
    "notebook>=6.5.5,<8",  # requires ipykernel, jinja2, jupyter, nbconvert, nbformat, packaging, requests
    "numba>=0.57.0,<1",
    "numpy<2.0.0",  # FIXME: Remove numpy<2.0.0 once cornac release a version newer than 2.2.1 that resolve ImportError: numpy.core.multiarray failed to import.
    "pandas>2.0.0,<3.0.0",  # requires numpy
    "pandera[strategies]>=0.6.5,<0.18;python_version<='3.8'",  # For generating fake datasets
    "pandera[strategies]>=0.15.0;python_version>='3.9'",
    "retrying>=1.3.4,<2",
    "scikit-learn>=1.2.0,<2",  # requires scipy, and introduce breaking change affects feature_extraction.text.TfidfVectorizer.min_df
    "scikit-surprise>=1.1.3",
    "scipy>=1.10.1,<=1.13.1",  # FIXME: Remove scipy<=1.13.1 once cornac release a version newer than 2.2.1.  See #2128
    "seaborn>=0.13.0,<1",  # requires matplotlib, packaging
    "transformers>=4.27.0,<5",  # requires packaging, pyyaml, requests, tqdm
]

# shared dependencies
extras_require = {
    "gpu": [
        "fastai>=2.7.11,<3",
        "nvidia-ml-py>=11.525.84",
        "tensorflow>=2.8.4,!=2.9.0.*,!=2.9.1,!=2.9.2,!=2.10.0.*,<2.16",  # Fixed TF due to constant security problems and breaking changes #2073
        "tf-slim>=1.1.0",  # No python_requires in its setup.py
        "torch>=2.0.1,<3",
    ],
    "spark": [
        "pyarrow>=10.0.1",
        "pyspark>=3.3.0,<=4",
    ],
    "dev": [
        "black>=23.3.0",
        "pytest>=7.2.1",
        "pytest-cov>=4.1.0",
        "pytest-mock>=3.10.0",  # for access to mock fixtures in pytest
    ],
}
# For the brave of heart
extras_require["all"] = list(set(sum([*extras_require.values()], [])))

# The following dependencies need additional testing
extras_require["experimental"] = [
    # xlearn requires cmake to be pre-installed
    "xlearn==0.40a1",
    # VW C++ binary needs to be installed manually for some code to work
    "vowpalwabbit>=8.9.0,<9",
    # nni needs to be upgraded
    "nni==1.5",
    "pymanopt>=0.2.5",
    "lightfm>=1.17,<2",
]

# The following dependency can be installed as below, however PyPI does not allow direct URLs.
# Temporary fix for pymanopt, only this commit works with TF2
# "pymanopt@https://github.com/pymanopt/pymanopt/archive/fb36a272cdeecb21992cfd9271eb82baafeb316d.zip",

setup(
    name="recommenders",
    version=version,
    description="Recommenders - Python utilities for building recommendation systems",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/recommenders-team/recommenders",
    project_urls={
        "Documentation": "https://recommenders-team.github.io/recommenders/intro.html",
        "Wiki": "https://github.com/recommenders-team/recommenders/wiki",
    },
    author="Recommenders contributors",
    author_email="recommenders-technical-discuss@lists.lfaidata.foundation",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    extras_require=extras_require,
    keywords="recommendations recommendation recommenders recommender system engine "
    "machine learning python spark gpu",
    install_requires=install_requires,
    package_dir={"recommenders": "recommenders"},
    python_requires=">=3.6",
    packages=find_packages(
        where=".",
        exclude=["contrib", "docs", "examples", "scenarios", "tests", "tools"],
    ),
    setup_requires=["numpy>=1.19"],
)

#!/usr/bin/env python3
"""
==============================================================================
eBPF Observability Demonstrator  (Python / BCC edition)
==============================================================================

PURPOSE
-------
This application demonstrates the power of eBPF (extended Berkeley Packet
Filter) for **system observability**.  It attaches tiny, safe programs into
the Linux kernel at runtime and collects rich telemetry about:

    1. System calls   – which syscalls are invoked, by whom, and how long
                        each one takes.
    2. Process events – process creation (fork), execution (exec), and
                        termination (exit).

The data is collected with virtually zero overhead thanks to eBPF's
JIT-compiled, in-kernel execution model.

ARCHITECTURE (how the pieces fit together)
------------------------------------------

  ┌──────────────┐        ┌──────────────────┐
  │  User-space  │        │  Kernel space     │
  │  (this file) │        │                   │
  │              │◄───────│  eBPF programs    │
  │  Python +    │  perf  │  (compiled C,     │
  │  BCC library │  ring  │   JIT'd to native │
  │              │  buffer│   machine code)   │
  └──────────────┘        └──────────────────┘

  1. We define eBPF programs in **C** (strings in this file).
  2. BCC compiles them with LLVM/Clang into eBPF bytecode.
  3. The kernel **verifier** checks the bytecode is safe
     (bounded loops, no invalid memory, no crashes).
  4. The kernel **JIT compiler** turns bytecode into native
     x86_64 instructions for near-zero overhead.
  5. We **attach** the programs to *tracepoints*:
       - syscalls/sys_enter_*   (syscall entry)
       - syscalls/sys_exit_*    (syscall return)
       - sched/sched_process_exec  (new program execution)
       - sched/sched_process_exit  (process termination)
       - sched/sched_process_fork  (process fork)
  6. When these events fire the eBPF program runs, fills a
     struct, and pushes it to a **perf ring buffer**.
  7. This Python process polls the ring buffer and renders
     the data in real time.

WHY TRACEPOINTS (not kprobes)?
------------------------------
Tracepoints are **stable** kernel interfaces.  They survive
kernel upgrades, whereas kprobes attach to *internal* function
names that may be renamed, inlined, or removed between kernel
versions.  Tracepoints are the recommended attachment point for
production monitoring.

WHY SEPARATE BPF OBJECTS?
-------------------------
Each tracepoint pair (enter + exit) is loaded as a separate BPF
object.  This is necessary because:
  - Each BPF object auto-attaches all its TRACEPOINT_PROBE functions.
  - Combining too many tracepoints into one object can exceed
    per-process perf event file descriptor limits.
  - Separate objects allow graceful degradation: if one syscall
    tracepoint is not available on a kernel, the rest still work.

RUNNING
-------
    sudo python3 ebpf_monitor.py            # 30 s default
    sudo python3 ebpf_monitor.py -d 60      # 60 seconds
    sudo python3 ebpf_monitor.py -p 1234    # filter to PID 1234

REQUIREMENTS
------------
    - Linux kernel >= 4.18 (tracepoints used here)
    - python3-bpfcc (BCC Python bindings)
    - Root privileges (eBPF requires CAP_SYS_ADMIN / CAP_BPF)
"""

# ──────────────────────────────────────────────────────────────
# Standard library imports
# ──────────────────────────────────────────────────────────────
import time
import datetime
import sys
import os
import argparse
import struct
from collections import defaultdict
import json

# ──────────────────────────────────────────────────────────────
# BCC - the Python front-end for eBPF
#
# BCC compiles our C code to eBPF bytecode, loads it into the
# kernel, and provides helpers to read data from perf buffers
# and eBPF maps.  It uses LLVM/Clang under the hood.
# ──────────────────────────────────────────────────────────────
from bcc import BPF


# ══════════════════════════════════════════════════════════════
#  eBPF C PROGRAM TEMPLATES
# ══════════════════════════════════════════════════════════════
#
# Each string below is a C program compiled at runtime by BCC.
# After compilation the kernel verifier checks it and the JIT
# compiler converts it to native machine code.
#
# KEY eBPF CONCEPTS visible in the code:
#
#   BPF_HASH(name, key_t, val_t)
#       A hash-map that lives in kernel memory.  Both the eBPF
#       program (kernel side) and Python (user side) can read it.
#       We use it to store syscall entry timestamps.
#
#   BPF_PERF_OUTPUT(name)
#       A per-CPU ring buffer for streaming events from kernel
#       to user space with minimal overhead.
#
#   bpf_get_current_pid_tgid()
#       Returns (tgid << 32 | tid).  Shifting right by 32 gives
#       the process ID (tgid = thread group ID = what userspace
#       calls "PID").
#
#   bpf_ktime_get_ns()
#       Monotonic clock in nanoseconds -- perfect for latency.
#
#   bpf_get_current_comm()
#       Copies the current task's 16-byte command name.
#
#   TRACEPOINT_PROBE(category, event)
#       BCC macro that generates an eBPF function and auto-
#       attaches it to the tracepoint category:event.
#       The 'args' variable gives typed access to the
#       tracepoint fields.
# ──────────────────────────────────────────────────────────────


def _make_syscall_program(syscall_name, syscall_nr):
    """
    Generate a BPF C program that traces one syscall (entry + exit).

    Why one program per syscall?
    ----------------------------
    Loading all tracepoints in a single BPF object can fail when
    the system has restrictive perf_event file descriptor limits.
    Splitting gives us:
      - Graceful degradation (if one fails, others still work)
      - Clearer error messages
      - Smaller per-program verification time

    The pattern is "duration measurement":
      Entry handler  -> store timestamp in BPF_HASH
      Exit handler   -> lookup timestamp, compute delta, emit event

    Args:
        syscall_name: e.g. "openat", "read", "write"
        syscall_nr:   x86_64 syscall number (used as hash key)
    """
    return r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
 * Event structure passed from kernel to user space via perf buffer.
 *
 * eBPF restricts stack allocation to 512 bytes, so we keep it lean.
 * TASK_COMM_LEN is 16 on Linux.
 */
struct sys_event_t {
    u32 pid;                    /* Process ID (tgid)                       */
    u32 uid;                    /* User ID of the calling process          */
    char comm[TASK_COMM_LEN];   /* Command name (e.g. "nginx", "python3") */
    char syscall_name[16];      /* Human-readable syscall name             */
    u64 timestamp;              /* Monotonic timestamp (ns)                */
    u64 duration_ns;            /* How long the syscall took (ns)          */
    s64 return_value;           /* Syscall return value (fd, bytes, errno) */
};

/*
 * BPF_HASH - a kernel-resident hash map.
 *
 * Key:   u32 PID (tgid) - identifies the calling process.
 * Value: u64 timestamp when the syscall was entered.
 *
 * When the same process's exit handler fires, we look up the
 * entry timestamp and compute the delta.
 */
BPF_HASH(start_SYSCALL_NAME, u32, u64);

/*
 * BPF_PERF_OUTPUT - per-CPU ring buffer.
 *
 * The kernel writes events here; user space polls and consumes
 * them.  This is the standard high-throughput path for eBPF
 * to user space communication.
 */
BPF_PERF_OUTPUT(events_SYSCALL_NAME);

/*
 * TRACEPOINT: syscalls/sys_enter_SYSCALL_NAME
 *
 * Fires when any process enters this syscall.
 * We simply record the monotonic timestamp so we can compute
 * the duration when the syscall returns.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_SYSCALL_NAME) {
    /* Extract PID from the combined pid_tgid value */
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    /* Store the entry timestamp keyed by PID */
    start_SYSCALL_NAME.update(&pid, &ts);
    return 0;
}

/*
 * TRACEPOINT: syscalls/sys_exit_SYSCALL_NAME
 *
 * Fires when the syscall returns.  We compute the duration,
 * fill the event struct, and push it to user space.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_SYSCALL_NAME) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Look up the entry timestamp */
    u64 *start_ts = start_SYSCALL_NAME.lookup(&pid);
    if (!start_ts)
        return 0;  /* No matching entry (e.g. started before tracing) */

    /* Calculate how long the syscall took */
    u64 duration = bpf_ktime_get_ns() - *start_ts;

    /* Fill the event structure */
    struct sys_event_t event = {};
    event.pid          = pid;
    event.uid          = bpf_get_current_uid_gid();
    event.timestamp    = bpf_ktime_get_ns();
    event.duration_ns  = duration;
    event.return_value = args->ret;  /* Tracepoint provides return value */

    /* Copy current process command name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Copy the syscall name string */
    __builtin_memcpy(event.syscall_name, "SYSCALL_NAME_STR", SYSCALL_NAME_LEN);

    /* Submit event to the perf ring buffer for user space to read */
    events_SYSCALL_NAME.perf_submit(args, &event, sizeof(event));

    /* Clean up the hash entry */
    start_SYSCALL_NAME.delete(&pid);
    return 0;
}
""".replace("SYSCALL_NAME_STR", syscall_name) \
   .replace("SYSCALL_NAME_LEN", str(len(syscall_name) + 1)) \
   .replace("SYSCALL_NAME", syscall_name)


# ──────────────────────────────────────────────────────────────
# PROGRAM 2: Process Lifecycle Monitor
# ──────────────────────────────────────────────────────────────
# Tracepoints under "sched" give us stable hooks for:
#   - sched_process_exec : a new binary is loaded (execve)
#   - sched_process_exit : a process terminates
#   - sched_process_fork : a new child process is created
#
# These tracepoints are architecture-independent and work
# across kernel versions without modification.
# ──────────────────────────────────────────────────────────────
BPF_PROCMON_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
 * Process lifecycle event structure.
 *
 * event_type encodes what happened:
 *   1 = exec  -> a new binary was loaded via execve()
 *   2 = exit  -> the process terminated
 *   3 = fork  -> a new child process was created
 *
 * For exec events, 'filename' contains the path to the new binary.
 * For fork events, we pack the child PID into 'filename' bytes.
 */
struct proc_event_t {
    u32 pid;                     /* Process ID (or parent PID for fork)     */
    u32 ppid;                    /* Parent PID                              */
    u32 uid;                     /* User ID                                 */
    u32 event_type;              /* 1=exec, 2=exit, 3=fork                  */
    u64 timestamp;               /* Monotonic timestamp (ns)                */
    char comm[TASK_COMM_LEN];    /* Command name                            */
    char filename[128];          /* Binary path (exec) or child PID (fork)  */
};

/*
 * Perf ring buffer for process events.
 * Same mechanism as syscall events -- per-CPU, lock-free, efficient.
 */
BPF_PERF_OUTPUT(proc_events);

/*
 * TRACEPOINT: sched/sched_process_exec
 *
 * Fires when a process calls execve() and a new binary is loaded.
 * This is invaluable for security monitoring -- you can see every
 * binary that executes on the system in real time, without modifying
 * any application code.
 *
 * The tracepoint format provides:
 *   - filename: path to the executed binary
 *   - pid: process ID of the new process
 *   - old_pid: PID before exec (same unless PID namespace changed)
 */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct proc_event_t event = {};

    event.pid        = args->pid;
    event.uid        = bpf_get_current_uid_gid();
    event.timestamp  = bpf_ktime_get_ns();
    event.event_type = 1;  /* exec */

    /* Copy the command name from the current task struct */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /*
     * The exec tracepoint provides the binary path.  We read the
     * command name from the current task struct instead, which is
     * always available and stable across kernel versions.
     * (The __data_loc 'filename' field requires special handling
     * in older BCC versions, so we use comm as a reliable fallback.)
     */

    proc_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/*
 * TRACEPOINT: sched/sched_process_exit
 *
 * Fires when a process terminates (voluntarily or via signal).
 * Combined with exec events, this gives full lifecycle visibility.
 *
 * The tracepoint format provides:
 *   - comm: the process command name
 *   - pid: the process ID
 *   - prio: scheduling priority
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct proc_event_t event = {};

    event.pid        = args->pid;
    event.uid        = bpf_get_current_uid_gid();
    event.timestamp  = bpf_ktime_get_ns();
    event.event_type = 2;  /* exit */

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    proc_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/*
 * TRACEPOINT: sched/sched_process_fork
 *
 * Fires when a process creates a child via fork() or clone().
 * We record both parent and child PIDs.
 *
 * The tracepoint format provides:
 *   - parent_comm: parent process name
 *   - parent_pid: parent PID
 *   - child_comm: child process name
 *   - child_pid: child PID
 *
 * Use case: detecting fork-bombs, tracking process genealogy,
 * understanding container startup sequences.
 */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct proc_event_t event = {};

    event.pid        = args->parent_pid;
    event.ppid       = args->parent_pid;
    event.uid        = bpf_get_current_uid_gid();
    event.timestamp  = bpf_ktime_get_ns();
    event.event_type = 3;  /* fork */

    /* Copy parent's command name from tracepoint data */
    bpf_probe_read_str(event.comm, sizeof(event.comm),
                       args->parent_comm);

    /*
     * Pack the child PID into the filename field.
     * This is a common eBPF trick: reuse existing struct fields
     * to avoid defining separate structs for each event type.
     * We'll unpack it in user space with struct.unpack().
     */
    u32 child_pid = args->child_pid;
    __builtin_memcpy(event.filename, &child_pid, sizeof(child_pid));

    proc_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


# ══════════════════════════════════════════════════════════════
#  SYSCALL DEFINITIONS
# ══════════════════════════════════════════════════════════════
# Each tuple is (tracepoint_name, x86_64_syscall_number).
#
# We trace the most common and observability-relevant syscalls.
# You can add more by appending to this list -- the code will
# automatically generate eBPF programs for each one.
# ══════════════════════════════════════════════════════════════
TRACED_SYSCALLS = [
    ("openat",  257),   # Opening files (the modern open())
    ("read",      0),   # Reading from file descriptors
    ("write",     1),   # Writing to file descriptors
    ("close",     3),   # Closing file descriptors
]


# ══════════════════════════════════════════════════════════════
#  USER-SPACE: Event processing and display
# ══════════════════════════════════════════════════════════════

class eBPFObservabilityMonitor:
    """
    Main monitor class.

    Lifecycle:
        1. __init__()  -- configure duration and filters
        2. start()     -- compile eBPF C -> bytecode, load into kernel,
                          attach to tracepoints, open perf buffers
        3. run()       -- poll perf buffers in a loop for 'duration' seconds
        4. stop()      -- detach probes, print final report, save JSON

    Why eBPF is better than traditional alternatives:
    -------------------------------------------------
    | Method        | Overhead | Safety    | Flexibility |
    |---------------|----------|-----------|-------------|
    | strace        | HIGH     | Safe      | Limited     |
    | auditd        | MEDIUM   | Safe      | Limited     |
    | kernel module | LOW      | DANGEROUS | High        |
    | eBPF          | VERY LOW | SAFE      | Very High   |

    strace uses ptrace(), which stops the process on every syscall
    (10-100x slower).  eBPF runs in-kernel with JIT compilation,
    avoiding context switches entirely.
    """

    def __init__(self, duration=30, filters=None):
        """
        Configure the monitor.

        Args:
            duration: How long to monitor (seconds).
            filters:  Dict with optional 'pid' and/or 'uid' keys
                      to limit which events are collected.
        """
        self.duration = duration
        self.filters = filters or {}
        self.running = False

        # ── BPF object storage ───────────────────────────────
        # Each syscall gets its own BPF object (separate compilation
        # unit and separate perf buffer).  This avoids hitting
        # perf event fd limits when attaching many tracepoints.
        self.bpf_objects = []      # List of (name, BPF) tuples
        self.bpf_proc = None       # Process lifecycle BPF object

        # ── Event storage (raw dicts for JSON export) ────────
        self.syscall_events = []
        self.process_events = []

        # ── Aggregate statistics ─────────────────────────────
        self.syscall_stats = defaultdict(int)           # syscall -> count
        self.syscall_durations = defaultdict(list)       # syscall -> [ns]
        self.per_process_syscalls = defaultdict(int)     # comm -> count
        self.process_stats = defaultdict(int)            # event_type -> count

        # Dedup for live stats printing
        self._last_stats_time = 0

    # ──────────────────────────────────────────────────────────
    #  STARTUP: compile, load, attach
    # ──────────────────────────────────────────────────────────
    def start(self):
        """
        Compile eBPF programs, load them into the kernel, and attach.

        This method triggers the following eBPF lifecycle:

        1. BCC invokes Clang to compile C -> LLVM IR -> eBPF bytecode.
        2. The bpf() syscall loads bytecode into the kernel.
        3. The kernel VERIFIER validates the program:
             - No unbounded loops (all loops must have a known bound)
             - No out-of-bounds memory access
             - Stack usage <= 512 bytes
             - All code paths terminate and return a value
             - No division by zero
             - No unreachable code
        4. The JIT compiler converts eBPF bytecode to native x86_64.
        5. The TRACEPOINT_PROBE macro auto-attaches to the kernel
           tracepoint when the BPF object is created.

        If any step fails, the kernel REJECTS the program and returns
        an error -- the system is NEVER at risk.  This is the key
        safety guarantee of eBPF.

        Returns:
            True if at least one program loaded successfully.
        """
        print(f"Starting eBPF Observability Monitor for {self.duration} seconds...")
        if self.filters:
            print(f"Filters: {self.filters}")
        syscall_names = [s[0] for s in TRACED_SYSCALLS]
        print(f"Monitoring: syscalls ({', '.join(syscall_names)})")
        print(f"            process lifecycle (exec, exit, fork)\n")

        self.running = True
        loaded_count = 0

        # ── Step 1: Load syscall monitors ────────────────────
        # Each syscall gets its own BPF object.  This way if one
        # tracepoint fails (e.g. not available on this kernel),
        # the others still work.
        print("[1/3] Compiling and loading syscall monitors...")
        for syscall_name, syscall_nr in TRACED_SYSCALLS:
            try:
                # Generate the C source for this specific syscall
                c_source = _make_syscall_program(syscall_name, syscall_nr)

                # BPF() compiles, loads, and auto-attaches tracepoints
                bpf_obj = BPF(text=c_source)

                # Open the perf buffer for this syscall's events
                # page_cnt=16 means 16 pages (64KB) per CPU -- enough
                # for moderate event rates without wasting memory.
                perf_name = f"events_{syscall_name}"
                bpf_obj[perf_name].open_perf_buffer(
                    self._make_sys_handler(syscall_name, bpf_obj), page_cnt=16
                )

                self.bpf_objects.append((syscall_name, bpf_obj))
                loaded_count += 1
                print(f"      {syscall_name}: OK")

            except Exception as e:
                # Graceful degradation: log and continue
                print(f"      {syscall_name}: SKIPPED ({e})")

        # ── Step 2: Load process lifecycle monitor ───────────
        print("[2/3] Compiling and loading process lifecycle monitor...")
        try:
            self.bpf_proc = BPF(text=BPF_PROCMON_PROGRAM)
            self.bpf_proc["proc_events"].open_perf_buffer(
                self._handle_proc_event, page_cnt=16
            )
            loaded_count += 1
            print("      process monitor: OK")
        except Exception as e:
            print(f"      process monitor: SKIPPED ({e})")
            self.bpf_proc = None

        # ── Step 3: Summary ──────────────────────────────────
        if loaded_count == 0:
            print("\n[ERROR] No eBPF programs could be loaded.")
            print("  Ensure you are running as root: sudo python3 ebpf_monitor.py")
            return False

        print(f"[3/3] {loaded_count} eBPF programs active\n")
        print("[OK] Monitoring active. Press Ctrl-C to stop early.\n")
        return True

    # ──────────────────────────────────────────────────────────
    #  EVENT HANDLERS
    # ──────────────────────────────────────────────────────────

    def _make_sys_handler(self, syscall_name, bpf_obj):
        """
        Create a closure that handles perf events for one syscall.

        Why a closure?  Each syscall has its own BPF object and
        perf buffer, but they all feed into the same event list.
        The closure captures 'syscall_name' and 'bpf_obj' so we
        know which syscall produced each event and can deserialise it.

        Args:
            syscall_name: e.g. "openat", "read", "write"
            bpf_obj:      the compiled BPF object for this syscall

        Returns:
            A callback function compatible with open_perf_buffer().
        """
        perf_name = f"events_{syscall_name}"

        def handler(cpu, data, size):
            """
            Perf buffer callback.

            Called by BCC each time an event arrives from the kernel.
            The perf buffer delivers events in batches per CPU.

            Args:
                cpu:  CPU number the event was generated on.
                data: Raw bytes of the sys_event_t struct.
                size: Size in bytes.
            """
            # Deserialise the C struct.  BCC auto-generates a
            # ctypes class from our struct definition.
            event = bpf_obj[perf_name].event(data)

            pid = event.pid
            uid = event.uid

            # ── Apply user-defined filters ───────────────────
            if self.filters.get('pid') and pid != self.filters['pid']:
                return
            if self.filters.get('uid') and uid != self.filters['uid']:
                return

            # ── Decode C strings ─────────────────────────────
            comm = event.comm.decode('utf-8', 'replace')

            # ── Store raw event ──────────────────────────────
            self.syscall_events.append({
                'pid': pid,
                'uid': uid,
                'comm': comm,
                'syscall': syscall_name,
                'timestamp': event.timestamp,
                'duration_ns': event.duration_ns,
                'return_value': event.return_value,
            })

            # ── Update aggregate statistics ──────────────────
            self.syscall_stats[syscall_name] += 1
            self.syscall_durations[syscall_name].append(event.duration_ns)
            self.per_process_syscalls[comm] += 1

        return handler

    def _handle_proc_event(self, cpu, data, size):
        """
        Handle process lifecycle events from the kernel.

        Event types:
            1 = exec  : a new binary was loaded (execve succeeded)
            2 = exit  : a process terminated
            3 = fork  : a new child was created (fork/clone)
        """
        event = self.bpf_proc["proc_events"].event(data)

        pid = event.pid

        # Apply PID filter
        if self.filters.get('pid') and pid != self.filters['pid']:
            return

        event_type = {1: 'exec', 2: 'exit', 3: 'fork'}.get(
            event.event_type, 'unknown'
        )

        comm = event.comm.decode('utf-8', 'replace')
        filename = event.filename.decode('utf-8', 'replace')

        # For fork events, the child PID is packed into filename bytes
        child_pid = None
        if event.event_type == 3:
            try:
                child_pid = struct.unpack('I', event.filename[:4])[0]
            except Exception:
                child_pid = 0
            filename = f"child_pid={child_pid}"

        self.process_events.append({
            'pid': pid,
            'ppid': event.ppid,
            'uid': event.uid,
            'comm': comm,
            'filename': filename,
            'timestamp': event.timestamp,
            'event_type': event_type,
        })

        self.process_stats[event_type] += 1

    # ──────────────────────────────────────────────────────────
    #  MAIN LOOP
    # ──────────────────────────────────────────────────────────

    def run(self):
        """
        Main event loop.

        We call perf_buffer_poll() which uses epoll internally --
        it blocks until events arrive or timeout expires (100 ms).
        This is NON-busy-waiting and very CPU-friendly.

        Every 5 seconds we print live statistics so the user can
        see the monitor is active and collecting data.
        """
        if not self.start():
            return False

        start_time = time.time()

        try:
            while self.running and (time.time() - start_time) < self.duration:
                # ── Poll ALL perf ring buffers ───────────────
                # Each BPF object has its own perf buffer.  We poll
                # them all in round-robin fashion.
                #
                # timeout=100 means "wait up to 100 ms for events".
                # This is the heart of the monitor: the kernel pushes
                # events, and we consume them here.
                for _, bpf_obj in self.bpf_objects:
                    bpf_obj.perf_buffer_poll(timeout=50)

                if self.bpf_proc:
                    self.bpf_proc.perf_buffer_poll(timeout=50)

                # ── Print live stats every 5 seconds ─────────
                elapsed = int(time.time() - start_time)
                if elapsed > 0 and elapsed % 5 == 0 and elapsed != self._last_stats_time:
                    self._last_stats_time = elapsed
                    self._print_live_stats(elapsed)

        except KeyboardInterrupt:
            print("\n\n[INTERRUPTED] Stopping early...")

        self.stop()
        return True

    # ──────────────────────────────────────────────────────────
    #  LIVE STATISTICS
    # ──────────────────────────────────────────────────────────

    def _print_live_stats(self, elapsed):
        """Print a compact summary while monitoring is running."""
        top3 = sorted(self.syscall_stats.items(),
                       key=lambda x: x[1], reverse=True)[:3]
        top3_str = ", ".join(f"{name}={count}" for name, count in top3)

        print(f"  [{elapsed:3d}s] syscalls={len(self.syscall_events):,}  "
              f"proc_events={len(self.process_events):,}  "
              f"top: {top3_str}")

    # ──────────────────────────────────────────────────────────
    #  SHUTDOWN AND REPORT
    # ──────────────────────────────────────────────────────────

    def stop(self):
        """Stop monitoring, print final report, save JSON."""
        self.running = False

        print("\n" + "=" * 72)
        print(" eBPF OBSERVABILITY REPORT")
        print("=" * 72)

        self._report_syscalls()
        self._report_processes()
        self._report_per_process()
        self._report_summary()
        self._save_json()

    def _report_syscalls(self):
        """
        Detailed system call analysis.

        Shows frequency, average latency, and P99 latency per syscall.
        P99 = 99th percentile -- the latency that 99% of calls are
        faster than.  This is crucial for SLA monitoring.
        """
        print("\n--- SYSTEM CALL ANALYSIS ---")
        n = len(self.syscall_events)
        print(f"Total syscalls traced: {n:,}")

        if not n:
            return

        print("\n  Syscall          Count     %     Avg(us)   P99(us)")
        print("  " + "-" * 58)

        for name, count in sorted(self.syscall_stats.items(),
                                   key=lambda x: x[1], reverse=True):
            pct = count / n * 100
            durations = sorted(self.syscall_durations[name])
            avg_us = sum(durations) / len(durations) / 1000
            # P99 latency: sort the durations and pick the 99th percentile
            p99_idx = int(len(durations) * 0.99)
            p99_us = durations[min(p99_idx, len(durations) - 1)] / 1000
            print(f"  {name:14s} {count:8,}  {pct:5.1f}%  {avg_us:9.2f}  {p99_us:9.2f}")

    def _report_processes(self):
        """
        Process lifecycle analysis.

        Shows exec/exit/fork counts and the most recent exec events.
        Exec events are particularly interesting for security -- they
        reveal every binary that ran on the system.
        """
        print("\n--- PROCESS LIFECYCLE ANALYSIS ---")
        print(f"Total process events: {len(self.process_events):,}")

        for etype, count in sorted(self.process_stats.items()):
            print(f"  {etype.upper():8s}: {count:,}")

        execs = [e for e in self.process_events if e['event_type'] == 'exec']
        if execs:
            show = min(10, len(execs))
            print(f"\n  Last {show} exec events:")
            for e in execs[-show:]:
                print(f"    PID {e['pid']:6d}  {e['comm']:16s}  {e['filename']}")

    def _report_per_process(self):
        """Which processes made the most syscalls."""
        print("\n--- TOP PROCESSES BY SYSCALL COUNT ---")
        top = sorted(self.per_process_syscalls.items(),
                     key=lambda x: x[1], reverse=True)[:10]
        for comm, count in top:
            print(f"  {comm:20s}: {count:,}")

    def _report_summary(self):
        """Final summary with totals."""
        total = len(self.syscall_events) + len(self.process_events)
        print("\n" + "=" * 72)
        print(f" Duration          : {self.duration} seconds")
        print(f" Total events      : {total:,}")
        print(f"   Syscall events  : {len(self.syscall_events):,}")
        print(f"   Process events  : {len(self.process_events):,}")
        print(f" Unique processes  : {len(self.per_process_syscalls)}")
        print(f" BPF programs used : {len(self.bpf_objects) + (1 if self.bpf_proc else 0)}")
        print("=" * 72)

    def _save_json(self):
        """
        Export all events to JSON for post-processing.

        The JSON file can be loaded into pandas, jq, or any
        analysis tool for deeper investigation.
        """
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ebpf_events_{ts}.json"

        data = {
            'metadata': {
                'duration_seconds': self.duration,
                'timestamp': ts,
                'filters': self.filters,
                'kernel': os.uname().release,
            },
            'statistics': {
                'syscall_counts': dict(self.syscall_stats),
                'process_counts': dict(self.process_stats),
                'per_process_syscalls': dict(self.per_process_syscalls),
            },
            # Last 500 events to keep file size reasonable
            'syscall_events': self.syscall_events[-500:],
            'process_events': self.process_events[-500:],
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        print(f"\n Events saved to: {filename}")


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='eBPF Observability Demonstrator -- monitor syscalls and '
                    'process lifecycle with near-zero overhead.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ebpf_monitor.py                  # 30s, all processes
  sudo python3 ebpf_monitor.py -d 60            # 60 seconds
  sudo python3 ebpf_monitor.py -p $(pidof nginx) # one process
  sudo python3 ebpf_monitor.py -u 1000          # one user
        """,
    )
    parser.add_argument(
        '-d', '--duration', type=int, default=30,
        help='Monitoring duration in seconds (default: 30)',
    )
    parser.add_argument(
        '-p', '--pid', type=int,
        help='Filter events to this PID only',
    )
    parser.add_argument(
        '-u', '--uid', type=int,
        help='Filter events to this UID only',
    )

    args = parser.parse_args()

    # ── Check root privilege ─────────────────────────────────
    # eBPF requires CAP_SYS_ADMIN or CAP_BPF.  In practice
    # this means running as root.
    if os.geteuid() != 0:
        print("ERROR: eBPF requires root privileges.")
        print("Run with: sudo python3 ebpf_monitor.py")
        sys.exit(1)

    filters = {}
    if args.pid:
        filters['pid'] = args.pid
    if args.uid:
        filters['uid'] = args.uid

    monitor = eBPFObservabilityMonitor(
        duration=args.duration,
        filters=filters,
    )
    monitor.run()


if __name__ == "__main__":
    main()

