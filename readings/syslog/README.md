# Syslog Attack Data

## Directory Structure
```
.
├── ATTACK.log (Memory logs during Syslog attack)
├── NORMAL.log (Memory logs during normal operation)
└── README.md
```

## Description
This directory contains the disk I/O logs captred by the GranuloTrack framework during a Syslog attack on `rsyslogd` (v8.2312.0) and during normal operation. 

## Log File Format

Each line in the log files is a JSON object with the following fields:

- `ts`: Timestamp of the event in nanoseconds.
- `name`: Name of the kernel thread handling the operation.
- `pid`: Process ID of the thread.
- `dev`: Device identifier (major/minor number).
- `rwflag`: Operation type (`1` for write, `0` for read).
- `sector`: Starting sector number of the I/O operation.
- `len`: Length of the I/O operation in bytes.
- `qdelta`: Time spent in the request queue (nanoseconds).
- `delta`: Total time taken for the operation (nanoseconds).

**Example:**
```json
{"ts": 1018860576520, "name": "kworker/u33:3", "pid": 2546487, "dev": 8388608, "rwflag": 1, "sector": 100355483, "len": 4096, "qdelta": 2415564, "delta": 4707475}
{"ts": 1018889084847, "name": "kworker/u33:3", "pid": 2546487, "dev": 8388608, "rwflag": 1, "sector": 100336563, "len": 4096, "qdelta": 2171240, "delta": 2947734}
{"ts": 1018895807928, "name": "kworker/u33:3", "pid": 2546487, "dev": 8388608, "rwflag": 1, "sector": 100795007, "len": 4096, "qdelta": 3458434, "delta": 4949770}
```

## Environment

* **Test Scenario**:

  * The dataset captures disk I/O activity during:

    * **Normal operation**
    * A **Syslog attack** on the `rsyslogd` daemon (**v8.2312.0**)
  * The `rsyslogd` service was configured to **receive logs over UDP** on the host system.

* **Containerized Monitoring**:

  * The GranuloTrack framework was executed inside a **Docker container** running **Ubuntu 20.04**, used to trace kernel-level disk I/O without interfering with application behavior.

* **Application Execution**:

  * The `rsyslogd` daemon was deployed **directly on the host** to accurately reflect real-world syslog handling and disk usage patterns.

* **Host System Specifications**:

  * **Processor**: 11th Gen Intel i5-1135G7 (8-core, 2.40 GHz, turbo enabled)
  * **RAM**: 8 GB
  * **Storage**: 185 GB
  * **Operating System**: Ubuntu 20.04
  * **Kernel**: 5.15.0-122-generic
  * **Architecture**: x86\_64

* **Docker Configuration**:

  * Launched with `--privileged` mode
  * Capabilities enabled:

    * `SYS_ADMIN`
    * `SYS_RESOURCE`
    * `SYS_PTRACE`
  * Host directories mounted for kernel access:

    * `/sys/kernel/debug`
    * `/sys/kernel/tracing` (for BPF and tracepoints)
    * `/proc`
    * `/lib/modules/$(uname -r)`
  * Used `--pid=host` to trace kernel threads and all host-side processes involved in disk I/O

* **Attack Traffic**:

  * Logs were generated and sent over **UDP** from a remote client connected via a **100 Gbps Ethernet link**, simulating a high-throughput Syslog flood scenario