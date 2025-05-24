# CVE Attack Data (CVE-2019-5782)

## Directory Structure
```
.
├── CPU.log (CPU burst log of the process)
├── MEM.log (Memory usage log of the process)
└── README.md
```

## Description
This directory contains the CPU and Memory usage logs of a process that was attacked using the [CVE-2019-5782](https://github.com/tunz/js-vuln-db/blob/master/v8/CVE-2019-5782.md) vulnerability. 

## Log File Format

### CPU.log

Each line in `CPU.log` has the following format:

```
<timestamp> - <cpu_id> - <cpu_usage>
```

- `timestamp`: Event timestamp in nanoseconds. (Start of the CPU burst)
- `cpu_id`: Identifier of the CPU core.
- `cpu_usage`: CPU usage in nanoseconds.

**Example:**
```
1743614355250000000 - 3 - 397544
1743614355250066519 - 3 - 2422505
1743614355250085752 - 3 - 2473437
```

### MEM.log

Each line in `MEM.log` has the following format:

```
<timestamp> - <source> - <operation> - <size>
```

- `timestamp`: Event timestamp in nanoseconds.
- `source`: Source of the memory operation (e.g., `USER`).
- `operation`: Type of memory operation (e.g., `ALLOC` or `FREE`).
- `size`: Size of the memory operation in bytes.

**Example:**
```
1743614355250000000 - USER - ALLOC - 106496
1743614355250195851 - USER - ALLOC - 118784
1743614355250390264 - USER - ALLOC - 118784
```

## Environment

* **Test Scenario**:

  * The dataset captures **CPU and memory usage** of a process during exploitation using **CVE-2019-5782**, a vulnerability in the Chrome V8 engine.
  * The exploit was executed against **Google Chrome version 71.0.3578.80**, installed on the host system.

* **Monitoring Setup**:

  * The GranuloTrack framework was executed inside a **Docker container** based on **Ubuntu 20.04**, used to trace user-space CPU and memory behavior of the vulnerable process during attack execution.

* **Application Execution**:

  * **Google Chrome** was installed and run **natively on the host machine**.
  * The vulnerable process was spawned by Chrome and targeted using a proof-of-concept for CVE-2019-5782.

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
  * Used `--pid=host` to monitor Chrome and related subprocesses at the system level
