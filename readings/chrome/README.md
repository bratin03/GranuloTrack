# Chrome Memory Usage Logs

## Directory Structure
```
.
├── MEM_Chrome_102.log   (Memory log for Chrome version 102.0.5005.61)
├── MEM_Chrome_133.log   (Memory log for Chrome version 133.0.6943.141)
└── README.md
```

## Description
This directory contains the Memory usage logs for the Chrome browser, specifically for two different versions: 102.0.5005.61 and 133.0.6943.141. The logs are generated using the GranuloTrack framework, which captures user-space memory behavior.

## Log File Format

Each line in the memory log has the following format:

```
<timestamp> - <source> - <operation> - <size>
```

- `timestamp`: Event timestamp in nanoseconds.
- `source`: Source of the memory operation (e.g., `USER`).
- `operation`: Type of memory operation (e.g., `ALLOC` or `FREE`).
- `size`: Size of the memory operation in bytes.

**Example:**
```
1744776553559228759 - USER - ALLOC - 413696
1744776553559230419 - USER - ALLOC - 823296
1744776553559239572 - USER - ALLOC - 823296
```

## Environment

* **Test Setup**:

  * Memory logs were collected for **Google Chrome** versions **102.0.5005.61** and **133.0.6943.141**.
  * Chrome was executed **natively on the host system**, while the **GranuloTrack** tracing framework ran inside a **Docker container** on the same machine.

* **Workload Details**:

  * A **2160p (4K)** YouTube video was played for **1 minute** in each Chrome version.
  * The **same video** and playback duration were used for both versions to ensure consistency.
  * The browser was in **foreground** and **uninterrupted** during playback, simulating a realistic user session.

* **Execution Environment**:

  * **Processor**: 11th Gen Intel i5-1135G7 (8-core, 2.40 GHz, turbo enabled)
  * **RAM**: 8 GB
  * **Storage**: 185 GB
  * **Operating System**: Ubuntu 20.04
  * **Kernel**: 5.15.0-122-generic
  * **Architecture**: x86\_64

* **Docker Configuration (GranuloTrack)**:

  * Launched with `--privileged` mode
  * Enabled capabilities:

    * `SYS_ADMIN`
    * `SYS_RESOURCE`
    * `SYS_PTRACE`
  * Mounted host directories:

    * `/sys/kernel/debug`
    * `/sys/kernel/tracing`
    * `/proc`
    * `/lib/modules/$(uname -r)`
  * Used `--pid=host` to trace memory events across all host processes
