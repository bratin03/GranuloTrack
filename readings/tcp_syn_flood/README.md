# TCP SYN Flood Attack Data

## Directory Structure
```
.
├── ATTACK.log (Memory logs during TCP SYN flood attack)
├── NORMAL.log (Memory logs during normal operation)
└── README.md
```

## Description
This directory contains memory logs in kernel space of `ksoftirqd` thread during a TCP SYN flood attack and normal operation on an Apache (v2.4.63) server captured by the GranuloTrack framework.

Each line in the log files follows this format:

```
<TIMESTAMP> - KERNEL - <ACTION> - <SIZE>
```

- `<TIMESTAMP>`: A unique timestamp for the event start of the memory operation in nanoseconds.
- `<ACTION>`: Either `ALLOC` (memory allocation) or `FREE` (memory deallocation).
- `<SIZE>`: The size of the memory operation in bytes.

**Example:**
```
1741796253063514368 - KERNEL - FREE - 256
1741796253063525632 - KERNEL - ALLOC - 256
1741796253063536896 - KERNEL - ALLOC - 640
```

## Environment

* **Test Scenario**:

  * The data was collected during a **single run** of an Apache web server (**v2.4.63**) under two conditions:

    * **Normal operation**
    * **During a TCP SYN flood attack**

* **Containerized Monitoring**:

  * The GranuloTrack tracing framework was run inside a **Docker container** based on **Ubuntu 20.04**, ensuring an isolated and reproducible environment for BPF-based kernel memory tracing.

* **Application Execution**:

  * The **Apache server** was deployed **natively on the host machine** to simulate realistic web server behavior under attack and normal conditions.

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
  * Used `--pid=host` to access and trace all system threads including `ksoftirqd`

* **Traffic Generation**:

  * The TCP SYN flood was triggered using a remote client connected via a **100 Gbps Ethernet link** to simulate a high-throughput attack scenario at 1000 packets per second (pps).
  * During normal operation, 100 clients sent 10 packets each to the Apache server, simulating typical web traffic.

* **Data Collection**:
    * The data was collected for each of the two scenarios (normal and attack) for all the `ksoftirqd` threads on all CPUs.
    * The data presented in this directory is shown for one of the `ksoftirqd` threads (CPU 0) for simplicity and for a limited time period (approximately 10 seconds) to illustrate the memory operations during the attack and normal operation.