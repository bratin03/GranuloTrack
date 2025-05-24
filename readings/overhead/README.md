# Overhead of the Modules

## Directory Structure
```txt
.
├── APP.csv
├── CPU.csv
├── MEM.csv
└── README.md
```

## Description

- `APP.csv`: Contains the overhead measurements of the GranuloTrack modules in real-life applications. The measurements were taken for MySQL (v8.4.4), Nginx (v1.27.1), and Redis (v7.3.0). The data contains the throughput of the application with one or all components enabled and no components enabled. The throughput is normalized to the throughput of the application with no components enabled.

- `CPU.csv`: Contains the overhead measurements of the GranuloTrack modules in CPU. It represents the amount of CPU time consumed by the GranuloTrack modules in CPU workloads. The data contains the CPU time consumed by the GranuloTrack modules with one or all components enabled and no components enabled. 

- `MEM.csv`: Contains the overhead measurements of the GranuloTrack modules in memory. It represents the amount of memory needed for the components of GranuloTrack.

## Environment

* **Containerized Setup**:

  * All GranuloTrack components were run inside a Docker container based on **Ubuntu 20.04**, ensuring a consistent and isolated environment for BPF tracing and minimizing host interference.

* **Application Deployment**:

  * Target applications (**MySQL v8.4.4**, **Nginx v1.27.1**, **Redis v7.3.0**) were executed **natively on the host system**.
  * The **client workload generator** was deployed on a **separate physical machine**, connected via a **100 Gbps Ethernet network** to ensure high-throughput testing.

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
    * `/proc` (for process/kernel statistics)
    * `/lib/modules/$(uname -r)` (for kernel modules)
  * Used `--pid=host` to share the host PID namespace, enabling full host-level process tracing

* **Workload Execution**:

  * For each measurement:

    * **100 clients** were used
    * Each client issued **1,000 requests**
  * Every experiment was repeated **20 times** to ensure consistency

* **Statistical Reporting**:

  * The dataset provided contains only the **averaged values** of the 20 runs per configuration
