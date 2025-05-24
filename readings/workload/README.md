# Workload Datasets

This directory contains various [workload](../../benchmark/) datasets captured.

## Directory Structure

```txt
.
├── CPU
│   ├── README.md
│   ├── W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv
│   ├── W2_GT_PERF_INST.csv
│   └── W2_GT_PERF_TIME_TIME.csv
├── IO
│   ├── LATENCY.csv
│   └── README.md
├── MEMORY
│   ├── DATA.csv
│   └── README.md
└── README.md
```

For further details on each dataset, refer to the respective `README.md` files in each subdirectory.

## Environment
* **Containerized Setup**:
  All experiments were conducted inside a Docker container running **Ubuntu 20.04** to ensure a consistent and isolated environment for BPF tracing.

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
  * Used `--pid=host` to share the host PID namespace, enabling full process tracing

* **Repetition & Statistical Reporting**:

  * Each experiment was repeated **at least 20 times**
  * The dataset provided here only containes the **average** of the collected data

