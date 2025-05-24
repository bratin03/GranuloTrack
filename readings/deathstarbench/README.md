# DeathStarBench CPU and Memory Logs

## Directory Structure
```
.
├── Normal_Cpu.log (CPU usage during normal operation)
├── Normal_Mem.log (Memory usage during normal operation)
├── README.md
├── Stress_Cpu.log (CPU usage during stress testing of CPU using `stress-ng`)
└── Stress_Mem.log (Memory usage during stress testing of memory using `stress-ng`)
```

## Description
This directory contains the CPU and Memory usage logs of the DeathStarBench application during normal operation and stress testing. The logs are generated using the GranuloTrack framework, which captures user-space CPU and memory behavior.

## Log File Format

### CPU logs
Each line in CPU logs has the following format:

```
<timestamp> - <cpu_id> - <cpu_usage>
```

- `timestamp`: Event timestamp in nanoseconds.
- `cpu_id`: Identifier of the CPU core.
- `cpu_usage`: CPU usage in nanoseconds.

**Example:**
```
1742835769023599104 - 13 - 460864
1742835769024154624 - 13 - 20537
1742835769052442368 - 13 - 282644
1742835769052654592 - 13 - 16913
1742835769088739072 - 13 - 325257
1742835769088922112 - 13 - 14741
```

### Memory logs

Each line in Memory logs has the following format:

```
<timestamp> - <source> - <operation> - <size> - <duration>
```

- `timestamp`: Event timestamp in nanoseconds.
- `source`: Source of the memory operation (e.g., `USER`).
- `operation`: Type of memory operation (e.g., `ALLOC` or `FREE`).
- `size`: Size of the memory operation in bytes.
- `duration`: Duration of the memory operation in nanoseconds.

**Example:**
```
1743759297730922496 - USER - FREE - 10485760 - 4128
1743759297730937088 - USER - FREE - 56623104 - 6120
1743759297730949376 - USER - ALLOC - 8392704 - 2844
1743759297730961408 - USER - ALLOC - 8392704 - 1488
1743759297730973184 - USER - ALLOC - 8392704 - 1730
```

## Environment

* **Benchmark Overview**:

  * This dataset captures CPU and memory usage of the **DeathStarBench** benchmark suite, focusing specifically on the **Compose Post** microservice from the Social Network application.
  * The Compose Post service is responsible for **creating and broadcasting posts** via HTTP (frontend) and Thrift (backend) interactions.

* **Deployment Setup**:

  * The microservices were deployed using a **Docker Compose Swarm file** for distributed container orchestration.
  * The **Compose Post microservice** was deployed on one **dedicated server**, while the **remaining backend services** were deployed on a **separate server**.
  * The server hosting Compose Post was intentionally **stressed** to evaluate behavior under resource contention.

* **Workload & Stress Simulation**:

  * A total of **16 parallel clients** issued **$10^7$** requests targeting the Compose Post microservice.
  * Clients were run from a **third machine** connected via **100 Gbps Ethernet** to the servers.
  * Stress was induced **only on the Compose Post server**:

    * **CPU Stress**:

      ```bash
      stress-ng --cpu 8 --timeout 600s
      ```
    * **Memory Stress**:

      ```bash
      stress-ng --vm 4 --vm-bytes 1G --timeout 600s
      ```

* **GranuloTrack Configuration**:

  * The GranuloTrack tracing framework was run inside a **Docker container** on the **Compose Post server**.
  * This container environment was based on **Ubuntu 20.04**, providing isolation for BPF tracing.

* **Compose Post Server Specifications**:

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
  * Used `--pid=host` to capture all process activity from the host system, including the Compose Post container and background stress generators

