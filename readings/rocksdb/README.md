# RocksDB Memory log

## Directory Structure
```
.
├── MEM_Rocksdb_5.log (Memory log for RocksDB version 5.18.3)
├── MEM_Rocksdb_6.log (Memory log for RocksDB version 6.27.3)
└── README.md
```

## Description
This directory contains the Memory usage logs for the RocksDB database system, specifically for two different versions: 5.18.3 and 6.27.3. The logs are generated using the GranuloTrack framework, which captures user-space memory behavior.

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

  * Memory usage logs were captured for **RocksDB** versions **5.18.3** and **6.27.3** running on the **same host machine**.
  * The RocksDB instance was benchmarked using the official **`db_bench`** tool.

* **Workload Details**:

  * The database was sequentially filled with **$10^5$** `Set` requests.
  * Each request inserted a value of **100 bytes**.
  * All configuration parameters of RocksDB were kept at their **default values**, except for:

    * **Write Buffer Size** set to **64 MB** to influence memory consumption and flushing behavior.

* **Execution Environment**:

  * The RocksDB process ran **natively on the host system**.
  * GranuloTrack ran inside a **Docker container** on the same host, tracing user-space memory allocation and deallocation events.

* **Host System Specifications**:

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
  * Used `--pid=host` to observe all relevant processes and memory operations