# GranuloTrack

## Directory Structure

```txt
.
├── benchmark
│   ├── CPU
│   │   ├── README.md
│   │   ├── WorkLoad_1.c
│   │   └── WorkLoad_2.c
│   ├── IO
│   │   ├── Read.c
│   │   ├── README.md
│   │   └── Write.c
│   ├── MEMORY
│   │   ├── ByteArray.py
│   │   ├── kmalloc
│   │   │   ├── kmalloc_lkm.c
│   │   │   ├── Makefile
│   │   │   └── Test.c
│   │   ├── Malloc.c
│   │   └── README.md
│   └── README.md
├── readings
│   ├── chrome
│   │   ├── MEM_Chrome_102.log
│   │   ├── MEM_Chrome_133.log
│   │   └── README.md
│   ├── cve_attack
│   │   ├── CPU.log
│   │   ├── MEM.log
│   │   └── README.md
│   ├── deathstarbench
│   │   ├── Normal_Cpu.log
│   │   ├── Normal_Mem.log
│   │   ├── README.md
│   │   ├── Stress_Cpu.log
│   │   └── Stress_Mem.log
│   ├── overhead
│   │   ├── APP.csv
│   │   ├── CPU.csv
│   │   ├── MEM.csv
│   │   └── README.md
│   ├── README.md
│   ├── rocksdb
│   │   ├── MEM_Rocksdb_5.log
│   │   ├── MEM_Rocksdb_6.log
│   │   └── README.md
│   ├── syslog
│   │   ├── ATTACK.log
│   │   ├── NORMAL.log
│   │   └── README.md
│   ├── tcp_syn_flood
│   │   ├── ATTACK.log
│   │   ├── NORMAL.log
│   │   └── README.md
│   └── workload
│       ├── CPU
│       │   ├── README.md
│       │   ├── W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv
│       │   ├── W2_GT_PERF_INST.csv
│       │   └── W2_GT_PERF_TIME_TIME.csv
│       ├── IO
│       │   ├── LATENCY.csv
│       │   └── README.md
│       ├── MEMORY
│       │   ├── DATA.csv
│       │   └── README.md
│       └── README.md
├── README.md
└── src
    ├── CorePulse.py
    ├── DiskFlow.py
    ├── MemTracker_Kernel.py
    ├── MemTracker_User.py
    └── README.md
```

## Description
- The `benchmark` directory contains source code for workload benchmarks in CPU, IO, and MEMORY categories.
- The `readings` directory contains logs and datasets from various experiments, including Chrome memory usage, CVE attacks, DeathStarBench workloads, and more.
- The `src` directory contains the source code for GranuloTrack, including usage instructions and tracking functionalities for CPU, IO, and memory.