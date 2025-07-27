# Readings of Experiments
This directory contains the readings of the experiments conducted for the benchmarking and evaluation of GranuloTrack.

## Directory Structure

```txt
.
├── chrome
│   ├── MEM_Chrome_102.log
│   ├── MEM_Chrome_133.log
│   └── README.md
├── cve_attack
│   ├── CPU.log
│   ├── MEM.log
│   └── README.md
├── deathstarbench
│   ├── Normal_Cpu.log
│   ├── Normal_Mem.log
│   ├── README.md
│   ├── Stress_Cpu.log
│   └── Stress_Mem.log
├── overhead
│   ├── APP.csv
│   ├── CPU.csv
│   ├── MEM.csv
│   └── README.md
├── README.md
├── rocksdb
│   ├── MEM_Rocksdb_5.log
│   ├── MEM_Rocksdb_6.log
│   └── README.md
├── syslog
│   ├── ATTACK.log
│   ├── NORMAL.log
│   └── README.md
├── tcp_syn_flood
│   ├── ATTACK.log
│   ├── NORMAL.log
│   └── README.md
├── load_balancer
│   ├── GranuloTrack.csv
│   ├── Htop.csv
│   ├── Nginx.csv
│   └── README.md
└── workload
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

## Description
This directory contains the readings of various experiments conducted to evaluate the performance and overhead of GranuloTrack. Each subdirectory contains logs or datasets related to specific experiments, such as Chrome memory usage, CVE attacks, DeathStarBench workloads, load balancing strategies comparison, and more.

### Key Experiments
- **Load Balancing Comparison**: Three strategies (Nginx, GranuloTrack, Htop) under stress conditions
- **Chrome Memory Analysis**: Memory usage patterns in Chrome browser versions
- **CVE Attack Detection**: Performance monitoring during security attacks
- **DeathStarBench Workloads**: Database and web service performance evaluation
- **Network Attack Detection**: TCP SYN flood and syslog attack monitoring
- **Performance Overhead**: GranuloTrack's impact on system performance