# Benchmark

## Directory Structure
```txt
.
├── CPU (CPU Workloads)
│   ├── README.md
│   ├── WorkLoad_1.c
│   └── WorkLoad_2.c
├── CVE (CVE Proof of Concept)
│   ├── POC.js
│   └── README.md
├── IO (Disk Workloads)
│   ├── Read.c
│   ├── README.md
│   └── Write.c
├── MEMORY (Memory Workloads)
│   ├── ByteArray.py
│   ├── kmalloc
│   │   ├── kmalloc_lkm.c
│   │   ├── Makefile
│   │   └── Test.c
│   ├── Malloc.c
│   └── README.md
└── README.md
```

## Description
This directory contains three types of workloads: CPU, IO, and Memory. Each workload is designed to test different aspects of system performance. It also includes a proof of concept (PoC) for a specific CVE vulnerability. For more details on each workload, refer to the respective `README.md` files in each subdirectory.