# CPU Workload

## Directory Structure
```txt
.
├── README.md (this file)
├── WorkLoad_1.c (CPU Workload 1)
└── WorkLoad_2.c (CPU Workload 2)
```

## Description
This directory contains two CPU workloads implemented in C. These workloads are designed to be used for benchmarking and performance testing of the `CorePulse` module.

### `WorkLoad_1.c`
This file contains a CPU workload that increments a integer variable in a loop. The workload is designed to consume CPU resources and expected to be swapped out of the cpu infrequently.

### `WorkLoad_2.c`
This file contains a CPU workload that simulates I/O operations by doing multiple `usleep` calls in a loop. This workload is designed to simulate an I/O-bound process, with frequent context switches and expected to be swapped out of the cpu frequently.

## Usage
Compile the workloads using `gcc` with `O0` optimization level:
```bash
gcc -O0 WorkLoad_1.c -o WorkLoad_1
gcc -O0 WorkLoad_2.c -o WorkLoad_2
```