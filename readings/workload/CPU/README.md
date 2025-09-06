# CPU Workload Dataset

CPU workload data collected from CPU benchmarks.

## Directory Structure

```
.
├── W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv    # Instruction count comparison for WorkLoad_1
├── W2_GT_PERF_INST.csv                     # Instruction count comparison for WorkLoad_2
├── W2_GT_PERF_TIME_TIME.csv                # Execution time comparison for WorkLoad_2
└── README.md
```

## How to Run

```bash
# Navigate to setup directory
cd ../../../setup/CPU/

# Compile and run workloads
make
./WorkLoad_1 [iterations]
./WorkLoad_2 [iterations]
```

## Description
- **W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv**: Instruction count comparison between GranuloTrack, GDB, and Perf for WorkLoad_1
- **W2_GT_PERF_INST.csv**: Instruction count comparison between GranuloTrack and Perf for WorkLoad_2
- **W2_GT_PERF_TIME_TIME.csv**: Execution time comparison between GranuloTrack, Perf, and Time command for WorkLoad_2