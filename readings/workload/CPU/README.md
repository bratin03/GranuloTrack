# CPU Workload Dataset
This dataset contains CPU workload data collected for [benchmarks](../../../benchmark/CPU/)

## Directory Structure
```txt
.
├── README.md
├── W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv
├── W2_GT_PERF_INST.csv
└── W2_GT_PERF_TIME_TIME.csv
```

## Description
- `W1_GT_GDB_PERF_INSTRUCTION_COUNT.csv`: Contains the instruction count for the [first workload](../../../benchmark/CPU/WorkLoad_1.c) for various number of iterations captured GranuloTrack, GDB, and Perf.
- `W2_GT_PERF_INST.csv`: Contains the instruction count for the [second workload](../../../benchmark/CPU/WorkLoad_2.c) for various number of iterations captured GranuloTrack and Perf.
- `W2_GT_PERF_TIME_TIME.csv`: Contains the execution time for the [second workload](../../../benchmark/CPU/WorkLoad_2.c) for various number of iterations captured GranuloTrack, Perf and Time Command.