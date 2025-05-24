# IO Workload Dataset
This dataset contains I/O workload data collected for [benchmarks](../../../benchmark/IO/)

## Directory Structure
```txt
.
├── LATENCY.csv
└── README.md
```

## Description
- `LATENCY.csv`: Contains the I/O latency data for various sizes of I/O operations made through [`write`](../../../benchmark/IO/Write.c) and [`read`](../../../benchmark/IO/Read.c). The data includes the requested I/O size and the total I/O latency captured by GranuloTrack for the respective processes. It containes the median, mean, maximum, 25th, and 75th percentiles of the I/O latency for each size of I/O operation. The sizes are 1 MB, 10 MB, 100 MB, and 1000 MB, with the data collected for both write and read operations.