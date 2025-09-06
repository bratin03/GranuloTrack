# IO Workload Dataset

I/O workload data collected from IO benchmarks.

## Directory Structure

```
.
├── LATENCY.csv                # I/O latency data for various operation sizes
└── README.md
```

## How to Run

```bash
# Navigate to setup directory
cd ../../../setup/IO/

# Compile and run workloads
make
./Read [size_in_mb]
./Write [size_in_mb]
```

## Description
- **LATENCY.csv**: I/O latency data for various I/O operation sizes (1MB, 10MB, 100MB, 1000MB)
- Contains median, mean, maximum, 25th, and 75th percentiles for both read and write operations
- Data collected using GranuloTrack's DiskFlow tracer