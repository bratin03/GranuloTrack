# Workload Datasets

Workload datasets captured from benchmark experiments.

## Directory Structure

```
.
├── CPU/                        # CPU workload performance data
├── IO/                         # I/O latency measurements
├── MEMORY/                     # Memory allocation data
└── README.md
```

## How to Run

```bash
# Navigate to setup directory
cd ../../setup/

# Run CPU benchmarks
cd CPU/
make
./WorkLoad_1 [iterations]
./WorkLoad_2 [iterations]

# Run IO benchmarks
cd ../IO/
make
./Read [size_in_mb]
./Write [size_in_mb]

# Run Memory benchmarks
cd ../MEMORY/
make
./Malloc [size_in_bytes]
python3 ByteArray.py [size_in_bytes]
```

## Description
- **CPU/**: Instruction count and performance timing data
- **IO/**: I/O latency measurements for various data sizes
- **MEMORY/**: Memory allocation patterns and timing data

