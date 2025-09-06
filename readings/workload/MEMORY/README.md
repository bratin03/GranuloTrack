# Memory Workload Dataset

Memory workload data collected from memory benchmarks.

## Directory Structure

```
.
├── DATA.csv                   # Memory allocation data for various sizes
└── README.md
```

## How to Run

```bash
# Navigate to setup directory
cd ../../../setup/MEMORY/

# Compile and run workloads
make
./Malloc [size_in_bytes]
python3 ByteArray.py [size_in_bytes]

# Run kernel memory workload
cd kmalloc/
make
sudo insmod kmalloc_lkm.ko
./Test [size_in_bytes]
sudo rmmod kmalloc_lkm
```

## Description
- **DATA.csv**: Memory allocation data for various allocation sizes
- **kmalloc**: Sizes from 2^5 (32 bytes) to 2^22 (4,194,304 bytes)
- **malloc/bytearray**: Sizes from 2^0 (1 byte) to 2^30 (1,073,741,824 bytes)
- Data collected using GranuloTrack's MemTracker tracers

