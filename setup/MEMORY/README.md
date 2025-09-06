# Memory Benchmarks

Memory allocation tests for system evaluation.

## How to Run

```bash
# Compile C workload
make

# Run benchmarks
./Malloc [size_in_bytes]                           # C malloc benchmark
python3 ByteArray.py [size_in_bytes]               # Python bytearray benchmark
./Memory_Rate_Generator [rate_mb_per_sec] [duration_seconds]  # Controlled allocation rates

# Kernel memory benchmark (requires root)
cd kmalloc/
make
sudo insmod kmalloc_lkm.ko
./Test [size_in_bytes]
sudo rmmod kmalloc_lkm

# Cleanup
make clean
cd kmalloc/
make clean
```

## Description
- **Malloc.c**: User-space memory allocation using malloc/free
- **ByteArray.py**: Python memory allocation using bytearray
- **Memory_Rate_Generator.c**: Controlled memory allocation rate generator (1MB/s, 10MB/s, 100MB/s)
- **kmalloc/**: Kernel-space memory allocation using kmalloc/kfree