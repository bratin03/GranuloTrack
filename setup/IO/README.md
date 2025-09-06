# IO Benchmarks

I/O performance tests for system evaluation.

## How to Run

```bash
# Compile
make

# Run benchmarks
./Read [size_in_mb]    # Sequential read operations
./Write [size_in_mb]   # Sequential write operations

# Cleanup
make clean
```

## Description
- **Read.c**: Sequential read operations with configurable data size
- **Write.c**: Sequential write operations with configurable data size