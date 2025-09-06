# CPU Benchmarks

CPU workload generators for system testing.

## How to Run

```bash
# Compile
make

# Run workloads
./WorkLoad_1 [iterations]      # CPU-intensive loop
./WorkLoad_2 [iterations]      # Memory access pattern
./CPU_Load_Generator [utilization_percent] [num_threads]  # Controlled CPU utilization

# Cleanup
make clean
```

## Description
- **WorkLoad_1.c**: CPU-intensive workload with nested loops
- **WorkLoad_2.c**: Memory access pattern workload with array operations
- **CPU_Load_Generator.c**: Controlled CPU utilization generator (25%, 50%, 75%, 100% levels)