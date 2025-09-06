#!/bin/bash

# RocksDB Memory Allocation Benchmark Script
# Evaluates memory allocation patterns between RocksDB versions 5.18.3 and 6.27.3

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Benchmark configuration based on paper description
NUM_OPERATIONS=100000  # 10^5 sequential Set operations
VALUE_SIZE=100         # 100-byte values
WRITE_BUFFER_SIZE=67108864  # 64 MB write buffer (64 * 1024 * 1024)

# Create results directory
mkdir -p results

echo "RocksDB Memory Allocation Benchmark"
echo "Configuration:"
echo "  - Operations: $NUM_OPERATIONS sequential Set operations"
echo "  - Value size: $VALUE_SIZE bytes"
echo "  - Write buffer: 64 MB"
echo ""

# Function to run benchmark for a specific version
run_benchmark() {
    local version=$1
    local db_bench_path=$2
    
    echo "Running benchmark for RocksDB $version..."
    
    # Clean up any existing database
    rm -rf /tmp/rocksdb_bench_$version
    
    # Run db_bench with specified parameters
    $db_bench_path \
        --benchmarks=fillseq \
        --num=$NUM_OPERATIONS \
        --value_size=$VALUE_SIZE \
        --write_buffer_size=$WRITE_BUFFER_SIZE \
        --db=/tmp/rocksdb_bench_$version \
        --compression_type=none \
        --disable_wal=true \
        --statistics=true \
        --histogram=true \
        > results/rocksdb_${version}_benchmark.log 2>&1
    
    echo "Benchmark for RocksDB $version completed. Results saved to results/rocksdb_${version}_benchmark.log"
}

# Check if db_bench binaries exist
if [ ! -f "rocksdb-5.18.3/db_bench" ]; then
    echo "Error: rocksdb-5.18.3/db_bench not found. Run ./install.sh first."
    exit 1
fi

# if [ ! -f "rocksdb-6.27.3/db_bench" ]; then
#     echo "Error: rocksdb-6.27.3/db_bench not found. Run ./install.sh first."
#     exit 1
# fi

# Run benchmarks
run_benchmark "5.18.3" "./rocksdb-5.18.3/db_bench"
run_benchmark "6.27.3" "./rocksdb-6.27.3/db_bench"

echo ""
echo "Benchmark completed successfully!"
echo "Results available in:"
echo "  - results/rocksdb_5.18.3_benchmark.log"
echo "  - results/rocksdb_6.27.3_benchmark.log"