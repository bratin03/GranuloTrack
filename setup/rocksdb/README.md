# RocksDB Benchmark

Memory allocation pattern comparison between RocksDB versions 5.18.3 and 6.27.3 under sequential write workloads.

## How to Run

```bash
# Install and build RocksDB versions
chmod +x install.sh
sudo ./install.sh

# Run benchmark
chmod +x benchmark.sh
./benchmark.sh

# Run with memory tracking
# Terminal 1: Start memory tracker
cd ../../src
sudo python3 MemTracker_Kernel.py --process_patterns "db_bench" --output_file rocksdb_memory.log

# Terminal 2: Run benchmark
cd ../setup/rocksdb
./benchmark.sh
```

## Description
- **install.sh**: Installation script for dependencies and RocksDB builds
- **benchmark.sh**: Main benchmark execution script
- **v5.18.3.tar.gz**: RocksDB 5.18.3 source code
- **v6.27.3.tar.gz**: RocksDB 6.27.3 source code
- **results/**: Benchmark results for both versions
