# RocksDB Memory Logs

Memory usage logs for RocksDB database versions 5.18.3 and 6.27.3.

## Directory Structure

```
.
├── MEM_Rocksdb_5.log          # Memory log for RocksDB version 5.18.3
├── MEM_Rocksdb_6.log          # Memory log for RocksDB version 6.27.3
└── README.md
```

## How to Run

```bash
# View RocksDB memory logs
ls *.log

# RocksDB version 5.18.3 memory log
cat MEM_Rocksdb_5.log

# RocksDB version 6.27.3 memory log
cat MEM_Rocksdb_6.log
```

## Description
- **MEM_Rocksdb_5.log**: Memory log for RocksDB version 5.18.3 during sequential write workload
- **MEM_Rocksdb_6.log**: Memory log for RocksDB version 6.27.3 during sequential write workload
- **Log Format**: timestamp - source - operation - size (in bytes)