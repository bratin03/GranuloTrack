#!/bin/bash

# RocksDB Clean Script
# Removes built binaries and build artifacts for RocksDB versions 5.18.3 and 6.27.3

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Cleaning RocksDB build artifacts..."

# Clean RocksDB 5.18.3
echo "Cleaning RocksDB 5.18.3..."
if [ -d "rocksdb-5.18.3" ]; then
    cd rocksdb-5.18.3
    make clean || true
    rm -f db_bench
    cd ..
    echo "RocksDB 5.18.3 cleaned"
else
    echo "RocksDB 5.18.3 directory not found"
fi

# Clean RocksDB 6.27.3
echo "Cleaning RocksDB 6.27.3..."
if [ -d "rocksdb-6.27.3" ]; then
    cd rocksdb-6.27.3
    make clean || true
    rm -f db_bench
    cd ..
    echo "RocksDB 6.27.3 cleaned"
else
    echo "RocksDB 6.27.3 directory not found"
fi

echo "RocksDB clean completed successfully!"
