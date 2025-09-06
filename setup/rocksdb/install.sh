#!/bin/bash

# RocksDB Installation Script
# Installs RocksDB versions 5.18.3 and 6.27.3 for memory allocation benchmarking

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Installing RocksDB versions 5.18.3 and 6.27.3..."

# Install dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libgflags-dev \
    libsnappy-dev \
    zlib1g-dev \
    libbz2-dev \
    liblz4-dev \
    libzstd-dev \
    libgtest-dev

# Build RocksDB 5.18.3
echo "Building RocksDB 5.18.3..."
cd rocksdb-5.18.3
if [ ! -f "db_bench" ]; then
    make clean || true
    DEBUG_LEVEL=0 EXTRA_CXXFLAGS="-Wno-deprecated-copy -Wno-range-loop-construct -Wno-error" EXTRA_CFLAGS="-Wno-error" make db_bench -j5
fi
cd ..

# Build RocksDB 6.27.3
echo "Building RocksDB 6.27.3..."
cd rocksdb-6.27.3
if [ ! -f "db_bench" ]; then
    make clean || true
    DEBUG_LEVEL=0 EXTRA_CXXFLAGS="-Wno-deprecated-copy -Wno-range-loop-construct -Wno-error" EXTRA_CFLAGS="-Wno-error" make db_bench -j5
fi
cd ..

echo "RocksDB installation completed successfully!"
echo "Available benchmarks:"
echo "  - rocksdb-5.18.3/db_bench"
echo "  - rocksdb-6.27.3/db_bench"
