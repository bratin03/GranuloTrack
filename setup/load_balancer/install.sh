#!/bin/bash

# Install script for GranuloTrack Load Balancer dependencies

echo "=== Installing GranuloTrack Load Balancer Dependencies ==="

# Update package list
echo "Updating package list..."
sudo apt-get update -y

# Install required system dependencies
echo "Installing system dependencies..."
sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libev-dev \
    libssl-dev \
    libunwind-dev \
    nlohmann-json3-dev \
    libgoogle-glog-dev \
    libabsl-dev \
    libboost-all-dev \
    libtbb-dev \
    libsimdjson-dev \
    git

# Remove old spdlog to avoid version conflicts
echo "Removing old libspdlog-dev..."
sudo apt-get remove -y libspdlog-dev

# Create temporary directory for libraries
echo "Cloning latest fmt and spdlog into /tmp/lib..."
mkdir -p /tmp/lib
cd /tmp/lib || exit

# Install latest fmt
echo "Installing latest fmt..."
git clone https://github.com/fmtlib/fmt.git
cd fmt || exit
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
cd /tmp/lib || exit

# Install latest spdlog
echo "Installing latest spdlog..."
git clone https://github.com/gabime/spdlog.git
cd spdlog || exit
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install

echo ""
echo "Dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "  mkdir -p build && cd build"
echo "  cmake .."
echo "  make -j\$(nproc)"
