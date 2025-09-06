# Setup

Performance benchmarks and workload generators for system testing.

## Directory Structure

```
.
├── real_world_apps/          # MySQL, Redis, Nginx testing
├── CPU/                      # CPU workload benchmarks
├── IO/                       # I/O performance tests
├── MEMORY/                   # Memory allocation tests
├── rocksdb/                  # RocksDB memory allocation patterns
├── chrome/                   # Chrome memory allocation analysis
├── deathstarbench/           # DeathStarBench microservice testing
└── CVE/                      # CVE proof of concept testing
```

## How to Run

```bash
# Install real-world applications
cd real_world_apps
sudo ./install.sh

# Run RocksDB benchmarks
cd rocksdb
sudo ./install.sh
./benchmark.sh

# Run Chrome memory analysis
cd chrome
sudo dpkg -i google-chrome-stable_102.0.5005.61-1_amd64.deb
sudo dpkg -i google-chrome-stable_133.0.6943.141-1_amd64.deb

# Run CPU benchmarks
cd CPU
make
./WorkLoad_1 [iterations]
./WorkLoad_2 [iterations]

# Run IO benchmarks
cd IO
make
./Read [size_in_mb]
./Write [size_in_mb]

# Run Memory benchmarks
cd MEMORY
make
./Malloc [size_in_bytes]
python3 ByteArray.py [size_in_bytes]
```