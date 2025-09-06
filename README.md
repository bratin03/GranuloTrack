# GranuloTrack

System monitoring framework for real-time performance tracking.

## Directory Structure

```
GranuloTrack/
├── setup/                      # Performance benchmarks and workload generators
│   ├── CPU/                    # CPU workload generators and stress tests
│   ├── IO/                     # Disk I/O performance benchmarks
│   ├── MEMORY/                 # Memory allocation and rate generators
│   ├── chrome/                 # Chrome browser memory analysis tools
│   ├── rocksdb/                # RocksDB database performance tests
│   ├── deathstarbench/         # Microservice workload testing suite
│   ├── CVE/                    # Security vulnerability testing tools
│   └── real_world_apps/        # MySQL, Redis, Nginx application testing
├── readings/                   # Experimental results and performance logs
│   ├── workload/               # CPU, IO, and memory workload data
│   ├── load_balancer/          # Load balancing strategy comparisons
│   ├── overhead/               # Performance overhead measurements
│   ├── chrome/                 # Chrome memory usage logs
│   ├── rocksdb/                # RocksDB memory allocation logs
│   ├── deathstarbench/         # Microservice performance logs
│   ├── cve_attack/             # Security attack performance logs
│   ├── syslog/                 # System log analysis data
│   └── tcp_syn_flood/          # Network attack simulation logs
└── src/                        # Core monitoring components for CPU, memory, and I/O tracking
    ├── CorePulse.py            # CPU performance tracer with hardware counters
    ├── DiskFlow.py             # Disk I/O monitoring with filtering
    ├── MemTracker_Kernel.py    # Kernel-space memory allocation tracer
    └── MemTracker_User.py      # User-space memory allocation tracer
```

For usage instructions, see README files in each subdirectory.