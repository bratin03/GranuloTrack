# Readings

Experimental results and performance logs from GranuloTrack evaluation.

## Directory Structure

```
.
├── chrome/                    # Chrome memory usage logs
├── cve_attack/               # CVE attack performance logs
├── deathstarbench/           # DeathStarBench workload logs
├── load_balancer/            # Load balancing comparison data
├── overhead/                 # Performance overhead measurements
├── rocksdb/                  # RocksDB memory allocation logs
├── syslog/                   # System log analysis
├── tcp_syn_flood/            # TCP SYN flood attack logs
└── workload/                 # CPU, IO, and memory workload data
```

## How to Run

```bash
# View Chrome memory logs
ls chrome/*.log

# View CVE attack logs
ls cve_attack/*.log

# View DeathStarBench logs
ls deathstarbench/*.log

# View load balancing data
ls load_balancer/*.csv

# View overhead measurements
ls overhead/*.csv

# View RocksDB memory logs
ls rocksdb/*.log

# View syslog attack data
ls syslog/*.log

# View TCP SYN flood data
ls tcp_syn_flood/*.log

# View workload datasets
ls workload/*/
```