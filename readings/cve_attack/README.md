# CVE Attack Data

CPU and memory usage logs during CVE-2019-5782 vulnerability exploitation.

## Directory Structure

```
.
├── CPU.log                    # CPU burst log during CVE-2019-5782 exploitation
├── MEM.log                    # Memory usage log during CVE-2019-5782 exploitation
└── README.md
```

## How to Run

```bash
# View CVE attack logs
ls *.log

# CPU burst log during attack
cat CPU.log

# Memory usage log during attack
cat MEM.log
```

## Description
- **CPU.log**: CPU burst log of the process during CVE-2019-5782 exploitation
- **MEM.log**: Memory usage log of the process during CVE-2019-5782 exploitation
- **CPU Format**: timestamp - cpu_id - cpu_usage (in nanoseconds)
- **Memory Format**: timestamp - source - operation - size (in bytes)
