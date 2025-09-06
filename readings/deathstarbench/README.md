# DeathStarBench Logs

CPU and memory usage logs of DeathStarBench application during normal operation and stress testing.

## Directory Structure

```
.
├── Normal_Cpu.log             # CPU usage during normal operation
├── Normal_Mem.log             # Memory usage during normal operation
├── Stress_Cpu.log             # CPU usage during stress testing
├── Stress_Mem.log             # Memory usage during stress testing
└── README.md
```

## How to Run

```bash
# View DeathStarBench logs
ls *.log

# Normal operation logs
cat Normal_Cpu.log
cat Normal_Mem.log

# Stress testing logs
cat Stress_Cpu.log
cat Stress_Mem.log
```

## Description
- **Normal_Cpu.log**: CPU usage during normal operation
- **Normal_Mem.log**: Memory usage during normal operation
- **Stress_Cpu.log**: CPU usage during stress testing using stress-ng
- **Stress_Mem.log**: Memory usage during stress testing using stress-ng
- **CPU Format**: timestamp - cpu_id - cpu_usage (in nanoseconds)
- **Memory Format**: timestamp - source - operation - size - duration (in nanoseconds)

