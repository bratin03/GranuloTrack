# Syslog Attack Data

Disk I/O logs during Syslog attack on rsyslogd and normal operation.

## Directory Structure

```
.
├── ATTACK.log                 # Memory logs during Syslog attack on rsyslogd
├── NORMAL.log                 # Memory logs during normal operation
└── README.md
```

## How to Run

```bash
# View syslog attack logs
ls *.log

# Memory logs during attack
cat ATTACK.log

# Memory logs during normal operation
cat NORMAL.log
```

## Description
- **ATTACK.log**: Memory logs during Syslog attack on rsyslogd (v8.2312.0)
- **NORMAL.log**: Memory logs during normal operation
- **Log Format**: JSON objects with timestamp, process info, device, operation type, and timing data