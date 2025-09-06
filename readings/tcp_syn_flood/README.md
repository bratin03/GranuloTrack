# TCP SYN Flood Attack Data

Memory logs in kernel space during TCP SYN flood attack and normal operation on Apache server.

## Directory Structure

```
.
├── ATTACK.log                 # Memory logs during TCP SYN flood attack
├── NORMAL.log                 # Memory logs during normal operation
└── README.md
```

## How to Run

```bash
# View TCP SYN flood attack logs
ls *.log

# Memory logs during attack
cat ATTACK.log

# Memory logs during normal operation
cat NORMAL.log
```

## Description
- **ATTACK.log**: Memory logs during TCP SYN flood attack on Apache (v2.4.63) server
- **NORMAL.log**: Memory logs during normal operation
- **Log Format**: timestamp - KERNEL - action - size (in bytes)