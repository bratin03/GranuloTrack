# Chrome Memory Logs

Memory usage logs for Chrome browser versions 102.0.5005.61 and 133.0.6943.141.

## Directory Structure

```
.
├── MEM_Chrome_102.log         # Memory log for Chrome version 102.0.5005.61
├── MEM_Chrome_133.log         # Memory log for Chrome version 133.0.6943.141
└── README.md
```

## How to Run

```bash
# View Chrome memory logs
ls *.log

# Chrome version 102 memory log
cat MEM_Chrome_102.log

# Chrome version 133 memory log
cat MEM_Chrome_133.log
```

## Description
- **MEM_Chrome_102.log**: Memory log for Chrome version 102.0.5005.61 during 4K video streaming
- **MEM_Chrome_133.log**: Memory log for Chrome version 133.0.6943.141 during 4K video streaming
- **Log Format**: timestamp - source - operation - size (in bytes)
