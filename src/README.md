# Source Code

Core monitoring components for CPU, memory, and disk I/O tracking using eBPF.

## Directory Structure

```
.
├── CorePulse.py              # CPU performance tracer with hardware counter integration
├── DiskFlow.py               # Disk I/O monitoring with filtering capabilities
├── MemTracker_Kernel.py      # Kernel-space memory allocation monitoring
├── MemTracker_User.py        # User-space memory allocation monitoring
├── load_balancer.py          # Load balancing implementation using GranuloTrack data
└── utils.py                  # Utility functions for data processing and analysis
```

## Prerequisites
- Linux Kernel 4.18+ with eBPF support
- Python 3.6+ with bcc toolkit
- Root privileges for eBPF program loading

## Components

- **CorePulse.py**: CPU performance tracer with hardware counter integration
- **DiskFlow.py**: Disk I/O monitoring with filtering capabilities
- **MemTracker_Kernel.py**: Kernel-space memory allocation monitoring
- **MemTracker_User.py**: User-space memory allocation monitoring

## How to Run

```python
# CPU monitoring
from CorePulse import CorePulse
tracer = CorePulse(process_patterns=["nginx", "apache"])
for event in tracer.stream_events():
    print(event)

# Disk I/O monitoring
from DiskFlow import DiskFlow
tracer = DiskFlow(process_patterns=["mysql", "postgres"])
for event in tracer.stream_events():
    print(event)

# Memory monitoring
from MemTracker_Kernel import MemTrackerKernel
tracer = MemTrackerKernel(process_patterns=["chrome", "firefox"])
for event in tracer.stream_events():
    print(event)
```