# GranuloTrack Source Code

## Directory Structure
```txt
.
├── CorePulse.py (CPU Monitoring)
├── DiskFlow.py (Disk I/O Monitoring)
├── MemTracker_Kernel.py (Memory Monitoring in Kernel Space)
├── MemTracker_User.py (Memory Monitoring in User Space)
└── README.md (this file)
```
## Prerequisites
1. Install `bcc` toolkit. Refer to the [bcc documentation](https://github.com/iovisor/bcc)

## Usage
The source code is divided into several modules:
- `CorePulse.py`: Code for CPU Monitoring.
- `DiskFlow.py`: Code for Disk I/O Monitoring.
- `MemTracker_User.py`: Code for Memory Monitoring in User Space.
- `MemTracker_Kernel.py`: Code for Memory Monitoring in Kernel Space.

For using the code, import the required module in your Python script, instantiate the class, and call the `stream_events()` method to start monitoring. This function will generate a stream of events as python dictionaries for further processing. `CorePulse` and `MemTracker` also support filtering by process IDs (PIDs) if specified or will trace all processes by default.

## Example
```python
# main.py

from CorePulse import CorePulse
import json

def main():
    # Optionally specify PIDs to trace; omit `pids` to trace all
    tracer = CorePulse(pids=[1234, 5678])  # Replace with actual PIDs
    try:
        for event in tracer.stream_events():
            print(json.dumps(event))  # Or do custom processing here
    except KeyboardInterrupt:
        print("Stopping trace...")
        tracer.stop()

if __name__ == "__main__":
    main()
```

## Output Format
The output from the `stream_events()` method is a dictionary containing the following for different events:
### `CorePulse`:
```python
{
    "cpu": int,           # CPU core number where the event occurred
    "instructions": int,  # Number of instructions executed during the burst
    "cycles": int,        # Number of CPU cycles consumed
    "time": int,          # Time in nanoseconds during which the burst occurred 
    "pid": int            # Process ID associated with the event
}
```
### `DiskFlow`:
```python
{
    "ts": int,            # Completion timestamp of the I/O event (nanoseconds)
    "name": str,          # Process name performing the I/O
    "pid": int,           # Process ID
    "dev": int,           # Device number
    "rwflag": int,        # Read/write flag (0=read, 1=write)
    "sector": int,        # Starting sector of the I/O
    "len": int,           # Length of the I/O in bytes
    "qdelta": int,        # Queue delay in nanoseconds
    "delta": int          # Total I/O latency in nanoseconds
}
```
### `MemTracker`:
```python
{
    "pid": int,           # Process ID associated with the memory event
    "size": int,          # Size of memory allocated or freed (in bytes)
    "type": int           # 0 for allocation, 1 for free
}
```