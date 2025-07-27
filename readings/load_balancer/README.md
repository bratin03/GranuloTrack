# Load Balancing Experiment Data

## Directory Structure
```
.
├── GranuloTrack.csv (Results from GranuloTrack-based load balancer)
├── Htop.csv (Results from Htop-based load balancer)
├── Nginx.csv (Results from Nginx least_time load balancer)
└── README.md
```

## Description
This directory contains the performance data from comparing three load balancing strategies under controlled stress conditions. The experiment evaluates Nginx Least Time (baseline), GranuloTrack-based load balancer (proposed), and Htop-based load balancer using 4 Apache servers with sequential CPU stress injection.

## Data File Format

### CSV Format
Each CSV file contains performance metrics with the following columns:

```
<timestamp>,<response_time>,<server_id>,<cpu_utilization>,<load_distribution>
```

- `timestamp`: Event timestamp in milliseconds
- `response_time`: HTTP response time in milliseconds
- `server_id`: Target server identifier (1-4)
- `cpu_utilization`: CPU utilization percentage
- `load_distribution`: Number of requests routed to this server

**Example:**
```
1640995200000,45.2,1,78.5,1250
1640995200050,52.1,2,82.3,1248
1640995200100,38.9,3,75.2,1252
```

## Environment

* **Test Infrastructure**:

  * **4 Apache servers** serving HTTP requests
  * **Client load**: 100 requests/second for 10 minutes
  * **Stress simulation**: Sequential CPU stress on each server using stress-ng
  * **Network**: 10 Gbps LAN connectivity

* **Load Balancing Strategies**:

  * **Nginx Least Time (Baseline)**: Uses `least_time` header routing to servers with lowest response time
  * **GranuloTrack-based Load Balancer (Proposed)**: Uses `\cputool{}` CPU burst monitoring with weighted moving average and priority queue routing
  * **Htop-based Load Balancer (Comparison)**: Uses CPU percentage monitoring via htop with same weighted moving average mechanism

* **Stress Testing**:

  * **Tool**: stress-ng
  * **Pattern**: Sequential stress on each server
  * **Duration**: 10 minutes per test phase
  * **Load**: 100 requests/second sustained client load

* **System Specifications**:

  * **Processor**: Intel Xeon Gold 6336Y (16-core, 2.40 GHz)
  * **RAM**: 8 GB
  * **Storage**: 50 GB
  * **Operating System**: Ubuntu 20.04.6 LTS
  * **Kernel**: 5.15.0-139-generic
  * **Architecture**: x86_64

* **Network Configuration**:

  * **Bandwidth**: 10 Gbps LAN
  * **Topology**: Direct LAN connectivity
  * **Cross-kernel validation**: Tested on kernels 5.15.0-139-generic and 6.0.0-64-generic

* **GranuloTrack Configuration**:

  * Real-time CPU burst monitoring on each server
  * Dynamic threshold adjustment for performance degradation
  * Priority-based server selection algorithm
  * Adaptive load distribution mechanisms

* **Experimental Methodology**:

  * **Baseline measurements**: Collected with monitoring disabled to establish reference performance
  * **Statistical reliability**: Each configuration executed for 300 seconds with 60-second warm-up
  * **Repetition**: Experiments repeated at least 20 times for statistical confidence
  * **Results reporting**: Averages with standard deviations in form μ ± σ
  * **System isolation**: CPU utilization verified below 5% during idle periods between experiments 