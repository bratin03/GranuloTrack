# GranuloTrack Load Balancer

High-performance C++ load balancer with intelligent server selection based on CPU utilization monitoring from both Htop and GranuloTrack sources.

## Description

The GranuloTrack Load Balancer implements an intelligent load balancing strategy that:
- Maintains a priority queue based on server utilization (higher utilization = higher priority)
- Uses weighted moving averages for stability (configurable weight factor)
- Implements adaptive thresholds to exclude underperforming or oversaturated servers
- Supports both Htop and GranuloTrack monitoring data
- Provides TCP client interface and UDP server update interface
- Processes vector-based utilization updates with individual sample weighting

## How to Run

### Prerequisites
```bash
# Install required dependencies
sudo apt-get update
sudo apt-get install libev-dev build-essential cmake pkg-config
```

### Build
```bash
# Install dependencies first
./install.sh

# Build the load balancer
make

# The binary will be created in bin/load_balancer
```

### Run
```bash
# Start the load balancer with configuration
./bin/load_balancer config.json
```

### Configuration
Edit `config.json` to customize:
- **Network settings**: Client and update listener IPs/ports
- **Algorithm parameters**: Weight factor, update threshold, min/max factors
- **Server list**: Add/remove backend servers with initial utilization values
- **Performance settings**: Connection limits, buffer sizes, timeouts

### Protocol
- **Client Requests**: TCP on port 8080 (HTTP over TCP)
- **Server Updates**: UDP on port 8081 (JSON over UDP)

### API Endpoints
- **GET /health**: Health check endpoint
- **GET /stats**: Server statistics and average utilization
- **Any other path**: Load balanced to selected backend server

### Server Updates (UDP)
Send vector-based utilization updates via UDP:
```json
{
    "server_id": "server1",
    "utilizations": [75.5, 78.2, 72.1, 80.0],
    "average_utilization": 76.45,
    "source": "granulotrack",
    "timestamp": 1640995200
}
```

### Update Processing
1. **Threshold Check**: If average utilization is within ±10% of current, discard update
2. **Weighted Processing**: Apply weighted average to each sample individually
3. **Final Calculation**: Compute overall weighted average from processed samples

## Directory Structure
```
load_balancer/
├── include/                    # Header files
│   ├── config.h               # Configuration structures and parser
│   ├── server_manager.h       # Server state management and priority queue
│   ├── http_handler.h         # HTTP request/response handling
│   └── load_balancer.h        # Main load balancer class
├── src/                       # Source files
│   ├── main.cpp               # Application entry point
│   ├── config_parser.cpp      # JSON configuration parsing
│   ├── server_manager.cpp     # Server management implementation
│   ├── http_handler.cpp       # HTTP handling implementation
│   └── load_balancer.cpp      # Main load balancer implementation
├── config.json                # Sample configuration file
├── CMakeLists.txt             # Build configuration
└── README.md                  # This file
```
