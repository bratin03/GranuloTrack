# Load Balancing Data

Performance data from comparing three load balancing strategies under controlled stress conditions.

## Directory Structure

```
.
├── GranuloTrack.csv           # Results from GranuloTrack-based load balancer
├── Htop.csv                   # Results from Htop-based load balancer
├── Nginx.csv                  # Results from Nginx least_time load balancer
└── README.md
```

## How to Run

```bash
# View load balancing comparison data
ls *.csv

# GranuloTrack-based load balancer results
cat GranuloTrack.csv

# Htop-based load balancer results
cat Htop.csv

# Nginx least_time load balancer results
cat Nginx.csv
```

## Description
- **GranuloTrack.csv**: Results from GranuloTrack-based load balancer using CPU burst monitoring
- **Htop.csv**: Results from Htop-based load balancer using CPU percentage monitoring
- **Nginx.csv**: Results from Nginx least_time load balancer (baseline)
- **CSV Format**: timestamp, response_time, server_id, cpu_utilization, load_distribution 