# Overhead Measurements

Performance overhead measurements of GranuloTrack modules.

## Directory Structure

```
.
├── APP.csv                    # Overhead measurements in real-life applications
├── CPU.csv                    # CPU time consumed by GranuloTrack modules
├── MEM.csv                    # Memory usage of GranuloTrack components
└── README.md
```

## How to Run

```bash
# View overhead data
ls *.csv

# Application overhead (MySQL, Nginx, Redis)
cat APP.csv

# CPU overhead measurements
cat CPU.csv

# Memory overhead measurements
cat MEM.csv
```

## Description
- **APP.csv**: Overhead measurements in real-life applications (MySQL, Nginx, Redis)
- **CPU.csv**: CPU time consumed by GranuloTrack modules in CPU workloads
- **MEM.csv**: Memory usage of GranuloTrack components
