# Disk Workload

## Directory Structure
```txt
.
├── Read.c (Disk Read Workload)
├── README.md (this file)
└── Write.c (Disk Write Workload)
```

## Description
This directory contains two disk workloads implemented in C. These workloads are designed to be used for benchmarking and performance testing of the `DiskFlow` module. The `O_DIRECT` and `O_SYNC` flags are used to bypass the page cache and ensure that the data is written directly to the disk.


### `Read.c`
This file contains a disk workload that reads data from a file (`test.txt`) in a loop until the file is completely read.

### `Write.c`
This file contains a disk workload that writes data to a file (`test.txt`) in a loop until the desired size is reached. It takes as a command line argument the size of the file to be written in MB.

## Usage
Compile the workloads using `gcc` with `O0` optimization level:
```bash
gcc -O0 Read.c -o Read
gcc -O0 Write.c -o Write
```