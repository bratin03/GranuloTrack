# Memory Workload Dataset
This dataset contains CPU workload data collected for [benchmarks](../../../benchmark/MEMORY/)

## Directory Structure
```txt
.
├── DATA.csv
└── README.md
```

## Description
- `DATA.csv`: Contains the memory workload data for various sizes of memory allocations made through [`malloc`](../../../benchmark/MEMORY/Malloc.c), [`bytearray`](../../../benchmark/MEMORY/ByteArray.py), and [`kmalloc`](../../../benchmark/MEMORY/kmalloc/). The data includes the requested allocation size and the total memory allocation captured by GranuloTrack for the respective processes. For `kmalloc`, allocation sizes range from 2<sup>5</sup> (32 bytes) to 2<sup>22</sup> (4,194,304 bytes). For `malloc` and `bytearray`, allocation sizes range from 2<sup>0</sup> (1 byte) to 2<sup>30</sup> (1,073,741,824 bytes), increasing in powers of 2.

