# Memory Workload

## Directory Structure
```txt
.
├── ByteArray.py (Python ByteArray Workload)
├── kmalloc (kmalloc Loadable Kernel Module)
│   ├── kmalloc_lkm.c (Source code)
│   ├── Makefile (Makefile for kmalloc)
│   └── Test.c (Test program for kmalloc)
├── Malloc.c (C Malloc Workload)
└── README.md (this file)
```

## Description
This directory contains three memory workloads implemented in C and Python. These workloads are designed to be used for benchmarking and performance testing of the `MemTracker` module. The `kmalloc` workload is implemented as a loadable kernel module, while the `ByteArray` and `Malloc` workloads are implemented in user space.

### `ByteArray.py`
This file contains a memory workload that uses Python's `bytearray` to allocate memory once.

### `kmalloc`
This Linux Kernel Module (LKM) enables user-space processes to allocate memory via `kmalloc` by writing a size value to the `/proc/kmalloc_lkm` interface. The allocated memory is automatically freed when the process closes the file, providing a simple way to simulate per-process kernel memory management and cleanup. To use the module, first load it to create the `/proc/kmalloc_lkm` interface. Then, run the user-space program that opens this proc file and writes the desired allocation size, triggering the kernel to allocate memory for that process. Closing the file causes the module to free the allocated memory automatically. Allocation and deallocation events are logged in the kernel. Finally, unload the module when done.

### `Malloc.c`
This file contains a memory workload that uses the C `malloc` function to allocate memory once. It allocates a specified amount of memory.

## Usage

### `ByteArray.py`
This file can be run directly using Python:
```bash
python3 ByteArray.py
```
### `kmalloc`
1. Enter the `kmalloc` directory:
```bash
cd kmalloc
```
2. Compile the kernel module:
```bash
make
```
3. Load the kernel module:
```bash
sudo insmod kmalloc_lkm.ko
```
4. Run the test program:
```bash
./Test
```
5. Unload the kernel module:
```bash
sudo rmmod kmalloc_lkm
```
6. Clean up the build files:
```bash
make clean
```

### `Malloc.c`
Compile the source code using `gcc` with `O0` optimization level:
```bash
gcc -O0 Malloc.c -o Malloc
```