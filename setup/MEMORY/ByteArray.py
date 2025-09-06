import sys


def allocate_memory(size_in_bytes):
    try:
        allocation = bytearray(size_in_bytes)  # Attempt to allocate memory
    except MemoryError:
        print("MemoryError")  # Print error if allocation fails


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ByteArray.py <size_in_bytes>")
        sys.exit(1)

    try:
        size = int(sys.argv[1])
        if size <= 0:
            print("Error: Size must be positive")
            sys.exit(1)
        allocate_memory(size)
    except ValueError:
        print("Error: Invalid size value")
        sys.exit(1)
