def allocate_memory(size_in_bytes):
    try:
        allocation = bytearray(size_in_bytes)  # Attempt to allocate memory
    except MemoryError:
        print("MemoryError")  # Print error if allocation fails


if __name__ == "__main__":
    allocate_memory(1024)  # Allocate 1024 bytes
