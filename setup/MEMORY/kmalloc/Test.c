/**
 * @file Test.c
 * @brief User-space application to allocate memory via /proc/kmalloc_lkm.
 *
 * This program writes a size value to /proc/kmalloc_lkm, triggering memory
 * allocation in the kernel module for the current process.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <size_in_bytes>\n", argv[0]);
    return 1;
  }

  int size = strtol(argv[1], NULL, 10);
  if (size <= 0) {
    printf("Error: Invalid size value\n");
    return 1;
  }

  const char *proc_path = "/proc/kmalloc_lkm";
  int fd = open(proc_path, O_WRONLY);
  if (fd == -1) {
    fprintf(stderr, "Error: Failed to open %s: %s\n", proc_path,
            strerror(errno));
    return 1;
  }

  // Write the size to the proc file
  ssize_t written = write(fd, &size, sizeof(size));
  if (written == -1) {
    fprintf(stderr, "Error: Failed to write to %s: %s\n", proc_path,
            strerror(errno));
    close(fd);
    return 1;
  } else if (written != sizeof(size)) {
    fprintf(stderr, "Error: Partial write to %s (wrote %zd bytes)\n", proc_path,
            written);
    close(fd);
    return 1;
  }

  printf("Successfully requested allocation of %d bytes via %s\n", size,
         proc_path);

  // Closing the file triggers automatic memory cleanup in the kernel module
  close(fd);
  return 0;
}
