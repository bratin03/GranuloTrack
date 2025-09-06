#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCK_SIZE 4096
#define WRITE_CHUNK_SIZE (BLOCK_SIZE) // Size of each write operation

int main(int argc, char *argv[]) {
  // Check for the correct number of arguments
  if (argc != 2) {
    return 1;
  }

  // Parse the file size from command line argument
  long file_size_mb = strtol(argv[1], NULL, 10);
  if (file_size_mb <= 0) {
    return 1;
  }

  size_t total_size =
      file_size_mb * 1024 * 1024; // Total buffer size for the specified MB

  // Open the file using the open syscall with O_DIRECT
  int fd = open("test.txt", O_WRONLY | O_CREAT | O_TRUNC | O_DIRECT,
                S_IRUSR | S_IWUSR);
  if (fd == -1) {
    return 1;
  }

  // Allocate the buffer aligned to BLOCK_SIZE
  char *buffer = aligned_alloc(BLOCK_SIZE, total_size);
  if (buffer == NULL) {
    close(fd);
    return 1;
  }

  // Fill the buffer with 'A' character
  memset(buffer, 'A', total_size);

  // Write the buffer in chunks of WRITE_CHUNK_SIZE
  size_t written_total = 0;
  while (written_total < total_size) {
    size_t to_write = (total_size - written_total > WRITE_CHUNK_SIZE)
                          ? WRITE_CHUNK_SIZE
                          : (total_size - written_total);
    ssize_t written = write(fd, buffer + written_total, to_write);
    if (written != (ssize_t)to_write) {
      free(buffer);
      close(fd);
      return 1;
    }
    written_total += written;
  }

  free(buffer);
  close(fd); // Close the file descriptor

  return 0;
}
