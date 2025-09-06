#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <size_in_bytes>\n", argv[0]);
    return 1;
  }

  unsigned long long size = strtoull(argv[1], NULL, 10);
  if (size == 0) {
    printf("Error: Invalid size value\n");
    return 1;
  }

  void *ptr = malloc(size); // Allocate memory of given size
  assert(ptr != NULL);      // Ensure allocation succeeded
  free(ptr);                // Free allocated memory
  return 0;
}
