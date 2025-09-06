#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MIN_ALLOC_SIZE (4 * 1024)    // 4KB minimum
#define MAX_ALLOC_SIZE (1024 * 1024) // 1MB maximum
#define ALLOC_COUNT 1000             // Number of allocations to track

typedef struct {
  void *ptr;
  size_t size;
  long long timestamp;
} allocation_t;

void *allocate_memory(size_t size) {
  void *ptr = malloc(size);
  if (ptr) {
    // Touch memory to ensure it's actually allocated
    memset(ptr, 0xAA, size);
  }
  return ptr;
}

void free_memory(void *ptr) {
  if (ptr) {
    free(ptr);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <allocation_rate_mb_per_sec> <duration_seconds>\n",
           argv[0]);
    printf("Example: %s 10 60  # 10MB/s for 60 seconds\n", argv[0]);
    return 1;
  }

  int target_rate_mbps = atoi(argv[1]);
  int duration_seconds = atoi(argv[2]);

  if (target_rate_mbps < 1 || target_rate_mbps > 1000) {
    printf("Error: Allocation rate must be between 1 and 1000 MB/s\n");
    return 1;
  }

  if (duration_seconds < 1 || duration_seconds > 3600) {
    printf("Error: Duration must be between 1 and 3600 seconds\n");
    return 1;
  }

  printf("Starting memory allocation generator: %d MB/s for %d seconds\n",
         target_rate_mbps, duration_seconds);

  // Calculate allocation parameters
  size_t total_bytes =
      (size_t)target_rate_mbps * 1024 * 1024 * duration_seconds;
  size_t bytes_per_second = (size_t)target_rate_mbps * 1024 * 1024;
  size_t bytes_per_interval =
      bytes_per_second / 10; // 10 intervals per second for precision

  allocation_t allocations[ALLOC_COUNT];
  int alloc_index = 0;
  size_t total_allocated = 0;
  struct timeval start_time, current_time;

  gettimeofday(&start_time, NULL);

  while (total_allocated < total_bytes) {
    gettimeofday(&current_time, NULL);
    long long elapsed_us = (current_time.tv_sec - start_time.tv_sec) * 1000000 +
                           (current_time.tv_usec - start_time.tv_usec);

    // Calculate target allocation for current time
    size_t target_allocated = (elapsed_us * bytes_per_second) / 1000000;

    if (total_allocated < target_allocated) {
      // Determine allocation size (varying between 4KB and 1MB)
      size_t alloc_size =
          MIN_ALLOC_SIZE + (rand() % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1));

      // Ensure we don't exceed target
      if (total_allocated + alloc_size > target_allocated) {
        alloc_size = target_allocated - total_allocated;
      }

      if (alloc_size >= MIN_ALLOC_SIZE) {
        void *ptr = allocate_memory(alloc_size);
        if (ptr) {
          allocations[alloc_index].ptr = ptr;
          allocations[alloc_index].size = alloc_size;
          allocations[alloc_index].timestamp = elapsed_us;

          total_allocated += alloc_size;
          alloc_index = (alloc_index + 1) % ALLOC_COUNT;

          printf("Allocated %zu bytes (total: %zu MB)\n", alloc_size,
                 total_allocated / (1024 * 1024));
        }
      }
    }

    // Small sleep to prevent excessive CPU usage
    usleep(1000); // 1ms
  }

  printf("Allocation complete. Total allocated: %zu MB\n",
         total_allocated / (1024 * 1024));
  printf("Holding allocations for 5 seconds...\n");
  sleep(5);

  // Free all allocations
  printf("Freeing allocations...\n");
  for (int i = 0; i < ALLOC_COUNT; i++) {
    if (allocations[i].ptr) {
      free_memory(allocations[i].ptr);
      allocations[i].ptr = NULL;
    }
  }

  printf("Memory allocation test completed.\n");
  return 0;
}
