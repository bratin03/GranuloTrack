#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TARGET_UTILIZATION 25    // Default 25%, can be overridden
#define MONITOR_INTERVAL 1000000 // 1 second in microseconds
#define PRECISION 1000           // Precision for sleep calculations

void *cpu_worker(void *arg) {
  int target_util = *(int *)arg;
  struct timeval start, current;
  long long busy_time, total_time, sleep_time;

  while (1) {
    gettimeofday(&start, NULL);

    // Busy loop for target utilization percentage
    do {
      gettimeofday(&current, NULL);
      busy_time = (current.tv_sec - start.tv_sec) * 1000000 +
                  (current.tv_usec - start.tv_usec);
    } while (busy_time < (MONITOR_INTERVAL * target_util / 100));

    // Sleep for the remaining time to achieve target utilization
    sleep_time = MONITOR_INTERVAL - busy_time;
    if (sleep_time > 0) {
      usleep(sleep_time);
    }
  }

  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <target_utilization_percent> <num_threads>\n", argv[0]);
    printf("Example: %s 75 4  # 75%% CPU utilization with 4 threads\n",
           argv[0]);
    return 1;
  }

  int target_util = atoi(argv[1]);
  int num_threads = atoi(argv[2]);

  if (target_util < 1 || target_util > 100) {
    printf("Error: Target utilization must be between 1 and 100\n");
    return 1;
  }

  if (num_threads < 1 || num_threads > 32) {
    printf("Error: Number of threads must be between 1 and 32\n");
    return 1;
  }

  printf("Starting CPU load generator: %d%% utilization with %d threads\n",
         target_util, num_threads);
  printf("Press Ctrl+C to stop\n");

  pthread_t threads[num_threads];
  int thread_args[num_threads];

  // Create worker threads
  for (int i = 0; i < num_threads; i++) {
    thread_args[i] = target_util;
    if (pthread_create(&threads[i], NULL, cpu_worker, &thread_args[i]) != 0) {
      printf("Error: Failed to create thread %d\n", i);
      return 1;
    }
  }

  // Wait for all threads
  for (int i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);
  }

  return 0;
}
