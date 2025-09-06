#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 Simulate I/O operations by using a loop with a sleep function.
*/

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <iterations>\n", argv[0]);
    return 1;
  }

  int iterations = strtol(argv[1], NULL, 10);
  if (iterations <= 0) {
    printf("Error: Invalid iterations value\n");
    return 1;
  }

  for (int i = 0; i < iterations; i++) // Loop for specified iterations
  {
    usleep(10); // Sleep for 10 microseconds
  }
  return 0; // Return 0 to indicate successful execution
}
