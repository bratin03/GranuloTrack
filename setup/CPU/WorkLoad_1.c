#include <stdio.h>
#include <stdlib.h>

/*
Consume CPU cycles by incrementing a variable in a loop.
*/

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <iterations>\n", argv[0]);
    return 1;
  }

  unsigned int iterations = strtoul(argv[1], NULL, 10);
  if (iterations == 0) {
    printf("Error: Invalid iterations value\n");
    return 1;
  }

  unsigned int a = 0;                           // Initialize a to 0
  for (unsigned int i = 0; i < iterations; i++) // Loop for specified iterations
  {
    a++; // Increment a by 1
  }
  return 0;
}
