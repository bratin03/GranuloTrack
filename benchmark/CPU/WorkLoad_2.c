/*
 Simulate I/O operations by using a loop with a sleep function.
*/

#include <unistd.h>

int main()
{
    int j = 100;                // Initialize j to 10000
    for (int i = 0; i < j; i++) // Loop from i = 0 to i < j (10000 times)
    {
        usleep(10); // Sleep for 10 microseconds
    }
    return 0; // Return 0 to indicate successful execution
}
