#include <stdlib.h>
#include <assert.h>

int main()
{
    unsigned long long size = (unsigned long long)(1 << 24); // 16MB
    void *ptr = malloc(size);                                // Allocate memory of given size
    assert(ptr != NULL);                                     // Ensure allocation succeeded
}
