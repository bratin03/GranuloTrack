#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define BLOCK_SIZE 4096 // Define the block size (must match filesystem)

int main()
{
    int fd;
    // Allocate a buffer aligned to BLOCK_SIZE
    char *buffer = aligned_alloc(BLOCK_SIZE, BLOCK_SIZE);
    if (buffer == NULL)
    {
        return 1;
    }

    // Open the file using the open syscall with O_DIRECT and O_SYNC
    fd = open("test.txt", O_RDONLY | O_DIRECT | O_SYNC);

    // Check if the file was opened successfully
    if (fd == -1)
    {
        free(buffer);
        return 1;
    }

    // Read the content of the file in chunks
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buffer, BLOCK_SIZE)) > 0)
    {
        // Loop reads file content; no action needed on data
    }

    // Check for read error
    if (bytesRead == -1)
    {
        close(fd);
        free(buffer);
        return 1;
    }

    // Close the file descriptor and free allocated memory
    close(fd);
    free(buffer);
    return 0;
}
