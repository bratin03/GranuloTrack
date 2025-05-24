/**
 * @file Test.c
 * @brief User-space application to allocate memory via /proc/kmalloc_lkm.
 *
 * This program writes a size value to /proc/kmalloc_lkm, triggering memory
 * allocation in the kernel module for the current process.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    const char *proc_path = "/proc/kmalloc_lkm";
    int fd = open(proc_path, O_WRONLY);
    if (fd == -1)
    {
        fprintf(stderr, "Error: Failed to open %s: %s\n", proc_path, strerror(errno));
        return 1;
    }

    int size = 1024 * 1024; // Allocate 1 MiB

    // Write the size to the proc file
    ssize_t written = write(fd, &size, sizeof(size));
    if (written == -1)
    {
        fprintf(stderr, "Error: Failed to write to %s: %s\n", proc_path, strerror(errno));
        close(fd);
        return 1;
    }
    else if (written != sizeof(size))
    {
        fprintf(stderr, "Error: Partial write to %s (wrote %zd bytes)\n", proc_path, written);
        close(fd);
        return 1;
    }

    printf("Successfully requested allocation of %d bytes via %s\n", size, proc_path);

    // Closing the file triggers automatic memory cleanup in the kernel module
    close(fd);
    return 0;
}
