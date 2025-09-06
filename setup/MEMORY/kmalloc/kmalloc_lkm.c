/**
 * @file kmalloc_lkm.c
 * @brief Linux Kernel Module for per-process memory allocation via /proc
 * interface.
 *
 * This module allows processes to allocate and automatically free memory using
 * `kmalloc` by writing a size to `/proc/kmalloc_lkm`. Memory is automatically
 * freed when the process closes the file.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("LKM to allocate and free memory using kmalloc");
MODULE_VERSION("1.0");

#define PROCFS_NAME "kmalloc_lkm"
#define PROCFS_MAX_SIZE 8

/**
 * @struct process_node
 * @brief A structure to track memory allocations by process.
 */
struct process_node {
  pid_t pid;                 /**< Process ID */
  void *allocated_memory;    /**< Pointer to allocated memory */
  size_t allocated_size;     /**< Size of allocated memory */
  struct process_node *next; /**< Pointer to next node in the list */
};

static struct proc_dir_entry *proc_file; /**< /proc entry for interface */
static struct process_node *process_list =
    NULL;                                   /**< Linked list of processes */
static char procfs_buffer[PROCFS_MAX_SIZE]; /**< Buffer for user input */

DEFINE_MUTEX(procfs_mutex); /**< Mutex to protect access to process list */

/**
 * @brief Find a process node in the list by PID.
 *
 * @param pid Process ID to search for.
 * @return Pointer to the matching process_node or NULL if not found.
 */
static struct process_node *process_find(pid_t pid) {
  struct process_node *curr = process_list;
  while (curr) {
    if (curr->pid == pid)
      return curr;
    curr = curr->next;
  }
  return NULL;
}

/**
 * @brief Insert a new process node for the given PID.
 *
 * @param pid Process ID.
 * @return Pointer to the newly inserted node or NULL on failure.
 */
static struct process_node *process_insert(pid_t pid) {
  struct process_node *node = kmalloc(sizeof(struct process_node), GFP_KERNEL);
  if (!node) {
    return NULL;
  }
  node->pid = pid;
  node->allocated_memory = NULL;
  node->allocated_size = 0;
  node->next = process_list;
  process_list = node;
  return node;
}

/**
 * @brief Delete the process node for the given PID and free its memory.
 *
 * @param pid Process ID.
 */
static void process_delete(pid_t pid) {
  struct process_node *curr = process_list;
  struct process_node *prev = NULL;
  while (curr) {
    if (curr->pid == pid) {
      if (prev)
        prev->next = curr->next;
      else
        process_list = curr->next;

      if (curr->allocated_memory)
        kfree(curr->allocated_memory);
      kfree(curr);
      return;
    }
    prev = curr;
    curr = curr->next;
  }
}

/**
 * @brief Write handler for the proc file.
 *
 * Expects a size_t value indicating how many bytes to allocate.
 *
 * @param file Pointer to file structure.
 * @param buffer User-space buffer.
 * @param length Number of bytes to write.
 * @param offset Offset (unused).
 * @return Number of bytes written or error code.
 */
static ssize_t procfile_write(struct file *file, const char __user *buffer,
                              size_t length, loff_t *offset) {
  pid_t pid = current->pid;
  struct process_node *node;
  size_t alloc_size;

  if (length != sizeof(int))
    return -EINVAL;

  if (copy_from_user(procfs_buffer, buffer, length))
    return -EFAULT;

  alloc_size = *((size_t *)procfs_buffer);

  if (alloc_size == 0)
    return -EINVAL;

  mutex_lock(&procfs_mutex);
  node = process_find(pid);
  if (!node) {
    node = process_insert(pid);
    if (!node) {
      mutex_unlock(&procfs_mutex);
      return -ENOMEM;
    }
  }

  if (node->allocated_memory) {
    kfree(node->allocated_memory);
  }

  node->allocated_memory = kmalloc(alloc_size, GFP_KERNEL);
  if (!node->allocated_memory) {
    mutex_unlock(&procfs_mutex);
    return -ENOMEM;
  }

  node->allocated_size = alloc_size;
  printk(KERN_INFO "I: Process %d allocated %zu bytes\n", pid, alloc_size);

  mutex_unlock(&procfs_mutex);
  return length;
}

/**
 * @brief Open handler for the proc file.
 *
 * Registers the process in the process list.
 *
 * @param inode Pointer to inode structure.
 * @param file Pointer to file structure.
 * @return 0 on success.
 */
static int procfile_open(struct inode *inode, struct file *file) {
  pid_t pid = current->pid;

  mutex_lock(&procfs_mutex);
  if (!process_find(pid)) {
    process_insert(pid);
  }
  mutex_unlock(&procfs_mutex);

  printk(KERN_INFO "I: Process %d opened the file\n", pid);
  return 0;
}

/**
 * @brief Release handler for the proc file.
 *
 * Frees allocated memory and removes the process from the list.
 *
 * @param inode Pointer to inode structure.
 * @param file Pointer to file structure.
 * @return 0 on success.
 */
static int procfile_release(struct inode *inode, struct file *file) {
  pid_t pid = current->pid;

  mutex_lock(&procfs_mutex);
  process_delete(pid);
  mutex_unlock(&procfs_mutex);

  printk(KERN_INFO "I: Process %d closed the file and freed memory\n", pid);
  return 0;
}

/** @brief File operations for the /proc entry. */
static const struct proc_ops proc_fops = {
    .proc_open = procfile_open,
    .proc_write = procfile_write,
    .proc_release = procfile_release,
};

/**
 * @brief Module initialization function.
 *
 * Creates the proc file entry.
 *
 * @return 0 on success, negative error code on failure.
 */
static int __init lkm_init(void) {
  proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_fops);
  if (!proc_file) {
    printk(KERN_ALERT "E: Could not create proc file\n");
    return -ENOMEM;
  }
  printk(KERN_INFO "I: /proc/%s created\n", PROCFS_NAME);
  return 0;
}

/**
 * @brief Module exit function.
 *
 * Cleans up all memory and removes the proc entry.
 */
static void __exit lkm_exit(void) {
  struct process_node *curr = process_list;
  while (curr) {
    struct process_node *next = curr->next;
    if (curr->allocated_memory)
      kfree(curr->allocated_memory);
    kfree(curr);
    curr = next;
  }
  remove_proc_entry(PROCFS_NAME, NULL);
  printk(KERN_INFO "I: LKM unloaded and /proc/%s removed\n", PROCFS_NAME);
}

module_init(lkm_init);
module_exit(lkm_exit);
