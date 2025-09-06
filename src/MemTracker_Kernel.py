#!/usr/bin/env python3
import threading
import queue
import time
import re
import os
import ctypes
import datetime
from collections import deque
from bcc import BPF, utils
from queue import Queue as EventQueue

# Debug configuration
DEBUG = True


class MemTracker_Kernel:
    """
    MemTracker_Kernel: A high-performance tracer for per-process kernel-space memory events.

    MemTracker_Kernel leverages eBPF to capture detailed kernel-space memory allocation events
    including kmalloc, kfree, kmem_cache_alloc, and kmem_cache_free operations. The tracer supports
    dynamic filtering by process ID or name patterns, enabling targeted analysis of kernel memory usage.

    Usage:
        # Trace specific processes by PID:
        tracer = MemTracker_Kernel(pids=[1234, 5678])

        # Trace processes by name pattern (regex):
        tracer = MemTracker_Kernel(process_patterns=["nginx", "apache"])

        # Trace all processes (high overhead):
        tracer = MemTracker_Kernel()

        # Stream events until interrupted:
        for ev in tracer.stream_events():
            print(ev)  # {'pid': int, 'size': int, 'type': int, 'timestamp': int, 'comm': str}

        # Clean shutdown:
        tracer.stop()

    Public methods:
        - stream_events(): generator yielding per-kernel-memory-event dictionaries with process names
        - stop(): clean shutdown of background polling threads
    """

    def __init__(
        self,
        pids=None,
        process_patterns=None,
        num_poll_threads=1,
        queue_size=10000,
        ringbuf_size=256,
    ):
        """
        Initialize the MemTracker_Kernel tracer with configurable filtering and performance settings.

        Args:
            pids: List of process IDs (integers) to filter by. Mutually exclusive with process_patterns.
            process_patterns: List of regex patterns (strings) to filter process names.
                            Mutually exclusive with pids.
            num_poll_threads: Number of polling threads (default: 1, recommended: 2-4 for high throughput).
                            Multiple threads improve event processing performance.
            queue_size: Maximum size of event queue (default: 10000). Larger values reduce
                       event loss but increase memory usage.
            ringbuf_size: Number of pages for event buffer (default: 256). Larger values reduce
                         buffer overflow but increase memory usage.

        Returns:
            None. Raises RuntimeError or BPF compilation error on initialization failure.

        Performance Tuning Guidelines:
        - High-throughput tracing (all processes): use 2-4 polling threads, ringbuf_size=512-1024
        - Filtered tracing (specific PIDs/patterns): 1-2 threads, ringbuf_size=256-512
        - Increase queue_size if "Possibly lost X samples" messages appear
        - Monitor CPU usage and adjust thread count accordingly
        """
        # Validate mutually exclusive filtering parameters
        if pids and process_patterns:
            raise ValueError(
                "Cannot specify both pids and process_patterns. Use one or the other."
            )

        # --- Python-side configuration and state management ---
        self.allowed_pids = pids or []
        self.process_patterns = process_patterns or []
        self.num_poll_threads = num_poll_threads
        self.queue_size = queue_size
        self.ringbuf_size = ringbuf_size

        # Determine filtering mode (mutually exclusive: pids OR regex OR none)
        self.filter_mode = "none"
        if self.allowed_pids:
            self.filter_mode = "pids"
        elif self.process_patterns:
            self.filter_mode = "regex"

        # Configure trace_all flag for unfiltered operation
        self.trace_all = self.filter_mode == "none"

        # Initialize debug logging for troubleshooting and performance analysis
        if DEBUG:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.debug_log_file = f"/tmp/memtracker_kernel_{timestamp}.log"
            with open(self.debug_log_file, "w") as f:
                f.write(f"MemTracker_Kernel started at {datetime.datetime.now()}\n")
                f.write(f"Filter mode: {self.filter_mode}\n")
                if self.allowed_pids:
                    f.write(f"Allowed PIDs: {self.allowed_pids}\n")
                if self.process_patterns:
                    f.write(f"Process patterns: {self.process_patterns}\n")
                f.write(
                    f"Buffer size: {self.ringbuf_size}, Poll threads: {self.num_poll_threads}\n"
                )

        # Initialize system resources and thread synchronization primitives
        self.num_cpus = len(utils.get_online_cpus())
        self.event_queue = EventQueue(maxsize=self.queue_size)
        self._running = True
        self._stop_event = threading.Event()  # Thread termination signal


        # Initialize event deduplication cache for multi-threaded configurations
        self._dedupe_lock = threading.Lock()
        self._recent_keys = set()  # Hash set for O(1) duplicate detection
        self._recent_order = deque()  # Insertion-order tracking for LRU eviction
        self._recent_keys_max = 256

        # --- BPF C program: Kernel-space memory event tracking ---
        self.bpf_program = f"""
#include <linux/ptrace.h>

// Dynamic filtering maps - all filtering happens in kernel space for performance
BPF_HASH(allowed_pids, u32, u32);        // PID -> 1 if allowed (for both PID and regex modes)
BPF_HASH(pending_reeval, u32, u32);      // PID -> 1 if needs re-evaluation (for exec events)
BPF_HASH(config, u32, u32);              // Configuration flags (trace_all setting)

struct proc_data {{
    u64 memory_requested;
    u64 memory_allocated;
    u64 memory_freed;
    u64 kernel_memory_allocated;
    u64 kernel_memory_freed;
}};
BPF_HASH(proc_data, u32, struct proc_data);

struct event_data {{
    u32 pid;
    u64 size;
    u32 type;       // 0 alloc, 1 free
    u64 timestamp;
    char comm[16];  // Process name (max 15 chars + null terminator)
}};
BPF_RINGBUF_OUTPUT(kern_events, RINGBUF_SIZE);  // Configurable event buffer, channel to user space

struct pointer_key {{
    u64 pid;
    u64 ptr;
}};
BPF_HASH(pointer_allocs, struct pointer_key, u64);
BPF_HASH(pointer_cache, struct pointer_key, u64);

TRACEPOINT_PROBE(kmem, kmalloc) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
    u32 trace_all_key = 0;
    u32 *trace_all = config.lookup(&trace_all_key);
    if (!trace_all || *trace_all == 0) {{
        u32 *allowed = allowed_pids.lookup(&pid);
        if (!allowed)
            return 0;
    }}
    
    u64 ptr = (u64)args->ptr;
    u64 size = args->bytes_alloc;
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{
        struct proc_data init = {{}};
        proc_data.update(&pid, &init);
        p = proc_data.lookup(&pid);
        if (!p) return 0;
    }}
    p->kernel_memory_allocated += size;
    struct pointer_key key = {{.pid = pid, .ptr = ptr}};
    pointer_allocs.update(&key, &size);
    
    struct event_data ev = {{
        .pid = pid,
        .size = size,
        .type = 0,
        .timestamp = bpf_ktime_get_ns()
    }};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    kern_events.ringbuf_output(&ev, sizeof(ev), 0);
    return 0;
}}

TRACEPOINT_PROBE(kmem, kfree) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
    u32 trace_all_key = 0;
    u32 *trace_all = config.lookup(&trace_all_key);
    if (!trace_all || *trace_all == 0) {{
        u32 *allowed = allowed_pids.lookup(&pid);
        if (!allowed)
            return 0;
    }}
    
    struct pointer_key key = {{.pid = pid, .ptr = (u64)args->ptr}};
    u64 *sizep = pointer_allocs.lookup(&key);
    if (!sizep) return 0;
    pointer_allocs.delete(&key);
    
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) return 0;
    p->kernel_memory_freed += *sizep;
    
    struct event_data ev = {{
        .pid = pid,
        .size = *sizep,
        .type = 1,
        .timestamp = bpf_ktime_get_ns()
    }};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    kern_events.ringbuf_output(&ev, sizeof(ev), 0);
    return 0;
}}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
    u32 trace_all_key = 0;
    u32 *trace_all = config.lookup(&trace_all_key);
    if (!trace_all || *trace_all == 0) {{
        u32 *allowed = allowed_pids.lookup(&pid);
        if (!allowed)
            return 0;
    }}
    
    u64 ptr = (u64)args->ptr;
    u64 size = args->bytes_alloc;
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{
        struct proc_data init = {{}};
        proc_data.update(&pid, &init);
        p = proc_data.lookup(&pid);
        if (!p) return 0;
    }}
    p->kernel_memory_allocated += size;
    struct pointer_key key = {{.pid = pid, .ptr = ptr}};
    pointer_cache.update(&key, &size);
    
    struct event_data ev = {{
        .pid = pid,
        .size = size,
        .type = 0,
        .timestamp = bpf_ktime_get_ns()
    }};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    kern_events.ringbuf_output(&ev, sizeof(ev), 0);
    return 0;
}}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
    u32 trace_all_key = 0;
    u32 *trace_all = config.lookup(&trace_all_key);
    if (!trace_all || *trace_all == 0) {{
        u32 *allowed = allowed_pids.lookup(&pid);
        if (!allowed)
            return 0;
    }}
    
    struct pointer_key key = {{.pid = pid, .ptr = (u64)args->ptr}};
    u64 *sizep = pointer_cache.lookup(&key);
    if (!sizep) return 0;
    pointer_cache.delete(&key);
    
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) return 0;
    p->kernel_memory_freed += *sizep;
    
    struct event_data ev = {{
        .pid = pid,
        .size = *sizep,
        .type = 1,
        .timestamp = bpf_ktime_get_ns()
    }};
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    kern_events.ringbuf_output(&ev, sizeof(ev), 0);
    return 0;
}}

/*
 * sched_process_fork: track new process creation
 * - Called when a new process is forked
 * - For PID mode: add child PID if parent is allowed
 * - For regex mode: mark for re-evaluation
 */
TRACEPOINT_PROBE(sched, sched_process_fork) {{
    u32 child_pid = args->child_pid;
    u32 parent_pid = args->parent_pid;
    
    // Check if parent is in allowed_pids (for PID inheritance)
    u32 *parent_allowed = allowed_pids.lookup(&parent_pid);
    if (parent_allowed) {{
        // Inherit parent's allowed status
        u32 allowed = 1;
        allowed_pids.update(&child_pid, &allowed);
    }}
    
    // For regex mode, mark child for re-evaluation
    u32 reeval = 1;
    pending_reeval.update(&child_pid, &reeval);
    
    return 0;
}}

/*
 * sched_process_exec: track process execution (name change)
 * - Called when a process executes a new program
 * - Mark process for re-evaluation in regex mode
 */
TRACEPOINT_PROBE(sched, sched_process_exec) {{
    u32 pid32 = (u32)(bpf_get_current_pid_tgid());
    
    // Mark this process for re-evaluation (name might have changed)
    u32 reeval = 1;
    pending_reeval.update(&pid32, &reeval);
    
    return 0;
}}

/*
 * sched_process_exit: cleanup on process exit
 * - Remove process from all tracking maps
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
    u32 trace_all_key = 0;
    u32 *trace_all = config.lookup(&trace_all_key);
    if (!trace_all || *trace_all == 0) {{
        u32 *allowed = allowed_pids.lookup(&pid);
        if (!allowed)
            return 0;
    }}
    
    proc_data.delete(&pid);
    allowed_pids.delete(&pid);
    pending_reeval.delete(&pid);
    return 0;
}}
"""

        # Compile the BPF module with system-specific configuration parameters
        self.b = BPF(
            text=self.bpf_program,
            cflags=[
                f"-DMAX_CPUS={self.num_cpus}",
                f"-DRINGBUF_SIZE={self.ringbuf_size}",
            ],
        )

        # Initialize dynamic filtering maps based on selected filtering mode
        self.update_thread = None  # Initialize to None for proper cleanup
        if self.filter_mode == "pids":
            self._initialize_pid_filter()
        elif self.filter_mode == "regex":
            self._initialize_regex_filter()
            # Start background thread for dynamic regex pattern re-evaluation
            self.update_thread = threading.Thread(
                target=self._regex_update_loop, daemon=True
            )
            self.update_thread.start()

        # Initialize configuration map with trace_all setting for BPF filtering
        self.b["config"][ctypes.c_uint32(0)] = ctypes.c_uint32(
            1 if self.trace_all else 0
        )

        # Initialize event polling infrastructure with configurable thread count
        self.ringbuf = self.b["kern_events"]
        self.ringbuf_consumer = self.b.ring_buffer_consume
        self.ringbuf_poll = self.b.ring_buffer_poll
        self.ringbuf.open_ring_buffer(self._handle_event)
        self.poll_threads = []

        # Create polling threads for concurrent event processing
        # Each thread operates independently to reduce buffer overflow
        for i in range(self.num_poll_threads):
            poll_thread = threading.Thread(
                target=self._poll_loop,
                args=(i,),  # Thread identifier for debugging
                daemon=False,  # Non-daemon threads for proper cleanup
            )
            poll_thread.start()
            self.poll_threads.append(poll_thread)

    def _initialize_pid_filter(self):
        """
        Initialize the allowed_pids map with the specified process IDs.
        """
        for pid in self.allowed_pids:
            self.b["allowed_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)

    def _initialize_regex_filter(self):
        """
        Initialize the regex filter by populating allowed_pids map with current processes.
        """
        try:
            regex_patterns = [re.compile(pattern) for pattern in self.process_patterns]

            for pid_dir in os.listdir("/proc"):
                if pid_dir.isdigit():
                    pid = int(pid_dir)
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            comm = f.read().strip()

                            # Check if process name matches any regex pattern
                            for regex in regex_patterns:
                                if regex.search(comm):
                                    # Add matching process to allowed_pids map
                                    self.b["allowed_pids"][ctypes.c_uint32(pid)] = (
                                        ctypes.c_uint32(1)
                                    )
                                    break

                    except (FileNotFoundError, PermissionError):
                        continue

        except Exception as e:
            print(f"Warning: Could not initialize regex filter: {e}")

    def _regex_update_loop(self):
        """
        Background thread for dynamic regex pattern re-evaluation of pending processes.
        """
        while self._running:
            try:
                # Collect processes requiring re-evaluation
                pending_pids = []

                # Retrieve all PIDs from pending_reeval map
                for key, value in self.b["pending_reeval"].items():
                    pending_pids.append(key.value)

                # Re-evaluate each pending process
                for pid in pending_pids:
                    self._reevaluate_process(pid)
                    # Remove from pending evaluation map
                    self.b["pending_reeval"].pop(ctypes.c_uint32(pid), None)

                # Periodic evaluation interval
                time.sleep(0.1)  # Check every 100ms

            except Exception as e:
                print(f"Warning: Error in regex update loop: {e}")
                time.sleep(1)  # Extended sleep interval on error

    def _reevaluate_process(self, pid):
        """
        Re-evaluate a process for regex pattern matching.

        :param pid: Process ID to re-evaluate
        """
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.read().strip()

                # Check if process name matches any regex pattern
                matches = False
                for pattern in self.process_patterns:
                    if re.search(pattern, comm):
                        matches = True
                        break

                if matches:
                    # Add matching process to allowed_pids map
                    self.b["allowed_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(f"Added PID {pid} ({comm}) to allowed_pids\n")
                else:
                    # Remove process from allowed_pids map if no longer matching
                    self.b["allowed_pids"].pop(ctypes.c_uint32(pid), None)
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(f"Removed PID {pid} ({comm}) from allowed_pids\n")

        except (FileNotFoundError, PermissionError):
            # Process no longer exists, remove from tracking maps
            self.b["allowed_pids"].pop(ctypes.c_uint32(pid), None)
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Process {pid} no longer exists, removed from maps\n")

    def _handle_event(self, cpu, data, size):
        """
        Internal callback for BPF events.
        :param cpu: CPU index that generated the event (int).
        :param data: raw event data buffer.
        :param size: size of the buffer.
        :returns: None. Puts a dict into self.event_queue with process information included.
        """
        try:
            evt = self.b["kern_events"].event(data)
        except Exception as e:
            # Defensive: if event parsing fails, skip.
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Failed to parse event: {e}\n")
            return

        # Validate event data to prevent corrupted values
        try:
            pid_val = int(evt.pid)
            size_val = int(evt.size)
            type_val = int(evt.type)
            timestamp_val = int(evt.timestamp)

            # Sanity checks for reasonable values
            if (
                pid_val < 0
                or pid_val > 1000000
                or size_val < 0
                or size_val > 1000000000000
                or type_val < 0
                or type_val > 10
                or timestamp_val < 0
                or timestamp_val > 1000000000000000000
            ):
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(
                            f"Invalid event values: pid={pid_val}, size={size_val}, type={type_val}, timestamp={timestamp_val}\n"
                        )
                return

        except (ValueError, OverflowError) as e:
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Event value conversion error: {e}\n")
            return

        # Construct deduplication key using timestamp and process ID for uniqueness
        key = (timestamp_val, pid_val)

        # Apply deduplication only for multi-threaded configurations to prevent race conditions
        if self.num_poll_threads > 1:
            # O(1) deduplication using hash set with insertion-order tracking via deque
            with self._dedupe_lock:
                if key in self._recent_keys:
                    # Duplicate event detected - discard silently
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(f"Dropped duplicate event: {key}\n")
                    return
                # Insert new event key into deduplication cache
                self._recent_keys.add(key)
                self._recent_order.append(key)
                # Maintain cache size using LRU eviction policy
                if len(self._recent_keys) > self._recent_keys_max:
                    # Evict oldest entry (FIFO order)
                    oldest_key = self._recent_order.popleft()
                    self._recent_keys.remove(oldest_key)

        event_data = {
            "pid": pid_val,
            "size": size_val,
            "type": type_val,
            "timestamp": timestamp_val,
            "comm": evt.comm.decode("utf-8", errors="ignore").rstrip("\x00"),
        }

        # Thread-safe event queue insertion with non-blocking approach
        try:
            # Non-blocking insertion to prevent deadlocks during high event rates
            self.event_queue.put_nowait(event_data)
        except queue.Full:
            # Drop event silently to prevent blocking and potential deadlocks
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Event queue capacity exceeded, dropping event\n")

    def _poll_loop(self, thread_id=0):
        """
        Background thread loop for event polling until termination signal.
        Threads must exit immediately when stop() is called.
        :param thread_id: Thread identifier for debugging
        :returns: None.
        """
        while self._running and not self._stop_event.is_set():
            try:
                # Use shorter timeout for responsive termination
                self.ringbuf_poll(timeout=50)
            except Exception as e:
                if self._running:
                    print(f"Poll error in thread {thread_id}: {e}")
                break

        # Thread termination - occurs when stop() is called
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write(f"Poll thread {thread_id} exited\n")

    def stream_events(self):
        """
        Generator yielding each kernel memory event as a Python dictionary.
        :yields: {'pid': int, 'size': int, 'type': int, 'timestamp': int, 'comm': str}
        Blocks until the next event or KeyboardInterrupt.
        """
        while self._running:
            try:
                yield self.event_queue.get(
                    timeout=0.01
                )  # Short timeout for responsive event processing
            except queue.Empty:
                # Check termination condition
                if not self._running:
                    break
                continue

    def stop(self):
        """
        Signal all background threads to stop and perform BPF resource cleanup.
        :returns: None.
        """
        print("Stopping MemTracker_Kernel...")
        self._running = False
        self._stop_event.set()

        # Join polling threads with timeout to prevent hanging
        for t in self.poll_threads:
            t.join(timeout=1.0)  # Shorter timeout for faster shutdown

        # Join regex update thread if it exists
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=1.0)

        # Force cleanup even if threads don't join properly
        try:
            self.b.cleanup()
            print("BPF resources cleaned up")
        except Exception as e:
            print(f"Error during BPF cleanup: {e}")


if __name__ == "__main__":
    import json

    # Initialize tracer with configurable polling threads for high-throughput tracing
    print("MemTracker_Kernel: High-performance kernel memory event tracer")
    print("Tracing all processes - consider using filters for better performance")
    print("Press Ctrl+C to stop...")

    tracer = MemTracker_Kernel(
        num_poll_threads=2,  # Reduced threads to prevent overload
        ringbuf_size=256,    # Reduced buffer size for stability
        process_patterns=["python", "bash", "ls"],  # Add filtering to prevent system overload
    )

    try:
        for evt in tracer.stream_events():
            # Each event is a dictionary with process information; output as JSON for parsing
            # Use flush=True to prevent buffering issues
            print(json.dumps(evt), flush=True)
            # Check termination condition (in case signal handler was called)
            if not tracer._running:
                break
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt...")
        tracer.stop()  # Graceful shutdown
        print("Exiting cleanly...")
    except Exception as e:
        print(f"Error: {e}")
        tracer.stop()  # Graceful shutdown
        print("Exiting due to error...")
