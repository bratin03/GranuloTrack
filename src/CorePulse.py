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


class CorePulse:
    """
    CorePulse: A high-performance tracer for per-process CPU burst analysis.

    CorePulse leverages eBPF to capture detailed CPU performance metrics including
    instruction counts, CPU cycles, and burst durations for individual processes.
    The tracer supports dynamic filtering by process ID or name patterns, enabling
    targeted analysis of specific workloads or applications.

    Usage:
        # Trace specific processes by PID:
        tracer = CorePulse(pids=[1234, 5678])

        # Trace processes by name pattern (regex):
        tracer = CorePulse(process_patterns=["nginx", "apache"])

        # Trace all processes (high overhead):
        tracer = CorePulse()

        # Stream events until interrupted:
        for ev in tracer.stream_events():
            print(ev)  # {'cpu': int, 'instructions': int, 'cycles': int, 'time': int, 'pid': int, 'comm': str}

        # Clean shutdown:
        tracer.stop()

    Public methods:
        - stream_events(): generator yielding per-burst event dictionaries
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
        Initialize the CorePulse tracer with configurable filtering and performance settings.

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
            self.debug_log_file = f"/tmp/corepulse_{timestamp}.log"
            with open(self.debug_log_file, "w") as f:
                f.write(f"CorePulse started at {datetime.datetime.now()}\n")
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

        # --- BPF C program: Kernel-space CPU burst tracking with hardware performance counters ---
        self.bpf_program = r"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        // Dynamic filtering maps - all filtering happens in kernel space for performance
        BPF_HASH(allowed_pids, u32, u32);        // PID -> 1 if allowed (for both PID and regex modes)
        BPF_HASH(pending_reeval, u32, u32);      // PID -> 1 if needs re-evaluation (for exec events)
        BPF_HASH(config, u32, u32);              // Configuration flags (trace_all setting)

        // Accumulated statistics per PID for burst calculation
        typedef struct time_info {
            u64 start_time;    // timestamp when process was last scheduled in
            u64 on_time;       // total ns on CPU so far (cumulative)
            u64 off_time;      // (unused) placeholder for future off-CPU tracking
            u64 instructions;  // total retired instructions (cumulative)
            u64 cycles;        // total CPU cycles (cumulative)
        } time_info;

        // One-time burst event passed to user space for analysis
        typedef struct cpu_burst {
            u32 cpu;           // CPU index where burst occurred
            u32 pid;           // process ID that generated the burst
            u64 instructions;  // instructions executed in this burst
            u64 cycles;        // CPU cycles consumed in this burst
            u64 time;          // duration (nanoseconds) of this burst
            u64 timestamp;     // timestamp when event was queued (nanoseconds)
            char comm[16];     // process name (max 15 chars + null terminator)
        } cpu_burst;

        // BPF maps for state tracking and hardware counter access:
        BPF_HASH(cpu_cycles, u32, time_info);      // aggregated stats per PID for burst calculation
        BPF_PERCPU_HASH(curr_run, u32, u64);        // timestamp when PID was scheduled in (per-CPU)
        BPF_PERCPU_ARRAY(data, u64);                // per-CPU snapshot of hardware performance counters
        BPF_PERF_ARRAY(clk, MAX_CPUS);              // hardware CPU cycle counters (per-CPU)
        BPF_PERF_ARRAY(inst, MAX_CPUS);             // hardware instruction counters (per-CPU)
        BPF_RINGBUF_OUTPUT(events, RINGBUF_SIZE);    // configurable event buffer, channel to user space

        #define CLOCK_ID       0
        #define INSTRUCTION_ID 1

        /*
         * sched_switch tracepoint: called on every context switch.
         * - Compute how long the previous process ran (delta ns)
         * - Read hardware performance counters before/after
         * - Update aggregated stats, then emit this burst as cpu_burst
         * Returns 0 to indicate success; returning non-zero would drop the event.
         */
        TRACEPOINT_PROBE(sched, sched_switch)
        {
            u64 ts       = bpf_ktime_get_ns();
            u32 prev_pid = args->prev_pid;
            int cpu      = bpf_get_smp_processor_id();
            char prev_comm[16];
            bpf_probe_read_kernel_str(&prev_comm, sizeof(prev_comm), args->prev_comm);

            // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
            // Uses runtime config map to avoid recompiling BPF program for different modes
            u32 trace_all_key = 0;
            u32 *trace_all = config.lookup(&trace_all_key);
            if (!trace_all || *trace_all == 0) {
                u32 *allowed = allowed_pids.lookup(&prev_pid);
                if (!allowed)
                    return 0;
            }

            // How long was prev_pid on CPU?
            u64 *tsp = curr_run.lookup(&prev_pid);
            if (!tsp)
                return 0;
            u64 delta = ts - *tsp;

            // Ensure we have an aggregate record
            time_info *ti = cpu_cycles.lookup(&prev_pid);
            if (!ti) {
                time_info init = {};
                init.start_time = ts;
                cpu_cycles.update(&prev_pid, &init);
                ti = cpu_cycles.lookup(&prev_pid);
                if (!ti)
                    return 0;
            }

            // Read hardware counters at switch-out
            u64 clk_start  = clk.perf_read(cpu);
            u64 inst_start = inst.perf_read(cpu);

            // Retrieve prior snapshots
            u32 clk_key  = CLOCK_ID;
            u32 inst_key = INSTRUCTION_ID;
            u64 *prev_clk  = data.lookup(&clk_key);
            u64 *prev_inst = data.lookup(&inst_key);

            // Safe delta computation (0 if no prior snapshot)
            u64 dcycles = prev_clk  ? clk_start  - *prev_clk  : 0;
            u64 dinsts  = prev_inst ? inst_start - *prev_inst : 0;

            // Update cumulative stats
            ti->on_time      += delta;
            ti->cycles       += dcycles;
            ti->instructions += dinsts;

            // Send burst event to Python
            cpu_burst burst = {
                .cpu          = cpu,
                .pid          = prev_pid,
                .time         = delta,
                .cycles       = dcycles,
                .instructions = dinsts,
                .timestamp    = bpf_ktime_get_ns(),
            };
            bpf_probe_read_kernel_str(&burst.comm, sizeof(burst.comm), args->prev_comm);
            events.ringbuf_output(&burst, sizeof(burst), 0);
            return 0;
        }

        /*
         * kretprobe on finish_task_switch: snapshots performance counters and records start time
         * This runs every time the scheduler picks a new task to run.
         */
        int trace_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
            u32 clk_k  = CLOCK_ID;
            u32 inst_k = INSTRUCTION_ID;
            int cpu    = bpf_get_smp_processor_id();

            // Snapshot counters at switch-in
            u64 clk_start  = clk.perf_read(cpu);
            u64 inst_start = inst.perf_read(cpu);
            data.update(&clk_k, &clk_start);
            data.update(&inst_k, &inst_start);

            // Record the time this PID was scheduled in
            u32 pid32 = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            
            // Dynamic filtering: check if PID is in allowed_pids map (skip if trace_all is set)
            // Uses runtime config map to avoid recompiling BPF program for different modes
            u32 trace_all_key = 0;
            u32 *trace_all = config.lookup(&trace_all_key);
            if (!trace_all || *trace_all == 0) {
                u32 *allowed = allowed_pids.lookup(&pid32);
                if (!allowed)
                    return 0;
            }
            
            u64 ts = bpf_ktime_get_ns();
            curr_run.update(&pid32, &ts);

            // Initialize aggregate if first-seen
            time_info *key = cpu_cycles.lookup(&pid32);
            if (!key) {
                time_info new_key = {};
                new_key.start_time = ts;
                cpu_cycles.update(&pid32, &new_key);
            }
            return 0;
        }

        /*
         * sched_process_exit: finalize statistics if a traced process exits
         * - Reads final hardware performance counters and on_time delta
         * - Deletes the PID from all maps
         */
        TRACEPOINT_PROBE(sched, sched_process_exit)
        {
            u32 pid32 = (u32)(bpf_get_current_pid_tgid());
            int cpu   = bpf_get_smp_processor_id();
            time_info *cycles = cpu_cycles.lookup(&pid32);
            if (cycles) {
                u64 clk_start  = clk.perf_read(cpu);
                u64 inst_start = inst.perf_read(cpu);
                u64 ts = bpf_ktime_get_ns();

                u32 clk_k  = CLOCK_ID;
                u32 inst_k = INSTRUCTION_ID;
                u64 *kptr = data.lookup(&clk_k);
                if (kptr) cycles->cycles += clk_start - *kptr;
                kptr = data.lookup(&inst_k);
                if (kptr) cycles->instructions += inst_start - *kptr;

                u64 *tsp = curr_run.lookup(&pid32);
                if (tsp) cycles->on_time += ts - *tsp;

                // Clean up all maps
                cpu_cycles.delete(&pid32);
                allowed_pids.delete(&pid32);
                pending_reeval.delete(&pid32);
            }
            return 0;
        }

        /*
         * sched_process_fork: track new process creation
         * - Called when a new process is forked
         * - For PID mode: add child PID if parent is allowed
         * - For regex mode: mark for re-evaluation
         */
        TRACEPOINT_PROBE(sched, sched_process_fork)
        {
            u32 child_pid = args->child_pid;
            u32 parent_pid = args->parent_pid;
            
            // Check if parent is in allowed_pids (for PID inheritance)
            u32 *parent_allowed = allowed_pids.lookup(&parent_pid);
            if (parent_allowed) {
                // Inherit parent's allowed status
                u32 allowed = 1;
                allowed_pids.update(&child_pid, &allowed);
            }
            
            // For regex mode, mark child for re-evaluation
            u32 reeval = 1;
            pending_reeval.update(&child_pid, &reeval);
            
            return 0;
        }

        /*
         * sched_process_exec: track process execution (name change)
         * - Called when a process executes a new program
         * - Mark process for re-evaluation in regex mode
         */
        TRACEPOINT_PROBE(sched, sched_process_exec)
        {
            u32 pid32 = (u32)(bpf_get_current_pid_tgid());
            
            // Mark this process for re-evaluation (name might have changed)
            u32 reeval = 1;
            pending_reeval.update(&pid32, &reeval);
            
            return 0;
        }
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
        if self.filter_mode == "pids":
            self._initialize_pid_filter()
        elif self.filter_mode == "regex":
            self._initialize_regex_filter()
            # Start background thread for dynamic regex pattern re-evaluation
            self.update_thread = threading.Thread(
                target=self._regex_update_loop, daemon=True
            )
            self.update_thread.start()

        # Initialize config map with trace_all setting
        self.b["config"][ctypes.c_uint32(0)] = ctypes.c_uint32(
            1 if self.trace_all else 0
        )

        # Attach kretprobe to finish_task_switch using pattern matching for function variants
        symbols = BPF.get_kprobe_functions(b"finish_task_switch.*")
        if symbols:
            # Select the first matching symbol and convert to string
            sym = list(symbols)[0].decode("utf-8")
            self.b.attach_kretprobe(event=sym, fn_name="trace_finish_task_switch")
        else:
            raise RuntimeError("finish_task_switch function not found")

        # Initialize hardware performance counters for CPU cycles and instructions
        PERF_TYPE_HARDWARE = 0
        PERF_COUNT_HW_CPU_CYCLES = 0
        PERF_COUNT_HW_INSTRUCTIONS = 1
        self.b["clk"].open_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES)
        self.b["inst"].open_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS)

        # Initialize event polling infrastructure with configurable thread count
        self.ringbuf = self.b["events"]
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
        :returns: None. Puts a dict into self.event_queue with process name included.
        """
        try:
            evt = self.b["events"].event(data)
        except Exception as e:
            # Defensive: if event parsing fails, skip.
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Failed to parse event: {e}\n")
            return

        # Validate event data to prevent corrupted values
        try:
            cpu_val = int(evt.cpu)
            instructions_val = int(evt.instructions)
            cycles_val = int(evt.cycles)
            time_val = int(evt.time)
            pid_val = int(evt.pid)
            timestamp_val = int(evt.timestamp)

            # Sanity checks for reasonable values
            if (
                cpu_val < 0
                or cpu_val > 1024
                or instructions_val < 0
                or instructions_val > 1000000000
                or cycles_val < 0
                or cycles_val > 1000000000
                or time_val < 0
                or time_val > 1000000000
                or pid_val < 0
                or pid_val > 1000000
                or timestamp_val < 0
                or timestamp_val > 1000000000000000000
            ):
                print(
                    f"Invalid event values: cpu={cpu_val}, instructions={instructions_val}, cycles={cycles_val}, time={time_val}, pid={pid_val}, timestamp={timestamp_val}"
                )
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(
                            f"Invalid event values: cpu={cpu_val}, instructions={instructions_val}, cycles={cycles_val}, time={time_val}, pid={pid_val}, timestamp={timestamp_val}\n"
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
            "cpu": cpu_val,
            "instructions": instructions_val,
            "cycles": cycles_val,
            "time": time_val,
            "pid": pid_val,
            "comm": evt.comm.decode("utf-8", errors="ignore").rstrip("\x00"),
            "timestamp": timestamp_val,
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
        Generator yielding each CPU burst event as a Python dictionary.
        :yields: {'cpu': int, 'instructions': int, 'cycles': int, 'time': int, 'pid': int, 'comm': str, 'timestamp': int}
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
        print("Stopping CorePulse...")
        self._running = False
        self._stop_event.set()

        # Join threads with timeout to prevent hanging
        for t in self.poll_threads:
            t.join(timeout=1.0)  # Shorter timeout for faster shutdown

        # Force cleanup even if threads don't join properly
        try:
            self.b.cleanup()
            print("BPF resources cleaned up")
        except Exception as e:
            print(f"Error during BPF cleanup: {e}")


if __name__ == "__main__":
    import json

    # Initialize tracer with configurable polling threads for high-throughput tracing
    print("CorePulse: High-performance CPU burst tracer")
    print("Tracing all processes - consider using filters for better performance")
    print("Press Ctrl+C to stop...")

    pulse = CorePulse(
        num_poll_threads=4,  # Multi-threaded polling for high performance
        ringbuf_size=512,  # Adequate buffer size for high throughput
    )

    try:
        for evt in pulse.stream_events():
            # Each event is a dictionary with process information; output as JSON for parsing
            # Use flush=True to prevent buffering issues
            print(json.dumps(evt), flush=True)
            # Check termination condition (in case signal handler was called)
            if not pulse._running:
                break
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt...")
        pulse.stop()  # Graceful shutdown
        os._exit(0)
    except Exception as e:
        print(f"Error: {e}")
        pulse.stop()  # Graceful shutdown
        os._exit(1)
