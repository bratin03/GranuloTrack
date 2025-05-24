#!/usr/bin/env python3
import threading
import queue
import time
from bcc import BPF, utils

class CorePulse:
    """
    CorePulse: A tracer for per-process CPU bursts, cycles, and instruction counts.

    Usage:
        # Trace specific PIDs only:
        tracer = CorePulse(pids=[1234, 5678])
        # Or trace all processes:
        tracer = CorePulse()

        # Iterate events until stopped (KeyboardInterrupt stops cleanly):
        for ev in tracer.stream_events():
            print(ev)  # {'cpu': int, 'instructions': int, 'cycles': int, 'time': int, 'pid': int}

        # Stop the background polling thread:
        tracer.stop()

    Public methods:
        - stream_events(): generator yielding per-burst dicts
        - stop(): clean shutdown of the BPF poll thread
    """

    def __init__(self, pids=None):
        """
        Initialize the CorePulse tracer.
        
        :param pids: list of PIDs (ints) to filter by. If None or empty, traces every process.
        :returns: None. On failure to compile or attach, raises RuntimeError or BPF compilation error.
        """
        # --- Python-side setup ---
        self.allowed_pids = pids or []
        self.trace_all = not bool(self.allowed_pids)
        self.num_cpus = len(utils.get_online_cpus())
        self.event_queue = queue.Queue()
        self._running = True

        # Build the inline-C check_pids() body:
        if self.trace_all:
            allowed_checks = "    return 1;"
        else:
            lines = [f"    if (pid == {pid}) return 1;" for pid in self.allowed_pids]
            lines.append("    return 0;")
            allowed_checks = "\n".join(lines)

        # --- BPF C program: tracks on-CPU bursts and hardware counters ---
        self.bpf_program = r"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        // Inline PID filter: returns 1 if this PID should be traced, else 0.
        static __always_inline int check_pids(u32 pid) {
        ##ALLOWED_CHECKS##
        }

        // Accumulated statistics per PID
        typedef struct time_info {
            u64 start_time;    // timestamp when process was last scheduled in
            u64 on_time;       // total ns on CPU so far
            u64 off_time;      // (unused) placeholder for future
            u64 instructions;  // total retired instructions
            u64 cycles;        // total CPU cycles
        } time_info;

        // One-time burst event passed to user space
        typedef struct cpu_burst {
            u32 cpu;           // CPU index
            u64 instructions;  // instructions in this burst
            u64 cycles;        // cycles in this burst
            u64 time;          // duration (ns) of this burst
            u32 pid;           // process ID
        } cpu_burst;

        // BPF maps:
        BPF_HASH(cpu_cycles, u32, time_info);      // aggregated stats per PID
        BPF_PERCPU_HASH(curr_run, u32, u64);        // timestamp when PID was scheduled in
        BPF_PERCPU_ARRAY(data, u64);                // per-CPU snapshot of perf counters
        BPF_PERF_ARRAY(clk, MAX_CPUS);              // hardware CPU cycle counters
        BPF_PERF_ARRAY(inst, MAX_CPUS);             // hardware instruction counters
        BPF_PERF_OUTPUT(events);                    // channel to user space

        #define CLOCK_ID       0
        #define INSTRUCTION_ID 1

        /*
         * sched_switch tracepoint: called on every context switch.
         * - Compute how long the previous process ran (delta ns)
         * - Read hardware counters before/after
         * - Update aggregated stats, then emit this burst as cpu_burst
         * Returns 0 to indicate success; returning non-zero would drop the event.
         */
        TRACEPOINT_PROBE(sched, sched_switch)
        {
            u64 ts       = bpf_ktime_get_ns();
            u32 prev_pid = args->prev_pid;
            int cpu      = bpf_get_smp_processor_id();

            if (!check_pids(prev_pid))
                return 0;

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
                .time         = delta,
                .cycles       = dcycles,
                .instructions = dinsts,
                .pid          = prev_pid,
            };
            events.perf_submit(args, &burst, sizeof(burst));
            return 0;
        }

        /*
         * kretprobe on finish_task_switch: snapshots counters and records start time
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
         * sched_process_exit: finalize stats if a traced process exits
         * - Reads final hardware counters and on_time delta
         * - Deletes the PID from the cpu_cycles map
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

                cpu_cycles.delete(&pid32);
            }
            return 0;
        }
        """

        # Inject our allowed-pid code and compile the BPF module
        prog = self.bpf_program.replace("##ALLOWED_CHECKS##", allowed_checks)
        self.b = BPF(text=prog, cflags=[f"-DMAX_CPUS={self.num_cpus}"])

        # Attach the finish_task_switch kretprobe (names vary by kernel version)
        if BPF.get_kprobe_functions(b'finish_task_switch'):
            self.b.attach_kretprobe(event="finish_task_switch",
                                    fn_name="trace_finish_task_switch")
        elif BPF.get_kprobe_functions(b'finish_task_switch.isra.0'):
            self.b.attach_kretprobe(event="finish_task_switch.isra.0",
                                    fn_name="trace_finish_task_switch")
        else:
            raise RuntimeError("finish_task_switch function not found")

        # Open the hardware perf events for cycles and instructions
        PERF_TYPE_HARDWARE         = 0
        PERF_COUNT_HW_CPU_CYCLES   = 0
        PERF_COUNT_HW_INSTRUCTIONS = 1
        self.b["clk"].open_perf_event(PERF_TYPE_HARDWARE,
                                      PERF_COUNT_HW_CPU_CYCLES)
        self.b["inst"].open_perf_event(PERF_TYPE_HARDWARE,
                                       PERF_COUNT_HW_INSTRUCTIONS)

        # Start polling for events in a background thread
        self.b["events"].open_perf_buffer(self._handle_event, page_cnt=256)
        self.poll_thread = threading.Thread(target=self._poll_loop,
                                            daemon=True)
        self.poll_thread.start()

    def _handle_event(self, cpu, data, size):
        """
        Internal callback for BPF perf events.
        :param cpu: CPU index that generated the event (int).
        :param data: raw event data buffer.
        :param size: size of the buffer.
        :returns: None. Puts a dict into self.event_queue.
        """
        evt = self.b["events"].event(data)
        self.event_queue.put({
            "cpu": evt.cpu,
            "instructions": evt.instructions,
            "cycles": evt.cycles,
            "time": evt.time,
            "pid": evt.pid
        })

    def _poll_loop(self):
        """
        Background thread loop: polls the perf buffer until stop() is called.
        :returns: None.
        """
        while self._running:
            try:
                self.b.perf_buffer_poll()
            except Exception as e:
                print("Error during polling:", e)
                break

    def stream_events(self):
        """
        Generator yielding each cpu_burst event as a Python dict.
        :yields: {'cpu': int, 'instructions': int, 'cycles': int, 'time': int, 'pid': int}
        Blocks until the next event or KeyboardInterrupt.
        """
        while self._running:
            try:
                yield self.event_queue.get(timeout=1)
            except queue.Empty:
                continue

    def stop(self):
        """
        Signal the polling thread to stop and wait for it to join.
        :returns: None.
        """
        self._running = False
        self.poll_thread.join()


if __name__ == '__main__':
    import json

    # Example usage: trace only PIDs 1 and 2. To trace all, omit pids argument.
    pulse = CorePulse()
    try:
        for evt in pulse.stream_events():
            # Each evt is a dict; print as JSON for easy parsing
            print(json.dumps(evt))
    except KeyboardInterrupt:
        pulse.stop()
