#!/usr/bin/env python3
import threading
import queue
import time
import json
from bcc import BPF, utils

class MemTracker_Kernel:
    """
    MemTracker_Kernel: A tracer for per-process kernel-space memory events (kmalloc, kfree,
    kmem_cache_alloc, kmem_cache_free) filtered by PID.

    Usage:
        # Trace specific PIDs only:
        tracer = MemTracker_Kernel(pids=[1234, 5678])
        # Or trace all processes:
        tracer = MemTracker_Kernel()

        for ev in tracer.stream_events():
            print(json.dumps(ev))  # {'pid': int, 'size': int, 'type': int}
        tracer.stop()
    """
    def __init__(self, pids=None):
        self.allowed_pids = pids or []
        self.trace_all = not bool(self.allowed_pids)
        self.event_queue = queue.Queue()
        self._running = True

        # Build inline C pid check
        if self.trace_all:
            checks = "    return 1;"
        else:
            lines = [f"    if (pid == {pid}) return 1;" for pid in self.allowed_pids]
            lines.append("    return 0;")
            checks = "\n".join(lines)

        bpf_text = f"""
#include <linux/ptrace.h>

static __always_inline int check_pids(u32 pid) {{
{checks}
}}

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
    u32 type; // 0 alloc, 1 free
}};
BPF_PERF_OUTPUT(kern_events);

struct pointer_key {{
    u64 pid;
    u64 ptr;
}};
BPF_HASH(pointer_allocs, struct pointer_key, u64);
BPF_HASH(pointer_cache, struct pointer_key, u64);

TRACEPOINT_PROBE(kmem, kmalloc) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u64 ptr = (u64)args->ptr;
    u64 size = args->bytes_alloc;
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    p->kernel_memory_allocated += size;
    struct pointer_key key = {{.pid = pid, .ptr = ptr}};
    pointer_allocs.update(&key, &size);
    struct event_data ev = {{.pid = pid, .size = size, .type = 0}};
    kern_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

TRACEPOINT_PROBE(kmem, kfree) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    struct pointer_key key = {{.pid = pid, .ptr = (u64)args->ptr}};
    u64 *sizep = pointer_allocs.lookup(&key);
    if (!sizep) return 0;
    pointer_allocs.delete(&key);
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) return 0;
    p->kernel_memory_freed += *sizep;
    struct event_data ev = {{.pid = pid, .size = *sizep, .type = 1}};
    kern_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u64 ptr = (u64)args->ptr;
    u64 size = args->bytes_alloc;
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    p->kernel_memory_allocated += size;
    struct pointer_key key = {{.pid = pid, .ptr = ptr}};
    pointer_cache.update(&key, &size);
    struct event_data ev = {{.pid = pid, .size = size, .type = 0}};
    kern_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    struct pointer_key key = {{.pid = pid, .ptr = (u64)args->ptr}};
    u64 *sizep = pointer_cache.lookup(&key);
    if (!sizep) return 0;
    pointer_cache.delete(&key);
    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) return 0;
    p->kernel_memory_freed += *sizep;
    struct event_data ev = {{.pid = pid, .size = *sizep, .type = 1}};
    kern_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

TRACEPOINT_PROBE(sched, sched_process_exit) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    proc_data.delete(&pid);
    return 0;
}}
"""
        self.bpf = BPF(text=bpf_text)
        self.bpf["kern_events"].open_perf_buffer(self._handle_event, page_cnt=4096)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

    def _handle_event(self, cpu, data, size):
        evt = self.bpf["kern_events"].event(data)
        self.event_queue.put({
            'pid': evt.pid,
            'size': evt.size,
            'type': evt.type
        })

    def _poll_loop(self):
        while self._running:
            try:
                self.bpf.perf_buffer_poll()
            except Exception as e:
                print("Error during polling:", e)
                break

    def stream_events(self, timeout=1):
        """Generator yielding each kernel memory event."""
        while self._running:
            try:
                yield self.event_queue.get(timeout=timeout)
            except queue.Empty:
                continue

    def stop(self):
        self._running = False
        self.poll_thread.join()

if __name__ == '__main__':
    tracer = MemTracker_Kernel()
    print(f"Tracing kernel memory events for PIDs {tracer.allowed_pids or 'ALL'}...")
    try:
        for ev in tracer.stream_events():
            print(json.dumps(ev))
    except KeyboardInterrupt:
        tracer.stop()
