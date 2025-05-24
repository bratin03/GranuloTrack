#!/usr/bin/env python3
import threading
import queue
import json
from bcc import BPF, utils

class MemTracker_User:
    """
    MemTracker_User: A tracer for per-process user-space memory events (mmap, munmap, brk, shmget, shmctl).

    Usage:
        tracer = MemTracker_User(pids=[1234, 5678])  # specific PIDs
        tracer = MemTracker_User()                   # all processes

        for ev in tracer.stream_events():
            print(json.dumps(ev))  # {'pid':int,'size':int,'type':int,'timediff':int}
        tracer.stop()
    """
    def __init__(self, pids=None):
        self.allowed_pids = pids or []
        self.trace_all = not bool(self.allowed_pids)
        self.event_queue = queue.Queue()
        self._running = True

        # Build C pid filter
        if self.trace_all:
            checks = "    return 1;"
        else:
            lines = [f"    if (pid == {pid}) return 1;" for pid in self.allowed_pids]
            lines.append("    return 0;")
            checks = "\n".join(lines)

        bpf_text = f"""
#include <linux/ptrace.h>
#include <linux/ipc.h>

static __always_inline int check_pids(u32 pid) {{
{checks}
}}

struct mmap_entry {{ u64 addr, length, prot, flags; int fd; u64 offset, entry_ts; }};
struct munmap_entry {{ u64 addr, length, entry_ts; }};
struct brk_entry   {{ u64 brk, entry_ts; }};

BPF_HASH(mmap_data, u32, struct mmap_entry);
BPF_HASH(munmap_data, u32, struct munmap_entry);
BPF_HASH(brk_data, u32, struct brk_entry);
BPF_HASH(proc_break, u32, u64);

struct proc_data {{
    u64 memory_requested;
    u64 memory_allocated;
    u64 memory_freed;
    u64 kernel_memory_allocated;
    u64 kernel_memory_freed;
}};
BPF_HASH(proc_data, u32, struct proc_data);

// shared memory and temporary syscall maps
BPF_HASH(shared_mem, u64, u64);
BPF_HASH(sys_enter_shmget, u32, u64);
BPF_HASH(sys_enter_shmctl, u32, u64);

struct event_data {{ u32 pid; u64 size; u32 type; u64 timediff; }};
BPF_PERF_OUTPUT(user_events);

// mmap probes
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct mmap_entry e = {{.addr=args->addr, .length=args->len, .prot=args->prot,
        .flags=args->flags, .fd=args->fd, .offset=args->off,
        .entry_ts=bpf_ktime_get_ns()}};
    mmap_data.update(&tid, &e);
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct mmap_entry *e = mmap_data.lookup(&tid);
    if (!e) return 0; mmap_data.delete(&tid);

    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    long ret = args->ret;
    if (ret == -1) p->memory_requested += e->length;
    else {{ p->memory_requested += e->length; p->memory_allocated += e->length; }}

    struct event_data ev = {{.pid=pid, .size=e->length, .type=0, .timediff=bpf_ktime_get_ns()-e->entry_ts}};
    user_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

// munmap probes
TRACEPOINT_PROBE(syscalls, sys_enter_munmap) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct munmap_entry e = {{.addr=args->addr, .length=args->len, .entry_ts=bpf_ktime_get_ns()}};
    munmap_data.update(&tid, &e);
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_munmap) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct munmap_entry *e = munmap_data.lookup(&tid);
    if (!e) return 0; munmap_data.delete(&tid);
    if (args->ret == -1) return 0;

    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    p->memory_freed += e->length;

    struct event_data ev = {{.pid=pid, .size=e->length, .type=1, .timediff=bpf_ktime_get_ns()-e->entry_ts}};
    user_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

// brk probes
TRACEPOINT_PROBE(syscalls, sys_enter_brk) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct brk_entry e = {{.brk=args->brk, .entry_ts=bpf_ktime_get_ns()}};
    brk_data.update(&tid, &e);
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_brk) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    struct brk_entry *e = brk_data.lookup(&tid);
    if (!e) return 0; brk_data.delete(&tid);

    u64 ret = args->ret;
    u64 *oldp = proc_break.lookup(&pid);
    u64 oldv = oldp ? *oldp : 0;
    if (!oldp) proc_break.update(&pid, &ret);

    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    u64 diff = ret > oldv ? ret-oldv : oldv-ret;
    if (ret > oldv) {{ p->memory_requested += diff; p->memory_allocated += diff; }}
    else p->memory_freed += diff;

    struct event_data ev = {{.pid=pid, .size=diff, .type=(ret>oldv?0:1), .timediff=bpf_ktime_get_ns()-e->entry_ts}};
    user_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

// shmget probes
TRACEPOINT_PROBE(syscalls, sys_enter_shmget) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    u64 size = args->size;
    sys_enter_shmget.update(&tid, &size);
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_shmget) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    u64 *sizep = sys_enter_shmget.lookup(&tid);
    if (!sizep) return 0; sys_enter_shmget.delete(&tid);
    if (args->ret < 0) return 0;
    u64 key = args->ret;
    shared_mem.update(&key, sizep);

    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    p->memory_requested += *sizep; p->memory_allocated += *sizep;

    struct event_data ev = {{.pid=pid, .size=*sizep, .type=0, .timediff=0}};
    user_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

// shmctl probes
TRACEPOINT_PROBE(syscalls, sys_enter_shmctl) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    if (args->cmd != IPC_RMID) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = args->shmid;
    sys_enter_shmctl.update(&tid, &id);
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_shmctl) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    u32 tid = bpf_get_current_pid_tgid();
    u64 *idp = sys_enter_shmctl.lookup(&tid);
    if (!idp) return 0; sys_enter_shmctl.delete(&tid);
    if (args->ret < 0) return 0;
    u64 key = *idp;
    u64 *sizep = shared_mem.lookup(&key);
    if (!sizep) return 0; shared_mem.delete(&key);

    struct proc_data *p = proc_data.lookup(&pid);
    if (!p) {{ struct proc_data init = {{}}; proc_data.update(&pid, &init); p = proc_data.lookup(&pid); if (!p) return 0; }}
    p->memory_freed += *sizep;

    struct event_data ev = {{.pid=pid, .size=*sizep, .type=1, .timediff=0}};
    user_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}

// cleanup on exit
TRACEPOINT_PROBE(sched, sched_process_exit) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_pids(pid)) return 0;
    proc_data.delete(&pid);
    return 0;
}}
"""
        self.bpf = BPF(text=bpf_text)
        self.bpf["user_events"].open_perf_buffer(self._handle_event, page_cnt=4096)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

    def _handle_event(self, cpu, data, size):
        evt = self.bpf["user_events"].event(data)
        self.event_queue.put({
            'pid': evt.pid,
            'size': evt.size,
            'type': evt.type,
            'timediff': evt.timediff,
        })

    def _poll_loop(self):
        while self._running:
            try:
                self.bpf.perf_buffer_poll()
            except Exception as e:
                print("Error during polling:", e)
                break

    def stream_events(self, timeout=1):
        while self._running:
            try:
                yield self.event_queue.get(timeout=timeout)
            except queue.Empty:
                continue

    def stop(self):
        self._running = False
        self.poll_thread.join()

if __name__ == '__main__':
    tracer = MemTracker_User()
    try:
        for ev in tracer.stream_events():
            print(json.dumps(ev))
    except KeyboardInterrupt:
        tracer.stop()
