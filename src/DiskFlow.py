"""
DiskFlow: eBPF-based Disk I/O Tracer

This Python module uses BCC (BPF Compiler Collection) to attach eBPF programs
to kernel block I/O events, measuring latency, queue time, process context,
and more.

It outputs a dictionary for each I/O event including:
- Timestamp
- Process name and PID
- Device number
- Read/write flag
- Sector and byte length
- Queue delay
- Total latency

Example usage:
    df = DiskFlow()
    try:
        for event in df.stream_events():
            print(json.dumps(event))
    except KeyboardInterrupt:
        df.stop()
"""

import json
import threading
import queue
from bcc import BPF

class DiskFlow:
    def __init__(self):
        """
        Initialize the DiskFlow profiler.
        """
        self.event_queue = queue.Queue()
        self._running = True

        # eBPF program
        self.bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/blk-mq.h>
        #include <linux/blkdev.h>

        struct start_req_t {
            u64 ts;
            u64 data_len;
        };

        struct val_t {
            u64 ts;
            u32 pid;
            char name[TASK_COMM_LEN];
        };

        struct tp_args {
            u64 __unused__;
            dev_t dev;
            sector_t sector;
            unsigned int nr_sector;
            unsigned int bytes;
            char rwbs[8];
            char comm[16];
            char cmd[];
        };

        struct hash_key {
            dev_t dev;
            u32 rwflag;
            sector_t sector;
        };

        struct data_t {
            u32 pid;
            u32 dev;
            u64 rwflag;
            u64 delta;
            u64 qdelta;
            u64 sector;
            u64 len;
            u64 ts;
            char name[TASK_COMM_LEN];
        };

        BPF_HASH(start, struct hash_key, struct start_req_t);
        BPF_HASH(infobyreq, struct hash_key, struct val_t);
        BPF_PERF_OUTPUT(events);

        static dev_t ddevt(struct gendisk *disk) {
            return (disk->major << 20) | disk->first_minor;
        }

        static int get_rwflag(u32 cmd_flags) {
        #ifdef REQ_WRITE
            return !!(cmd_flags & REQ_WRITE);
        #elif defined(REQ_OP_SHIFT)
            return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
        #else
            return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
        #endif
        }

        #define RWBS_LEN 8

        static int get_rwflag_tp(char *rwbs) {
            for (int i = 0; i < RWBS_LEN; i++) {
                if (rwbs[i] == 'W')
                    return 1;
                if (rwbs[i] == '\\0')
                    return 0;
            }
            return 0;
        }

        static int __trace_pid_start(struct hash_key key) {
            struct val_t val = {};
            if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
                val.pid = bpf_get_current_pid_tgid() >> 32;
                val.ts = bpf_ktime_get_ns();  // Always record timestamp
                infobyreq.update(&key, &val);
            }
            return 0;
        }

        int trace_pid_start(struct pt_regs *ctx, struct request *req) {
            struct hash_key key = {
                .dev = ddevt(req->__RQ_DISK__),
                .rwflag = get_rwflag(req->cmd_flags),
                .sector = req->__sector
            };
            return __trace_pid_start(key);
        }

        int trace_pid_start_tp(struct tp_args *args) {
            struct hash_key key = {
                .dev = args->dev,
                .rwflag = get_rwflag_tp(args->rwbs),
                .sector = args->sector
            };
            return __trace_pid_start(key);
        }

        int trace_req_start(struct pt_regs *ctx, struct request *req) {
            struct hash_key key = {
                .dev = ddevt(req->__RQ_DISK__),
                .rwflag = get_rwflag(req->cmd_flags),
                .sector = req->__sector
            };
            struct start_req_t start_req = {
                .ts = bpf_ktime_get_ns(),
                .data_len = req->__data_len
            };
            start.update(&key, &start_req);
            return 0;
        }

        static int __trace_req_completion(void *ctx, struct hash_key key) {
            struct start_req_t *startp;
            struct val_t *valp;
            struct data_t data = {};
            u64 ts;
            startp = start.lookup(&key);
            if (startp == 0) {
                return 0;
            }
            ts = bpf_ktime_get_ns();
            data.delta = ts - startp->ts;
            data.ts = ts / 1000;
            data.qdelta = 0;
            data.len = startp->data_len;
            valp = infobyreq.lookup(&key);
            if (valp == 0) {
                data.name[0] = '?';
                data.name[1] = 0;
            } else {
                data.qdelta = startp->ts - valp->ts;
                data.pid = valp->pid;
                data.sector = key.sector;
                data.dev = key.dev;
                bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
            }
            data.rwflag = key.rwflag;
            events.perf_submit(ctx, &data, sizeof(data));
            start.delete(&key);
            infobyreq.delete(&key);
            return 0;
        }

        int trace_req_completion(struct pt_regs *ctx, struct request *req) {
            struct hash_key key = {
                .dev = ddevt(req->__RQ_DISK__),
                .rwflag = get_rwflag(req->cmd_flags),
                .sector = req->__sector
            };
            return __trace_req_completion(ctx, key);
        }

        int trace_req_completion_tp(struct tp_args *args) {
            struct hash_key key = {
                .dev = args->dev,
                .rwflag = get_rwflag_tp(args->rwbs),
                .sector = args->sector
            };
            return __trace_req_completion(args, key);
        }
        """

        # Replace kernel-specific request field
        if BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
            self.bpf_text = self.bpf_text.replace("__RQ_DISK__", "rq_disk")
        else:
            self.bpf_text = self.bpf_text.replace("__RQ_DISK__", "q->disk")

        # Load and compile BPF program
        self.b = BPF(text=self.bpf_text)

        # Attach start probes
        if BPF.tracepoint_exists("block", "block_io_start"):
            self.b.attach_tracepoint(tp="block:block_io_start", fn_name="trace_pid_start_tp")
        elif BPF.get_kprobe_functions(b"__blk_account_io_start"):
            self.b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
        elif BPF.get_kprobe_functions(b"blk_account_io_start"):
            self.b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
        else:
            raise RuntimeError("No block I/O start probe found.")

        # Attach I/O request start probes
        if BPF.get_kprobe_functions(b"blk_start_request"):
            self.b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
        self.b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

        # Attach I/O completion probes
        if BPF.tracepoint_exists("block", "block_io_done"):
            self.b.attach_tracepoint(tp="block:block_io_done", fn_name="trace_req_completion_tp")
        elif BPF.get_kprobe_functions(b"__blk_account_io_done"):
            self.b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
        elif BPF.get_kprobe_functions(b"blk_account_io_done"):
            self.b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
        else:
            raise RuntimeError("No block I/O done probe found.")

        # Open BPF perf buffer to receive events
        self.b["events"].open_perf_buffer(self._handle_event, page_cnt=64)

        # Start polling thread
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

    def _handle_event(self, cpu, data, size):
        """
        Handles BPF event, converts to dictionary, and queues it.
        """
        event = self.b["events"].event(data)
        event_dict = {
            "ts": event.ts,
            "name": event.name.decode('utf-8', 'replace'),
            "pid": event.pid,
            "dev": event.dev,
            "rwflag": event.rwflag,
            "sector": event.sector,
            "len": event.len,
            "qdelta": event.qdelta,
            "delta": event.delta,
        }
        self.event_queue.put(event_dict)

    def _poll_loop(self):
        """
        Continuously polls the perf buffer for BPF events.
        """
        while self._running:
            try:
                self.b.perf_buffer_poll()
            except Exception as e:
                print("Error during polling:", e)
                break

    def stream_events(self):
        """
        Generator that yields disk I/O events as dictionaries.
        """
        while self._running:
            try:
                event = self.event_queue.get(timeout=1)
                yield event
            except queue.Empty:
                continue

    def stop(self):
        """
        Stop polling loop and wait for background thread to exit.
        """
        self._running = False
        self.poll_thread.join()

# Run module directly
if __name__ == '__main__':
    df = DiskFlow()
    try:
        for event in df.stream_events():
            print(json.dumps(event))
    except KeyboardInterrupt:
        df.stop()
