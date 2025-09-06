#!/usr/bin/env python3

import threading
import queue
import re
import os
import datetime
import json
import sys
import ctypes
import time
from collections import deque
from bcc import BPF, utils

from queue import Queue as EventQueue

# Debug configuration
DEBUG = True


class DiskFlow:
    """
    DiskFlow: High-performance disk I/O tracer with comprehensive kernel-space filtering.

    DiskFlow leverages eBPF to capture detailed disk I/O events including latency, queue time,
    process context, and device information. Supports dynamic filtering by process ID, process name
    patterns, device, I/O type, size, sector range, and latency with all filtering performed in kernel space.

    Usage:
        # Trace with various filters:
        tracer = DiskFlow(
            pids=[1234, 5678],                    # Process IDs
            process_patterns=["nginx", "apache"], # Process name patterns
            device_filter=['sda', 'nvme0n1'],     # Devices
            rw_filter='write',                    # I/O type
            size_min=4096, size_max=1048576,      # Size range
            sector_range=(1000, 2000),            # Sector range
            latency_min=1000000, latency_max=10000000  # Latency range
        )

        # Stream events until interrupted:
        for ev in tracer.stream_events():
            print(ev)  # {'ts': int, 'name': str, 'pid': int, 'dev': int, 'rwflag': int, 'sector': int, 'len': int, 'qdelta': int, 'delta': int}

        # Clean shutdown:
        tracer.stop()

    Public methods:
        - stream_events(): generator yielding per-I/O event dictionaries with process names
        - stop(): clean shutdown of background polling threads
    """

    def __init__(
        self,
        pids=None,
        process_patterns=None,
        device_filter=None,  # List of dev numbers or device names
        rw_filter=None,  # 'read', 'write', or None
        size_min=None,  # Minimum I/O size in bytes
        size_max=None,  # Maximum I/O size in bytes
        sector_range=None,  # (start_sector, end_sector)
        latency_min=None,  # Minimum latency in nanoseconds
        latency_max=None,  # Maximum latency in nanoseconds
        num_poll_threads=1,
        queue_size=10000,
        ringbuf_size=256,
    ):
        """
        Initialize the DiskFlow tracer with configurable filtering and performance settings.

        Args:
            pids: List of process IDs to filter by (mutually exclusive with process_patterns)
            process_patterns: List of regex patterns to filter process names
            device_filter: List of device numbers or device names
            rw_filter: 'read', 'write', or None for both
            size_min/size_max: I/O size range in bytes
            sector_range: Tuple of (start_sector, end_sector)
            latency_min/latency_max: Latency range in nanoseconds
            num_poll_threads: Number of polling threads (default: 1)
            queue_size: Event queue size (default: 10000)
            ringbuf_size: Ring buffer pages (default: 256)
        """
        # Validate mutually exclusive filtering parameters
        if pids and process_patterns:
            raise ValueError(
                "Cannot specify both pids and process_patterns. Use one or the other."
            )

        # --- Python-side configuration and state management ---
        self.allowed_pids = pids or []
        self.process_patterns = process_patterns or []
        self.device_filter_raw = device_filter
        self.rw_filter = rw_filter
        self.size_min = size_min
        self.size_max = size_max
        self.sector_range = sector_range

        self.latency_min = latency_min
        self.latency_max = latency_max
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
            self.debug_log_file = f"/tmp/diskflow_{timestamp}.log"
            with open(self.debug_log_file, "w") as f:
                f.write(f"DiskFlow started at {datetime.datetime.now()}\n")
                f.write(f"Filter mode: {self.filter_mode}\n")
                if self.allowed_pids:
                    f.write(f"Allowed PIDs: {self.allowed_pids}\n")
                if self.process_patterns:
                    f.write(f"Process patterns: {self.process_patterns}\n")
                f.write(f"Device filter: {device_filter}\n")
                # Determine rw filter value for kernel space
                rw_filter_value = 2  # Default to both
                if rw_filter == "read":
                    rw_filter_value = 0
                elif rw_filter == "write":
                    rw_filter_value = 1
                f.write(f"RW filter: {rw_filter} (kernel value: {rw_filter_value})\n")
                f.write(
                    f"Size range: {size_min}-{size_max} bytes (kernel: {self.size_min if self.size_min is not None else -1}-{self.size_max if self.size_max is not None else -1})\n"
                )
                f.write(
                    f"Sector range: {sector_range} (kernel: {self.sector_range[0] if self.sector_range else -1}-{self.sector_range[1] if self.sector_range else -1})\n"
                )
                f.write(
                    f"Latency range: {self.latency_min}-{self.latency_max} ns (kernel: {self.latency_min if self.latency_min is not None else -1}-{self.latency_max if self.latency_max is not None else -1})\n"
                )
                f.write(
                    f"Buffer size: {self.ringbuf_size}, Poll threads: {self.num_poll_threads}\n"
                )

        # Initialize system resources and thread synchronization primitives
        self.event_queue = EventQueue(maxsize=queue_size)
        self._running = True
        self._stop_event = threading.Event()
        self._dedupe_lock = threading.Lock()
        self._recent_keys = set()
        self._recent_order = deque()
        self._recent_keys_max = 1000  # Maximum deduplication cache size

        # Parse filters after debug logging is initialized
        self.device_filter = self._parse_device_filter(device_filter)
        self.regex_patterns = None
        if self.process_patterns:
            self.regex_patterns = [
                re.compile(pattern) for pattern in self.process_patterns
            ]
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(
                        f"Initialized regex filter with patterns: {self.process_patterns}\n"
                    )

        # BPF C program for kernel-space disk I/O event tracking
        self.bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/blk-mq.h>
        #include <linux/blkdev.h>
        #include <linux/sched.h>

        // Dynamic filtering maps - all filtering in kernel space
        BPF_HASH(allowed_pids, u32, u32);        // PID allowlist
        BPF_HASH(pending_reeval, u32, u32);      // PIDs needing re-evaluation
        BPF_HASH(config, u32, u32);              // Configuration flags
        BPF_HASH(filter_ranges, u32, u64);       // Filter ranges (-1 = no limit)
        // Config: 0=filter_pid, 1=filter_dev, 2=filter_rw
        // Ranges: 3=size_min, 4=size_max, 5=sector_min, 6=sector_max, 7=latency_min, 8=latency_max

        // Data structures for I/O tracking
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

        // BPF maps for state tracking and event output
        BPF_HASH(start, struct hash_key, struct start_req_t);
        BPF_HASH(infobyreq, struct hash_key, struct val_t);
        BPF_RINGBUF_OUTPUT(events, RINGBUF_SIZE);

        // Extract device number from gendisk
        static dev_t ddevt(struct gendisk *disk) {{
            return (disk->major << 20) | disk->first_minor;
        }}

        // Determine read/write flag from request flags
        static int get_rwflag(u32 cmd_flags) {{
        #ifdef REQ_WRITE
            return !!(cmd_flags & REQ_WRITE);
        #elif defined(REQ_OP_SHIFT)
            return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
        #else
            return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
        #endif
        }}

        #define RWBS_LEN 8

        // Check if device is allowed
        static int filter_dev(u32 dev) {
            ##DEV_FILTER_MACRO##
        }

        // Check if read/write operation matches filter
        static int filter_rw(u32 rwflag) {
            u32 filter_rw_key = 2;
            u32 *filter_rw_val = config.lookup(&filter_rw_key);
            if (!filter_rw_val)
                return 1;  // No filter set, allow all
            
            if (*filter_rw_val == 0) {
                return (rwflag == 0);
            } else if (*filter_rw_val == 1) {
                return (rwflag == 1);
            } else {
                return 1;
            }
        }

        // Check if size is within allowed range
        static int filter_size(u64 size) {
            u32 size_min_key = 3;
            u32 size_max_key = 4;
            u64 *size_min = filter_ranges.lookup(&size_min_key);
            u64 *size_max = filter_ranges.lookup(&size_max_key);
            
            if (size_min && *size_min != (u64)-1) {
                if (size < *size_min)
                    return 0;
            }
            
            if (size_max && *size_max != (u64)-1) {
                if (size > *size_max)
                    return 0;
            }
            
            return 1;
        }

        // Check if sector is within allowed range
        static int filter_sector(u64 sector) {
            u32 sector_min_key = 5;
            u32 sector_max_key = 6;
            u64 *sector_min = filter_ranges.lookup(&sector_min_key);
            u64 *sector_max = filter_ranges.lookup(&sector_max_key);
            
            if (sector_min && *sector_min != (u64)-1) {
                if (sector < *sector_min)
                    return 0;
            }
            
            if (sector_max && *sector_max != (u64)-1) {
                if (sector > *sector_max)
                    return 0;
            }
            
            return 1;
        }

        // Check if latency is within allowed range
        static int filter_latency(u64 latency) {
            u32 latency_min_key = 7;
            u32 latency_max_key = 8;
            u64 *latency_min = filter_ranges.lookup(&latency_min_key);
            u64 *latency_max = filter_ranges.lookup(&latency_max_key);
            
            if (latency_min && *latency_min != (u64)-1) {
                if (latency < *latency_min)
                    return 0;
            }
            
            if (latency_max && *latency_max != (u64)-1) {
                if (latency > *latency_max)
                    return 0;
            }
            
            return 1;
        }

        // Determine read/write flag from tracepoint rwbs string
        static int get_rwflag_tp(char *rwbs) {{
            for (int i = 0; i < RWBS_LEN; i++) {{
                if (rwbs[i] == 'W')
                    return 1;
                if (rwbs[i] == '\\0')
                    return 0;
            }}
            return 0;
        }}

        // Record process information when I/O starts
        static int __trace_pid_start(struct hash_key key, u64 size) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            
            // Apply PID filtering
            u32 filter_pid_key = 0;
            u32 *filter_pid = config.lookup(&filter_pid_key);
            if (filter_pid && *filter_pid == 1) {
                u32 *allowed = allowed_pids.lookup(&pid);
                if (!allowed)
                    return 0;
            }
            
            // Apply device filtering
            u32 filter_dev_key = 1;
            u32 *filter_dev_enabled = config.lookup(&filter_dev_key);
            if (filter_dev_enabled && *filter_dev_enabled == 1) {
                if (!filter_dev(key.dev))
                    return 0;
            }
            
            // Apply filters
            if (!filter_rw(key.rwflag))
                return 0;
            if (!filter_size(size))
                return 0;
            if (!filter_sector(key.sector))
                return 0;
            
            struct val_t val = {};
            if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
                val.pid = pid;
                val.ts = bpf_ktime_get_ns();  // Always record timestamp
                infobyreq.update(&key, &val);
            }
            return 0;
        }

        // kprobe: record process information on I/O start
        int trace_pid_start(struct pt_regs *ctx, struct request *req) {
            struct hash_key key;
            key.dev = ddevt(req->__RQ_DISK__);
            key.rwflag = get_rwflag(req->cmd_flags);
            key.sector = req->__sector;
            u64 size = req->__data_len;
            return __trace_pid_start(key, size);
        }

        // tracepoint: record process information on I/O start
        int trace_pid_start_tp(struct tp_args *args) {
            struct hash_key key;
            key.dev = args->dev;
            key.rwflag = get_rwflag_tp(args->rwbs);
            key.sector = args->sector;
            u64 size = args->bytes;
            return __trace_pid_start(key, size);
        }

        // kprobe: record request start time
        int trace_req_start(struct pt_regs *ctx, struct request *req) {
            struct hash_key key;
            key.dev = ddevt(req->__RQ_DISK__);
            key.rwflag = get_rwflag(req->cmd_flags);
            key.sector = req->__sector;
            
            // Apply filters
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 filter_pid_key = 0;
            u32 *filter_pid = config.lookup(&filter_pid_key);
            if (filter_pid && *filter_pid == 1) {
                u32 *allowed = allowed_pids.lookup(&pid);
                if (!allowed)
                    return 0;
            }
            
            u32 filter_dev_key = 1;
            u32 *filter_dev_enabled = config.lookup(&filter_dev_key);
            if (filter_dev_enabled && *filter_dev_enabled == 1) {
                if (!filter_dev(key.dev))
                    return 0;
            }
            
            if (!filter_rw(key.rwflag))
                return 0;
            
            u64 size = req->__data_len;
            if (!filter_size(size))
                return 0;
            
            if (!filter_sector(key.sector))
                return 0;
            
            struct start_req_t start_req;
            start_req.ts = bpf_ktime_get_ns();
            start_req.data_len = req->__data_len;
            start.update(&key, &start_req);
            return 0;
        }

        // Process I/O completion and generate events
        static int __trace_req_completion(void *ctx, struct hash_key key) {
            struct start_req_t *startp;
            struct val_t *valp;
            struct data_t *data;
            
            startp = start.lookup(&key);
            if (startp == 0) {
                return 0;
            }
            
            // Reserve space in ring buffer
            data = events.ringbuf_reserve(sizeof(struct data_t));
            if (!data) {
                return 0;
            }
            
            u64 ts = bpf_ktime_get_ns();
            data->delta = ts - startp->ts;
            data->ts = ts / 1000;
            data->qdelta = 0;
            data->len = startp->data_len;
            
            // Apply latency filtering
            if (!filter_latency(data->delta)) {
                events.ringbuf_discard(data, 0);
                start.delete(&key);
                infobyreq.delete(&key);
                return 0;
            }
            
            // Look up process information
            valp = infobyreq.lookup(&key);
            if (valp == 0) {
                u32 filter_pid_key = 0;
                u32 *filter_pid = config.lookup(&filter_pid_key);
                if (filter_pid && *filter_pid == 1) {
                    events.ringbuf_discard(data, 0);
                    start.delete(&key);
                    return 0;
                }
                
                data->name[0] = '?';
                data->name[1] = 0;
                data->pid = 0;
            } else {
                u32 filter_pid_key = 0;
                u32 *filter_pid = config.lookup(&filter_pid_key);
                if (filter_pid && *filter_pid == 1) {
                    u32 *allowed = allowed_pids.lookup(&valp->pid);
                    if (!allowed) {
                        events.ringbuf_discard(data, 0);
                        start.delete(&key);
                        infobyreq.delete(&key);
                        return 0;
                    }
                }
                
                data->qdelta = startp->ts - valp->ts;
                data->pid = valp->pid;
                bpf_probe_read_kernel(&data->name, sizeof(data->name), valp->name);
            }
            data->sector = key.sector;
            data->dev = key.dev;
            data->rwflag = key.rwflag;
            
            // Submit event to ring buffer
            events.ringbuf_submit(data, 0);
            
            // Clean up tracking maps
            start.delete(&key);
            infobyreq.delete(&key);
            return 0;
        }

        // kprobe: process I/O completion
        int trace_req_completion(struct pt_regs *ctx, struct request *req) {
            struct hash_key key;
            key.dev = ddevt(req->__RQ_DISK__);
            key.rwflag = get_rwflag(req->cmd_flags);
            key.sector = req->__sector;
            return __trace_req_completion(ctx, key);
        }

        // tracepoint: process I/O completion
        int trace_req_completion_tp(struct tp_args *args) {
            struct hash_key key;
            key.dev = args->dev;
            key.rwflag = get_rwflag_tp(args->rwbs);
            key.sector = args->sector;
            return __trace_req_completion(args, key);
        }

        // Track process scheduling for dynamic filtering
        TRACEPOINT_PROBE(sched, sched_switch)
        {
            u32 next_pid = args->next_pid;
            return 0;
        }

        // Track process execution for regex re-evaluation
        TRACEPOINT_PROBE(sched, sched_process_exec)
        {
            u32 pid32 = (u32)(bpf_get_current_pid_tgid());
            u32 reeval = 1;
            pending_reeval.update(&pid32, &reeval);
            return 0;
        }
        """

        # Replace kernel-specific request field
        if BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
            self.bpf_text = self.bpf_text.replace("__RQ_DISK__", "rq_disk")
        else:
            self.bpf_text = self.bpf_text.replace("__RQ_DISK__", "q->disk")

        # Generate device filter macro
        dev_filter_macro = self._generate_device_filter_macro()

        # Substitute the macro in BPF text
        bpf_text_with_devices = self.bpf_text.replace(
            "##DEV_FILTER_MACRO##", dev_filter_macro
        )

        # Load and compile BPF program
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write("Loading and compiling BPF program...\n")
                f.write(f"Device filter macro: {dev_filter_macro}\n")

        self.b = BPF(
            text=bpf_text_with_devices,
            cflags=[
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

        # Initialize config map with filter settings
        # Key 0: filter_pid (1 if PID filtering is enabled, 0 if disabled)
        self.b["config"][ctypes.c_uint32(0)] = ctypes.c_uint32(
            1 if (self.allowed_pids or self.process_patterns) else 0
        )
        # Key 1: filter_dev (1 if device filtering is enabled, 0 if disabled)
        self.b["config"][ctypes.c_uint32(1)] = ctypes.c_uint32(
            1 if self.device_filter else 0
        )
        # Key 2: filter_rw (0=read only, 1=write only, 2=both read and write)
        rw_filter_value = 2  # Default to both
        if self.rw_filter == "read":
            rw_filter_value = 0
        elif self.rw_filter == "write":
            rw_filter_value = 1
        self.b["config"][ctypes.c_uint32(2)] = ctypes.c_uint32(rw_filter_value)

        # Initialize filter ranges (-1 means no limit)
        # Size filters
        size_min_val = ctypes.c_uint64(
            self.size_min if self.size_min is not None else -1
        )
        size_max_val = ctypes.c_uint64(
            self.size_max if self.size_max is not None else -1
        )
        self.b["filter_ranges"][ctypes.c_uint32(3)] = size_min_val  # size_min
        self.b["filter_ranges"][ctypes.c_uint32(4)] = size_max_val  # size_max

        # Sector filters
        if self.sector_range is not None:
            sector_min_val = ctypes.c_uint64(self.sector_range[0])
            sector_max_val = ctypes.c_uint64(self.sector_range[1])
        else:
            sector_min_val = ctypes.c_uint64(-1)
            sector_max_val = ctypes.c_uint64(-1)
        self.b["filter_ranges"][ctypes.c_uint32(5)] = sector_min_val  # sector_min
        self.b["filter_ranges"][ctypes.c_uint32(6)] = sector_max_val  # sector_max

        # Latency filters
        latency_min_val = ctypes.c_uint64(
            self.latency_min if self.latency_min is not None else -1
        )
        latency_max_val = ctypes.c_uint64(
            self.latency_max if self.latency_max is not None else -1
        )
        self.b["filter_ranges"][ctypes.c_uint32(7)] = latency_min_val  # latency_min
        self.b["filter_ranges"][ctypes.c_uint32(8)] = latency_max_val  # latency_max

        # Attach start probes
        if BPF.tracepoint_exists("block", "block_io_start"):
            self.b.attach_tracepoint(
                tp="block:block_io_start", fn_name="trace_pid_start_tp"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached block:block_io_start tracepoint\n")
        elif BPF.get_kprobe_functions(b"__blk_account_io_start"):
            self.b.attach_kprobe(
                event="__blk_account_io_start", fn_name="trace_pid_start"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached __blk_account_io_start kprobe\n")
        elif BPF.get_kprobe_functions(b"blk_account_io_start"):
            self.b.attach_kprobe(
                event="blk_account_io_start", fn_name="trace_pid_start"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached blk_account_io_start kprobe\n")
        else:
            raise RuntimeError("No block I/O start probe found.")

        # Attach I/O request start probes
        if BPF.get_kprobe_functions(b"blk_start_request"):
            self.b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached blk_start_request kprobe\n")
        self.b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write("Attached blk_mq_start_request kprobe\n")

        # Attach I/O completion probes
        if BPF.tracepoint_exists("block", "block_io_done"):
            self.b.attach_tracepoint(
                tp="block:block_io_done", fn_name="trace_req_completion_tp"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached block:block_io_done tracepoint\n")
        elif BPF.get_kprobe_functions(b"__blk_account_io_done"):
            self.b.attach_kprobe(
                event="__blk_account_io_done", fn_name="trace_req_completion"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached __blk_account_io_done kprobe\n")
        elif BPF.get_kprobe_functions(b"blk_account_io_done"):
            self.b.attach_kprobe(
                event="blk_account_io_done", fn_name="trace_req_completion"
            )
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Attached blk_account_io_done kprobe\n")
        else:
            raise RuntimeError("No block I/O done probe found.")

        # Open BPF ring buffer to receive events
        self.b["events"].open_ring_buffer(self._handle_event)
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write(f"Opened ring buffer with {self.ringbuf_size} pages\n")

        # Start polling threads
        self.poll_threads = []
        for i in range(num_poll_threads):
            thread = threading.Thread(target=self._poll_loop, args=(i,), daemon=True)
            thread.start()
            self.poll_threads.append(thread)
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Started polling thread {i}\n")

    def _parse_device_filter(self, device_filter):
        """Parse device filter to convert device names to device numbers."""
        if not device_filter:
            return None

        device_numbers = set()

        for device in device_filter:
            if isinstance(device, (list, tuple)) and len(device) == 2:
                # Already a device number [major, minor]
                major, minor = device
                device_num = (major << 20) | minor
                device_numbers.add(device_num)
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(
                            f"Added device number {device_num} (major:{major}, minor:{minor})\n"
                        )
            elif isinstance(device, str):
                # Device name like 'sda', 'nvme0n1' or full path like '/dev/nvme0n1'
                try:
                    import stat

                    # Handle both full paths and device names
                    if device.startswith("/"):
                        device_path = device  # Full path provided
                    else:
                        device_path = f"/dev/{device}"  # Just device name

                    if os.path.exists(device_path):
                        st = os.stat(device_path)
                        # Convert st.st_rdev (major << 8 | minor) to BPF format (major << 20 | minor)
                        major = (st.st_rdev >> 8) & 0x1FF  # 9 bits for major number
                        minor = st.st_rdev & 0xFF  # 8 bits for minor number
                        device_num = (major << 20) | minor
                        device_numbers.add(device_num)
                        if DEBUG:
                            with open(self.debug_log_file, "a") as f:
                                f.write(
                                    f"Resolved device '{device}' to device number {device_num}\n"
                                )
                    else:
                        if DEBUG:
                            with open(self.debug_log_file, "a") as f:
                                f.write(f"Warning: Device {device} not found\n")
                except Exception as e:
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(
                                f"Warning: Could not resolve device {device}: {e}\n"
                            )
            elif isinstance(device, int):
                # Already a device number
                device_numbers.add(device)
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(f"Added device number {device}\n")

        return device_numbers if device_numbers else None

    def _handle_event(self, cpu, data, size):
        """Internal callback for BPF ring buffer events."""
        try:
            event = self.b["events"].event(data)
        except Exception as e:
            # Defensive: if event parsing fails, skip
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Failed to parse event: {e}\n")
            return

        # Validate event data
        try:
            event_dict = {
                "ts": int(event.ts),
                "name": event.name.decode("utf-8", "replace").rstrip("\x00"),
                "pid": int(event.pid),
                "dev": int(event.dev),
                "rwflag": int(event.rwflag),
                "sector": int(event.sector),
                "len": int(event.len),
                "qdelta": int(event.qdelta),
                "delta": int(event.delta),
            }

            # Sanity checks for corrupted data
            if (
                event_dict["ts"] < 0
                or event_dict["pid"] < 0
                or event_dict["dev"] < 0
                or event_dict["sector"] < 0
                or event_dict["len"] < 0
                or event_dict["qdelta"] < 0
                or event_dict["delta"] < 0
            ):
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(
                            f"Dropped corrupted event with negative values: {event_dict}\n"
                        )
                return

            if event_dict["ts"] > 0xFFFFFFFFFFFFFFFF or event_dict["pid"] > 0xFFFFFFFF:
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(
                            f"Dropped corrupted event with excessive values: {event_dict}\n"
                        )
                return

        except (ValueError, AttributeError) as e:
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Failed to convert event data: {e}\n")
            return

        # Apply deduplication only for multi-threaded configurations to prevent race conditions
        if self.num_poll_threads > 1:
            # O(1) deduplication using hash set with insertion-order tracking via deque
            with self._dedupe_lock:
                key = (event_dict["ts"], event_dict["pid"], event_dict["sector"])
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

        # Thread-safe event queue insertion with non-blocking approach
        try:
            # Non-blocking insertion to prevent deadlocks during high event rates
            self.event_queue.put_nowait(event_dict)
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Queued event: {event_dict}\n")
        except queue.Full:
            # Drop event silently to prevent blocking and potential deadlocks
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write("Event queue capacity exceeded, dropping event\n")

    def get_config_status(self):
        """Get current configuration status for debugging."""
        config_status = {}
        try:
            # Get filter_pid setting
            filter_pid_key = ctypes.c_uint32(0)
            filter_pid_val = self.b["config"][filter_pid_key]
            config_status["filter_pid"] = filter_pid_val.value if filter_pid_val else 0

            # Get filter_dev setting
            filter_dev_key = ctypes.c_uint32(1)
            filter_dev_val = self.b["config"][filter_dev_key]
            config_status["filter_dev"] = filter_dev_val.value if filter_dev_val else 0

            # Get filter_rw setting
            filter_rw_key = ctypes.c_uint32(2)
            filter_rw_val = self.b["config"][filter_rw_key]
            config_status["filter_rw"] = filter_rw_val.value if filter_rw_val else 2

            # Get filter ranges
            filter_ranges = {}
            for key, name in [
                (3, "size_min"),
                (4, "size_max"),
                (5, "sector_min"),
                (6, "sector_max"),
                (7, "latency_min"),
                (8, "latency_max"),
            ]:
                range_key = ctypes.c_uint32(key)
                range_val = self.b["filter_ranges"][range_key]
                filter_ranges[name] = range_val.value if range_val else -1
            config_status["filter_ranges"] = filter_ranges

            # Get allowed_pids count
            allowed_pids_count = len(self.b["allowed_pids"])
            config_status["allowed_pids_count"] = allowed_pids_count

            # Get pending_reeval count
            pending_reeval_count = len(self.b["pending_reeval"])
            config_status["pending_reeval_count"] = pending_reeval_count

        except Exception as e:
            config_status["error"] = str(e)

        return config_status

    def _generate_device_filter_macro(self):
        """Generate device filter macro for BPF compilation."""
        if not self.device_filter:
            return "return 0;  // No devices allowed"

        macro_lines = []
        for device_num in self.device_filter:
            macro_lines.append(f"if (dev == {device_num}) return 1;")

        macro_lines.append("return 0;  // Device not in allowed list")
        return "\n            ".join(macro_lines)

    def _initialize_pid_filter(self):
        """Initialize allowed_pids map with specified process IDs."""
        for pid in self.allowed_pids:
            self.b["allowed_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write(f"Initialized PID filter with {len(self.allowed_pids)} PIDs\n")

    def _initialize_regex_filter(self):
        """Initialize regex filter by populating allowed_pids map."""
        try:
            regex_patterns = [re.compile(pattern) for pattern in self.process_patterns]

            for pid_dir in os.listdir("/proc"):
                if pid_dir.isdigit():
                    pid = int(pid_dir)
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            comm = f.read().strip()
                        # Check if process name matches any regex pattern
                        for pattern in regex_patterns:
                            if pattern.search(comm):
                                self.b["allowed_pids"][ctypes.c_uint32(pid)] = (
                                    ctypes.c_uint32(1)
                                )
                                if DEBUG:
                                    with open(self.debug_log_file, "a") as f:
                                        f.write(
                                            f"Initial match: PID {pid} ({comm}) matches pattern\n"
                                        )
                                break
                    except (FileNotFoundError, OSError):
                        continue
        except Exception as e:
            if DEBUG:
                with open(self.debug_log_file, "a") as f:
                    f.write(f"Error initializing regex filter: {e}\n")

    def _regex_update_loop(self):
        """Background thread for dynamic regex pattern re-evaluation."""
        while self._running:
            try:
                # Check for processes that need re-evaluation
                pending_pids = []
                for k, v in self.b["pending_reeval"].items():
                    pending_pids.append(k.value)
                    self.b["pending_reeval"].pop(k)

                # Re-evaluate pending processes
                for pid in pending_pids:
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            comm = f.read().strip()

                        # Check if process still matches any regex pattern
                        matched = False
                        for pattern in self.process_patterns:
                            if pattern.search(comm):
                                matched = True
                                break

                        if matched:
                            # Add matching process to allowed_pids map
                            self.b["allowed_pids"][ctypes.c_uint32(pid)] = (
                                ctypes.c_uint32(1)
                            )
                            if DEBUG:
                                with open(self.debug_log_file, "a") as f:
                                    f.write(
                                        f"Added PID {pid} ({comm}) to allowed_pids\n"
                                    )
                        else:
                            # Remove process from allowed_pids map if no longer matching
                            self.b["allowed_pids"].pop(ctypes.c_uint32(pid), None)
                            if DEBUG:
                                with open(self.debug_log_file, "a") as f:
                                    f.write(
                                        f"Removed PID {pid} ({comm}) from allowed_pids\n"
                                    )
                    except (FileNotFoundError, OSError):
                        # Process no longer exists, remove from maps
                        self.b["allowed_pids"].pop(ctypes.c_uint32(pid), None)
                        if DEBUG:
                            with open(self.debug_log_file, "a") as f:
                                f.write(
                                    f"Process {pid} no longer exists, removed from maps\n"
                                )

                time.sleep(0.1)  # Check every 100ms
            except Exception as e:
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(f"Error in regex update loop: {e}\n")
                time.sleep(1)  # Extended sleep interval on error

    def _poll_loop(self, thread_id):
        """Continuously polls ring buffer for BPF events."""
        while self._running:
            try:
                self.b.ring_buffer_consume()
            except Exception as e:
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(f"Error during polling (thread {thread_id}): {e}\n")
                break

    def stream_events(self):
        """Generator yielding disk I/O events as dictionaries."""
        while self._running:
            try:
                event = self.event_queue.get(timeout=1)
                yield event
            except queue.Empty:
                continue

    def stop(self):
        """Stop polling loops and wait for background threads to exit."""
        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write(f"Stopping DiskFlow tracer\n")

        self._running = False
        self._stop_event.set()  # Signal thread termination

        # Stop update thread if it exists
        if hasattr(self, "update_thread") and self.update_thread.is_alive():
            try:
                self.update_thread.join(timeout=1)
                if self.update_thread.is_alive():
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(f"Warning: update_thread did not stop gracefully\n")
            except Exception as e:
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(f"Error joining update_thread: {e}\n")

        # Wait for all polling threads to finish
        for i, thread in enumerate(self.poll_threads):
            try:
                thread.join(timeout=1)
                if thread.is_alive():
                    if DEBUG:
                        with open(self.debug_log_file, "a") as f:
                            f.write(
                                f"Warning: poll_thread {i} did not stop gracefully\n"
                            )
            except Exception as e:
                if DEBUG:
                    with open(self.debug_log_file, "a") as f:
                        f.write(f"Error joining poll_thread {i}: {e}\n")

        if DEBUG:
            with open(self.debug_log_file, "a") as f:
                f.write(f"DiskFlow tracer stopped\n")


if __name__ == "__main__":
    import json

    # Initialize tracer with configurable polling threads for high-throughput tracing
    print("DiskFlow: High-performance disk I/O tracer")
    print("Tracing all processes - consider using filters for better performance")
    print("Press Ctrl+C to stop...")

    df = DiskFlow(
        num_poll_threads=4,  # Multi-threaded polling for high performance
        ringbuf_size=512,  # Adequate buffer size for high throughput
        queue_size=20000,  # Larger event queue
    )

    try:
        for evt in df.stream_events():
            print(json.dumps(evt), flush=True)
            if not df._running:
                break
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt...")
        df.stop()
        print("Exiting cleanly...")
    except Exception as e:
        print(f"Error: {e}")
        df.stop()
        print("Exiting due to error...")
