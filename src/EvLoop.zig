const std = @import("std");
const root = @import("root");
const build_opts = @import("build_opts");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const co = @import("co.zig");
const log = @import("log.zig");
const net = @import("net.zig");
const Rc = @import("Rc.zig");
const assert = std.debug.assert;
const Ptr = cc.Ptr;

// =============================================================

const EvLoop = @This();

/// avoid touching freed ptr, see evloop.run()
destroyed: std.AutoHashMapUnmanaged(*const Fd, void) = .{},

/// cache I/O event changes | [fd] = original_state(epoll_state)
change_list: std.AutoHashMapUnmanaged(*const Fd, Fd.State) = .{},

/// monotonic time (in milliseconds)
time: u64,

/// epoll instance (fd)
epfd: c_int,

// =============================================================

comptime {
    // @compileLog("sizeof(Fd):", @sizeOf(Fd));
    // @compileLog("sizeof(anyframe):", @sizeOf(anyframe));
    // @compileLog("sizeof(?anyframe):", @sizeOf(?anyframe));
}

/// wrap the raw fd to work with evloop
pub const Fd = struct {
    read_frame: ?anyframe = null, // waiting for readable event
    write_frame: ?anyframe = null, // waiting for writable event
    fd: c_int,
    rc: Rc = .{},
    canceled: bool = false,

    /// for evloop.change_list
    pub const State = packed struct {
        read: bool,
        write: bool,

        pub fn is_empty(self: State) bool {
            return !self.read and !self.write;
        }

        pub fn to_events(self: State) u32 {
            var events: u32 = 0;

            if (self.read)
                events |= EVENTS.read;

            if (self.write)
                events |= EVENTS.write;

            if (events != 0)
                events |= EVENTS.ET;

            return events;
        }
    };

    /// ownership of `fd` is transferred to `fdobj`
    pub fn new(fd: c_int) *Fd {
        const self = g.allocator.create(Fd) catch unreachable;
        self.* = .{ .fd = fd };
        return self;
    }

    pub fn ref(self: *Fd) *Fd {
        self.rc.ref();
        return self;
    }

    pub fn unref(self: *Fd) void {
        return self.free();
    }

    pub fn free(self: *Fd) void {
        if (self.rc.unref() > 0) return;

        assert(self.read_frame == null);
        assert(self.write_frame == null);

        g.evloop.on_close_fd(self);
        _ = cc.close(self.fd);

        g.allocator.destroy(self);

        // record to the destroyed list, see `evloop.run()`
        g.evloop.destroyed.put(g.allocator, self, {}) catch unreachable;
    }

    pub fn get_state(self: *const Fd) State {
        return .{
            .read = self.read_frame != null,
            .write = self.write_frame != null,
        };
    }

    pub fn get_events(self: *const Fd) u32 {
        var events: u32 = 0;

        if (self.read_frame != null)
            events |= EVENTS.read;

        if (self.write_frame != null)
            events |= EVENTS.write;

        if (events != 0)
            events |= EVENTS.ET;

        return events;
    }

    pub fn cancel(self: *Fd) void {
        if (self.canceled)
            return;

        self.canceled = true;

        _ = self.ref();
        defer self.unref();

        if (self.read_frame) |frame|
            co.do_resume(frame);

        if (self.write_frame) |frame|
            co.do_resume(frame);

        assert(self.read_frame == null);
        assert(self.write_frame == null);
    }

    /// return `true` if canceled and set errno to `ECANCELED`
    pub fn is_canceled(self: *const Fd) bool {
        if (self.canceled) {
            cc.set_errno(c.ECANCELED);
            return true;
        }
        return false;
    }
};

// =============================================================

const EVENTS = opaque {
    pub const read: u32 = c.EPOLLIN | c.EPOLLRDHUP | c.EPOLLPRI;
    pub const write: u32 = c.EPOLLOUT;
    pub const err: u32 = c.EPOLLERR | c.EPOLLHUP;
    pub const ET: u32 = c.EPOLLET;
};

// =============================================================

/// struct epoll_event
const Ev = opaque {
    /// raw type
    pub const Raw = c.struct_epoll_event;

    pub const SIZE = @sizeOf(Raw);
    pub const ALIGN = @alignOf(Raw);

    /// value type
    pub const V = Array(1);

    /// array type
    pub fn Array(comptime N: comptime_int) type {
        // it is currently not possible to directly return an array type with the align attribute
        // https://github.com/ziglang/zig/issues/7465
        return struct {
            buf: [N * SIZE]u8 align(ALIGN),

            // ======================= for Array =======================

            const Self = @This();

            pub inline fn at(self: *Self, i: usize) *Ev {
                return from(&self.buf[i * SIZE]);
            }

            /// return N
            pub inline fn len(_: *const Self) usize {
                return N;
            }

            // ======================= for Value =======================

            pub inline fn init(events: u32, fdobj: *const Fd) V {
                var v: V = undefined;
                v.ptr().set_events(events);
                v.ptr().set_fdobj(fdobj);
                return v;
            }

            pub inline fn ptr(v: *V) *Ev {
                return v.at(0);
            }
        };
    }

    pub inline fn from(ptr: anytype) Ptr(Ev, @TypeOf(ptr)) {
        return @ptrCast(Ptr(Ev, @TypeOf(ptr)), ptr);
    }

    pub inline fn get_events(self: *const Ev) u32 {
        return c.epev_get_events(self);
    }

    pub inline fn get_fdobj(self: *const Ev) *Fd {
        return cc.ptrcast(*Fd, c.epev_get_ptrdata(self));
    }

    pub inline fn set_events(self: *Ev, events: u32) void {
        return c.epev_set_events(self, events);
    }

    pub inline fn set_fdobj(self: *Ev, fdobj: *const Fd) void {
        return c.epev_set_ptrdata(self, fdobj);
    }
};

// =============================================================

pub noinline fn init() EvLoop {
    const epfd = cc.epoll_create1(c.EPOLL_CLOEXEC) orelse {
        log.err(@src(), "epoll_create() failed: (%d) %m", .{cc.errno()});
        cc.exit(1);
    };
    return .{
        .epfd = epfd,
        .time = cc.monotime(),
    };
}

/// return true if ok (internal api)
noinline fn ev_ctl(self: *EvLoop, op: c_int, fd: c_int, ev: ?*Ev) bool {
    cc.epoll_ctl(self.epfd, op, fd, ev) orelse {
        const op_name = switch (op) {
            c.EPOLL_CTL_ADD => "ADD",
            c.EPOLL_CTL_MOD => "MOD",
            c.EPOLL_CTL_DEL => "DEL",
            else => unreachable,
        };
        const events = if (ev) |e| cc.to_ulong(e.get_events()) else 0;
        log.err(@src(), "epoll_ctl(%d, %s, %d, events:%lu) failed: (%d) %m", .{ self.epfd, op_name, fd, events, cc.errno() });
        return false;
    };
    return true;
}

/// return true if ok
fn ev_add(self: *EvLoop, fdobj: *const Fd, events: u32) bool {
    var ev = Ev.V.init(events, fdobj);
    return self.ev_ctl(c.EPOLL_CTL_ADD, fdobj.fd, ev.ptr());
}

/// return true if ok
fn ev_mod(self: *EvLoop, fdobj: *const Fd, events: u32) bool {
    var ev = Ev.V.init(events, fdobj);
    return self.ev_ctl(c.EPOLL_CTL_MOD, fdobj.fd, ev.ptr());
}

/// return true if ok
fn ev_del(self: *EvLoop, fdobj: *const Fd) bool {
    return self.ev_ctl(c.EPOLL_CTL_DEL, fdobj.fd, null);
}

// ======================================================================

fn set_frame(fdobj: *Fd, comptime field_name: []const u8, frame: anyframe) void {
    assert(!fdobj.canceled);
    assert(@field(fdobj, field_name) == null);
    @field(fdobj, field_name) = frame;
}

/// `frame` used for assert() check
fn unset_frame(fdobj: *Fd, comptime field_name: []const u8, frame: anyframe) void {
    assert(@field(fdobj, field_name) == frame);
    @field(fdobj, field_name) = null;
}

const EvType = enum {
    read,
    write,

    pub fn field_name(self: EvType) []const u8 {
        return switch (self) {
            .read => "read_frame",
            .write => "write_frame",
        };
    }
};

/// before suspend {}
fn add_listener(self: *EvLoop, fdobj: *Fd, comptime ev: EvType, frame: anyframe) void {
    self.cache_change(fdobj); // save the original state
    set_frame(fdobj, comptime ev.field_name(), frame);
}

/// after suspend {}
fn del_listener(self: *EvLoop, fdobj: *Fd, comptime ev: EvType, frame: anyframe) void {
    self.cache_change(fdobj); // save the original state
    unset_frame(fdobj, comptime ev.field_name(), frame);
}

fn cache_change(self: *EvLoop, fdobj: *const Fd) void {
    const res = self.change_list.getOrPut(g.allocator, fdobj) catch unreachable;
    if (!res.found_existing)
        res.value_ptr.* = fdobj.get_state();
}

fn apply_change(self: *EvLoop) void {
    var it = self.change_list.iterator();
    while (it.next()) |v| {
        const fdobj = v.key_ptr.*;
        const state: Fd.State = v.value_ptr.*;
        const old_events = state.to_events();
        const new_events = fdobj.get_events();
        if (old_events == new_events) {
            continue;
        } else if (old_events == 0) {
            assert(self.ev_add(fdobj, new_events));
        } else if (new_events == 0) {
            assert(self.ev_del(fdobj));
        } else {
            assert(self.ev_mod(fdobj, new_events));
        }
    }
    self.change_list.clearRetainingCapacity();
}

fn on_close_fd(self: *EvLoop, fdobj: *const Fd) void {
    if (self.change_list.fetchRemove(fdobj)) |v| {
        const state: Fd.State = v.value;
        if (!state.is_empty())
            assert(self.ev_del(fdobj));
    }
}

// ========================================================================

pub const Timer = struct {
    timeout: ?u64 = null,

    /// return true if the `deadline` has been reached,
    /// false otherwise (and update the timer state).
    pub fn check_deadline(self: *Timer, deadline: u64) bool {
        if (g.evloop.time >= deadline) {
            return true;
        } else {
            const timeout = deadline - g.evloop.time;
            if (self.timeout == null or timeout < self.timeout.?)
                self.timeout = timeout;
            return false;
        }
    }

    /// for epoll_wait
    pub fn get_timeout(self: *const Timer) c_int {
        if (self.timeout) |timeout|
            return cc.to_int(timeout);
        return -1;
    }
};

pub fn run(self: *EvLoop) void {
    var evs: Ev.Array(100) = undefined;

    while (true) {
        self.time = cc.monotime();

        // handling timeout events and get the next interval
        var timer: Timer = .{};
        nosuspend root.call_module_fn(.check_timeout, .{&timer});

        // empty the list before starting a new epoll_wait
        self.destroyed.clearRetainingCapacity();

        // apply the event changes (epoll_ctl)
        self.apply_change();

        // waiting for I/O events
        const n = cc.epoll_wait(self.epfd, evs.at(0), cc.to_int(evs.len()), timer.get_timeout()) orelse switch (cc.errno()) {
            c.EINTR => -1,
            else => {
                log.err(@src(), "epoll_wait(%d) failed: (%d) %m", .{ self.epfd, cc.errno() });
                cc.exit(1);
            },
        };

        // handling I/O events
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            if (@mod(i, 10) == 0)
                self.time = cc.monotime();

            const ev = evs.at(cc.to_usize(i));

            const revents = ev.get_events();
            const fdobj = ev.get_fdobj();

            // check if `fdobj` has been destroyed
            if (self.destroyed.contains(fdobj))
                continue;

            // add ref count
            _ = fdobj.ref();
            defer fdobj.unref();

            if (fdobj.read_frame != null and revents & (EVENTS.read | EVENTS.err) != 0)
                co.do_resume(fdobj.read_frame.?);

            if (fdobj.write_frame != null and revents & (EVENTS.write | EVENTS.err) != 0)
                co.do_resume(fdobj.write_frame.?);
        }
    }
}

// ========================================================================

// socket API (non-blocking + coroutine)

comptime {
    assert(c.EAGAIN == c.EWOULDBLOCK);
}

/// return `null` if fdobj is canceled. \
/// used for external modules, not for this module: \
/// because the coroutine chains consume at least 24 bytes per level (x86_64).
pub fn wait_readable(self: *EvLoop, fdobj: *Fd) ?void {
    self.add_listener(fdobj, .read, @frame());
    suspend {}
    self.del_listener(fdobj, .read, @frame());

    if (fdobj.is_canceled())
        return null;
}

/// return `null` if fdobj is canceled. \
/// used for external modules, not for this module: \
/// because the coroutine chains consume at least 24 bytes per level (x86_64).
pub fn wait_writable(self: *EvLoop, fdobj: *Fd) ?void {
    self.add_listener(fdobj, .write, @frame());
    suspend {}
    self.del_listener(fdobj, .write, @frame());

    if (fdobj.is_canceled())
        return null;
}

pub fn connect(self: *EvLoop, fdobj: *Fd, addr: *const cc.SockAddr) ?void {
    cc.connect(fdobj.fd, addr) orelse {
        if (cc.errno() != c.EINPROGRESS)
            return null;

        self.add_listener(fdobj, .write, @frame());
        suspend {}
        self.del_listener(fdobj, .write, @frame());

        if (fdobj.is_canceled())
            return null;

        if (net.getsockopt_int(fdobj.fd, c.SOL_SOCKET, c.SO_ERROR, "SO_ERROR")) |err| {
            if (err == 0) return;
            cc.set_errno(err);
            return null;
        } else {
            // getsockopt failed
            return null;
        }
    };
}

pub fn accept(self: *EvLoop, fdobj: *Fd, src_addr: ?*cc.SockAddr) ?c_int {
    while (!fdobj.is_canceled()) {
        return cc.accept4(fdobj.fd, src_addr, c.SOCK_NONBLOCK | c.SOCK_CLOEXEC) orelse {
            if (cc.errno() != c.EAGAIN)
                return null;

            self.add_listener(fdobj, .read, @frame());
            suspend {}
            self.del_listener(fdobj, .read, @frame());

            continue;
        };
    } else return null;
}

const ReadErr = error{ eof, errno };

/// read the `buf` full (for stream-based file/socket/pipe)
pub fn read(self: *EvLoop, fdobj: *Fd, buf: []u8) ReadErr!void {
    var nread: usize = 0;

    while (nread < buf.len) {
        if (fdobj.is_canceled())
            return ReadErr.errno; // ECANCELED

        if (cc.read(fdobj.fd, buf[nread..])) |n| {
            if (n == 0)
                return ReadErr.eof;
            nread += n;
        } else {
            if (cc.errno() != c.EAGAIN)
                return ReadErr.errno;
        }

        // https://man7.org/linux/man-pages/man7/epoll.7.html
        if (nread < buf.len) {
            self.add_listener(fdobj, .read, @frame());
            suspend {}
            self.del_listener(fdobj, .read, @frame());
        }
    }
}

pub fn read_udp(self: *EvLoop, fdobj: *Fd, buf: []u8, src_addr: ?*cc.SockAddr) ?usize {
    while (!fdobj.is_canceled()) {
        return cc.recvfrom(fdobj.fd, buf, 0, src_addr) orelse {
            if (cc.errno() != c.EAGAIN)
                return null;

            self.add_listener(fdobj, .read, @frame());
            suspend {}
            self.del_listener(fdobj, .read, @frame());

            continue;
        };
    } else return null;
}

pub fn write(self: *EvLoop, fdobj: *Fd, data: []const u8) ?void {
    var nsend: usize = 0;

    while (nsend < data.len) {
        if (fdobj.is_canceled())
            return null;

        if (cc.send(fdobj.fd, data[nsend..], 0)) |n| {
            nsend += n;
        } else {
            if (cc.errno() != c.EAGAIN)
                return null;
        }

        // https://man7.org/linux/man-pages/man7/epoll.7.html
        if (nsend < data.len) {
            self.add_listener(fdobj, .write, @frame());
            suspend {}
            self.del_listener(fdobj, .write, @frame());
        }
    }
}

/// the `iovec` struct will be modified
pub fn writev(self: *EvLoop, fdobj: *Fd, in_iovec: []cc.iovec_t) ?void {
    var iovec = in_iovec;
    var iovec_len = cc.iovec_len(iovec);

    while (iovec_len > 0) {
        if (fdobj.is_canceled())
            return null;

        if (cc.writev(fdobj.fd, iovec)) |n| {
            iovec_len -= n;
            cc.iovec_skip(&iovec, n);
        } else {
            if (cc.errno() != c.EAGAIN)
                return null;
        }

        // https://man7.org/linux/man-pages/man7/epoll.7.html
        if (iovec_len > 0) {
            self.add_listener(fdobj, .write, @frame());
            suspend {}
            self.del_listener(fdobj, .write, @frame());
        }
    }
}
