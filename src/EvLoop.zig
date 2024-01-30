const c = @import("c.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const net = @import("net.zig");
const coro = @import("coro.zig");
const root = @import("root");
const std = @import("std");
const trait = std.meta.trait;
const assert = std.debug.assert;
const heap = std.heap;

const EvLoop = @This();

/// epoll instance (fd)
epfd: c_int,

/// avoid touching freed ptr, see evloop.run()
destroyed: std.AutoHashMapUnmanaged(*const FdObj, void) = .{},

/// cache fd's add/del operation (reducing epoll_ctl calls)
change_list: std.AutoHashMapUnmanaged(*const FdObj, Change.Set) = .{},

// =============================================================

const Change = opaque {
    pub const T = u8;

    pub const ADD_READ: T = 1 << 0;
    pub const DEL_READ: T = 1 << 1;
    pub const ADD_WRITE: T = 1 << 2;
    pub const DEL_WRITE: T = 1 << 3;

    /// wrapper for T
    pub const Set = struct {
        set: T = 0,

        pub fn is_empty(self: Set) bool {
            return self.set == 0;
        }

        /// has all
        pub fn has(self: Set, v: T) bool {
            return self.set & v == v;
        }

        pub fn has_any(self: Set, v: T) bool {
            return self.set & v != 0;
        }

        pub fn del(self: *Set, v: T) void {
            self.set &= ~v;
        }

        pub fn add(self: *Set, v: T) void {
            self.set |= v;

            if (self.has(ADD_READ | DEL_READ))
                self.del(ADD_READ | DEL_READ);

            if (self.has(ADD_WRITE | DEL_WRITE))
                self.del(ADD_WRITE | DEL_WRITE);
        }
    };
};

// =============================================================

/// wrap the raw fd to work with evloop
pub const FdObj = struct {
    read_frame: ?anyframe = null, // waiting for readable event
    write_frame: ?anyframe = null, // waiting for writable event
    ref_count: u32 = 1,
    fd: c_int,

    pub fn new(fd: c_int) *FdObj {
        const self = cc.malloc_one(FdObj).?;
        self.* = .{ .fd = fd };
        return self;
    }

    pub fn ref(self: *FdObj) *FdObj {
        assert(self.ref_count > 0);
        self.ref_count += 1;
        return self;
    }

    pub const unref = free;

    pub fn free(self: *FdObj, evloop: *EvLoop) void {
        assert(self.ref_count > 0);
        self.ref_count -= 1;

        if (self.ref_count == 0) {
            assert(self.read_frame == null);
            assert(self.write_frame == null);

            evloop.on_close_fd(self);
            _ = c.close(self.fd);

            cc.free(self);

            // record to the destroyed list, see `evloop.run()`
            evloop.destroyed.put(heap.raw_c_allocator, self, {}) catch unreachable;
        }
    }
};

// =============================================================

/// epoll_event is a packed struct and need to be wrapped
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

            pub inline fn init(events: u32, fd_obj: *const FdObj) V {
                var v: V = undefined;
                v.ptr().set_events(events);
                v.ptr().set_fd_obj(fd_obj);
                return v;
            }

            pub inline fn ptr(v: *V) *Ev {
                return v.at(0);
            }
        };
    }

    pub inline fn from(ptr: anytype) if (trait.isConstPtr(@TypeOf(ptr))) *const Ev else *Ev {
        return if (comptime trait.isConstPtr(@TypeOf(ptr)))
            @ptrCast(*const Ev, ptr)
        else
            @ptrCast(*Ev, ptr);
    }

    pub inline fn get_events(self: *const Ev) u32 {
        return c.epev_get_events(self);
    }

    pub inline fn get_fd_obj(self: *const Ev) *FdObj {
        return cc.ptrcast(*FdObj, c.epev_get_ptrdata(self));
    }

    pub inline fn set_events(self: *Ev, events: u32) void {
        return c.epev_set_events(self, events);
    }

    pub inline fn set_fd_obj(self: *Ev, fd_obj: *const FdObj) void {
        return c.epev_set_ptrdata(self, fd_obj);
    }
};

// =============================================================

extern fn epoll_create1(flags: c_int) c_int;
extern fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: ?*const anyopaque) c_int;
extern fn epoll_wait(epfd: c_int, evs: *anyopaque, n_evs: c_int, timeout: c_int) c_int;

// =============================================================

pub fn init() EvLoop {
    const epfd = epoll_create1(c.EPOLL_CLOEXEC);
    if (epfd < 0) {
        log.err(@src(), "failed to create epoll: (%d) %m", .{cc.errno()});
        c.exit(1);
    }
    return .{ .epfd = epfd };
}

/// return true if ok (internal api)
fn ctl(self: *EvLoop, op: c_int, fd: c_int, ev: ?*const Ev) bool {
    if (epoll_ctl(self.epfd, op, fd, ev) < 0) {
        const op_name = switch (op) {
            c.EPOLL_CTL_ADD => "ADD",
            c.EPOLL_CTL_MOD => "MOD",
            c.EPOLL_CTL_DEL => "DEL",
            else => unreachable,
        };
        const events = if (ev) |e| cc.to_ulong(e.get_events()) else 0;
        log.err(@src(), "epoll_ctl(%d, %s, %d, events=%lu) failed: (%d) %m", .{ self.epfd, op_name, fd, events, cc.errno() });
        return false;
    }
    return true;
}

/// return true if ok
fn add(self: *EvLoop, fd_obj: *const FdObj, events: u32) bool {
    return self.ctl(c.EPOLL_CTL_ADD, fd_obj.fd, Ev.V.init(events, fd_obj).ptr());
}

/// return true if ok
fn mod(self: *EvLoop, fd_obj: *const FdObj, events: u32) bool {
    return self.ctl(c.EPOLL_CTL_MOD, fd_obj.fd, Ev.V.init(events, fd_obj).ptr());
}

/// return true if ok
fn del(self: *EvLoop, fd_obj: *const FdObj) bool {
    return self.ctl(c.EPOLL_CTL_DEL, fd_obj.fd, null);
}

// ======================================================================

fn set_frame(fd_obj: *FdObj, comptime field_name: []const u8, frame: anyframe) void {
    assert(@field(fd_obj, field_name) == null);
    @field(fd_obj, field_name) = frame;
}

/// `frame` used for assert() check
fn unset_frame(fd_obj: *FdObj, comptime field_name: []const u8, frame: anyframe) void {
    assert(@field(fd_obj, field_name) == frame);
    @field(fd_obj, field_name) = null;
}

/// before suspend {}
fn add_readable(self: *EvLoop, fd_obj: *FdObj, frame: anyframe) void {
    set_frame(fd_obj, "read_frame", frame);
    return self.cache_change(fd_obj, Change.ADD_READ);
}

/// after suspend {}
fn del_readable(self: *EvLoop, fd_obj: *FdObj, frame: anyframe) void {
    unset_frame(fd_obj, "read_frame", frame);
    return self.cache_change(fd_obj, Change.DEL_READ);
}

/// before suspend {}
fn add_writable(self: *EvLoop, fd_obj: *FdObj, frame: anyframe) void {
    set_frame(fd_obj, "write_frame", frame);
    return self.cache_change(fd_obj, Change.ADD_WRITE);
}

/// after suspend {}
fn del_writable(self: *EvLoop, fd_obj: *FdObj, frame: anyframe) void {
    unset_frame(fd_obj, "write_frame", frame);
    return self.cache_change(fd_obj, Change.DEL_WRITE);
}

fn cache_change(self: *EvLoop, fd_obj: *const FdObj, change: Change.T) void {
    const v = self.change_list.getOrPut(heap.raw_c_allocator, fd_obj) catch unreachable;
    const change_set = v.value_ptr;
    if (v.found_existing) {
        change_set.add(change);
        if (change_set.is_empty())
            assert(self.change_list.remove(fd_obj));
    } else {
        change_set.* = .{};
        change_set.add(change);
        assert(!change_set.is_empty());
    }
}

fn apply_change(self: *EvLoop) void {
    var it = self.change_list.iterator();
    while (it.next()) |v| {
        const fd_obj = v.key_ptr.*;
        const change_set = v.value_ptr.*;
        assert(!change_set.is_empty());

        var new_events: u32 = 0;
        if (fd_obj.read_frame != null) new_events |= EVENTS.read;
        if (fd_obj.write_frame != null) new_events |= EVENTS.write;

        if (new_events == 0) {
            // del
            assert(change_set.has_any(Change.DEL_READ | Change.DEL_WRITE));
            assert(self.del(fd_obj));
        } else {
            // add or mod(r+w <=> r/w)
            var chg_events: u32 = 0;
            if (change_set.has(Change.ADD_READ)) chg_events |= EVENTS.read;
            if (change_set.has(Change.ADD_WRITE)) chg_events |= EVENTS.write;

            if (chg_events == new_events)
                assert(self.add(fd_obj, new_events | c.EPOLLET))
            else
                assert(self.mod(fd_obj, new_events | c.EPOLLET));
        }
    }
    self.change_list.clearRetainingCapacity();
}

fn on_close_fd(self: *EvLoop, fd_obj: *const FdObj) void {
    if (self.change_list.fetchRemove(fd_obj)) |v| {
        if (v.value.has_any(Change.DEL_READ | Change.DEL_WRITE))
            assert(self.del(fd_obj));
    }
}

// ========================================================================

const EVENTS = opaque {
    pub const read: u32 = c.EPOLLIN | c.EPOLLRDHUP | c.EPOLLPRI;
    pub const write: u32 = c.EPOLLOUT;
    pub const err: u32 = c.EPOLLERR | c.EPOLLHUP;
};

/// check for timeout events and handles them, then return the next timeout interval (ms)
fn check_timeout() c_int {
    // if there are other timer requirements in the future,
    // a general-purpose manager for timer objects is needed,
    // featuring the ability to sort and store timer objects by timeout duration.
    return root.check_timeout();
}

pub fn run(self: *EvLoop) void {
    var evs: Ev.Array(64) = undefined;

    while (true) {
        // handling timeout events and get the next interval
        const timeout = check_timeout();

        // empty the list before starting a new epoll_wait
        self.destroyed.clearRetainingCapacity();

        // apply the event changes (epoll_ctl)
        self.apply_change();

        // waiting for I/O events
        const n = epoll_wait(self.epfd, evs.at(0), cc.to_int(evs.len()), timeout);
        if (n < 0 and cc.errno() != c.EINTR) {
            log.err(@src(), "epoll_wait(%d) failed: (%d) %m", .{ self.epfd, cc.errno() });
            c.exit(1);
        }

        // handling I/O events
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const ev = evs.at(cc.to_usize(i));

            const revents = ev.get_events();
            const fd_obj = ev.get_fd_obj();

            // check if `fd_obj` has been destroyed
            if (self.destroyed.contains(fd_obj))
                continue;

            // add ref count
            _ = fd_obj.ref();
            defer fd_obj.unref(self);

            if (fd_obj.read_frame != null and revents & (EVENTS.read | EVENTS.err) != 0)
                coro.do_resume(fd_obj.read_frame.?);

            if (fd_obj.write_frame != null and revents & (EVENTS.write | EVENTS.err) != 0)
                coro.do_resume(fd_obj.write_frame.?);
        }
    }
}

// ========================================================================

// socket API (non-blocking + async)

comptime {
    assert(c.EAGAIN == c.EWOULDBLOCK);
}

pub fn accept(self: *EvLoop, fd_obj: *FdObj, addr: ?*c.struct_sockaddr, addrlen: ?*c.socklen_t) ?c_int {
    while (true) {
        const res = c.accept4(fd_obj.fd, addr, addrlen, c.SOCK_NONBLOCK | c.SOCK_CLOEXEC);
        if (res >= 0)
            return res;

        if (cc.errno() != c.EAGAIN)
            return null;

        self.add_readable(fd_obj, @frame());
        suspend {}
        self.del_readable(fd_obj, @frame());
    }
}

pub fn recvfrom(self: *EvLoop, fd_obj: *FdObj, buf: []u8, flags: c_int, addr: ?*c.struct_sockaddr, addrlen: ?*c.socklen_t) ?usize {
    while (true) {
        const res = c.recvfrom(fd_obj.fd, buf.ptr, buf.len, flags, addr, addrlen);
        if (res >= 0)
            return cc.to_usize(res);

        if (cc.errno() != c.EAGAIN)
            return null;

        self.add_readable(fd_obj, @frame());
        suspend {}
        self.del_readable(fd_obj, @frame());
    }
}

/// length 0 means EOF
pub fn recv(self: *EvLoop, fd_obj: *FdObj, buf: []u8, flags: c_int) ?usize {
    while (true) {
        const res = c.recv(fd_obj.fd, buf.ptr, buf.len, flags);
        if (res >= 0)
            return cc.to_usize(res);

        if (cc.errno() != c.EAGAIN)
            return null;

        self.add_readable(fd_obj, @frame());
        suspend {}
        self.del_readable(fd_obj, @frame());
    }
}

/// read exactly `buf.len` bytes (res:null and errno:0 means EOF)
pub fn recv_exactly(self: *EvLoop, fd_obj: *FdObj, buf: []u8, flags: c_int) ?void {
    var nread: usize = 0;
    while (nread < buf.len) {
        const n = self.recv(fd_obj, buf[nread..], flags) orelse return null;
        if (n == 0) {
            cc.set_errno(0); // EOF
            return null;
        }
        nread += n;
    }
}

// =====================================================================

pub fn @"test: evloop api"() !void {
    _ = add;
    _ = mod;
    _ = del;
    _ = Ev.get_events;
    _ = Ev.get_fd_obj;
    _ = Ev.set_events;
    _ = Ev.set_fd_obj;
}
