const c = @import("c.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const root = @import("root");
const std = @import("std");
const trait = std.meta.trait;

const Epoll = @This();

epfd: c_int,

// =============================================================

/// epoll_event is a packed struct and need to be wrapped
pub const Event = opaque {
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

            pub inline fn at(self: *Self, i: usize) *Event {
                return from(&self.buf[i * SIZE]);
            }

            /// return N
            pub inline fn len(_: *const Self) usize {
                return N;
            }

            // ======================= for Value =======================

            pub inline fn init(events: u32, frame: anyframe) V {
                var v: V = undefined;
                v.ptr().set_events(events);
                v.ptr().set_frame(frame);
                return v;
            }

            pub inline fn ptr(v: *V) *Event {
                return v.at(0);
            }
        };
    }

    pub inline fn from(ptr: anytype) if (trait.isConstPtr(@TypeOf(ptr))) *const Event else *Event {
        return if (comptime trait.isConstPtr(@TypeOf(ptr)))
            @ptrCast(*const Event, ptr)
        else
            @ptrCast(*Event, ptr);
    }

    pub inline fn get_events(self: *const Event) u32 {
        return c.epev_get_events(self);
    }

    pub inline fn get_frame(self: *const Event) anyframe {
        return @ptrCast(anyframe, @alignCast(std.Target.stack_align, c.epev_get_ptrdata(self)));
    }

    pub inline fn set_events(self: *Event, events: u32) void {
        return c.epev_set_events(self, events);
    }

    pub inline fn set_frame(self: *Event, frame: anyframe) void {
        return c.epev_set_ptrdata(self, @ptrCast(*const anyopaque, frame));
    }
};

// =============================================================

extern fn epoll_create1(flags: c_int) c_int;
extern fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: ?*const anyopaque) c_int;
extern fn epoll_wait(epfd: c_int, evs: *anyopaque, n_evs: c_int, timeout: c_int) c_int;

// =============================================================

pub fn create() Epoll {
    const epfd = epoll_create1(0);
    if (epfd < 0) {
        log.err(@src(), "failed to create epoll: (%d) %m", .{cc.errno()});
        c.exit(1);
    }
    return .{ .epfd = epfd };
}

/// return true if ok
fn ctl(self: Epoll, op: c_int, fd: c_int, ev: ?*const Event) bool {
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
pub fn add(self: Epoll, fd: c_int, events: u32, frame: anyframe) bool {
    return ctl(self, c.EPOLL_CTL_ADD, fd, Event.V.init(events, frame).ptr());
}

/// return true if ok
pub fn mod(self: Epoll, fd: c_int, events: u32, frame: anyframe) bool {
    return ctl(self, c.EPOLL_CTL_MOD, fd, Event.V.init(events, frame).ptr());
}

/// return true if ok
pub fn del(self: Epoll, fd: c_int) bool {
    return ctl(self, c.EPOLL_CTL_DEL, fd, null);
}

/// check for timeout events and handles them, then return the next timeout interval (ms)
fn check_timeout() c_int {
    // if there are other timer requirements in the future,
    // a general-purpose manager for timer objects is needed,
    // featuring the ability to sort and store timer objects by timeout duration.
    return root.check_timeout();
}

pub fn loop(self: Epoll) void {
    var evs: Event.Array(64) = undefined;

    while (true) {
        const n = epoll_wait(self.epfd, evs.at(0), cc.to_int(evs.len()), check_timeout());
        if (n < 0 and cc.errno() != c.EINTR) {
            log.err(@src(), "epoll_wait(%d) failed: (%d) %m", .{ self.epfd, cc.errno() });
            c.exit(1);
        }

        // I/O events
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            // suspend and resume only occurs in Epoll.zig
            const ev = evs.at(cc.to_usize(i));
            _events = ev.get_events();
            resume ev.get_frame();
        }
    }
}

// =====================================================================

/// arg: epoll_event.events (epoll_wait)
var _events: u32 = 0;

pub fn do_accept(self: Epoll, listen_sock: c_int, callback: fn (sock: c_int) void) void {
    if (!self.add(listen_sock, c.EPOLLIN, @frame())) {
        log.err(@src(), "failed to register event for listen_sock: %d", .{listen_sock});
        c.exit(1);
    }
    while (true) {
        suspend {}
        const sock = c.accept4(listen_sock, null, null, c.SOCK_NONBLOCK);
        if (sock >= 0) {
            nosuspend callback(sock);
        } else {
            const err = cc.errno();
            if (err != c.EAGAIN and err != c.EWOULDBLOCK)
                log.err(@src(), "accept4(%d) failed: (%d) %m", .{ listen_sock, err });
        }
    }
}

// =====================================================================

pub fn @"test: epoll api"() !void {
    _ = create;
    _ = add;
    _ = mod;
    _ = del;
    _ = loop;
    _ = Event.get_events;
    _ = Event.get_frame;
    _ = Event.set_events;
    _ = Event.set_frame;
}
