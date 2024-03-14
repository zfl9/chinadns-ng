//! - provide type-safety version of C functions
//! - fix improperly translated C code/declarations

const c = @import("c.zig");
const g = @import("g.zig");
const fmtchk = @import("fmtchk.zig");

const std = @import("std");
const meta = std.meta;
const trait = meta.trait;
const testing = std.testing;

const assert = std.debug.assert;
const isConstPtr = trait.isConstPtr;

// ==============================================================

/// in stage1, `if (b) expr1 else expr2` expressions do not compile correctly \
/// if they are present in the argument tuple, so use this function to wrap it
pub inline fn b2v(b: bool, true_v: anytype, false_v: anytype) @TypeOf(true_v, false_v) {
    return if (b) true_v else false_v;
}

/// in stage1, `if (b) expr1 else expr2` expressions do not compile correctly \
/// if they are present in the argument tuple, so use this function to wrap it
pub inline fn b2s(b: bool, true_v: ConstStr, false_v: ConstStr) ConstStr {
    return if (b) true_v else false_v;
}

// ==============================================================

pub const Str = [*:0]u8;
pub const ConstStr = [*:0]const u8;

// ==============================================================

/// remove const qualification of pointer `ptr`
/// TODO: zig 0.11 has @constCast()
pub inline fn remove_const(ptr: anytype) RemoveConst(@TypeOf(ptr)) {
    return @intToPtr(RemoveConst(@TypeOf(ptr)), @ptrToInt(ptr));
}

/// remove const qualification of pointer type `T`
pub fn RemoveConst(comptime T: type) type {
    if (comptime trait.isConstPtr(T)) {
        var info = @typeInfo(T);
        info.Pointer.is_const = false;
        return @Type(info);
    }
    return T;
}

// ==============================================================

pub inline fn ptrcast(comptime P: type, ptr: anytype) P {
    return @ptrCast(P, @alignCast(@alignOf(meta.Child(P)), ptr));
}

fn IntCast(comptime DestType: type) type {
    return struct {
        pub inline fn cast(integer: anytype) DestType {
            return @intCast(DestType, integer);
        }
    };
}

pub const to_schar = IntCast(c.schar).cast;
pub const to_uchar = IntCast(c.uchar).cast;

pub const to_short = IntCast(c_short).cast;
pub const to_ushort = IntCast(c_ushort).cast;

pub const to_int = IntCast(c_int).cast;
pub const to_uint = IntCast(c_uint).cast;

pub const to_long = IntCast(c_long).cast;
pub const to_ulong = IntCast(c_ulong).cast;

pub const to_longlong = IntCast(c_longlong).cast;
pub const to_ulonglong = IntCast(c_ulonglong).cast;

pub const to_isize = IntCast(isize).cast;
pub const to_usize = IntCast(usize).cast;

pub const to_i8 = IntCast(i8).cast;
pub const to_u8 = IntCast(u8).cast;

pub const to_i16 = IntCast(i16).cast;
pub const to_u16 = IntCast(u16).cast;

pub const to_i32 = IntCast(i32).cast;
pub const to_u32 = IntCast(u32).cast;

pub const to_i64 = IntCast(i64).cast;
pub const to_u64 = IntCast(u64).cast;

// ==============================================================

/// end with sentinel 0
pub inline fn is_cstr(comptime S: type) bool {
    return @typeInfo(StrSlice(S, false)).Pointer.sentinel != null;
}

/// string => []u8, []const u8, [:0]u8, [:0]const u8
pub inline fn strslice(str: anytype) StrSlice(@TypeOf(str), false) {
    const S = @TypeOf(str);
    if (comptime trait.isManyItemPtr(S)) {
        comptime assert(meta.sentinel(S).? == 0);
        return std.mem.sliceTo(str, 0);
    }
    return str;
}

/// string => []const u8, [:0]const u8
pub inline fn strslice_c(str: anytype) StrSlice(@TypeOf(str), true) {
    return strslice(str);
}

fn StrSlice(comptime S: type, comptime force_const: bool) type {
    const info = @typeInfo(S);

    if (info != .Pointer)
        @compileError("expected pointer, found " ++ @typeName(S));

    if (meta.Elem(S) != u8)
        @compileError("expected u8 pointer, found " ++ @typeName(S));

    const sentinel = meta.sentinel(S);

    if (sentinel) |end| {
        if (end != 0)
            @compileError("expected sentinel 0, found " ++ @typeName(S));
    }

    const ptr_info = info.Pointer;

    switch (ptr_info.size) {
        .One => if (@typeInfo(ptr_info.child) != .Array)
            @compileError("expected u8 array pointer, found " ++ @typeName(S)),

        .Many => if (sentinel == null)
            @compileError("expected many pointer with sentinel, found " ++ @typeName(S)),

        .Slice => {},

        .C => @compileError("expected non-C pointer, found " ++ @typeName(S)),
    }

    if (force_const or ptr_info.is_const) {
        return if (sentinel != null)
            [:0]const u8
        else
            []const u8;
    } else {
        return if (sentinel != null)
            [:0]u8
        else
            []u8;
    }
}

// ==============================================================

/// caller own the returned memory | g.allocator.free(buf)
pub fn strdup(str: anytype) [:0]u8 {
    const s = strslice_c(str);
    return strdup_internal(s, g.allocator.alloc(u8, s.len + 1) catch unreachable);
}

/// note: `str` and `buf` cannot overlap
/// similar to strdup, but copy to the given buffer
pub fn strdup_r(str: anytype, buf: []u8) ?[:0]u8 {
    const s = strslice_c(str);
    if (s.len > buf.len - 1) return null;
    return strdup_internal(s, buf);
}

/// `s`: strslice_c(str)
fn strdup_internal(s: anytype, buf: []u8) [:0]u8 {
    if (comptime is_cstr(@TypeOf(s))) {
        @memcpy(buf.ptr, s.ptr, s.len + 1);
    } else {
        @memcpy(buf.ptr, s.ptr, s.len);
        buf[s.len] = 0;
    }
    return buf[0..s.len :0];
}

// ==============================================================

extern fn __errno_location() *c_int;

pub inline fn errno() c_int {
    return __errno_location().*;
}

pub inline fn set_errno(err: c_int) void {
    __errno_location().* = err;
}

// ==============================================================

pub const FILE = opaque {};

pub extern const stdin: *FILE;
pub extern const stdout: *FILE;
pub extern const stderr: *FILE;

// ==============================================================

pub inline fn fprintf(file: *FILE, comptime fmt: [:0]const u8, args: anytype) void {
    const raw = struct {
        extern fn fprintf(file: *FILE, fmt: ConstStr, ...) c_int;
    };
    fmtchk.check(fmt, args);
    _ = @call(.{}, raw.fprintf, .{ file, fmt.ptr } ++ args);
}

/// print to stdout
pub inline fn printf(comptime fmt: [:0]const u8, args: anytype) void {
    return fprintf(stdout, fmt, args);
}

/// print to stderr
pub inline fn printf_err(comptime fmt: [:0]const u8, args: anytype) void {
    return fprintf(stderr, fmt, args);
}

/// print to string-buffer
/// return the written c-string
pub fn snprintf(buffer: []u8, comptime fmt: [:0]const u8, args: anytype) [:0]u8 {
    const raw = struct {
        extern fn snprintf(buf: [*]u8, len: usize, fmt: ConstStr, ...) c_int;
    };

    fmtchk.check(fmt, args);

    // at least one character and the null terminator
    assert(buffer.len >= 2);

    // number of characters (not including the terminating null character) which would have been written to buffer if bufsz was ignored,
    // or a negative value if an encoding error (for string and character conversion specifiers) occurred
    const should_strlen = @call(.{}, raw.snprintf, .{ buffer.ptr, buffer.len, fmt.ptr } ++ args);

    // reserve space for '\0'
    if (0 <= should_strlen and should_strlen <= buffer.len - 1)
        return buffer[0..to_usize(should_strlen) :0];

    // buffer space not enough
    if (should_strlen > 0)
        return buffer[0..(buffer.len - 1) :0];

    // encoding error
    buffer[0] = 0;
    return buffer[0..0 :0];
}

// ==============================================================

pub extern fn fopen(filename: ConstStr, mode: ConstStr) ?*FILE;

pub inline fn fclose(file: *FILE) ?void {
    const raw = struct {
        extern fn fclose(file: *FILE) c_int;
    };
    return if (raw.fclose(file) == c.EOF) null;
}

pub inline fn fgets(file: *FILE, buf: []u8) ?Str {
    const raw = struct {
        extern fn fgets(buf: [*]u8, len: c_int, file: *FILE) ?Str;
    };
    return raw.fgets(buf.ptr, to_int(buf.len), file);
}

pub inline fn feof(file: *FILE) bool {
    const raw = struct {
        extern fn feof(file: *FILE) c_int;
    };
    return raw.feof(file) != 0;
}

/// if file is `null` then flush all output streams
pub inline fn fflush(file: ?*FILE) ?void {
    const raw = struct {
        extern fn fflush(file: ?*FILE) c_int;
    };
    return if (raw.fflush(file) == c.EOF) null;
}

pub inline fn setvbuf(file: *FILE, buffer: ?[*]u8, mode: c_int, size: usize) ?void {
    const raw = struct {
        extern fn setvbuf(file: *FILE, buffer: ?[*]u8, mode: c_int, size: usize) c_int;
    };
    return if (raw.setvbuf(file, buffer, mode, size) != 0) null;
}

// ==============================================================

pub inline fn time() c.time_t {
    const raw = struct {
        extern fn time(t: ?*c.time_t) c.time_t;
    };
    return raw.time(null);
}

pub inline fn localtime(t: c.time_t) ?*c.struct_tm {
    const raw = struct {
        extern fn localtime(t: *const c.time_t) ?*c.struct_tm;
    };
    return raw.localtime(&t);
}

// ==============================================================

pub extern fn rand() c_int;

pub extern fn getenv(env_name: ConstStr) ?ConstStr;

pub inline fn setenv(env_name: ConstStr, value: ConstStr, is_replace: bool) ?void {
    const raw = struct {
        extern fn setenv(env_name: ConstStr, value: ConstStr, is_replace: c_int) c_int;
    };
    return if (raw.setenv(env_name, value, @boolToInt(is_replace)) == -1) null;
}

pub extern fn exit(status: c_int) noreturn;
pub extern fn abort() noreturn;

pub inline fn connect(fd: c_int, addr: *const SockAddr) ?void {
    const raw = struct {
        extern fn connect(fd: c_int, addr: *const anyopaque, addrlen: c.socklen_t) c_int;
    };
    return if (raw.connect(fd, addr, addr.len()) == -1) null;
}

pub inline fn accept4(fd: c_int, addr: ?*SockAddr, flags: c_int) ?c_int {
    const raw = struct {
        extern fn accept4(fd: c_int, addr: ?*anyopaque, addrlen: ?*c.socklen_t, flags: c_int) c_int;
    };
    var addrlen: c.socklen_t = @sizeOf(SockAddr);
    const p_addrlen = if (addr != null) &addrlen else null;
    const res = raw.accept4(fd, addr, p_addrlen, flags);
    return if (res >= 0) res else null;
}

pub inline fn send(fd: c_int, data: []const u8, flags: c_int) ?usize {
    const raw = struct {
        extern fn send(fd: c_int, buf: [*]const u8, len: usize, flags: c_int) isize;
    };
    const n = raw.send(fd, data.ptr, data.len, flags);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn recv(fd: c_int, buf: []u8, flags: c_int) ?usize {
    const raw = struct {
        extern fn recv(fd: c_int, buf: [*]u8, len: usize, flags: c_int) isize;
    };
    const n = raw.recv(fd, buf.ptr, buf.len, flags);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn sendto(fd: c_int, buf: []const u8, flags: c_int, addr: *const SockAddr) ?usize {
    const raw = struct {
        extern fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, addr: *const anyopaque, addrlen: c.socklen_t) isize;
    };
    const n = raw.sendto(fd, buf.ptr, buf.len, flags, addr, addr.len());
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn recvfrom(fd: c_int, buf: []u8, flags: c_int, addr: *SockAddr) ?usize {
    const raw = struct {
        extern fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, addr: *anyopaque, addrlen: *c.socklen_t) isize;
    };
    var addrlen: c.socklen_t = @sizeOf(SockAddr);
    const n = raw.recvfrom(fd, buf.ptr, buf.len, flags, addr, &addrlen);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn read(fd: c_int, buf: []u8) ?usize {
    const raw = struct {
        extern fn read(fd: c_int, buf: [*]u8, len: usize) isize;
    };
    const n = raw.read(fd, buf.ptr, buf.len);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn write(fd: c_int, buf: []const u8) ?usize {
    const raw = struct {
        extern fn write(fd: c_int, buf: [*]const u8, len: usize) isize;
    };
    const n = raw.write(fd, buf.ptr, buf.len);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn pipe2(fds: *[2]c_int, flags: c_int) ?void {
    const raw = struct {
        extern fn pipe2(fds: *[2]c_int, flags: c_int) c_int;
    };
    return if (raw.pipe2(fds, flags) == -1) null;
}

pub inline fn socket(family: c_int, type_: c_int, protocol: c_int) ?c_int {
    const raw = struct {
        extern fn socket(family: c_int, type: c_int, protocol: c_int) c_int;
    };
    const res = raw.socket(family, type_, protocol);
    return if (res >= 0) res else null;
}

pub inline fn close(fd: c_int) ?void {
    const raw = struct {
        extern fn close(fd: c_int) c_int;
    };
    return if (raw.close(fd) == -1) null;
}

pub inline fn bind(fd: c_int, addr: *const SockAddr) ?void {
    const raw = struct {
        extern fn bind(fd: c_int, addr: *const anyopaque, addrlen: c.socklen_t) c_int;
    };
    return if (raw.bind(fd, addr, addr.len()) == -1) null;
}

pub inline fn listen(fd: c_int, backlog: c_int) ?void {
    const raw = struct {
        extern fn listen(fd: c_int, backlog: c_int) c_int;
    };
    return if (raw.listen(fd, backlog) == -1) null;
}

pub inline fn getsockname(fd: c_int, addr: *SockAddr) ?void {
    const raw = struct {
        extern fn getsockname(fd: c_int, addr: *anyopaque, addrlen: *c.socklen_t) c_int;
    };
    var addrlen: c.socklen_t = @sizeOf(SockAddr);
    return if (raw.getsockname(fd, addr, &addrlen) == -1) null;
}

pub inline fn getpeername(fd: c_int, addr: *SockAddr) ?void {
    const raw = struct {
        extern fn getpeername(fd: c_int, addr: *anyopaque, addrlen: *c.socklen_t) c_int;
    };
    var addrlen: c.socklen_t = @sizeOf(SockAddr);
    return if (raw.getpeername(fd, addr, &addrlen) == -1) null;
}

pub inline fn getsockopt(fd: c_int, level: c_int, opt: c_int, optval: *anyopaque, optlen: *c.socklen_t) ?void {
    const raw = struct {
        extern fn getsockopt(fd: c_int, level: c_int, opt: c_int, optval: *anyopaque, optlen: *c.socklen_t) c_int;
    };
    return if (raw.getsockopt(fd, level, opt, optval, optlen) == -1) null;
}

pub inline fn setsockopt(fd: c_int, level: c_int, opt: c_int, optval: *const anyopaque, optlen: c.socklen_t) ?void {
    const raw = struct {
        extern fn setsockopt(fd: c_int, level: c_int, opt: c_int, optval: *const anyopaque, optlen: c.socklen_t) c_int;
    };
    return if (raw.setsockopt(fd, level, opt, optval, optlen) == -1) null;
}

pub inline fn getsockopt_int(fd: c_int, level: c_int, opt: c_int) ?c_int {
    var res: c_int = undefined;
    var reslen: c.socklen_t = @sizeOf(c_int);
    getsockopt(fd, level, opt, &res, &reslen) orelse return null;
    assert(reslen == @sizeOf(c_int));
    return res;
}

pub inline fn setsockopt_int(fd: c_int, level: c_int, opt: c_int, optval: c_int) ?void {
    return setsockopt(fd, level, opt, &optval, @sizeOf(c_int));
}

pub extern fn ntohs(net_v: u16) u16;
pub extern fn ntohl(net_v: u32) u32;

pub extern fn htons(host_v: u16) u16;
pub extern fn htonl(host_v: u32) u32;

pub inline fn inet_pton(family: c_int, str_ip: ConstStr, net_ip: *anyopaque) bool {
    const raw = struct {
        extern fn inet_pton(family: c_int, str_ip: ConstStr, net_ip: *anyopaque) c_int;
    };
    return raw.inet_pton(family, str_ip, net_ip) == 1;
}

pub inline fn inet_ntop(family: c_int, net_ip: *const anyopaque, str_buf: *IpStrBuf) ?void {
    const raw = struct {
        extern fn inet_ntop(family: c_int, net_ip: *const anyopaque, str_buf: [*]u8, str_bufsz: c.socklen_t) ?ConstStr;
    };
    return if (raw.inet_ntop(family, net_ip, str_buf, str_buf.len) == null) null;
}

// =============================================================

pub inline fn epoll_create1(flags: c_int) ?c_int {
    const raw = struct {
        extern fn epoll_create1(flags: c_int) c_int;
    };
    const res = raw.epoll_create1(flags);
    return if (res >= 0) res else null;
}

pub inline fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: ?*anyopaque) ?void {
    const raw = struct {
        extern fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: ?*anyopaque) c_int;
    };
    return if (raw.epoll_ctl(epfd, op, fd, ev) == -1) null;
}

pub inline fn epoll_wait(epfd: c_int, evs: *anyopaque, n_evs: c_int, timeout: c_int) ?c_int {
    const raw = struct {
        extern fn epoll_wait(epfd: c_int, evs: *anyopaque, n_evs: c_int, timeout: c_int) c_int;
    };
    const res = raw.epoll_wait(epfd, evs, n_evs, timeout);
    return if (res >= 0) res else null;
}

// ==============================================================

/// SIG_DFL may have address 0
pub const sighandler_t = ?std.meta.FnPtr(fn (sig: c_int) callconv(.C) void);

pub inline fn signal(sig: c_int, handler: sighandler_t) ?void {
    const raw = struct {
        extern fn signal(sig: c_int, handler: sighandler_t) sighandler_t;
    };
    return if (raw.signal(sig, handler) == SIG_ERR()) null;
}

pub inline fn SIG_DFL() sighandler_t {
    return @ptrCast(sighandler_t, c.SIG_DEFAULT());
}

pub inline fn SIG_IGN() sighandler_t {
    return @ptrCast(sighandler_t, c.SIG_IGNORE());
}

inline fn SIG_ERR() sighandler_t {
    return @ptrCast(sighandler_t, c.SIG_ERROR());
}

// ==============================================================

/// ipv4/ipv6 address strbuf (char_array with sentinel 0)
pub const IpStrBuf = [c.INET6_ADDRSTRLEN - 1:0]u8;

pub fn get_ipstr_family(ip: ConstStr) ?c.sa_family_t {
    var net_ip: [c.IPV6_LEN]u8 = undefined;

    if (inet_pton(c.AF_INET, ip, &net_ip))
        return c.AF_INET;

    if (inet_pton(c.AF_INET6, ip, &net_ip))
        return c.AF_INET6;

    return null;
}

// ==============================================================

pub const SockAddr = extern union {
    sa: c.struct_sockaddr,
    sin: c.struct_sockaddr_in,
    sin6: c.struct_sockaddr_in6,

    pub inline fn family(self: *const SockAddr) c.sa_family_t {
        return self.sa.sa_family;
    }

    /// sizeof(sin) or sizeof(sin6)
    pub inline fn len(self: *const SockAddr) c.socklen_t {
        assert(self.is_sin() or self.is_sin6());
        return if (self.is_sin())
            @sizeOf(c.struct_sockaddr_in)
        else
            @sizeOf(c.struct_sockaddr_in6);
    }

    pub inline fn is_sin(self: *const SockAddr) bool {
        return self.family() == c.AF_INET;
    }

    pub inline fn is_sin6(self: *const SockAddr) bool {
        return self.family() == c.AF_INET6;
    }

    pub fn eql(self: *const SockAddr, other: *const SockAddr) bool {
        const af = self.family();
        return af == other.family() and switch (af) {
            c.AF_INET => std.mem.eql(u8, std.mem.asBytes(&self.sin), std.mem.asBytes(&other.sin)),
            c.AF_INET6 => std.mem.eql(u8, std.mem.asBytes(&self.sin6), std.mem.asBytes(&other.sin6)),
            else => false,
        };
    }

    /// assuming the `ip` and `port` are valid
    pub fn from_text(ip: ConstStr, port: u16) SockAddr {
        var self: SockAddr = undefined;
        @memset(std.mem.asBytes(&self), 0, @sizeOf(SockAddr));

        if (get_ipstr_family(ip).? == c.AF_INET) {
            const sin = &self.sin;
            sin.sin_family = c.AF_INET;
            assert(inet_pton(c.AF_INET, ip, &sin.sin_addr));
            sin.sin_port = htons(port);
        } else {
            const sin6 = &self.sin6;
            sin6.sin6_family = c.AF_INET6;
            assert(inet_pton(c.AF_INET6, ip, &sin6.sin6_addr));
            sin6.sin6_port = htons(port);
        }

        return self;
    }

    pub fn to_text(self: *const SockAddr, ip: *IpStrBuf, port: *u16) void {
        if (self.is_sin()) {
            const sin = &self.sin;
            assert(inet_ntop(c.AF_INET, &sin.sin_addr, ip) != null);
            port.* = ntohs(sin.sin_port);
        } else {
            assert(self.is_sin6());
            const sin6 = &self.sin6;
            assert(inet_ntop(c.AF_INET6, &sin6.sin6_addr, ip) != null);
            port.* = ntohs(sin6.sin6_port);
        }
    }
};

// ==============================================================

pub const iovec_t = extern struct {
    iov_base: [*]u8,
    iov_len: usize,
};

pub const msghdr_t = extern struct {
    msg_name: ?*SockAddr = null,
    msg_namelen: c.socklen_t = 0,
    msg_iov: [*]iovec_t,
    msg_iovlen: usize,
    msg_control: ?[*]u8 = null,
    msg_controllen: usize = 0,
    msg_flags: c_int = 0,

    pub fn iov_items(self: *const msghdr_t) []iovec_t {
        return self.msg_iov[0..self.msg_iovlen];
    }

    /// data length
    pub fn calc_len(self: *const msghdr_t) usize {
        var len: usize = 0;
        for (self.iov_items()) |*iov|
            len += iov.iov_len;
        return len;
    }

    /// for sendmsg
    pub fn skip_iov(self: *const msghdr_t, skip_len: usize) void {
        assert(skip_len > 0);
        var remain_skip = skip_len;
        for (self.iov_items()) |*iov| {
            if (iov.iov_len == 0) continue;
            const n = std.math.min(iov.iov_len, remain_skip);
            iov.iov_base += n;
            iov.iov_len -= n;
            remain_skip -= n;
            if (remain_skip == 0) return;
        }
        unreachable;
    }
};

pub const mmsghdr_t = extern struct {
    msg_hdr: msghdr_t,
    msg_len: c_uint = undefined, // return value of recvmsg/sendmsg
};

// ===============================================================

pub inline fn recvmsg(fd: c_int, msg: *msghdr_t, flags: c_int) ?usize {
    const n = c.RECVMSG(fd, @ptrCast(*c.MSGHDR, msg), flags);
    return if (n >= 0) to_usize(n) else null;
}

pub inline fn sendmsg(fd: c_int, msg: *const msghdr_t, flags: c_int) ?usize {
    const n = c.SENDMSG(fd, @ptrCast(*const c.MSGHDR, msg), flags);
    return if (n >= 0) to_usize(n) else null;
}

// ===============================================================

extern var RECVMMSG: std.meta.FnPtr(fn (fd: c_int, vec: *anyopaque, vlen: c_uint, flags: c_int, timeout: ?*c.struct_timespec) callconv(.C) c_int);
extern var SENDMMSG: std.meta.FnPtr(fn (fd: c_int, vec: *anyopaque, vlen: c_uint, flags: c_int) callconv(.C) c_int);

pub inline fn recvmmsg(fd: c_int, msgs: []mmsghdr_t, flags: c_int) ?[]mmsghdr_t {
    assert(msgs.len > 0);
    const n = RECVMMSG(fd, msgs.ptr, to_uint(msgs.len), flags, null);
    return if (n > 0) msgs[0..to_usize(n)] else null;
}

pub inline fn sendmmsg(fd: c_int, msgs: []mmsghdr_t, flags: c_int) ?[]mmsghdr_t {
    assert(msgs.len > 0);
    const n = SENDMMSG(fd, msgs.ptr, to_uint(msgs.len), flags);
    return if (n > 0) msgs[0..to_usize(n)] else null;
}

// ==============================================================

pub fn @"test: strdup"() !void {
    const org_str = "helloworld";

    const dup_str = strdup(org_str);
    defer g.allocator.free(dup_str);

    try testing.expectEqual(@as(usize, 10), org_str.len);
    try testing.expectEqual(org_str.len, dup_str.len);
    try testing.expectEqualStrings(org_str, dup_str);

    dup_str[dup_str.len - 1] = 'x';
    try testing.expectEqualStrings(org_str[0 .. org_str.len - 1], dup_str[0 .. dup_str.len - 1]);
}

pub fn @"test: strslice"() !void {
    const hello = "hello";
    const N = hello.len;

    const slice = strslice(hello);
    try testing.expectEqual([:0]const u8, @TypeOf(slice));
    try testing.expectEqualStrings(hello, slice);
    try testing.expectEqual(hello.len, slice.len);
    try testing.expectEqual(hello.len, std.mem.indexOfSentinel(u8, 0, slice));

    const const_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice(&const_buf)));

    const const_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice(&const_buf_z)));

    var var_buf: [N]u8 = hello.*;
    try testing.expectEqual([]u8, @TypeOf(strslice(&var_buf)));

    var var_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]u8, @TypeOf(strslice(&var_buf_z)));
}

pub fn @"test: strslice_c"() !void {
    const hello = "hello";
    const N = hello.len;

    const slice = strslice_c(hello);
    try testing.expectEqual([:0]const u8, @TypeOf(slice));
    try testing.expectEqualStrings(hello, slice);
    try testing.expectEqual(hello.len, slice.len);
    try testing.expectEqual(hello.len, std.mem.indexOfSentinel(u8, 0, slice));

    const const_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice_c(&const_buf)));

    const const_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice_c(&const_buf_z)));

    var var_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice_c(&var_buf)));

    var var_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice_c(&var_buf_z)));
}

pub fn @"test: errno"() !void {
    set_errno(c.EAGAIN);
    try testing.expectEqual(c.EAGAIN, errno());
}

pub fn @"test: fopen fclose"() !void {
    // random string as filename
    const pool = "123456789-ABCDEF"; // string-literal => *const [16:0]u8
    var filename: [128:0]u8 = undefined;
    for (filename) |*ch| ch.* = pool[to_usize(rand()) % pool.len];
    filename[filename.len] = 0;

    try testing.expectEqual(*const [16:0]u8, @TypeOf(pool));
    try testing.expectEqual(@as(usize, 16), pool.len);
    try testing.expectEqual(@as(u8, 0), pool[pool.len]);
    try testing.expectEqual(16 + 1, @sizeOf(@TypeOf(pool.*))); // .len + sentinel(0)

    try testing.expectEqual(128, filename.len);
    try testing.expectEqual(@sizeOf(@TypeOf(filename)), filename.len + 1);
    try testing.expectEqual(@as(usize, 128), std.mem.indexOfSentinel(u8, 0, &filename));

    // open non-exist file
    {
        const file = fopen(&filename, "rb");
        defer if (file) |f| fclose(f) orelse unreachable;

        // assuming it fails because the file doesn's exist
        if (file == null)
            try testing.expectEqual(c.ENOENT, errno());
    }

    // open ./build.zig file
    {
        const file = fopen("./build.zig", "rb") orelse unreachable;
        defer fclose(file) orelse unreachable;
    }
}

pub fn @"test: snprintf"() !void {
    var buffer: [11]u8 = undefined;
    const helloworld = "helloworld";
    const str = snprintf(&buffer, "%s", .{helloworld});
    try testing.expect(helloworld.len == 10);
    try testing.expectEqual(helloworld.len, str.len);
    try testing.expectEqualStrings(helloworld, str);
    try testing.expectEqualSentinel(u8, 0, helloworld, str);
}

pub fn @"test: snprintf overflow"() !void {
    var buffer: [10]u8 = undefined;
    const helloworld = "helloworld";
    const str = snprintf(&buffer, "%s", .{helloworld});
    try testing.expectEqual(@as(usize, 9), str.len);
    try testing.expectEqualSlices(u8, helloworld[0..9], str);
    try testing.expectEqualStrings(helloworld[0..9 :'d'], str);
    try testing.expectEqual(@as(usize, 9), std.mem.indexOfSentinel(u8, 0, str));
}
