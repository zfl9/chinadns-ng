//! - provide type-safety version of C functions
//! - fix improperly translated C code/declarations

const std = @import("std");
const c = @import("c.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const fmtchk = @import("fmtchk.zig");
const meta = std.meta;
const testing = std.testing;
const assert = std.debug.assert;
const isConstPtr = meta.trait.isConstPtr;
const isManyItemPtr = meta.trait.isManyItemPtr;
const isSlice = meta.trait.isSlice;

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
    if (comptime isSlice(@TypeOf(ptr)))
        return remove_const(ptr.ptr)[0..ptr.len];
    return @intToPtr(RemoveConst(@TypeOf(ptr)), @ptrToInt(ptr));
}

/// remove const qualification of pointer type `T`
pub fn RemoveConst(comptime T: type) type {
    if (isConstPtr(T)) {
        var info = @typeInfo(T);
        info.Pointer.is_const = false;
        return @Type(info);
    }
    return T;
}

/// return the `bytes` type of the given `pointer` type, preserving the `const` attribute
pub fn Bytes(comptime P: type, t: enum { ptr, slice }) type {
    if (isConstPtr(P))
        return if (t == .ptr) [*]const u8 else []const u8
    else
        return if (t == .ptr) [*]u8 else []u8;
}

/// return the `*const T` or `*T` (depends on the `P`)
pub fn Ptr(comptime T: type, comptime P: type) type {
    return if (isConstPtr(P)) *const T else *T;
}

// ==============================================================

/// return `p1 - p2` (same semantics as C)
/// https://github.com/ziglang/zig/issues/1738
pub inline fn ptrdiff(comptime T: type, p1: [*]const T, p2: [*]const T) isize {
    const addr1 = to_isize(@ptrToInt(p1));
    const addr2 = to_isize(@ptrToInt(p2));
    return @divExact(addr1 - addr2, @sizeOf(T));
}

/// return `p1 - p2`, assume the result is non-negative
pub inline fn ptrdiff_u(comptime T: type, p1: [*]const T, p2: [*]const T) usize {
    return to_usize(ptrdiff(T, p1, p2));
}

/// `@ptrCast(P, @alignCast(alignment, ptr))`
pub inline fn ptrcast(comptime P: type, ptr: anytype) P {
    return @ptrCast(P, @alignCast(meta.alignment(P), ptr));
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

pub inline fn calc_hashv(mem: []const u8) c_uint {
    return c.calc_hashv(mem.ptr, mem.len);
}

pub inline fn memeql(a: []const u8, b: []const u8) bool {
    return a.len == b.len and c.memcmp(a.ptr, b.ptr, a.len) == 0;
}

/// avoid static buffers all over the place, wasting memory
pub noinline fn static_buf(size: usize) []u8 {
    const static = struct {
        var buf: []u8 = &.{};
    };
    if (size > static.buf.len) {
        if (static.buf.len == 0) {
            static.buf = g.allocator.alloc(u8, size) catch unreachable;
        } else if (g.allocator.resize(static.buf, size)) |buf| {
            static.buf = buf;
        } else {
            g.allocator.free(static.buf);
            static.buf = g.allocator.alloc(u8, size) catch unreachable;
        }
    }
    return static.buf.ptr[0..size];
}

/// convert to C string (global static buffer)
pub inline fn to_cstr(str: []const u8) Str {
    return to_cstr_x(&.{str});
}

/// convert to C string (global static buffer)
pub noinline fn to_cstr_x(str_list: []const []const u8) Str {
    var total_len: usize = 0;
    for (str_list) |str|
        total_len += str.len;

    const buf = static_buf(total_len + 1);

    var ptr = buf.ptr;
    for (str_list) |str| {
        @memcpy(ptr, str.ptr, str.len);
        ptr += str.len;
    }
    ptr[0] = 0;

    return @ptrCast(Str, buf.ptr);
}

/// end with sentinel 0
pub inline fn is_cstr(comptime S: type) bool {
    return @typeInfo(StrSlice(S, false)).Pointer.sentinel != null;
}

/// string => []u8, []const u8, [:0]u8, [:0]const u8
pub inline fn strslice(str: anytype) StrSlice(@TypeOf(str), false) {
    const S = @TypeOf(str);
    if (comptime isManyItemPtr(S)) {
        comptime assert(meta.sentinel(S).? == 0);
        return str[0..c.strlen(str) :0];
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

pub extern fn fopen(path: ConstStr, mode: ConstStr) ?*FILE;

/// flush(file) and close(fd)
pub extern fn fclose(file: *FILE) c_int;

/// return the number of bytes written \
/// `res < data.len` means write error
pub inline fn fwrite(file: *FILE, data: []const u8) usize {
    const raw = struct {
        extern fn fwrite(ptr: [*]const u8, size: usize, nitems: usize, file: *FILE) usize;
    };
    return raw.fwrite(data.ptr, 1, data.len, file);
}

pub inline fn setvbuf(file: *FILE, buffer: ?[*]u8, mode: c_int, size: usize) ?void {
    const raw = struct {
        extern fn setvbuf(file: *FILE, buffer: ?[*]u8, mode: c_int, size: usize) c_int;
    };
    return if (raw.setvbuf(file, buffer, mode, size) != 0) null;
}

// ==============================================================

/// unix timestamp in seconds
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

/// CLOCK_MONOTONIC in milliseconds (ms). \
/// please consider using `g.evloop.time` (faster)
pub inline fn monotime() u64 {
    return c.monotime();
}

// ==============================================================

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

pub inline fn recvfrom(fd: c_int, buf: []u8, flags: c_int, addr: ?*SockAddr) ?usize {
    const raw = struct {
        extern fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, addr: ?*anyopaque, addrlen: ?*c.socklen_t) isize;
    };
    var len: c.socklen_t = @sizeOf(SockAddr);
    const addrlen = if (addr != null) &len else null;
    const n = raw.recvfrom(fd, buf.ptr, buf.len, flags, addr, addrlen);
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

pub inline fn writev(fd: c_int, iovec: []const iovec_t) ?usize {
    const raw = struct {
        extern fn writev(fd: c_int, iovec: [*]const iovec_t, iovec_n: c_int) isize;
    };
    const n = raw.writev(fd, iovec.ptr, to_int(iovec.len));
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

pub inline fn open(filename: ConstStr, flags: c_int, newfile_mode: ?c.mode_t) ?c_int {
    const raw = struct {
        extern fn open(file: ConstStr, oflag: c_int, ...) c_int;
    };
    const fd = raw.open(filename, flags, newfile_mode orelse 0);
    return if (fd >= 0) fd else null;
}

pub inline fn is_dir(path: ConstStr) bool {
    return c.is_dir(path);
}

pub inline fn fstat_size(fd: c_int) ?usize {
    const sz = c.fstat_size(fd);
    return if (sz >= 0) to_usize(sz) else null;
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

pub inline fn signal(sig: c_int, handler: sighandler_t) void {
    return c.sig_register(sig, handler);
}

pub inline fn SIG_DFL() sighandler_t {
    return @ptrCast(sighandler_t, c.SIG_DEFAULT());
}

pub inline fn SIG_IGN() sighandler_t {
    return @ptrCast(sighandler_t, c.SIG_IGNORE());
}

// ==============================================================

pub const IpStrBuf = [c.INET6_ADDRSTRLEN - 1:0]u8;
pub const IpNetBuf = [c.IPV6_LEN]u8;

pub fn ip_to_net(ip: ConstStr, buf: *IpNetBuf) ?[]u8 {
    if (inet_pton(c.AF_INET, ip, buf))
        return buf[0..c.IPV4_LEN];
    if (inet_pton(c.AF_INET6, ip, buf))
        return buf[0..c.IPV6_LEN];
    return null;
}

pub fn ip_family(ip: ConstStr) ?c.sa_family_t {
    var buf: IpNetBuf = undefined;
    const net_ip = ip_to_net(ip, &buf) orelse return null;
    return if (net_ip.len == c.IPV4_LEN) c.AF_INET else c.AF_INET6;
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

        if (ip_family(ip).? == c.AF_INET) {
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

pub fn iovec_len(iovec: []const iovec_t) usize {
    var len: usize = 0;
    for (iovec) |*iov|
        len += iov.iov_len;
    return len;
}

pub fn iovec_dupe(iovec: []const iovec_t) []u8 {
    const len = iovec_len(iovec);
    const buffer = g.allocator.alloc(u8, len) catch unreachable;
    var offset: usize = 0;
    for (iovec) |*iov| {
        @memcpy(buffer[offset..].ptr, iov.iov_base, iov.iov_len);
        offset += iov.iov_len;
    }
    return buffer;
}

pub fn iovec_skip(iovec: *[]iovec_t, in_skip_len: usize) void {
    var skip_len = in_skip_len;
    while (skip_len > 0) {
        const iov = &iovec.*[0];
        if (skip_len >= iov.iov_len) {
            iovec.* = iovec.*[1..];
            skip_len -= iov.iov_len;
        } else {
            iov.iov_base += skip_len;
            iov.iov_len -= skip_len;
            return;
        }
    }
}

pub const msghdr_t = extern struct {
    msg_name: ?*SockAddr = null,
    msg_namelen: c.socklen_t = 0,
    msg_iov: [*]iovec_t,
    msg_iovlen: usize,
    msg_control: ?[*]u8 = null,
    msg_controllen: usize = 0,
    msg_flags: c_int = 0,
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

pub inline fn mmap(addr: ?*const anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: c.off_t) ?[]u8 {
    const raw = struct {
        extern fn mmap(addr: ?*const anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: c.off_t) [*]u8;
    };
    const mem = raw.mmap(addr, len, prot, flags, fd, offset);
    return if (mem != @ptrCast([*]u8, c.MAP_FAILED))
        mem[0..len]
    else
        null;
}

pub inline fn munmap(mem: []const u8) ?void {
    const raw = struct {
        extern fn munmap(addr: *const anyopaque, len: usize) c_int;
    };
    if (mem.len == 0) return; // see the mmap_file
    return if (raw.munmap(mem.ptr, mem.len) == -1) null;
}

/// mmap a file to memory (readonly)
pub fn mmap_file(filename: ConstStr) ?[]const u8 {
    const fd = open(filename, c.O_RDONLY | c.O_CLOEXEC, null) orelse return null;
    defer _ = close(fd);

    const size = fstat_size(fd) orelse return null;
    if (size == 0) return &[_]u8{};

    return mmap(null, size, c.PROT_READ, c.MAP_PRIVATE, fd, 0);
}

// ==============================================================

/// Initializes the wolfSSL library for use. \
/// Must be called once per application and before any other call to the library.
pub fn SSL_library_init() void {
    assert(c.wolfSSL_Init() == c.WOLFSSL_SUCCESS);
}

/// the returned string is a pointer to the static buffer
pub fn SSL_error_string(err: c_int) ConstStr {
    return switch (err) {
        c.WOLFSSL_ERROR_SYSCALL => c.strerror(errno()),
        else => c.wolfSSL_ERR_error_string(@bitCast(c_uint, err), null),
    };
}

/// client-side only
pub fn SSL_CTX_new() *c.WOLFSSL_CTX {
    const ctx = c.wolfSSL_CTX_new(c.wolfTLS_client_method()).?;

    // tls12 + tls13
    assert(c.wolfSSL_CTX_SetMinVersion(ctx, c.WOLFSSL_TLSV1_2) == 1);

    // cipher list
    // openssl has a separate API for tls13, but wolfssl only has one
    const chacha20 = "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    const aes128gcm = "TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
    const cipher_list = if (c.has_aes()) aes128gcm ++ ":" ++ chacha20 else chacha20 ++ ":" ++ aes128gcm;
    assert(c.wolfSSL_CTX_set_cipher_list(ctx, cipher_list) == 1);

    // options
    _ = c.wolfSSL_CTX_set_options(ctx, c.WOLFSSL_OP_NO_COMPRESSION | c.WOLFSSL_OP_NO_RENEGOTIATION);

    return ctx;
}

pub fn SSL_CTX_load_CA_certs(ctx: *c.WOLFSSL_CTX, path: ConstStr) ?void {
    const ok = if (is_dir(path))
        c.wolfSSL_CTX_load_verify_locations(ctx, null, path)
    else // file
        c.wolfSSL_CTX_load_verify_locations(ctx, path, null);
    return if (ok == 1) {} else null;
}

pub fn SSL_CTX_load_sys_CA_certs(ctx: *c.WOLFSSL_CTX) ?void {
    return if (c.wolfSSL_CTX_load_system_CA_certs(ctx) == 1) {} else null;
}

pub fn SSL_new(ctx: *c.WOLFSSL_CTX) *c.WOLFSSL {
    return c.wolfSSL_new(ctx).?;
}

pub fn SSL_free(ssl: *c.WOLFSSL) void {
    return c.wolfSSL_free(ssl);
}

pub fn SSL_set_fd(ssl: *c.WOLFSSL, fd: c_int) ?void {
    return if (c.wolfSSL_set_fd(ssl, fd) == 1) {} else null;
}

/// set SNI && enable cert validation during SSL handshake
pub fn SSL_set_host(ssl: *c.WOLFSSL, host: ?ConstStr, cert_verify: bool) ?void {
    if (host) |name| {
        // tls_ext: SNI (ClientHello)
        if (c.wolfSSL_UseSNI(ssl, c.WOLFSSL_SNI_HOST_NAME, name, to_ushort(c.strlen(name))) != 1)
            return null;

        // check hostname on ssl cert validation
        if (cert_verify and c.wolfSSL_check_domain_name(ssl, name) != 1)
            return null;
    }

    // ssl cert validation
    const mode = if (cert_verify) c.WOLFSSL_VERIFY_PEER else c.WOLFSSL_VERIFY_NONE;
    c.wolfSSL_set_verify(ssl, mode, null);
}

/// for SSL I/O operation
fn SSL_get_error(ssl: *c.WOLFSSL, res: c_int) c_int {
    var err = c.wolfSSL_get_error(ssl, res);
    if (err == c.SOCKET_PEER_CLOSED_E or err == c.SOCKET_ERROR_E)
        // convert to socket error (errno)
        err = if (errno() == 0) // TCP EOF
            c.WOLFSSL_ERROR_ZERO_RETURN
        else
            c.WOLFSSL_ERROR_SYSCALL;
    return err;
}

/// perform SSL/TLS handshake (underlying transport is established) \
/// `p_err`: to save the failure reason (SSL_ERROR_*)
pub fn SSL_connect(ssl: *c.WOLFSSL, p_err: *c_int) ?void {
    const res = c.wolfSSL_connect(ssl);
    if (res == 1) {
        return {};
    } else {
        p_err.* = SSL_get_error(ssl, res);
        return null;
    }
}

/// the name of the protocol used for the connection
pub fn SSL_get_version(ssl: *const c.WOLFSSL) ConstStr {
    return c.wolfSSL_get_version(ssl);
}

/// the name of the cipher used for the connection
pub fn SSL_get_cipher(ssl: *c.WOLFSSL) ConstStr {
    return c.wolfSSL_get_cipher(ssl) orelse "NULL";
}

/// return the number of bytes read (> 0) \
/// `p_err`: to save the failure reason (SSL_ERROR_*)
pub fn SSL_read(ssl: *c.WOLFSSL, buf: []u8, p_err: *c_int) ?usize {
    const res = c.wolfSSL_read(ssl, buf.ptr, to_int(buf.len));
    if (res > 0) {
        return to_usize(res);
    } else {
        p_err.* = SSL_get_error(ssl, res);
        return null;
    }
}

/// assume SSL_MODE_ENABLE_PARTIAL_WRITE is not in use \
/// `p_err`: to save the failure reason (SSL_ERROR_*)
pub fn SSL_write(ssl: *c.WOLFSSL, buf: []const u8, p_err: *c_int) ?void {
    const res = c.wolfSSL_write(ssl, buf.ptr, to_int(buf.len));
    if (res > 0) {
        return {};
    } else {
        p_err.* = SSL_get_error(ssl, res);
        return null;
    }
}

// ==============================================================

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
