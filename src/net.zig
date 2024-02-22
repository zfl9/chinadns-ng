const c = @import("c.zig");
const g = @import("g.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const std = @import("std");
const trait = std.meta.trait;
const assert = std.debug.assert;

// ===============================================================

pub inline fn init() void {
    return c.net_init();
}

// ===============================================================

/// ipv4/ipv6 address strbuf (char_array with sentinel 0)
pub const IpStrBuf = [c.INET6_ADDRSTRLEN - 1:0]u8;

pub fn get_ipstr_family(ip: cc.ConstStr) ?c.sa_family_t {
    var net_ip: [c.IPV6_BINADDR_LEN]u8 = undefined;

    if (c.inet_pton(c.AF_INET, ip, &net_ip) == 1)
        return c.AF_INET;

    if (c.inet_pton(c.AF_INET6, ip, &net_ip) == 1)
        return c.AF_INET6;

    return null;
}

// ===============================================================

pub const Addr = extern union {
    sa: c.struct_sockaddr,
    sin: c.struct_sockaddr_in,
    sin6: c.struct_sockaddr_in6,

    pub inline fn family(self: *const Addr) c.sa_family_t {
        return self.sa.sa_family;
    }

    /// sizeof(sin) or sizeof(sin6)
    pub inline fn len(self: *const Addr) c.socklen_t {
        assert(self.is_sin() or self.is_sin6());
        return if (self.is_sin())
            @sizeOf(c.struct_sockaddr_in)
        else
            @sizeOf(c.struct_sockaddr_in6);
    }

    pub inline fn is_sin(self: *const Addr) bool {
        return self.family() == c.AF_INET;
    }

    pub inline fn is_sin6(self: *const Addr) bool {
        return self.family() == c.AF_INET6;
    }

    /// assuming the `ip` and `port` are valid
    pub fn from_text(ip: cc.ConstStr, port: u16) Addr {
        var self: Addr = undefined;
        @memset(std.mem.asBytes(&self), 0, @sizeOf(Addr));

        if (get_ipstr_family(ip).? == c.AF_INET) {
            const sin = &self.sin;
            sin.sin_family = c.AF_INET;
            _ = c.inet_pton(c.AF_INET, ip, &sin.sin_addr);
            sin.sin_port = c.htons(port);
        } else {
            const sin6 = &self.sin6;
            sin6.sin6_family = c.AF_INET6;
            _ = c.inet_pton(c.AF_INET6, ip, &sin6.sin6_addr);
            sin6.sin6_port = c.htons(port);
        }

        return self;
    }

    pub fn to_text(self: *const Addr, ip: cc.Str, port: *u16) void {
        if (self.is_sin()) {
            const sin = &self.sin;
            _ = c.inet_ntop(c.AF_INET, &sin.sin_addr, ip, c.INET_ADDRSTRLEN);
            port.* = c.ntohs(sin.sin_port);
        } else {
            assert(self.is_sin6());
            const sin6 = &self.sin6;
            _ = c.inet_ntop(c.AF_INET6, &sin6.sin6_addr, ip, c.INET6_ADDRSTRLEN);
            port.* = c.ntohs(sin6.sin6_port);
        }
    }
};

// ===============================================================

pub const SockType = enum {
    tcp,
    udp,

    /// string literal
    pub fn str(self: SockType) cc.ConstStr {
        return switch (self) {
            .tcp => "tcp",
            .udp => "udp",
        };
    }

    /// c.SOCK_STREAM, c.SOCK_DGRAM
    pub fn value(self: SockType) c_int {
        return switch (self) {
            .tcp => c.SOCK_STREAM,
            .udp => c.SOCK_DGRAM,
        };
    }
};

noinline fn new_sock(family: c.sa_family_t, socktype: SockType) ?c_int {
    const fd = c.socket(family, socktype.value() | c.SOCK_NONBLOCK | c.SOCK_CLOEXEC, 0);
    if (fd == -1) {
        const str_family = if (family == c.AF_INET) "ipv4" else "ipv6";
        log.err(@src(), "socket(%s, %s) failed: (%d) %m", .{ str_family, socktype.str(), cc.errno() });
        return null;
    }
    return fd;
}

pub fn new_listen_sock(family: c.sa_family_t, socktype: SockType) ?c_int {
    const fd = new_sock(family, socktype) orelse return null;
    setup_listen_sock(fd, family);
    return fd;
}

pub fn new_tcp_conn_sock(family: c.sa_family_t) ?c_int {
    const fd = new_sock(family, .tcp) orelse return null;
    setup_tcp_conn_sock(fd);
    return fd;
}

// ===============================================================

/// `optname`: for printing
pub noinline fn getsockopt(fd: c_int, level: c_int, opt: c_int, optname: cc.ConstStr) ?c_int {
    var value: c_int = undefined;
    var valuelen: c.socklen_t = @sizeOf(c_int);
    if (c.getsockopt(fd, level, opt, &value, &valuelen) == -1) {
        log.err(@src(), "getsockopt(%d, level:%d, opt:%s) failed: (%d) %m", .{ fd, level, optname, cc.errno() });
        return null;
    }
    assert(valuelen == @sizeOf(c_int));
    return value;
}

/// `optname`: for printing
pub noinline fn setsockopt(fd: c_int, level: c_int, opt: c_int, optname: cc.ConstStr, value: c_int) ?void {
    if (c.setsockopt(fd, level, opt, &value, @sizeOf(c_int)) == -1) {
        log.err(@src(), "setsockopt(%d, level:%d, opt:%s, value:%d) failed: (%d) %m", .{ fd, level, optname, value, cc.errno() });
        return null;
    }
}

fn setup_listen_sock(fd: c_int, family: c.sa_family_t) void {
    _ = setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, "SO_REUSEADDR", 1);

    if (g.reuse_port)
        _ = setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEPORT, "SO_REUSEPORT", 1);

    if (family == c.AF_INET6)
        _ = setsockopt(fd, c.IPPROTO_IPV6, c.IPV6_V6ONLY, "IPV6_V6ONLY", 0);
}

pub fn setup_tcp_conn_sock(fd: c_int) void {
    _ = setsockopt(fd, c.IPPROTO_TCP, c.TCP_NODELAY, "TCP_NODELAY", 1);

    _ = setsockopt(fd, c.SOL_SOCKET, c.SO_KEEPALIVE, "SO_KEEPALIVE", 1);
    _ = setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPIDLE, "TCP_KEEPIDLE", 60);
    _ = setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPCNT, "TCP_KEEPCNT", 3);
    _ = setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPINTVL, "TCP_KEEPINTVL", 5);
}

// ===============================================================

pub const iovec_t = extern struct {
    iov_base: [*]u8,
    iov_len: usize,
};

pub const msghdr_t = extern struct {
    msg_name: ?*Addr = null,
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
        var remain_skip = skip_len;
        for (self.iov_items()) |*iov| {
            if (iov.iov_len == 0) continue;
            const n = std.math.min(iov.iov_len, remain_skip);
            iov.iov_base += n;
            iov.iov_len -= n;
            remain_skip -= n;
            if (remain_skip == 0) return;
        }
    }
};

pub const mmsghdr_t = extern struct {
    msg_hdr: msghdr_t,
    msg_len: c_uint = undefined, // return value of recvmsg/sendmsg
};

// ===============================================================

pub inline fn recvmsg(fd: c_int, msg: *msghdr_t, flags: c_int) isize {
    return c.RECVMSG(fd, @ptrCast(*c.MSGHDR, msg), flags);
}

pub inline fn sendmsg(fd: c_int, msg: *const msghdr_t, flags: c_int) isize {
    return c.SENDMSG(fd, @ptrCast(*const c.MSGHDR, msg), flags);
}

/// return empty slice if failed
pub inline fn recvmmsg(fd: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.RECVMMSG.?(fd, vec, vlen, flags, null);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

/// return empty slice if failed
pub inline fn sendmmsg(fd: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.SENDMMSG.?(fd, vec, vlen, flags);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

// ===============================================================

pub noinline fn getpeername(fd: c_int, addr: *Addr) ?void {
    var addrlen: c.socklen_t = @sizeOf(Addr);
    if (c.getpeername(fd, &addr.sa, &addrlen) == -1) {
        log.err(@src(), "getpeername(%d) failed: (%d) %m", .{ fd, cc.errno() });
        return null;
    }
}

pub fn sendto(fd: c_int, msg: []const u8, flags: c_int, to_addr: *const Addr) isize {
    return c.sendto(fd, msg.ptr, msg.len, flags, &to_addr.sa, to_addr.len());
}

// ===============================================================

pub fn @"test: net api"() !void {
    _ = recvmsg;
    _ = sendmsg;
    _ = recvmmsg;
    _ = sendmmsg;
    _ = Addr;
    _ = Addr.family;
    _ = Addr.len;
    _ = Addr.is_sin;
    _ = Addr.is_sin6;
    _ = Addr.from_text;
    _ = Addr.to_text;
}
