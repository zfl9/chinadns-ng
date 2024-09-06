const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");

// ===============================================================

pub inline fn init() void {
    return c.net_init();
}

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

pub noinline fn new_sock(family: c.sa_family_t, socktype: SockType) ?c_int {
    return cc.socket(family, socktype.value() | c.SOCK_NONBLOCK | c.SOCK_CLOEXEC, 0) orelse {
        const str_family = if (family == c.AF_INET) "ipv4" else "ipv6";
        log.err(@src(), "socket(%s, %s) failed: (%d) %m", .{ str_family, socktype.str(), cc.errno() });
        return null;
    };
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
pub noinline fn getsockopt_int(fd: c_int, level: c_int, opt: c_int, optname: cc.ConstStr) ?c_int {
    return cc.getsockopt_int(fd, level, opt) orelse {
        log.err(@src(), "getsockopt(%d, level:%d, opt:%s) failed: (%d) %m", .{ fd, level, optname, cc.errno() });
        return null;
    };
}

/// `optname`: for printing
pub noinline fn setsockopt_int(fd: c_int, level: c_int, opt: c_int, optname: cc.ConstStr, value: c_int) ?void {
    return cc.setsockopt_int(fd, level, opt, value) orelse {
        log.err(@src(), "setsockopt(%d, level:%d, opt:%s, value:%d) failed: (%d) %m", .{ fd, level, optname, value, cc.errno() });
        return null;
    };
}

fn setup_listen_sock(fd: c_int, family: c.sa_family_t) void {
    _ = setsockopt_int(fd, c.SOL_SOCKET, c.SO_REUSEADDR, "SO_REUSEADDR", 1);

    if (g.flags.reuse_port)
        _ = setsockopt_int(fd, c.SOL_SOCKET, c.SO_REUSEPORT, "SO_REUSEPORT", 1);

    if (family == c.AF_INET6)
        _ = setsockopt_int(fd, c.IPPROTO_IPV6, c.IPV6_V6ONLY, "IPV6_V6ONLY", 0);
}

pub fn setup_tcp_conn_sock(fd: c_int) void {
    _ = setsockopt_int(fd, c.IPPROTO_TCP, c.TCP_NODELAY, "TCP_NODELAY", 1);

    _ = setsockopt_int(fd, c.SOL_SOCKET, c.SO_KEEPALIVE, "SO_KEEPALIVE", 1);
    _ = setsockopt_int(fd, c.IPPROTO_TCP, c.TCP_KEEPIDLE, "TCP_KEEPIDLE", 60);
    _ = setsockopt_int(fd, c.IPPROTO_TCP, c.TCP_KEEPCNT, "TCP_KEEPCNT", 3);
    _ = setsockopt_int(fd, c.IPPROTO_TCP, c.TCP_KEEPINTVL, "TCP_KEEPINTVL", 5);
}
