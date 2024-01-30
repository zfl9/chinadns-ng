const c = @import("c.zig");
const g = @import("g.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const std = @import("std");
const trait = std.meta.trait;

pub inline fn init() void {
    return c.net_init();
}

pub inline fn ignore_sigpipe() void {
    return c.ignore_sigpipe();
}

// ===============================================================

/// ipv4/ipv6 address strbuf (char_array with sentinel 0)
pub const IpStrBuf = [c.INET6_ADDRSTRLEN - 1:0]u8;

pub const Addr = extern union {
    sa: c.struct_sockaddr,
    sin: c.struct_sockaddr_in,
    sin6: c.struct_sockaddr_in6,

    pub inline fn family(self: *const Addr) c.sa_family_t {
        return self.sa.sa_family;
    }

    pub inline fn is_sin(self: *const Addr) bool {
        return self.family() == c.AF_INET;
    }

    pub inline fn is_sin6(self: *const Addr) bool {
        return self.family() == c.AF_INET6;
    }

    pub inline fn len(self: *const Addr) c.socklen_t {
        return if (self.is_sin())
            @sizeOf(c.struct_sockaddr_in)
        else
            @sizeOf(c.struct_sockaddr_in6);
    }

    /// convert to raw c pointer (*skaddr or *const skaddr)
    pub inline fn skaddr(self: anytype) if (trait.isConstPtr(@TypeOf(self))) *const c.skaddr else *c.skaddr {
        return if (comptime trait.isConstPtr(@TypeOf(self)))
            @ptrCast(*const c.skaddr, self)
        else
            @ptrCast(*c.skaddr, self);
    }

    pub inline fn from_text(ip: cc.ConstStr, port: u16) Addr {
        var self: Addr = undefined;
        std.mem.set(u8, std.mem.asBytes(&self), 0);
        c.skaddr_from_text((&self).skaddr(), ip, port);
        return self;
    }

    pub inline fn to_text(self: *const Addr, ip: cc.Str, port: *u16) void {
        return c.skaddr_to_text(self.skaddr(), ip, port);
    }
};

// ===============================================================

/// AF_INET, AF_INET6, null(invalid)
pub inline fn get_ipstr_family(ip: cc.ConstStr) ?c.sa_family_t {
    const res = c.get_ipstr_family(ip);
    return if (res == -1) null else @intCast(c.sa_family_t, res);
}

pub inline fn new_tcp_socket(family: c.sa_family_t, for_listen: bool) c_int {
    return c.new_tcp_socket(family, for_listen, g.reuse_port);
}

pub inline fn new_udp_socket(family: c.sa_family_t, for_listen: bool) c_int {
    return c.new_udp_socket(family, for_listen, g.reuse_port);
}

pub inline fn set_reuse_port(sock: c_int) void {
    return c.set_reuse_port(sock);
}

/// create dns listen socket (tcp + udp)
pub fn new_dns_server(ip: cc.ConstStr, port: u16) [2]c_int {
    const sockaddr = Addr.from_text(ip, port);

    const tcpsock = new_tcp_socket(sockaddr.family(), true);
    const udpsock = new_udp_socket(sockaddr.family(), true);

    if (c.bind(tcpsock, &sockaddr.sa, sockaddr.len()) < 0) {
        log.err(@src(), "failed to bind tcpsock %d: (%d) %m", .{ tcpsock, cc.errno() });
        c.exit(1);
    }
    if (c.bind(udpsock, &sockaddr.sa, sockaddr.len()) < 0) {
        log.err(@src(), "failed to bind udpsock %d: (%d) %m", .{ udpsock, cc.errno() });
        c.exit(1);
    }

    // mark the socket as a listener
    if (c.listen(tcpsock, 256) < 0) {
        log.err(@src(), "failed to listen tcpsock %d: (%d) %m", .{ tcpsock, cc.errno() });
        c.exit(1);
    }

    return .{ tcpsock, udpsock };
}

// ===============================================================

pub const iovec_t = extern struct {
    iov_base: *anyopaque,
    iov_len: usize,
};

pub const msghdr_t = extern struct {
    msg_name: ?*anyopaque = null,
    msg_namelen: c.socklen_t = 0,
    msg_iov: [*]iovec_t,
    msg_iovlen: usize,
    msg_control: ?*anyopaque = null,
    msg_controllen: usize = 0,
    msg_flags: c_int = 0,
};

pub const mmsghdr_t = extern struct {
    msg_hdr: msghdr_t,
    msg_len: c_uint = undefined, // return value of recvmsg/sendmsg
};

// ===============================================================

pub inline fn recvmsg(sock: c_int, msg: *msghdr_t, flags: c_int) isize {
    return c.RECVMSG(sock, @ptrCast(*c.MSGHDR, msg), flags);
}

pub inline fn sendmsg(sock: c_int, msg: *const msghdr_t, flags: c_int) isize {
    return c.SENDMSG(sock, @ptrCast(*const c.MSGHDR, msg), flags);
}

/// return empty slice if failed
pub inline fn recvmmsg(sock: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    std.debug.assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.RECVMMSG.?(sock, vec, vlen, flags, null);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

/// return empty slice if failed
pub inline fn sendmmsg(sock: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    std.debug.assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.SENDMMSG.?(sock, vec, vlen, flags);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

// ===============================================================

pub fn @"test: net api"() !void {
    _ = recvmsg;
    _ = sendmsg;
    _ = recvmmsg;
    _ = sendmmsg;
    _ = new_udp_socket;
    _ = Addr;
    _ = Addr.family;
    _ = Addr.is_sin;
    _ = Addr.is_sin6;
    _ = Addr.len;
    _ = Addr.from_text;
    _ = Addr.to_text;
}
