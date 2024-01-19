const c = @import("c.zig");
const cc = @import("cc.zig");
const std = @import("std");
const trait = std.meta.trait;

pub inline fn init() void {
    return c.net_init();
}

pub inline fn ignore_sigpipe() void {
    return c.ignore_sigpipe();
}

// ===============================================================

pub const SockAddr = extern union {
    sa: c.struct_sockaddr,
    sin: c.struct_sockaddr_in,
    sin6: c.struct_sockaddr_in6,

    pub inline fn family(self: *const SockAddr) c.sa_family_t {
        return self.sa.sa_family;
    }

    pub inline fn is_sin(self: *const SockAddr) bool {
        return self.family() == c.AF_INET;
    }

    pub inline fn is_sin6(self: *const SockAddr) bool {
        return self.family() == c.AF_INET6;
    }

    pub inline fn size(self: *const SockAddr) usize {
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

    pub inline fn from_text(ip: cc.ConstStr, port: u16) SockAddr {
        var self: SockAddr = undefined;
        std.mem.set(u8, std.mem.asBytes(&self), 0);
        c.skaddr_from_text((&self).skaddr(), ip, port);
        return self;
    }

    pub inline fn to_text(self: *const SockAddr, ip: cc.Str, port: *u16) void {
        return c.skaddr_to_text(self.skaddr(), ip, port);
    }
};

// ===============================================================

/// AF_INET, AF_INET6, null(invalid)
pub inline fn get_ipstr_family(ip: cc.ConstStr) ?c.sa_family_t {
    const res = c.get_ipstr_family(ip);
    return if (res == -1) null else @intCast(c.sa_family_t, res);
}

pub inline fn set_reuse_port(sockfd: c_int) void {
    return c.set_reuse_port(sockfd);
}

pub inline fn new_udp_socket(family: c.sa_family_t, for_bind: bool) c_int {
    return c.new_udp_socket(family, for_bind);
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

pub inline fn recvmsg(sockfd: c_int, msg: *msghdr_t, flags: c_int) isize {
    return c.RECVMSG(sockfd, @ptrCast(*c.MSGHDR, msg), flags);
}

pub inline fn sendmsg(sockfd: c_int, msg: *const msghdr_t, flags: c_int) isize {
    return c.SENDMSG(sockfd, @ptrCast(*const c.MSGHDR, msg), flags);
}

/// return empty slice if failed
pub inline fn recvmmsg(sockfd: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    std.debug.assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.RECVMMSG.?(sockfd, vec, vlen, flags, null);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

/// return empty slice if failed
pub inline fn sendmmsg(sockfd: c_int, msgs: []mmsghdr_t, flags: c_int) []mmsghdr_t {
    std.debug.assert(msgs.len > 0);
    const vec = @ptrCast([*]c.MMSGHDR, msgs.ptr);
    const vlen = cc.to_uint(msgs.len);
    const n = c.SENDMMSG.?(sockfd, vec, vlen, flags);
    return if (n > 0) msgs[0..cc.to_usize(n)] else msgs[0..0];
}

// ===============================================================

pub fn @"test: net api"() !void {
    _ = recvmsg;
    _ = sendmsg;
    _ = recvmmsg;
    _ = sendmmsg;
    _ = new_udp_socket;
    _ = SockAddr;
    _ = SockAddr.family;
    _ = SockAddr.is_sin;
    _ = SockAddr.is_sin6;
    _ = SockAddr.size;
    _ = SockAddr.from_text;
    _ = SockAddr.to_text;
}
