const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");
const DynStr = @import("DynStr.zig");
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const dnl = @import("dnl.zig");
const co = @import("co.zig");
const g = @import("g.zig");
const server = @import("server.zig");

const Upstream = @This();

// config info
group: *const Group,

proto: Proto,
host: []const u8, // DoH
ip: []const u8,
port: u16,
path: []const u8, // DoH

url: [:0]const u8, // for printing
addr: net.Addr,

// runtime info
fdobj: ?*EvLoop.Fd = null,

pub const InProto = enum { tcp, udp };

/// send query to upstream
pub fn send(self: *Upstream, qmsg: *RcMsg, in_proto: InProto) void {
    switch (self.proto) {
        .tcp_in => if (in_proto == .tcp) self.send_tcp(qmsg),

        .tcp => self.send_tcp(qmsg),

        .udp_in => if (in_proto == .udp) self.send_udp(qmsg),

        .udp => self.send_udp(qmsg),

        .https => self.send_https(qmsg),

        else => unreachable,
    }
}

fn send_tcp(self: *Upstream, qmsg: *RcMsg) void {
    return co.create(_send_tcp, .{ self, qmsg });
}

fn _send_tcp(self: *Upstream, qmsg: *RcMsg) void {
    defer co.terminate(@frame());

    const fd = net.new_tcp_conn_sock(self.addr.family()) orelse return;

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    // must be exec before the suspend point
    _ = qmsg.ref();
    defer qmsg.unref();

    const e: struct { op: cc.ConstStr, msg: ?cc.ConstStr = null } = e: {
        g.evloop.connect(fdobj, &self.addr) orelse break :e .{ .op = "connect" };

        var iov = [_]net.iovec_t{
            .{
                .iov_base = std.mem.asBytes(&c.htons(qmsg.len)),
                .iov_len = @sizeOf(u16),
            },
            .{
                .iov_base = qmsg.msg().ptr,
                .iov_len = qmsg.len,
            },
        };
        const msg = net.msghdr_t{
            .msg_iov = &iov,
            .msg_iovlen = iov.len,
        };
        g.evloop.sendmsg(fdobj, &msg, 0) orelse break :e .{ .op = "send_query" };

        // read the len
        var rlen: u16 = undefined;
        g.evloop.recv_exactly(fdobj, std.mem.asBytes(&rlen), 0) orelse
            break :e .{ .op = "read_len", .msg = if (cc.errno() == 0) "the connection is closed" else null };

        rlen = c.ntohs(rlen);
        if (rlen == 0)
            break :e .{ .op = "read_len", .msg = "the length field is 0" };

        const rmsg = RcMsg.new(rlen);
        defer rmsg.free();

        // read the body
        rmsg.len = rlen;
        g.evloop.recv_exactly(fdobj, rmsg.msg(), 0) orelse
            break :e .{ .op = "read_body", .msg = if (cc.errno() == 0) "the connection is closed" else null };

        // send to requester
        server.on_reply(rmsg, self);

        return;
    };

    log.err(@src(), "%s(%d, '%s') failed: (%d) %m", .{ e.op, fd, self.url.ptr, cc.errno() });
}

fn send_udp(self: *Upstream, qmsg: *RcMsg) void {
    _ = qmsg;
    _ = self;
    // TODO
}

fn send_https(self: *Upstream, qmsg: *RcMsg) void {
    _ = qmsg;
    _ = self;
    // TODO
}

pub const Proto = enum {
    tcp_or_udp, // "1.1.1.1" (only for parsing)
    tcp_in, // "tcp://1.1.1.1" (enabled when the query msg is received over tcp)
    udp_in, // "udp://1.1.1.1" (enabled when the query msg is received over udp)
    tcp, // "tcp://1.1.1.1"
    udp, // "udp://1.1.1.1"
    https, // "https://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        // zig fmt: off
        const map = .{
            .{ .str = "",         .proto = .tcp_or_udp  },
            .{ .str = "tcp://",   .proto = .tcp         },
            .{ .str = "udp://",   .proto = .udp         },
            .{ .str = "https://", .proto = .https       },
        };
        // zig fmt: on
        inline for (map) |v| {
            if (std.mem.eql(u8, str, v.str))
                return v.proto;
        }
        return null;
    }

    /// "tcp://" (string literal)
    pub fn to_str(self: Proto) []const u8 {
        return switch (self) {
            .tcp_or_udp, .tcp_in, .udp_in => "",
            .tcp => "tcp://",
            .udp => "udp://",
            .https => "https://",
        };
    }

    pub fn require_host(self: Proto) bool {
        return self == .https;
    }

    pub fn require_path(self: Proto) bool {
        return self == .https;
    }

    pub fn std_port(self: Proto) u16 {
        return switch (self) {
            .https => 443,
            else => 53,
        };
    }

    pub fn is_std_port(self: Proto, port: u16) bool {
        return port == self.std_port();
    }
};

pub const Group = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},
    tag: Tag,

    pub const Tag = enum {
        china,
        trust,
    };

    pub fn init(tag: Tag) Group {
        return .{ .tag = tag };
    }

    pub inline fn items(self: *const Group) []Upstream {
        return self.list.items;
    }

    pub inline fn is_empty(self: *const Group) bool {
        return self.items().len == 0;
    }

    /// "[proto://][host@]ip[#port][path]"
    pub noinline fn add(self: *Group, in_value: []const u8) ?void {
        @setCold(true);

        var value = in_value;

        // proto
        const proto = b: {
            if (std.mem.indexOf(u8, value, "://")) |i| {
                const proto = value[0 .. i + 3];
                value = value[i + 3 ..];
                break :b Proto.from_str(proto) orelse {
                    opt.err_print(@src(), "invalid proto", proto);
                    return null;
                };
            }
            break :b Proto.tcp_or_udp;
        };

        // host, only DoH needs it
        const host = b: {
            if (std.mem.indexOf(u8, value, "@")) |i| {
                const host = value[0..i];
                value = value[i + 1 ..];
                if (host.len == 0) {
                    opt.err_print(@src(), "invalid host", host);
                    return null;
                }
                if (!proto.require_host()) {
                    opt.err_print(@src(), "no host required", host);
                    return null;
                }
                break :b host;
            }
            break :b "";
        };

        // path, only DoH needs it
        const path = b: {
            if (std.mem.indexOfScalar(u8, value, '/')) |i| {
                const path = value[i..];
                value = value[0..i];
                if (!proto.require_path()) {
                    opt.err_print(@src(), "no path required", path);
                    return null;
                }
                break :b path;
            }
            break :b "";
        };

        // port
        const port = b: {
            if (std.mem.indexOfScalar(u8, value, '#')) |i| {
                const port = value[i + 1 ..];
                value = value[0..i];
                break :b opt.check_port(port) orelse return null;
            }
            break :b proto.std_port();
        };

        // ip
        const ip = value;
        opt.check_ip(ip) orelse return null;

        if (proto == .tcp_or_udp) {
            self.do_add(.tcp_in, host, ip, port, path);
            self.do_add(.udp_in, host, ip, port, path);
        } else {
            self.do_add(proto, host, ip, port, path);
        }
    }

    noinline fn do_add(self: *Group, proto: Proto, host: []const u8, ip: []const u8, port: u16, path: []const u8) void {
        @setCold(true);

        for (self.items()) |v| {
            // zig fmt: off
            if (v.proto == proto
                and std.mem.eql(u8, v.host, host)
                and std.mem.eql(u8, v.ip, ip)
                and v.port == port
                and std.mem.eql(u8, v.path, path)) return;
            // zig fmt: on
        }

        var tmpbuf: net.IpStrBuf = undefined;

        var url = DynStr{};

        url.set_ex(&.{
            // https://
            proto.to_str(),
            // host@
            host,
            cc.b2v(host.len > 0, "@", ""),
            // ip
            ip,
            // #port
            cc.b2v(proto.is_std_port(port), "", cc.snprintf(&tmpbuf, "#%u", .{cc.to_uint(port)})),
            // path
            path,
        });

        var item = Upstream{
            .group = self,
            .proto = proto,
            .host = host,
            .ip = ip,
            .port = port,
            .path = path,
            .url = url.str,
            .addr = net.Addr.from_text(cc.strdup_r(ip, &tmpbuf).?, port),
        };

        const raw_values = .{ host, ip, path };
        const field_names = .{ "host", "ip", "path" };
        inline for (field_names) |field_name, i| {
            const raw_v = raw_values[i];
            if (raw_v.len > 0) {
                const pos = std.mem.indexOfPosLinear(u8, url.str, 0, raw_v).?;
                @field(item, field_name) = url.str[pos .. pos + raw_v.len]; // pointer to allocated memory
            } else {
                @field(item, field_name) = ""; // pointer to const string
            }
        }

        self.list.append(std.heap.raw_c_allocator, item) catch unreachable;
    }

    /// nosuspend
    pub fn send(self: *const Group, qmsg: *RcMsg, from_tcp: bool) void {
        const in_proto: InProto = if (from_tcp) .tcp else .udp;
        for (self.items()) |*upstream|
            upstream.send(qmsg, in_proto);
    }
};

pub fn @"test: Upstream api"() !void {
    // _ =
}
