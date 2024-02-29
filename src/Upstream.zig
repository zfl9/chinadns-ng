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
const co = @import("co.zig");
const g = @import("g.zig");
const server = @import("server.zig");
const assert = std.debug.assert;

// ======================================================

comptime {
    // @compileLog("sizeof(Upstream):", @sizeOf(Upstream), "alignof(Upstream):", @alignOf(Upstream));
    // @compileLog("sizeof([]const u8):", @sizeOf([]const u8), "alignof([]const u8):", @alignOf([]const u8));
    // @compileLog("sizeof([:0]const u8):", @sizeOf([:0]const u8), "alignof([:0]const u8):", @alignOf([:0]const u8));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
    // @compileLog("sizeof(Proto):", @sizeOf(Proto), "alignof(Proto):", @alignOf(Proto));
}

const Upstream = @This();

// runtime info
fdobj: ?*EvLoop.Fd = null, // udp

// config info
group: *const Group,

host: []const u8, // DoH
path: []const u8, // DoH
url: [:0]const u8, // for printing

addr: cc.SockAddr,

proto: Proto,

// ======================================================

fn eql(self: *const Upstream, proto: Proto, addr: *const cc.SockAddr, host: []const u8, path: []const u8) bool {
    // zig fmt: off
    return self.proto == proto
        and self.addr.eql(addr)
        and std.mem.eql(u8, self.host, host)
        and std.mem.eql(u8, self.path, path);
    // zig fmt: on
}

/// for `udp` and `udp_in` upstream
fn on_eol(self: *Upstream) void {
    assert(self.proto == .udp or self.proto == .udp_in);

    const fdobj = self.fdobj orelse return;
    self.fdobj = null; // set to null

    assert(fdobj.write_frame == null);

    // test code
    // log.debug(
    //     @src(),
    //     "udp upstream socket(fd:%d, url:'%s', group:%s) is end-of-life ...",
    //     .{ fdobj.fd, self.url.ptr, @tagName(self.group.tag).ptr },
    // );

    if (fdobj.read_frame) |frame| {
        co.do_resume(frame);
    } else {
        // this coroutine may be sending a response to the tcp client (suspended)
    }
}

/// for `udp` and `udp_in` upstream
fn is_eol(self: *const Upstream, in_fdobj: *EvLoop.Fd) bool {
    return self.fdobj != in_fdobj;
}

/// [nosuspend] send query to upstream
fn send(self: *Upstream, qmsg: *RcMsg) void {
    switch (self.proto) {
        .tcp_in, .tcp => self.send_tcp(qmsg),
        .udp_in, .udp => self.send_udp(qmsg),
        .https => self.send_https(qmsg),
        else => unreachable,
    }
}

fn send_tcp(self: *Upstream, qmsg: *RcMsg) void {
    return co.create(_send_tcp, .{ self, qmsg });
}

fn _send_tcp(self: *Upstream, qmsg: *RcMsg) void {
    defer co.terminate(@frame(), @frameSize(_send_tcp));

    const fd = net.new_tcp_conn_sock(self.addr.family()) orelse return;

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    // must be exec before the suspend point
    _ = qmsg.ref();
    defer qmsg.unref();

    const e: struct { op: cc.ConstStr, msg: ?cc.ConstStr = null } = e: {
        g.evloop.connect(fdobj, &self.addr) orelse break :e .{ .op = "connect" };

        var iov = [_]cc.iovec_t{
            .{
                .iov_base = std.mem.asBytes(&cc.htons(qmsg.len)),
                .iov_len = @sizeOf(u16),
            },
            .{
                .iov_base = qmsg.msg().ptr,
                .iov_len = qmsg.len,
            },
        };
        const msg = cc.msghdr_t{
            .msg_iov = &iov,
            .msg_iovlen = iov.len,
        };
        g.evloop.sendmsg(fdobj, &msg, 0) orelse break :e .{ .op = "send_query" };

        // read the len
        var rlen: u16 = undefined;
        g.evloop.recv_exactly(fdobj, std.mem.asBytes(&rlen), 0) orelse
            break :e .{ .op = "read_len", .msg = if (cc.errno() == 0) "connection closed" else null };

        rlen = cc.ntohs(rlen);
        if (rlen == 0)
            break :e .{ .op = "read_len", .msg = "length field is 0" };

        const rmsg = RcMsg.new(rlen);
        defer rmsg.free();

        // read the msg
        rmsg.len = rlen;
        g.evloop.recv_exactly(fdobj, rmsg.msg(), 0) orelse
            break :e .{ .op = "read_msg", .msg = if (cc.errno() == 0) "connection closed" else null };

        // send to requester
        server.on_reply(rmsg, self);

        return;
    };

    const src = @src();
    if (e.msg) |msg|
        log.err(src, "%s(%d, '%s') failed: %s", .{ e.op, fd, self.url.ptr, msg })
    else
        log.err(src, "%s(%d, '%s') failed: (%d) %m", .{ e.op, fd, self.url.ptr, cc.errno() });
}

fn send_udp(self: *Upstream, qmsg: *RcMsg) void {
    const fd = if (self.fdobj) |fdobj| fdobj.fd else b: {
        const fd = net.new_sock(self.addr.family(), .udp) orelse return;
        co.create(recv_udp, .{ self, fd });
        assert(self.fdobj != null);
        break :b fd;
    };

    if (self.group.tag == .trust and g.trustdns_packet_n > 1) {
        var iov = [_]cc.iovec_t{
            .{
                .iov_base = qmsg.msg().ptr,
                .iov_len = qmsg.len,
            },
        };

        var msgv: [g.TRUSTDNS_PACKET_MAX]cc.mmsghdr_t = undefined;

        msgv[0] = .{
            .msg_hdr = .{
                .msg_name = &self.addr,
                .msg_namelen = self.addr.len(),
                .msg_iov = &iov,
                .msg_iovlen = iov.len,
            },
        };

        // repeat msg
        var i: u8 = 1;
        while (i < g.trustdns_packet_n) : (i += 1)
            msgv[i] = msgv[0];

        if (cc.sendmmsg(fd, &msgv, 0) != null) return;
    } else {
        if (cc.sendto(fd, qmsg.msg(), 0, &self.addr) != null) return;
    }

    // error handling
    log.err(@src(), "send_query(%d, '%s') failed: (%d) %m", .{ fd, self.url.ptr, cc.errno() });
}

fn recv_udp(self: *Upstream, fd: c_int) void {
    defer co.terminate(@frame(), @frameSize(recv_udp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    self.fdobj = fdobj;

    var free_rmsg: ?*RcMsg = null;
    defer if (free_rmsg) |rmsg| rmsg.free();

    while (!self.is_eol(fdobj)) {
        const rmsg = free_rmsg orelse RcMsg.new(c.DNS_EDNS_MAXSIZE);
        free_rmsg = null;

        defer {
            if (rmsg.is_unique())
                free_rmsg = rmsg
            else
                rmsg.unref();
        }

        const rlen = while (!self.is_eol(fdobj)) {
            break cc.recv(fd, rmsg.buf(), 0) orelse {
                if (cc.errno() != c.EAGAIN) {
                    log.err(@src(), "recv(%d, '%s') failed: (%d) %m", .{ fd, self.url.ptr, cc.errno() });
                    return;
                }
                g.evloop.wait_readable(fdobj);
                continue;
            };
        } else return;

        rmsg.len = cc.to_u16(rlen);

        server.on_reply(rmsg, self);
    }
}

fn send_https(self: *Upstream, qmsg: *RcMsg) void {
    _ = qmsg;

    // TODO
    log.warn(@src(), "currently https upstream is not supported: %s", .{self.url.ptr});
}

// ======================================================

pub const Proto = enum {
    tcp_or_udp, // only exists in the parsing stage
    tcp_in, // "1.1.1.1" (enabled when the query msg is received over tcp)
    udp_in, // "1.1.1.1" (enabled when the query msg is received over udp)
    tcp, // "tcp://1.1.1.1"
    udp, // "udp://1.1.1.1"
    https, // "https://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        // zig fmt: off
        const map = .{
            .{ .str = "tcp://",   .proto = .tcp   },
            .{ .str = "udp://",   .proto = .udp   },
            .{ .str = "https://", .proto = .https },
        };
        // zig fmt: on
        inline for (map) |v| {
            if (std.mem.eql(u8, str, v.str))
                return v.proto;
        }
        return null;
    }

    /// "tcp://" (string literal)
    pub fn to_str(self: Proto) [:0]const u8 {
        return switch (self) {
            .tcp_in, .udp_in => "",
            .tcp => "tcp://",
            .udp => "udp://",
            .https => "https://",
            else => unreachable,
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

// ======================================================

pub const Group = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},

    udp_life: Life = .{},
    udpin_life: Life = .{},

    tag: Tag,

    /// for udp/udp_in upstream
    const Life = struct {
        create_time: c.time_t = 0,
        query_count: u8 = 0,

        const LIFE_MAX = 20;
        const QUERY_MAX = 30;

        /// called before the first query
        pub fn check_eol(self: *Life, now_time: c.time_t) bool {
            // zig fmt: off
            const eol = self.query_count >= QUERY_MAX
                        or now_time < self.create_time
                        or now_time - self.create_time >= LIFE_MAX;
            // zig fmt: on
            if (eol) {
                self.create_time = now_time;
                self.query_count = 0;
            }
            return eol;
        }

        pub fn on_query(self: *Life, add_count: u8) void {
            self.query_count +|= add_count;
        }
    };

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

    noinline fn parse_failed(msg: [:0]const u8, value: []const u8) ?void {
        opt.err_print(@src(), msg, value);
        return null;
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
                break :b Proto.from_str(proto) orelse
                    return parse_failed("invalid proto", proto);
            }
            break :b Proto.tcp_or_udp;
        };

        // host, only DoH needs it
        const host = b: {
            if (std.mem.indexOf(u8, value, "@")) |i| {
                const host = value[0..i];
                value = value[i + 1 ..];
                if (host.len == 0)
                    return parse_failed("invalid host", host);
                if (!proto.require_host())
                    return parse_failed("no host required", host);
                break :b host;
            }
            break :b "";
        };

        // path, only DoH needs it
        const path = b: {
            if (std.mem.indexOfScalar(u8, value, '/')) |i| {
                const path = value[i..];
                value = value[0..i];
                if (!proto.require_path())
                    return parse_failed("no path required", path);
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

        var tmpbuf: cc.IpStrBuf = undefined;

        const addr = cc.SockAddr.from_text(cc.strdup_r(ip, &tmpbuf).?, port);

        for (self.items()) |*v| {
            if (v.eql(proto, &addr, host, path))
                return;
        }

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
            .addr = addr,
            .host = host,
            .path = path,
            .url = url.str,
        };

        const raw_values = .{ host, path };
        const field_names = .{ "host", "path" };
        inline for (field_names) |field_name, i| {
            const raw_v = raw_values[i];
            if (raw_v.len > 0) {
                const pos = std.mem.indexOfPosLinear(u8, url.str, 0, raw_v).?;
                @field(item, field_name) = url.str[pos .. pos + raw_v.len]; // pointer to allocated memory
            } else {
                @field(item, field_name) = ""; // pointer to const string
            }
        }

        self.list.append(g.allocator, item) catch unreachable;
    }

    /// nosuspend
    pub fn send(self: *Group, qmsg: *RcMsg, from_tcp: bool, first_query: bool) void {
        const in_proto: Proto = if (from_tcp) .tcp_in else .udp_in;

        const verbose_info = if (g.verbose) .{
            .qid = dns.get_id(qmsg.msg()),
            .from = cc.b2s(from_tcp, "tcp", "udp"),
        } else undefined;

        const now_time = cc.time();

        var udp_eol: ?bool = null;
        var udpin_eol: ?bool = null;

        var udp_touched = false;
        var udpin_touched = false;

        for (self.items()) |*upstream| {
            if (upstream.proto == .tcp_in or upstream.proto == .udp_in)
                if (in_proto != upstream.proto) continue;

            if (g.verbose)
                log.info(
                    @src(),
                    "forward query(qid:%u, from:%s) to upstream %s",
                    .{ cc.to_uint(verbose_info.qid), verbose_info.from, upstream.url.ptr },
                );

            if (first_query) {
                const eol = switch (upstream.proto) {
                    .udp => udp_eol orelse b: {
                        const eol = self.udp_life.check_eol(now_time);
                        udp_eol = eol;
                        break :b eol;
                    },
                    .udp_in => udpin_eol orelse b: {
                        const eol = self.udpin_life.check_eol(now_time);
                        udpin_eol = eol;
                        break :b eol;
                    },
                    else => false,
                };
                if (eol)
                    upstream.on_eol();
            }

            switch (upstream.proto) {
                .udp => udp_touched = true,
                .udp_in => udpin_touched = true,
                else => {},
            }

            upstream.send(qmsg);
        }

        const add_count = if (self.tag == .trust) g.trustdns_packet_n else 1;

        if (udp_touched)
            self.udp_life.on_query(add_count);

        if (udpin_touched)
            self.udpin_life.on_query(add_count);
    }
};

// ======================================================

pub fn @"test: Upstream api"() !void {
    // _ =
}
