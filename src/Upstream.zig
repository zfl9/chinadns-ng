const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const co = @import("co.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");
const server = @import("server.zig");
const Tag = @import("tag.zig").Tag;
const DynStr = @import("DynStr.zig");
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const flags_op = @import("flags_op.zig");
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
ctx: ?*anyopaque = null,

// config info
host: ?cc.ConstStr, // DoT SNI
url: cc.ConstStr, // for printing
addr: cc.SockAddr,
proto: Proto,
tag: Tag,

// ======================================================

fn init(tag: Tag, proto: Proto, addr: *const cc.SockAddr, host: []const u8, ip: []const u8, port: u16) Upstream {
    const dupe_host: ?cc.ConstStr = if (host.len > 0)
        (g.allocator.dupeZ(u8, host) catch unreachable).ptr
    else
        null;

    var portbuf: [10]u8 = undefined;
    const url = cc.to_cstr_x(&.{
        // tcp://
        proto.to_str(),
        // host@
        host,
        cc.b2v(host.len > 0, "@", ""),
        // ip
        ip,
        // #port
        cc.b2v(proto.is_std_port(port), "", cc.snprintf(&portbuf, "#%u", .{cc.to_uint(port)})),
    });
    const dupe_url = (g.allocator.dupeZ(u8, cc.strslice_c(url)) catch unreachable).ptr;

    return .{
        .tag = tag,
        .proto = proto,
        .addr = addr.*,
        .host = dupe_host,
        .url = dupe_url,
    };
}

fn deinit(self: *const Upstream) void {
    assert(self.ctx == null);

    if (self.host) |host|
        g.allocator.free(cc.strslice_c(host));

    g.allocator.free(cc.strslice_c(self.url));
}

// ======================================================

fn eql(self: *const Upstream, proto: Proto, addr: *const cc.SockAddr, host: []const u8) bool {
    // zig fmt: off
    return self.proto == proto
        and self.addr.eql(addr)
        and std.mem.eql(u8, cc.strslice_c(self.host orelse ""), host);
    // zig fmt: on
}

/// [nosuspend] send query to upstream
fn send(self: *Upstream, qmsg: *RcMsg) void {
    switch (self.proto) {
        .tcpi, .tcp => self.tcp_send(qmsg),
        .udpi, .udp => self.udp_send(qmsg),
        .tls => self.tls_send(qmsg),
        else => unreachable,
    }
}

// ======================================================

fn udp_get_fdobj(self: *const Upstream) ?*EvLoop.Fd {
    assert(self.proto == .udpi or self.proto == .udp);
    return cc.ptrcast(?*EvLoop.Fd, self.ctx);
}

fn udp_set_fdobj(self: *Upstream, fdobj: ?*EvLoop.Fd) void {
    assert(self.proto == .udpi or self.proto == .udp);
    self.ctx = fdobj;
}

fn udp_send(self: *Upstream, qmsg: *RcMsg) void {
    const fd = if (self.udp_get_fdobj()) |fdobj| fdobj.fd else b: {
        const fd = net.new_sock(self.addr.family(), .udp) orelse return;
        co.create(udp_recv, .{ self, fd });
        assert(self.udp_get_fdobj() != null);
        break :b fd;
    };

    if (self.tag == .gfw and g.trustdns_packet_n > 1) {
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
    log.err(@src(), "send_query(%d, '%s') failed: (%d) %m", .{ fd, self.url, cc.errno() });
}

fn udp_recv(self: *Upstream, fd: c_int) void {
    defer co.terminate(@frame(), @frameSize(udp_recv));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    self.udp_set_fdobj(fdobj);

    var free_rmsg: ?*RcMsg = null;
    defer if (free_rmsg) |rmsg| rmsg.free();

    while (!self.udp_is_eol(fdobj)) {
        const rmsg = free_rmsg orelse RcMsg.new(c.DNS_EDNS_MAXSIZE);
        free_rmsg = null;

        defer {
            if (rmsg.is_unique())
                free_rmsg = rmsg
            else
                rmsg.unref();
        }

        const rlen = while (!self.udp_is_eol(fdobj)) {
            break cc.recv(fd, rmsg.buf(), 0) orelse {
                if (cc.errno() != c.EAGAIN) {
                    log.err(@src(), "recv(%d, '%s') failed: (%d) %m", .{ fd, self.url, cc.errno() });
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

fn udp_is_eol(self: *const Upstream, in_fdobj: *EvLoop.Fd) bool {
    return self.udp_get_fdobj() != in_fdobj;
}

fn udp_on_eol(self: *Upstream) void {
    const fdobj = self.udp_get_fdobj() orelse return;
    self.udp_set_fdobj(null); // set to null

    assert(fdobj.write_frame == null);

    // log.debug(
    //     @src(),
    //     "udp upstream socket(fd:%d, url:'%s', group:%s) is end-of-life ...",
    //     .{ fdobj.fd, self.url, @tagName(self.group.tag).ptr },
    // );

    if (fdobj.read_frame) |frame| {
        co.do_resume(frame);
    } else {
        // this coroutine may be sending a response to the tcp client (suspended)
    }
}

// ======================================================

const TcpCtx = struct {
    upstream: *const Upstream,
    fdobj: ?*EvLoop.Fd = null,
    send_list: MsgQueue = .{}, // qmsg to be sent
    ack_list: std.AutoHashMapUnmanaged(u16, *RcMsg) = .{}, // qmsg to be ack
    pending_n: u16 = 0, // outstanding queries: send_list + ack_list
    healthy: bool = false, // current connection processed at least one query ?

    /// must <= u16_max
    const PENDING_MAX = 1000;

    const MsgQueue = struct {
        head: ?*Node = null,
        tail: ?*Node = null,
        waiter: ?anyframe = null,

        const Node = struct {
            msg: *RcMsg,
            next: *Node,
        };

        /// `null`: cancel wait
        var _pushed_msg: ?*RcMsg = null;

        fn do_push(self: *MsgQueue, msg: *RcMsg, pos: enum { front, back }) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                _pushed_msg = msg;
                co.do_resume(waiter);
                return;
            }

            const node = g.allocator.create(Node) catch unreachable;
            node.* = .{
                .msg = msg,
                .next = undefined,
            };

            if (self.is_empty()) {
                self.head = node;
                self.tail = node;
            } else switch (pos) {
                .front => {
                    node.next = self.head.?;
                    self.head = node;
                },
                .back => {
                    self.tail.?.next = node;
                    self.tail = node;
                },
            }
        }

        pub fn push(self: *MsgQueue, msg: *RcMsg) void {
            return self.do_push(msg, .back);
        }

        pub fn push_front(self: *MsgQueue, msg: *RcMsg) void {
            return self.do_push(msg, .front);
        }

        /// `null`: cancel wait
        pub fn pop(self: *MsgQueue, blocking: bool) ?*RcMsg {
            if (self.head) |node| {
                defer g.allocator.destroy(node);
                if (node == self.tail) {
                    self.head = null;
                    self.tail = null;
                } else {
                    self.head = node.next;
                    assert(self.tail != null);
                }
                return node.msg;
            } else {
                if (!blocking)
                    return null;
                self.waiter = @frame();
                suspend {}
                self.waiter = null;
                return _pushed_msg;
            }
        }

        pub fn cancel_wait(self: *MsgQueue) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                _pushed_msg = null;
                co.do_resume(waiter);
            }
        }

        pub fn is_empty(self: *const MsgQueue) bool {
            return self.head == null;
        }

        /// clear && msg.unref()
        pub fn clear(self: *MsgQueue) void {
            while (self.pop(false)) |msg|
                msg.unref();
        }
    };

    pub fn new(upstream: *const Upstream) *TcpCtx {
        const self = g.allocator.create(TcpCtx) catch unreachable;
        self.* = .{
            .upstream = upstream,
        };
        return self;
    }

    /// [tcp_send] add to send queue, `qmsg.ref++`
    pub fn push_qmsg(self: *TcpCtx, qmsg: *RcMsg) void {
        if (self.pending_n >= PENDING_MAX) {
            log.warn(@src(), "too many pending queries: %u", .{cc.to_uint(self.pending_n)});
            return;
        }

        self.pending_n += 1;
        self.send_list.push(qmsg.ref());

        if (self.fdobj == null)
            self.start();
    }

    /// [async] used to send qmsg to upstream
    /// pop from send_list && add to ack_list
    fn pop_qmsg(self: *TcpCtx, in_fdobj: *EvLoop.Fd) ?*RcMsg {
        if (!self.fdobj_ok(in_fdobj)) return null;
        const qmsg = self.send_list.pop(true) orelse return null;
        self.on_sending(qmsg);
        return qmsg;
    }

    /// add qmsg to ack_list
    fn on_sending(self: *TcpCtx, qmsg: *RcMsg) void {
        const qid = dns.get_id(qmsg.msg());
        self.ack_list.putNoClobber(g.allocator, qid, qmsg) catch unreachable;
    }

    /// remove qmsg from ack_list && qmsg.unref()
    fn on_reply(self: *TcpCtx, rmsg: *const RcMsg) void {
        const qid = dns.get_id(rmsg.msg());
        if (self.ack_list.fetchRemove(qid)) |kv| {
            self.healthy = true;
            self.pending_n -= 1;
            const qmsg = kv.value;
            qmsg.unref();
        } else {
            log.warn(@src(), "unexpected msg_id:%u from %s", .{ cc.to_uint(qid), self.upstream.url });
        }
    }

    /// network/socket error
    fn on_failed(self: *TcpCtx) void {
        self.fdobj = null;
        self.send_list.cancel_wait();

        if (self.healthy) {
            self.clear_ack_list(.resend);
            if (!self.send_list.is_empty()) self.start();
        } else {
            self.clear_ack_list(.unref);
            self.send_list.clear();
            self.pending_n = 0;
        }
    }

    fn clear_ack_list(self: *TcpCtx, op: enum { resend, unref }) void {
        var it = self.ack_list.valueIterator();
        while (it.next()) |value_ptr| {
            const qmsg = value_ptr.*;
            switch (op) {
                .resend => self.send_list.push_front(qmsg),
                .unref => qmsg.unref(),
            }
        }
        self.ack_list.clearRetainingCapacity();
    }

    /// check if disconnected or reconnected
    fn fdobj_ok(self: *const TcpCtx, in_fdobj: *const EvLoop.Fd) bool {
        return in_fdobj == self.fdobj;
    }

    fn start(self: *TcpCtx) void {
        assert(self.fdobj == null);
        assert(self.pending_n > 0);
        assert(!self.send_list.is_empty());
        assert(self.ack_list.count() == 0);

        self.healthy = false;
        co.create(TcpCtx.send, .{self});
    }

    fn send(self: *TcpCtx) void {
        defer co.terminate(@frame(), @frameSize(TcpCtx.send));

        // nosuspend
        const fd = net.new_tcp_conn_sock(self.upstream.addr.family()) orelse return self.on_failed();

        const fdobj = EvLoop.Fd.new(fd);
        self.fdobj = fdobj;

        defer {
            if (self.fdobj_ok(fdobj))
                self.on_failed();
            fdobj.free();
        }

        // async
        const err: cc.ConstStr = e: {
            g.evloop.connect(fdobj, &self.upstream.addr) orelse break :e "connect";

            co.create(recv, .{self});

            while (self.pop_qmsg(fdobj)) |qmsg| {
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
                g.evloop.sendmsg(fdobj, &msg, 0) orelse break :e "send_query";
            }

            return;
        };

        log.err(@src(), "%s(%d, '%s') failed: (%d) %m", .{ err, fdobj.fd, self.upstream.url, cc.errno() });
    }

    fn recv(self: *TcpCtx) void {
        defer co.terminate(@frame(), @frameSize(recv));

        // nosuspend
        const fdobj = self.fdobj.?.ref();

        defer {
            if (self.fdobj_ok(fdobj))
                self.on_failed();
            fdobj.unref();
        }

        // async
        const err: struct { op: cc.ConstStr, msg: ?cc.ConstStr = null } = e: {
            var free_rmsg: ?*RcMsg = null;
            defer if (free_rmsg) |rmsg| rmsg.free();

            while (self.fdobj_ok(fdobj)) {
                // read the len
                var rlen: u16 = undefined;
                g.evloop.recv_exactly(fdobj, std.mem.asBytes(&rlen), 0) orelse
                    if (cc.errno() == 0) return else break :e .{ .op = "read_len" };

                rlen = cc.ntohs(rlen);
                if (rlen < c.DNS_MSG_MINSIZE)
                    break :e .{ .op = "read_len", .msg = "invalid msg len" };

                const rmsg: *RcMsg = if (free_rmsg) |rmsg| rmsg.realloc(rlen) else RcMsg.new(rlen);
                free_rmsg = null;

                defer {
                    if (rmsg.is_unique())
                        free_rmsg = rmsg
                    else
                        rmsg.unref();
                }

                // read the msg
                rmsg.len = rlen;
                g.evloop.recv_exactly(fdobj, rmsg.msg(), 0) orelse
                    break :e .{ .op = "read_msg", .msg = if (cc.errno() == 0) "connection closed" else null };

                if (self.fdobj_ok(fdobj))
                    self.on_reply(rmsg);

                server.on_reply(rmsg, self.upstream);
            }

            return;
        };

        const src = @src();
        if (err.msg) |msg|
            log.err(src, "%s(%d, '%s') failed: %s", .{ err.op, fdobj.fd, self.upstream.url, msg })
        else
            log.err(src, "%s(%d, '%s') failed: (%d) %m", .{ err.op, fdobj.fd, self.upstream.url, cc.errno() });
    }
};

fn tcp_ctx(self: *Upstream) *TcpCtx {
    assert(self.proto == .tcpi or self.proto == .tcp);
    if (self.ctx == null)
        self.ctx = TcpCtx.new(self);
    return cc.ptrcast(*TcpCtx, self.ctx.?);
}

fn tcp_send(self: *Upstream, qmsg: *RcMsg) void {
    self.tcp_ctx().push_qmsg(qmsg);
}

// ======================================================

fn tls_send(self: *Upstream, qmsg: *RcMsg) void {
    _ = qmsg;

    // TODO
    log.warn(@src(), "currently tls upstream is not supported: %s", .{self.url});
}

// ======================================================

pub const Proto = enum {
    raw, // "1.1.1.1" (tcpi + udpi) only exists in the parsing stage
    tcpi, // "tcpi://1.1.1.1" (enabled when the query msg is received over tcp)
    udpi, // "udpi://1.1.1.1" (enabled when the query msg is received over udp)

    tcp, // "tcp://1.1.1.1"
    udp, // "udp://1.1.1.1"
    tls, // "tls://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        const map = .{
            .{ .str = "tcp://", .proto = .tcp },
            .{ .str = "udp://", .proto = .udp },
            .{ .str = "tls://", .proto = .tls },
        };
        inline for (map) |v| {
            if (std.mem.eql(u8, str, v.str))
                return v.proto;
        }
        return null;
    }

    /// "tcp://" (string literal)
    pub fn to_str(self: Proto) [:0]const u8 {
        return switch (self) {
            .tcpi => "tcpi://",
            .udpi => "udpi://",
            .tcp => "tcp://",
            .udp => "udp://",
            .tls => "tls://",
            else => unreachable,
        };
    }

    pub fn require_host(self: Proto) bool {
        return self == .tls;
    }

    pub fn std_port(self: Proto) u16 {
        return switch (self) {
            .tls => 853,
            else => 53,
        };
    }

    pub fn is_std_port(self: Proto, port: u16) bool {
        return port == self.std_port();
    }
};

// ======================================================

/// for udp upstream
const UdpLife = struct {
    create_time: c.time_t = 0,
    query_count: u8 = 0,

    const LIFE_MAX = 20;
    const QUERY_MAX = 10;

    /// called before the first query
    pub fn check_eol(self: *UdpLife, now_time: c.time_t) bool {
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

    pub fn on_query(self: *UdpLife, add_count: u8) void {
        self.query_count +|= add_count;
    }
};

// ======================================================

pub const Group = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},
    udpi_life: UdpLife = .{},
    udp_life: UdpLife = .{},

    pub inline fn items(self: *const Group) []Upstream {
        return self.list.items;
    }

    pub inline fn is_empty(self: *const Group) bool {
        return self.items().len == 0;
    }

    /// assume list non-empty
    pub inline fn get_tag(self: *const Group) Tag {
        return self.items()[0].tag;
    }

    // ======================================================

    fn parse_failed(msg: [:0]const u8, value: []const u8) ?void {
        opt.print(@src(), msg, value);
        return null;
    }

    /// "[proto://][host@]ip[#port]"
    pub fn add(self: *Group, tag: Tag, in_value: []const u8) ?void {
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
            break :b Proto.raw;
        };

        // host, only DoT needs it
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

        if (proto == .raw) {
            // `bind_tcp/bind_udp` conditions can't be checked because `opt.parse()` is being executed
            self.do_add(tag, .tcpi, host, ip, port);
            self.do_add(tag, .udpi, host, ip, port);
        } else {
            self.do_add(tag, proto, host, ip, port);
        }
    }

    fn do_add(self: *Group, tag: Tag, proto: Proto, host: []const u8, ip: []const u8, port: u16) void {
        const addr = cc.SockAddr.from_text(cc.to_cstr(ip), port);

        for (self.items()) |*upstream| {
            if (upstream.eql(proto, &addr, host))
                return;
        }

        const ptr = self.list.addOne(g.allocator) catch unreachable;
        ptr.* = Upstream.init(tag, proto, &addr, host, ip, port);
    }

    pub fn rm_useless(self: *Group) void {
        @setCold(true);

        var len = self.items().len;
        while (len > 0) : (len -= 1) {
            const i = len - 1;
            const upstream = &self.items()[i];
            const rm = switch (upstream.proto) {
                .tcpi => !g.flags.has(.bind_tcp),
                .udpi => !g.flags.has(.bind_udp),
                else => continue,
            };
            if (rm) {
                upstream.deinit();
                _ = self.list.orderedRemove(i);
            }
        }
    }

    // ======================================================

    /// [nosuspend]
    pub fn send(self: *Group, qmsg: *RcMsg, flags: SendFlags) void {
        const first_query = flags.has(.first_query);
        const from_tcp = flags.has(.from_tcp);

        const verbose_info = if (g.verbose()) .{
            .qid = dns.get_id(qmsg.msg()),
            .from = cc.b2s(from_tcp, "tcp", "udp"),
        } else undefined;

        const now_time = if (first_query) cc.time() else undefined;

        var udpi_eol: ?bool = null;
        var udp_eol: ?bool = null;

        var udpi_used = false;
        var udp_used = false;

        const in_proto: Proto = if (from_tcp) .tcpi else .udpi;

        for (self.items()) |*upstream| {
            if (upstream.proto == .tcpi or upstream.proto == .udpi)
                if (upstream.proto != in_proto) continue;

            if (g.verbose())
                log.info(
                    @src(),
                    "forward query(qid:%u, from:%s) to upstream %s",
                    .{ cc.to_uint(verbose_info.qid), verbose_info.from, upstream.url },
                );

            if (upstream.proto == .udpi or upstream.proto == .udp) {
                if (upstream.proto == .udpi)
                    udpi_used = true
                else
                    udp_used = true;

                if (first_query) {
                    const eol = if (upstream.proto == .udpi)
                        udpi_eol orelse b: {
                            const eol = self.udpi_life.check_eol(now_time);
                            udpi_eol = eol;
                            break :b eol;
                        }
                    else
                        udp_eol orelse b: {
                            const eol = self.udp_life.check_eol(now_time);
                            udp_eol = eol;
                            break :b eol;
                        };

                    if (eol)
                        upstream.udp_on_eol();
                }
            }

            upstream.send(qmsg);
        }

        if (udpi_used or udp_used) {
            const add_count = if (self.get_tag() == .gfw) g.trustdns_packet_n else 1;
            if (udpi_used) self.udpi_life.on_query(add_count);
            if (udp_used) self.udp_life.on_query(add_count);
        }
    }
};

pub const SendFlags = enum(u8) {
    first_query = 1 << 0, // qctx_list: empty -> non-empty
    from_tcp = 1 << 1, // query from tcp or udp(default)
    _,
    usingnamespace flags_op.get(SendFlags);
};
