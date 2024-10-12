const std = @import("std");
const build_opts = @import("build_opts");
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
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const Node = @import("Node.zig");
const str2int = @import("str2int.zig");
const assert = std.debug.assert;

// ======================================================

comptime {
    // @compileLog("sizeof(Upstream):", @sizeOf(Upstream), "alignof(Upstream):", @alignOf(Upstream));
    // @compileLog("sizeof([]const u8):", @sizeOf([]const u8), "alignof([]const u8):", @alignOf([]const u8));
    // @compileLog("sizeof([:0]const u8):", @sizeOf([:0]const u8), "alignof([:0]const u8):", @alignOf([:0]const u8));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
    // @compileLog("sizeof(Proto):", @sizeOf(Proto), "alignof(Proto):", @alignOf(Proto));
    // @compileLog("sizeof(UDP):", @sizeOf(UDP), "alignof(UDP):", @alignOf(UDP));
    // @compileLog("sizeof(TCP):", @sizeOf(TCP), "alignof(TCP):", @alignOf(TCP));
}

const Upstream = @This();

// session
session: ?*anyopaque = null, // `struct UDP` or `struct TCP`

// config
host: ?cc.ConstStr, // DoT SNI
url: cc.ConstStr, // for printing
addr: cc.SockAddr,
count: ParamValue, // max queries per session (0 means no limit)
life: ParamValue, // max lifetime(sec) per session (0 means no limit)
proto: Proto,
tag: Tag,

const ParamValue = u16;
const DEFAULT_COUNT: ParamValue = 10;
const DEFAULT_LIFE: ParamValue = 10;

// ======================================================

/// for `Group.do_add` (at startup)
fn eql(self: *const Upstream, proto: Proto, addr: *const cc.SockAddr, host: []const u8) bool {
    return self.proto == proto and
        self.addr.eql(addr) and
        std.mem.eql(u8, cc.strslice_c(self.host orelse ""), host);
}

/// for `Group.do_add` (at startup)
fn init(
    tag: Tag,
    proto: Proto,
    addr: *const cc.SockAddr,
    host: []const u8,
    ip: []const u8,
    port: u16,
    count: ParamValue,
    life: ParamValue,
) Upstream {
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
        .count = count,
        .life = life,
    };
}

/// for `Group.rm_useless` (at startup)
fn deinit(self: *const Upstream) void {
    assert(self.session == null);

    if (self.host) |host|
        g.allocator.free(cc.strslice_c(host));

    g.allocator.free(cc.strslice_c(self.url));
}

// ======================================================

/// [nosuspend] send query to upstream
fn send(self: *Upstream, qmsg: *RcMsg) void {
    nosuspend switch (self.proto) {
        .udpi, .udp => if (self.udp_session()) |s| s.send_query(qmsg),
        .tcpi, .tcp, .tls => if (self.tcp_session()) |s| s.send_query(qmsg),
        else => unreachable,
    };
}

fn udp_session(self: *Upstream) ?*UDP {
    return self.get_session(UDP);
}

fn tcp_session(self: *Upstream) ?*TCP {
    return self.get_session(TCP);
}

fn get_session(self: *Upstream, comptime T: type) ?*T {
    if (self.session == null)
        self.session = T.new(self);
    return cc.ptrcast(?*T, self.session);
}

fn session_eql(self: *const Upstream, in_session: ?*const anyopaque) bool {
    return self.session == in_session;
}

// ======================================================

/// for check_timeout (response timeout)
var _session_list: Node = undefined;

pub fn module_init() void {
    _session_list.init();
}

pub fn check_timeout(timer: *EvLoop.Timer) void {
    var it = _session_list.iterator();
    while (it.next()) |node| {
        const session_node = SessionNode.from(node);
        switch (session_node.type) {
            .udp => {
                const session = session_node.udp();
                if (timer.check_deadline(session.get_deadline()))
                    session.free()
                else
                    break;
            },
            .tcp => {
                const session = session_node.tcp();
                if (timer.check_deadline(session.get_deadline()))
                    session.free()
                else
                    break;
            },
        }
    }
}

const SessionNode = struct {
    type: enum { udp, tcp }, // `struct UDP` or `struct TCP`
    node: Node = undefined, // _session_list node

    pub fn from(node: *Node) *SessionNode {
        return @fieldParentPtr(SessionNode, "node", node);
    }

    pub fn udp(self: *SessionNode) *UDP {
        assert(self.type == .udp);
        return @fieldParentPtr(UDP, "session_node", self);
    }

    pub fn tcp(self: *SessionNode) *TCP {
        assert(self.type == .tcp);
        return @fieldParentPtr(TCP, "session_node", self);
    }

    pub fn on_work(self: *SessionNode, from_idle_state: bool) void {
        if (from_idle_state)
            _session_list.link_to_tail(&self.node)
        else
            _session_list.move_to_tail(&self.node);
    }

    pub fn on_idle(self: *SessionNode) void {
        self.node.unlink();
    }
};

// ======================================================

/// udp session
const UDP = struct {
    session_node: SessionNode = .{ .type = .udp }, // _session_list node
    upstream: *Upstream,
    fdobj: *EvLoop.Fd,
    query_list: std.AutoHashMapUnmanaged(u16, void) = .{}, // outstanding queries (qid)
    create_time: u64,
    query_time: u64 = undefined, // last query time
    query_count: u16 = 0, // total query count
    freed: bool = false,

    pub fn new(upstream: *Upstream) ?*UDP {
        const fd = net.new_sock(upstream.addr.family(), .udp) orelse return null;
        const self = g.allocator.create(UDP) catch unreachable;
        self.* = .{
            .upstream = upstream,
            .fdobj = EvLoop.Fd.new(fd),
            .create_time = g.evloop.time,
        };
        return self;
    }

    /// call path:
    /// - reply_receiver
    /// - check_timeout
    fn free(self: *UDP) void {
        if (self.freed) return;
        self.freed = true;

        if (!self.is_idle())
            self.session_node.on_idle();

        if (self.upstream.session_eql(self))
            self.upstream.session = null;

        self.fdobj.cancel();
        self.fdobj.free();

        self.query_list.clearAndFree(g.allocator);

        g.allocator.destroy(self);
    }

    pub fn get_deadline(self: *const UDP) u64 {
        assert(!self.is_idle());
        return self.query_time + cc.to_u64(g.upstream_timeout) * 1000;
    }

    /// [nosuspend]
    pub fn send_query(self: *UDP, qmsg: *RcMsg) void {
        if (self.is_retire()) {
            const new_session = new(self.upstream);
            self.upstream.session = new_session;

            if (new_session) |s|
                nosuspend s.send_query(qmsg);

            if (self.is_idle())
                self.free();

            return;
        }

        if (self.upstream.tag == .gfw and g.trustdns_packet_n > 1) {
            var iov = [_]cc.iovec_t{
                .{
                    .iov_base = qmsg.msg().ptr,
                    .iov_len = qmsg.len,
                },
            };

            var msgv: [g.TRUSTDNS_PACKET_MAX]cc.mmsghdr_t = undefined;

            msgv[0] = .{
                .msg_hdr = .{
                    .msg_name = &self.upstream.addr,
                    .msg_namelen = self.upstream.addr.len(),
                    .msg_iov = &iov,
                    .msg_iovlen = iov.len,
                },
            };

            // repeat msg
            var i: u8 = 1;
            while (i < g.trustdns_packet_n) : (i += 1)
                msgv[i] = msgv[0];

            _ = cc.sendmmsg(self.fdobj.fd, &msgv, 0) orelse self.on_error("send");
        } else {
            _ = cc.sendto(self.fdobj.fd, qmsg.msg(), 0, &self.upstream.addr) orelse self.on_error("send");
        }

        self.session_node.on_work(self.is_idle());

        self.query_list.put(g.allocator, dns.get_id(qmsg.msg()), {}) catch unreachable;
        self.query_time = g.evloop.time;
        self.query_count +|= 1;

        // start recv coroutine, must be at the end
        if (self.query_count == 1)
            co.start(reply_receiver, .{self}); // may call self.free()
    }

    /// no outstanding queries
    fn is_idle(self: *const UDP) bool {
        return self.query_list.count() == 0;
    }

    /// no more queries will be sent. \
    /// freed when the queries completes.
    fn is_retire(self: *const UDP) bool {
        if (!self.upstream.session_eql(self))
            return true;

        if ((self.upstream.count > 0 and self.query_count >= self.upstream.count) or
            (self.upstream.life > 0 and g.evloop.time >= self.create_time + cc.to_u64(self.upstream.life) * 1000))
        {
            self.upstream.session = null;
            return true;
        }

        return false;
    }

    fn reply_receiver(self: *UDP) void {
        defer co.terminate(@frame(), @frameSize(reply_receiver));

        defer self.free();

        var free_rmsg: ?*RcMsg = null;
        defer if (free_rmsg) |rmsg| rmsg.free();

        while (true) {
            const rmsg = free_rmsg orelse RcMsg.new(c.DNS_EDNS_MAXSIZE);
            free_rmsg = null;

            defer {
                if (rmsg.is_unique())
                    free_rmsg = rmsg
                else
                    rmsg.unref();
            }

            const len = g.evloop.read_udp(self.fdobj, rmsg.buf(), null) orelse return self.on_error("recv");
            rmsg.len = cc.to_u16(len);

            const prev_idle = self.is_idle();

            // update query_list
            if (len >= dns.header_len()) {
                const qid = dns.get_id(rmsg.msg());
                _ = self.query_list.remove(qid);
            }

            // will modify the msg.id
            nosuspend server.on_reply(rmsg, self.upstream);

            // all queries completed
            if (self.is_idle()) {
                if (!prev_idle)
                    self.session_node.on_idle();

                if (self.is_retire())
                    return; // free
            }
        }
    }

    fn on_error(self: *const UDP, op: cc.ConstStr) void {
        if (!self.fdobj.canceled)
            log.warn(@src(), "%s(%s) failed: (%d) %m", .{ op, self.upstream.url, cc.errno() });
    }
};

// ======================================================

pub const has_tls = build_opts.enable_wolfssl;

pub const TLS = struct {
    ssl: ?*c.WOLFSSL = null,

    var _ctx: ?*c.WOLFSSL_CTX = null;

    /// called at startup
    pub fn init() void {
        if (_ctx != null) return;

        cc.SSL_library_init();

        const ctx = cc.SSL_CTX_new();
        _ctx = ctx;

        if (g.cert_verify) {
            const src = @src();
            if (g.ca_certs.is_null())
                cc.SSL_CTX_load_sys_CA_certs(ctx) orelse {
                    log.err(src, "failed to load system CA certs, please provide --ca-certs", .{});
                    cc.exit(1);
                }
            else
                cc.SSL_CTX_load_CA_certs(ctx, g.ca_certs.cstr()) orelse {
                    log.err(src, "failed to load CA certs: %s", .{g.ca_certs.cstr()});
                    cc.exit(1);
                };
        }
    }

    pub fn new_ssl(self: *TLS, fd: c_int, host: ?cc.ConstStr) ?void {
        assert(self.ssl == null);

        const ssl = cc.SSL_new(_ctx.?);

        var ok = false;
        defer if (!ok) cc.SSL_free(ssl);

        cc.SSL_set_fd(ssl, fd) orelse return null;
        cc.SSL_set_host(ssl, host, g.cert_verify) orelse return null;

        ok = true;
        self.ssl = ssl;
    }

    // free the ssl obj
    pub fn on_close(self: *TLS) void {
        const ssl = self.ssl orelse return;
        self.ssl = null;

        cc.SSL_free(ssl);
    }
};

/// tcp/tls session
const TCP = struct {
    session_node: SessionNode = .{ .type = .tcp }, // _session_list node
    upstream: *Upstream,
    fdobj: ?*EvLoop.Fd = null, // tcp connection
    tls: TLS_ = .{}, // tls connection (DoT)
    send_list: MsgQueue = .{}, // qmsg to be sent
    ack_list: std.AutoHashMapUnmanaged(u16, *RcMsg) = .{}, // qmsg to be ack
    create_time: u64, // last connect time
    query_time: u64 = undefined, // last query time
    query_count: u16 = 0, // total query count
    pending_n: u16 = 0, // outstanding queries: send_list + ack_list
    flags: packed struct {
        freed: bool = false, // free()
        starting: bool = false, // start()
        stopping: bool = false, // stop()
        in_sender: bool = false, // query_sender()
    } = .{},

    const TLS_ = if (has_tls) TLS else struct {};

    /// must <= u16_max
    const PENDING_MAX = std.math.maxInt(u16);

    const MsgQueue = struct {
        head: ?*Msg = null,
        tail: ?*Msg = null,
        waiter: ?anyframe = null,

        const Msg = struct {
            msg: *RcMsg,
            next: *Msg,
        };

        fn co_data() *?*RcMsg {
            return co.data(?*RcMsg);
        }

        fn do_push(self: *MsgQueue, msg: *RcMsg, pos: enum { front, back }) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                co_data().* = msg;
                co.do_resume(waiter);
                return;
            }

            const node = g.allocator.create(Msg) catch unreachable;
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
        pub fn pop(self: *MsgQueue, comptime suspending: bool) ?*RcMsg {
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
                if (!suspending)
                    return null;
                self.waiter = @frame();
                suspend {}
                self.waiter = null;
                return co_data().*;
            }
        }

        pub fn cancel_wait(self: *const MsgQueue) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                co_data().* = null;
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

    pub fn new(upstream: *Upstream) *TCP {
        const self = g.allocator.create(TCP) catch unreachable;
        self.* = .{
            .upstream = upstream,
            .create_time = g.evloop.time,
        };
        return self;
    }

    pub fn free(self: *TCP) void {
        if (self.flags.freed) return;
        self.flags.freed = true;

        if (!self.is_idle())
            self.session_node.on_idle();

        if (self.upstream.session_eql(self))
            self.upstream.session = null;

        self.send_list.cancel_wait();

        if (self.fdobj) |fdobj| {
            fdobj.cancel();
            fdobj.free();
            self.fdobj = null;
        }

        if (has_tls)
            self.tls.on_close();

        self.send_list.clear();
        self.clear_ack_list(.unref);
        self.ack_list.clearAndFree(g.allocator);

        g.allocator.destroy(self);
    }

    pub fn get_deadline(self: *const TCP) u64 {
        assert(!self.is_idle());
        return self.query_time + cc.to_u64(g.upstream_timeout) * 1000;
    }

    /// no outstanding queries
    fn is_idle(self: *const TCP) bool {
        return self.pending_n == 0;
    }

    /// no more queries will be sent. \
    /// freed when the queries completes.
    fn is_retire(self: *const TCP) bool {
        if (!self.upstream.session_eql(self))
            return true;

        if ((self.upstream.count > 0 and self.query_count >= self.upstream.count) or
            (self.upstream.life > 0 and g.evloop.time >= self.create_time + cc.to_u64(self.upstream.life) * 1000))
        {
            self.upstream.session = null;
            return true;
        }

        return false;
    }

    /// add to send queue, `qmsg.ref++`
    pub fn send_query(self: *TCP, qmsg: *RcMsg) void {
        if (self.is_retire()) {
            const new_session = new(self.upstream);
            self.upstream.session = new_session;

            nosuspend new_session.send_query(qmsg);

            if (self.is_idle())
                self.free();

            return;
        }

        if (self.pending_n >= PENDING_MAX) {
            log.warn(@src(), "too many pending queries: %u", .{cc.to_uint(self.pending_n)});
            return;
        }

        self.session_node.on_work(self.is_idle());

        self.pending_n += 1;
        self.send_list.push(qmsg.ref());

        self.query_time = g.evloop.time;
        self.query_count +|= 1;

        // must be at the end
        if (self.fdobj == null)
            self.start();
    }

    /// [suspending] pop from send_list && add to ack_list
    fn pop_qmsg(self: *TCP) ?*RcMsg {
        const qmsg = self.send_list.pop(true) orelse return null;
        self.on_send_msg(qmsg);
        return qmsg;
    }

    /// add qmsg to ack_list
    fn on_send_msg(self: *TCP, qmsg: *RcMsg) void {
        const qid = dns.get_id(qmsg.msg());
        if (self.ack_list.fetchPut(g.allocator, qid, qmsg) catch unreachable) |old| {
            old.value.unref();
            self.pending_n -= 1;
            assert(self.pending_n > 0);
            log.warn(@src(), "duplicated qid:%u to %s", .{ cc.to_uint(qid), self.upstream.url });
        }
    }

    /// remove qmsg from ack_list && qmsg.unref()
    fn on_recv_msg(self: *TCP, rmsg: *const RcMsg) void {
        const qid = dns.get_id(rmsg.msg());
        if (self.ack_list.fetchRemove(qid)) |kv| {
            self.pending_n -= 1;
            kv.value.unref();
        } else {
            log.warn(@src(), "unexpected msg_id:%u from %s", .{ cc.to_uint(qid), self.upstream.url });
        }
    }

    fn stop(self: *TCP) void {
        if (self.flags.in_sender) {
            self.flags.stopping = true;
            return;
        }

        if (self.flags.stopping or self.flags.freed)
            return;

        {
            // cleanup
            self.flags.stopping = true;
            defer self.flags.stopping = false;

            self.send_list.cancel_wait();

            if (self.fdobj) |fdobj| {
                fdobj.cancel();
                fdobj.free();
                self.fdobj = null;
            }

            if (has_tls)
                self.tls.on_close();
        }

        if (self.pending_n > 0) {
            if (!self.flags.starting) {
                // restart
                self.clear_ack_list(.resend);
                self.start(); // must be at the end
            } else {
                // local error
                self.clear_ack_list(.unref);
                self.send_list.clear();
                self.pending_n = 0;
                self.session_node.on_idle();
            }
        } else {
            // idle
            if (!self.flags.starting and self.is_retire())
                self.free();
        }
    }

    fn clear_ack_list(self: *TCP, op: enum { resend, unref }) void {
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

    /// may call `self.free()`
    fn start(self: *TCP) void {
        assert(self.fdobj == null);
        assert(self.pending_n > 0);
        assert(!self.send_list.is_empty());
        assert(self.ack_list.count() == 0);

        self.create_time = g.evloop.time;

        self.flags.starting = true;
        co.start(query_sender, .{self});
        self.flags.starting = false;

        if (self.is_idle() and self.is_retire())
            self.free();
    }

    fn query_sender(self: *TCP) void {
        defer co.terminate(@frame(), @frameSize(query_sender));

        defer self.stop();

        const fd = net.new_tcp_conn_sock(self.upstream.addr.family()) orelse return;
        self.fdobj = EvLoop.Fd.new(fd);

        self.connect() orelse return;

        self.flags.in_sender = true;
        co.start(reply_receiver, .{self});
        self.flags.in_sender = false;

        if (self.flags.stopping) {
            self.flags.stopping = false;
            return; // do stop()
        }

        while (self.pop_qmsg()) |qmsg|
            self.send(qmsg) orelse return;
    }

    fn reply_receiver(self: *TCP) void {
        defer co.terminate(@frame(), @frameSize(reply_receiver));

        defer self.stop();

        var free_rmsg: ?*RcMsg = null;
        defer if (free_rmsg) |rmsg| rmsg.free();

        while (true) {
            // read the len
            var len: u16 = undefined;
            self.recv(std.mem.asBytes(&len)) orelse return;

            // check the len
            len = cc.ntohs(len);
            if (len < dns.header_len()) {
                log.warn(@src(), "recv(%s) failed: invalid len:%u", .{ self.upstream.url, cc.to_uint(len) });
                return;
            }

            const rmsg: *RcMsg = if (free_rmsg) |rmsg| rmsg.realloc(len) else RcMsg.new(len);
            free_rmsg = null;

            defer {
                if (rmsg.is_unique())
                    free_rmsg = rmsg
                else
                    rmsg.unref();
            }

            // read the msg
            rmsg.len = len;
            self.recv(rmsg.msg()) orelse return;

            const prev_idle = self.is_idle();

            // update ack_list
            self.on_recv_msg(rmsg);

            // will modify the msg.id
            nosuspend server.on_reply(rmsg, self.upstream);

            // all queries completed
            if (self.is_idle()) {
                if (!prev_idle)
                    self.session_node.on_idle();

                if (self.is_retire())
                    return; // stop and free
            }
        }
    }

    /// `errmsg`: null means strerror(errno)
    fn on_error(self: *const TCP, op: cc.ConstStr, errmsg: ?cc.ConstStr) ?void {
        const src = @src();

        if (self.fdobj.?.canceled)
            return null;

        if (errmsg) |msg|
            log.warn(src, "%s(%s) failed: %s", .{ op, self.upstream.url, msg })
        else
            log.warn(src, "%s(%s) failed: (%d) %m", .{ op, self.upstream.url, cc.errno() });

        return null;
    }

    fn ssl(self: *const TCP) *c.WOLFSSL {
        return self.tls.ssl.?;
    }

    fn connect(self: *TCP) ?void {
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;
            g.evloop.connect(fdobj, &self.upstream.addr) orelse break :e null;

            if (has_tls and self.upstream.proto == .tls) {
                self.tls.new_ssl(fdobj.fd, self.upstream.host) orelse break :e "unable to create ssl object";

                while (true) {
                    var err: c_int = undefined;
                    cc.SSL_connect(self.ssl(), &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_WANT_READ => {
                            g.evloop.wait_readable(fdobj) orelse return null;
                            continue;
                        },
                        c.WOLFSSL_ERROR_WANT_WRITE => {
                            g.evloop.wait_writable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    break;
                }

                if (g.verbose())
                    log.info(@src(), "%s | %s | %s", .{
                        self.upstream.url,
                        cc.SSL_get_version(self.ssl()),
                        cc.SSL_get_cipher(self.ssl()),
                    });
            }

            return;
        };

        return self.on_error("connect", errmsg);
    }

    fn send(self: *TCP, qmsg: *RcMsg) ?void {
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;

            if (self.upstream.proto != .tls) {
                var iovec = [_]cc.iovec_t{
                    .{
                        .iov_base = std.mem.asBytes(&cc.htons(qmsg.len)),
                        .iov_len = @sizeOf(u16),
                    },
                    .{
                        .iov_base = qmsg.msg().ptr,
                        .iov_len = qmsg.len,
                    },
                };
                g.evloop.writev(fdobj, &iovec) orelse break :e null;
            } else if (has_tls) {
                // merge into one ssl record
                var buf: [2 + c.DNS_QMSG_MAXSIZE]u8 align(2) = undefined;
                const data = buf[0 .. 2 + qmsg.len];
                std.mem.bytesAsValue(u16, data[0..2]).* = cc.htons(qmsg.len);
                @memcpy(data[2..].ptr, qmsg.msg().ptr, qmsg.len);

                while (true) {
                    var err: c_int = undefined;
                    cc.SSL_write(self.ssl(), data, &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_WANT_WRITE => {
                            g.evloop.wait_writable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    break;
                }
            } else unreachable;

            return;
        };

        return self.on_error("send", errmsg);
    }

    /// read the `buf` full
    fn recv(self: *TCP, buf: []u8) ?void {
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;

            if (self.upstream.proto != .tls) {
                g.evloop.read(fdobj, buf) catch |err| switch (err) {
                    error.eof => return null,
                    error.errno => break :e null,
                };
            } else if (has_tls) {
                var nread: usize = 0;
                while (nread < buf.len) {
                    var err: c_int = undefined;
                    const n = cc.SSL_read(self.ssl(), buf[nread..], &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_ZERO_RETURN => { // TLS EOF
                            return null;
                        },
                        c.WOLFSSL_ERROR_WANT_READ => {
                            g.evloop.wait_readable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    nread += n;
                }
            } else unreachable;

            return;
        };

        return self.on_error("recv", errmsg);
    }
};

// ======================================================

pub const Proto = enum {
    raw, // "1.1.1.1" (tcpi + udpi) only exists in the parsing stage
    udpi, // "udpi://1.1.1.1" (enabled when the query msg is received over udp)
    tcpi, // "tcpi://1.1.1.1" (enabled when the query msg is received over tcp)

    udp, // "udp://1.1.1.1"
    tcp, // "tcp://1.1.1.1"
    tls, // "tls://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        const map = if (has_tls) .{
            .{ .str = "udp://", .proto = .udp },
            .{ .str = "tcp://", .proto = .tcp },
            .{ .str = "tls://", .proto = .tls },
        } else .{
            .{ .str = "udp://", .proto = .udp },
            .{ .str = "tcp://", .proto = .tcp },
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
            .udpi => "udpi://",
            .tcpi => "tcpi://",
            .udp => "udp://",
            .tcp => "tcp://",
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

pub const Group = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},

    pub inline fn items(self: *const Group) []Upstream {
        return self.list.items;
    }

    pub inline fn is_empty(self: *const Group) bool {
        return self.items().len == 0;
    }

    // ======================================================

    fn parse_failed(msg: [:0]const u8, value: []const u8) ?void {
        opt.print(@src(), msg, value);
        return null;
    }

    /// "[proto://][host@]ip[#port][?count=N][?life=N]"
    pub fn add(self: *Group, tag: Tag, url: []const u8) ?void {
        @setCold(true);

        var rest = url;

        // proto
        const proto = b: {
            if (std.mem.indexOf(u8, rest, "://")) |i| {
                const proto = rest[0 .. i + 3];
                rest = rest[i + 3 ..];
                break :b Proto.from_str(proto) orelse
                    return parse_failed("invalid proto", proto);
            }
            break :b Proto.raw;
        };

        // host, only DoT needs it
        const host = b: {
            if (std.mem.indexOf(u8, rest, "@")) |i| {
                const host = rest[0..i];
                rest = rest[i + 1 ..];
                if (host.len == 0)
                    return parse_failed("invalid host", host);
                if (!proto.require_host())
                    return parse_failed("no host required", host);
                break :b host;
            }
            break :b "";
        };

        var count = DEFAULT_COUNT;
        var life = DEFAULT_LIFE;

        // ?param=value
        while (std.mem.lastIndexOfScalar(u8, rest, '?')) |i| {
            const name_value = rest[i + 1 ..];
            rest = rest[0..i];
            const sep = std.mem.indexOfScalar(u8, name_value, '=') orelse
                return parse_failed("invalid param format", name_value);
            const name = name_value[0..sep];
            const value_str = name_value[sep + 1 ..];
            const value_int = str2int.parse(ParamValue, value_str, 10) orelse
                return parse_failed("invalid param value", name_value);
            if (std.mem.eql(u8, name, "count")) {
                count = value_int;
            } else if (std.mem.eql(u8, name, "life")) {
                life = value_int;
            } else {
                return parse_failed("unknown param name", name_value);
            }
        }

        // port
        const port = b: {
            if (std.mem.lastIndexOfScalar(u8, rest, '#')) |i| {
                const port = rest[i + 1 ..];
                rest = rest[0..i];
                break :b opt.check_port(port) orelse return null;
            }
            break :b proto.std_port();
        };

        // ip
        const ip = rest;
        opt.check_ip(ip) orelse return null;

        if (proto == .raw) {
            // `bind_tcp/bind_udp` conditions can't be checked because `opt.parse()` is being executed
            self.do_add(tag, .udpi, host, ip, port, count, life);
            self.do_add(tag, .tcpi, host, ip, port, count, life);
        } else {
            self.do_add(tag, proto, host, ip, port, count, life);
        }
    }

    fn do_add(
        self: *Group,
        tag: Tag,
        proto: Proto,
        host: []const u8,
        ip: []const u8,
        port: u16,
        count: ParamValue,
        life: ParamValue,
    ) void {
        const addr = cc.SockAddr.from_text(cc.to_cstr(ip), port);

        for (self.items()) |*upstream| {
            if (upstream.eql(proto, &addr, host)) {
                upstream.count = count;
                upstream.life = life;
                return;
            }
        }

        const ptr = self.list.addOne(g.allocator) catch unreachable;
        ptr.* = Upstream.init(tag, proto, &addr, host, ip, port, count, life);
    }

    pub fn rm_useless(self: *Group) void {
        @setCold(true);

        var has_udpi = false;
        var has_tcpi = false;
        for (g.bind_ports) |p| {
            if (p.udp) has_udpi = true;
            if (p.tcp) has_tcpi = true;
        }

        var len = self.items().len;
        while (len > 0) : (len -= 1) {
            const i = len - 1;
            const upstream = &self.items()[i];
            const rm = switch (upstream.proto) {
                .udpi => !has_udpi,
                .tcpi => !has_tcpi,
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
    pub fn send(self: *Group, qmsg: *RcMsg, udpi: bool) void {
        const verbose_info = if (g.verbose()) .{
            .qid = dns.get_id(qmsg.msg()),
            .from = cc.b2s(udpi, "udp", "tcp"),
        } else undefined;

        const in_proto: Proto = if (udpi) .udpi else .tcpi;

        for (self.items()) |*upstream| {
            if (upstream.proto == .udpi or upstream.proto == .tcpi)
                if (upstream.proto != in_proto) continue;

            if (g.verbose())
                log.info(
                    @src(),
                    "forward query(qid:%u, from:%s) to upstream %s",
                    .{ cc.to_uint(verbose_info.qid), verbose_info.from, upstream.url },
                );

            nosuspend upstream.send(qmsg);
        }
    }
};
