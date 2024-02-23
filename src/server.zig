const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const heap = std.heap;
const assert = std.debug.assert;

const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const net = @import("net.zig");
const dnl = @import("dnl.zig");
const dns = @import("dns.zig");
const Upstream = @import("Upstream.zig");
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const NoAAAA = @import("NoAAAA.zig");
const co = @import("co.zig");

const QueryCtx = struct {
    qid: u16,
    id: c.be16, // original id
    fdobj: *EvLoop.Fd, // requester's fdobj
    src_addr: net.Addr, // udp requester's sock_addr (`sa_family == 0` means tcp)
    req_time: c.time_t,
    name_tag: dnl.Tag,
    china_got: bool = false,
    trust_msg: ?*RcMsg = null,

    // linked list
    prev: ?*QueryCtx = null,
    next: ?*QueryCtx = null,

    fn new(qid: u16, id: c.be16, fdobj: *EvLoop.Fd, src_addr: ?*const net.Addr, name_tag: dnl.Tag) *QueryCtx {
        const self = g.allocator.create(QueryCtx) catch unreachable;
        self.* = .{
            .qid = qid,
            .id = id,
            .fdobj = fdobj.ref(),
            .src_addr = undefined,
            .req_time = cc.time(),
            .name_tag = name_tag,
        };
        if (src_addr) |p| // udp
            self.src_addr = p.*
        else // tcp
            self.src_addr.sa.sa_family = 0;
        return self;
    }

    fn free(self: *const QueryCtx) void {
        self.fdobj.unref();
        if (self.trust_msg) |msg| {
            assert(msg.is_unique());
            msg.unref();
        }
        g.allocator.destroy(self);
    }

    pub fn is_from_tcp(self: *const QueryCtx) bool {
        return self.src_addr.sa.sa_family == 0;
    }

    pub const List = struct {
        map: std.AutoHashMapUnmanaged(u16, *QueryCtx) = .{},

        // linked list
        head: ?*QueryCtx = null,
        tail: ?*QueryCtx = null,

        var _last_qid: u16 = 0;

        pub fn len(self: *const List) usize {
            return self.map.count();
        }

        fn link(self: *List, qctx: *QueryCtx) void {
            qctx.prev = self.tail;
            qctx.next = null;

            if (self.tail) |tail| {
                assert(self.head != null);
                tail.next = qctx;
                self.tail = qctx;
            } else {
                assert(self.head == null);
                self.head = qctx;
                self.tail = qctx;
            }
        }

        fn unlink(self: *List, qctx: *const QueryCtx) void {
            if (qctx.prev) |prev| {
                prev.next = qctx.next;
            } else {
                assert(qctx == self.head);
                self.head = qctx.next;
            }

            if (qctx.next) |next| {
                next.prev = qctx.prev;
            } else {
                assert(qctx == self.tail);
                self.tail = qctx.prev;
            }
        }

        /// [on_query] msg.id => qid
        pub fn add(self: *List, msg: []u8, fdobj: *EvLoop.Fd, src_addr: ?*const net.Addr, name_tag: dnl.Tag) ?*QueryCtx {
            if (self.len() >= std.math.maxInt(u16) + 1) {
                log.err(@src(), "too many pending requests: %zu", .{self.len()});
                return null;
            }

            _last_qid +%= 1;
            const qid = _last_qid;

            const id = dns.get_id(msg);
            dns.set_id(msg, qid);

            const qctx = QueryCtx.new(qid, id, fdobj, src_addr, name_tag);
            self.map.putNoClobber(heap.raw_c_allocator, qid, qctx) catch unreachable;
            self.link(qctx);
            return qctx;
        }

        /// [on_reply] msg.id => original_id
        pub fn get(self: *const List, msg: []u8) ?*QueryCtx {
            const qid = dns.get_id(msg);
            const qctx = self.map.get(qid) orelse return null;
            dns.set_id(msg, qctx.id);
            return qctx;
        }

        /// remove from list and free(qctx)
        pub fn del(self: *List, qctx: *const QueryCtx) void {
            self.unlink(qctx);
            assert(self.map.remove(qctx.qid));
            qctx.free();
        }

        /// in insertion order, it is safe to `del` the current element
        pub fn iterator(self: *const List) Iterator {
            return .{ .elem = self.head };
        }

        pub const Iterator = struct {
            elem: ?*QueryCtx,

            pub fn next(it: *Iterator) ?*QueryCtx {
                const elem = it.elem orelse return null;
                defer it.elem = elem.next;
                return elem;
            }
        };
    };
};

/// qid => *query_ctx
var _qctx_list: QueryCtx.List = .{};

// =======================================================================================================

fn listen_tcp(fd: c_int, ip: cc.ConstStr) void {
    defer co.terminate(@frame(), @frameSize(listen_tcp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    while (true) {
        var src_addr: net.Addr = undefined;
        const conn_fd = g.evloop.accept(fdobj, &src_addr) orelse {
            log.err(@src(), "accept(fd:%d, %s#%u) failed: (%d) %m", .{ fd, ip, cc.to_uint(g.bind_port), cc.errno() });
            continue;
        };
        net.setup_tcp_conn_sock(conn_fd);
        co.create(service_tcp, .{ conn_fd, &src_addr });
    }
}

fn service_tcp(fd: c_int, p_src_addr: *const net.Addr) void {
    defer co.terminate(@frame(), @frameSize(service_tcp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    // copy to local variable
    const src_addr = p_src_addr.*;

    var ip: net.IpStrBuf = undefined;
    var port: u16 = undefined;
    if (g.verbose) src_addr.to_text(&ip, &port);

    if (g.verbose) log.info(@src(), "new connection:%d from %s#%u", .{ fd, &ip, cc.to_uint(port) });
    defer if (g.verbose) log.info(@src(), "close connection:%d from %s#%u", .{ fd, &ip, cc.to_uint(port) });

    const e: struct { op: cc.ConstStr, msg: ?cc.ConstStr = null } = e: {
        var free_qmsg: ?*RcMsg = null;
        defer if (free_qmsg) |qmsg| qmsg.free();

        while (true) {
            // read len (be16)
            var len: u16 = undefined;
            g.evloop.recv_exactly(fdobj, std.mem.asBytes(&len), 0) orelse
                if (cc.errno() == 0) return else break :e .{ .op = "read_len" };

            len = c.ntohs(len);
            if (len < c.DNS_MSG_MINSIZE or len > c.DNS_QMSG_MAXSIZE) {
                log.err(@src(), "invalid query_msg length: %u", .{cc.to_uint(len)});
                break :e .{ .op = "read_len", .msg = "invalid query_msg length" };
            }

            const qmsg = free_qmsg orelse RcMsg.new(c.DNS_QMSG_MAXSIZE);
            free_qmsg = null;

            // read msg
            qmsg.len = len;
            g.evloop.recv_exactly(fdobj, qmsg.msg(), 0) orelse
                break :e .{ .op = "read_msg", .msg = if (cc.errno() == 0) "connection closed" else null };

            on_query(qmsg, fdobj, &src_addr, true);

            if (qmsg.is_unique())
                free_qmsg = qmsg
            else
                qmsg.unref();
        }
    };

    if (!g.verbose) src_addr.to_text(&ip, &port);

    if (e.msg) |msg|
        log.err(@src(), "%s(fd:%d, %s#%u) failed: %s", .{ e.op, fd, &ip, cc.to_uint(port), msg })
    else
        log.err(@src(), "%s(fd:%d, %s#%u) failed: (%d) %m", .{ e.op, fd, &ip, cc.to_uint(port), cc.errno() });
}

fn listen_udp(fd: c_int, bind_ip: cc.ConstStr) void {
    defer co.terminate(@frame(), @frameSize(listen_udp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    var free_qmsg: ?*RcMsg = null;
    defer if (free_qmsg) |qmsg| qmsg.free();

    while (true) {
        const qmsg = free_qmsg orelse RcMsg.new(c.DNS_QMSG_MAXSIZE);
        free_qmsg = null;

        var src_addr: net.Addr = undefined;
        const len = g.evloop.recvfrom(fdobj, qmsg.buf(), 0, &src_addr) orelse {
            log.err(@src(), "recvfrom(fd:%d, %s#%u) failed: (%d) %m", .{ fd, bind_ip, cc.to_uint(g.bind_port), cc.errno() });
            continue;
        };
        qmsg.len = cc.to_u16(len);

        on_query(qmsg, fdobj, &src_addr, false);

        if (qmsg.is_unique())
            free_qmsg = qmsg
        else
            qmsg.unref();
    }
}

fn on_query(qmsg: *RcMsg, fdobj: *EvLoop.Fd, src_addr: *const net.Addr, from_tcp: bool) void {
    const msg = qmsg.msg();

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose or !dnl.is_empty()) &ascii_namebuf else null;
    var wire_namelen: c_int = undefined;
    if (!dns.check_query(msg, p_ascii_namebuf, &wire_namelen)) return;

    const name_tag = dnl.get_name_tag(&ascii_namebuf, dns.to_ascii_namelen(wire_namelen));
    const qtype = dns.get_qtype(msg, wire_namelen);

    if (g.verbose) {
        var ip: net.IpStrBuf = undefined;
        var port: u16 = undefined;
        src_addr.to_text(&ip, &port);
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:%u, '%s') from %s#%u",
            .{ cc.to_uint(dns.get_id(msg)), name_tag.desc(), cc.to_uint(qtype), &ascii_namebuf, &ip, cc.to_uint(port) },
        );
    }

    // no-AAAA filter
    if (qtype == c.DNS_RECORD_TYPE_AAAA) {
        if (g.noaaaa_query.filter(name_tag)) |by_rule| {
            if (g.verbose)
                log.info(
                    @src(),
                    "query(id:%u, tag:%s, qtype:AAAA, '%s') filterd by rule: %s",
                    .{ cc.to_uint(dns.get_id(msg)), name_tag.desc(), &ascii_namebuf, by_rule },
                );
            dns.to_reply_msg(msg);
            return send_reply(msg, fdobj, src_addr, from_tcp);
        }
    }

    const qctx = _qctx_list.add(msg, fdobj, if (from_tcp) null else src_addr, name_tag) orelse return;

    if (name_tag == .chn or name_tag == .none) {
        if (g.verbose)
            log.info(
                @src(),
                "forward query(qid:%u, from:%s, '%s') to china upstream group",
                .{ cc.to_uint(qctx.qid), cc.b2s(from_tcp, "tcp", "udp"), &ascii_namebuf },
            );
        nosuspend g.china_group.send(qmsg, from_tcp);
    }

    if (name_tag == .gfw or name_tag == .none) {
        if (g.verbose)
            log.info(
                @src(),
                "forward query(qid:%u, from:%s, '%s') to trust upstream group",
                .{ cc.to_uint(qctx.qid), cc.b2s(from_tcp, "tcp", "udp"), &ascii_namebuf },
            );
        nosuspend g.trust_group.send(qmsg, from_tcp);
    }
}

const ReplyLog = struct {
    qid: u16,
    tag: ?dnl.Tag,
    qtype: u16,
    name: cc.ConstStr,
    url: cc.ConstStr,

    /// string literal
    fn tag_desc(self: *const ReplyLog) cc.ConstStr {
        return if (self.tag) |tag| tag.desc() else "null";
    }

    pub noinline fn reply(self: *const ReplyLog, action: cc.ConstStr, alt_url: ?cc.ConstStr) void {
        const url = alt_url orelse self.url;
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:%u, '%s') from %s [%s]",
            .{ cc.to_uint(self.qid), self.tag_desc(), cc.to_uint(self.qtype), self.name, url, action },
        );
    }

    pub noinline fn add_ip(self: *const ReplyLog, setnames: cc.ConstStr) void {
        log.info(
            @src(),
            "add answer_ip(qid:%u, tag:%s, qtype:%u, '%s') to %s",
            .{ cc.to_uint(self.qid), self.tag_desc(), cc.to_uint(self.qtype), self.name, setnames },
        );
    }
};

fn use_china_reply(rmsg: *RcMsg, wire_namelen: c_int) bool {
    _ = rmsg;
    _ = wire_namelen;
    return true;
}

fn use_trust_reply(rmsg: *RcMsg, wire_namelen: c_int) bool {
    _ = rmsg;
    _ = wire_namelen;
    return true;
}

pub fn on_reply(in_rmsg: *RcMsg, upstream: *const Upstream) void {
    var rmsg = in_rmsg;

    var ascii_name: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    var wire_namelen: c_int = undefined;
    if (!dns.check_reply(rmsg.msg(), &ascii_name, &wire_namelen)) return;

    var replylog: ReplyLog = if (g.verbose) .{
        .qid = dns.get_id(rmsg.msg()),
        .tag = null,
        .qtype = dns.get_qtype(rmsg.msg(), wire_namelen),
        .name = &ascii_name,
        .url = upstream.url,
    } else undefined;

    const qctx = _qctx_list.get(rmsg.msg()) orelse {
        if (g.verbose)
            replylog.reply("ignore", null);
        return;
    };

    replylog.tag = qctx.name_tag;

    switch (upstream.group.tag) {
        .china => {
            if (qctx.name_tag == .chn or use_china_reply(rmsg, wire_namelen)) {
                if (g.verbose) {
                    replylog.reply("accept", null);

                    if (qctx.trust_msg != null)
                        replylog.reply("filter", "<previous-trustdns>");
                }

                if (qctx.name_tag == .chn and !g.chnip_setnames.is_empty()) {
                    if (g.verbose)
                        replylog.add_ip(g.chnip_setnames.str);
                    dns.add_ip(rmsg.msg(), wire_namelen, true);
                }
            } else {
                if (g.verbose)
                    replylog.reply("filter", null);

                if (qctx.trust_msg) |trust_msg| {
                    if (g.verbose)
                        replylog.reply("accept", "<previous-trustdns>");
                    rmsg = trust_msg;
                } else {
                    // waiting for trustdns
                    qctx.china_got = true;
                    return;
                }
            }
        },
        .trust => {
            if (qctx.name_tag == .gfw or qctx.china_got or use_trust_reply(rmsg, wire_namelen)) {
                if (g.verbose)
                    replylog.reply("accept", null);

                if (qctx.name_tag == .gfw and !g.gfwip_setnames.is_empty()) {
                    if (g.verbose)
                        replylog.add_ip(g.gfwip_setnames.str);
                    dns.add_ip(rmsg.msg(), wire_namelen, false);
                }
            } else {
                // waiting for chinadns
                if (g.verbose)
                    replylog.reply(if (qctx.trust_msg == null) "delay" else "ignore", null);

                if (qctx.trust_msg == null)
                    qctx.trust_msg = rmsg.ref();

                return;
            }
        },
    }

    send_reply(rmsg.msg(), qctx.fdobj, &qctx.src_addr, qctx.is_from_tcp());

    _qctx_list.del(qctx);
}

fn send_reply(msg: []const u8, fdobj: *EvLoop.Fd, src_addr: *const net.Addr, from_tcp: bool) void {
    if (from_tcp) {
        var iov = [_]net.iovec_t{
            .{
                .iov_base = std.mem.asBytes(&c.htons(cc.to_u16(msg.len))),
                .iov_len = @sizeOf(u16),
            },
            .{
                .iov_base = cc.remove_const(msg.ptr),
                .iov_len = msg.len,
            },
        };
        const msghdr = net.msghdr_t{
            .msg_iov = &iov,
            .msg_iovlen = iov.len,
        };
        if (g.evloop.sendmsg(fdobj, &msghdr, 0) != null) return;
    } else {
        // TODO: check the message length and set the `TC` flag if necessary
        if (net.sendto(fdobj.fd, msg, 0, src_addr) >= 0) return;
    }

    // error handling
    var ip: net.IpStrBuf = undefined;
    var port: u16 = undefined;
    src_addr.to_text(&ip, &port);

    log.err(
        @src(),
        "reply(id:%u, sz:%zu) to %s://%s#%u failed: (%d) %m",
        .{ cc.to_uint(dns.get_id(msg)), msg.len, cc.b2s(from_tcp, "tcp", "udp"), &ip, cc.to_uint(port), cc.errno() },
    );
}

/// qctx will be free()
fn on_timeout(qctx: *QueryCtx) void {
    if (g.verbose) {
        if (qctx.is_from_tcp())
            _ = net.getpeername(qctx.fdobj.fd, &qctx.src_addr);

        var ip: net.IpStrBuf = undefined;
        var port: u16 = undefined;
        qctx.src_addr.to_text(&ip, &port);

        log.info(
            @src(),
            "query(qid:%u, id:%u, tag:%s) from %s#%u timeout",
            .{ cc.to_uint(qctx.qid), cc.to_uint(qctx.id), qctx.name_tag.desc(), &ip, cc.to_uint(port) },
        );
    }

    _qctx_list.del(qctx);
}

pub fn check_timeout() c_int {
    const now = cc.time();
    var it = _qctx_list.iterator();
    while (it.next()) |qctx| {
        const deadline = qctx.req_time + g.upstream_timeout;
        if (now >= deadline) {
            on_timeout(qctx);
        } else {
            return cc.to_int((deadline - now) * 1000); // ms
        }
    }
    return -1;
}

// ===============================================================

/// listen socket (tcp + udp)
fn create_socks(ip: cc.ConstStr, port: u16) [2]c_int {
    const e: struct { op: cc.ConstStr, t: cc.ConstStr } = e: {
        const addr = net.Addr.from_text(ip, port);

        const tcp = net.new_listen_sock(addr.family(), .tcp) orelse c.exit(1);
        const udp = net.new_listen_sock(addr.family(), .udp) orelse c.exit(1);

        if (c.bind(tcp, &addr.sa, addr.len()) < 0)
            break :e .{ .op = "bind", .t = "tcp" };

        if (c.bind(udp, &addr.sa, addr.len()) < 0)
            break :e .{ .op = "bind", .t = "udp" };

        // mark the socket as a listener
        if (c.listen(tcp, 256) < 0)
            break :e .{ .op = "listen", .t = "tcp" };

        return .{ tcp, udp };
    };

    log.err(@src(), "%s(%s, %s#%u) failed: (%d) %m", .{ e.op, e.t, ip, cc.to_uint(port), cc.errno() });
    c.exit(1);
}

pub fn start() void {
    for (g.bind_ips.items) |ip| {
        const fds = create_socks(ip.?, g.bind_port);
        co.create(listen_tcp, .{ fds[0], ip.? });
        co.create(listen_udp, .{ fds[1], ip.? });
    }
}
