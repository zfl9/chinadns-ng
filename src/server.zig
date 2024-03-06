const std = @import("std");
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

comptime {
    // @compileLog("sizeof(QueryCtx):", @sizeOf(QueryCtx), "alignof(QueryCtx):", @alignOf(QueryCtx));
    // @compileLog("sizeof(c.time_t):", @sizeOf(c.time_t), "alignof(c.time_t):", @alignOf(c.time_t));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
}

const QueryCtx = struct {
    // linked list
    prev: ?*QueryCtx = null,
    next: ?*QueryCtx = null,

    // alignment: 8/4
    fdobj: *EvLoop.Fd, // requester's fdobj
    trust_msg: ?*RcMsg = null,
    req_time: c.time_t,

    // alignment: 4
    src_addr: cc.SockAddr,

    // alignment: 2
    qid: u16,
    id: c.be16, // original id
    bufsz: u16, // udp requester's receive bufsz

    // alignment: 1
    name_tag: dnl.Tag,
    from_tcp: bool,
    china_got: bool = false,

    fn new(qid: u16, id: c.be16, bufsz: u16, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, from_tcp: bool, name_tag: dnl.Tag) *QueryCtx {
        const self = g.allocator.create(QueryCtx) catch unreachable;
        self.* = .{
            .qid = qid,
            .id = id,
            .bufsz = bufsz,
            .fdobj = fdobj.ref(),
            .src_addr = src_addr.*,
            .from_tcp = from_tcp,
            .name_tag = name_tag,
            .req_time = cc.time(),
        };
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

    pub const List = struct {
        map: std.AutoHashMapUnmanaged(u16, *QueryCtx) = .{},

        // linked list
        head: ?*QueryCtx = null,
        tail: ?*QueryCtx = null,

        var _last_qid: u16 = 0;

        pub fn len(self: *const List) usize {
            return self.map.count();
        }

        pub fn is_empty(self: *const List) bool {
            return self.len() == 0;
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
        pub fn add(
            self: *List,
            msg: []u8,
            wire_namelen: c_int,
            fdobj: *EvLoop.Fd,
            src_addr: *const cc.SockAddr,
            from_tcp: bool,
            name_tag: dnl.Tag,
            first_query: *bool,
        ) ?*QueryCtx {
            if (self.len() >= std.math.maxInt(u16) + 1) {
                log.err(@src(), "too many pending requests: %zu", .{self.len()});
                return null;
            }

            first_query.* = self.is_empty();

            _last_qid +%= 1;
            const qid = _last_qid;

            const id = dns.get_id(msg);
            dns.set_id(msg, qid);

            const bufsz = if (from_tcp)
                cc.to_u16(c.DNS_MSG_MAXSIZE)
            else
                dns.get_bufsz(msg, wire_namelen);

            const qctx = QueryCtx.new(qid, id, bufsz, fdobj, src_addr, from_tcp, name_tag);

            self.map.putNoClobber(g.allocator, qid, qctx) catch unreachable;
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
            self.del_nofree(qctx);
            qctx.free();
        }

        /// remove from list
        pub fn del_nofree(self: *List, qctx: *const QueryCtx) void {
            self.unlink(qctx);
            assert(self.map.remove(qctx.qid));
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
        var src_addr: cc.SockAddr = undefined;
        const conn_fd = g.evloop.accept(fdobj, &src_addr) orelse {
            log.err(@src(), "accept(fd:%d, %s#%u) failed: (%d) %m", .{ fd, ip, cc.to_uint(g.bind_port), cc.errno() });
            continue;
        };
        net.setup_tcp_conn_sock(conn_fd);
        co.create(service_tcp, .{ conn_fd, &src_addr });
    }
}

fn service_tcp(fd: c_int, p_src_addr: *const cc.SockAddr) void {
    defer co.terminate(@frame(), @frameSize(service_tcp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    // copy to local variable
    const src_addr = p_src_addr.*;

    var ip: cc.IpStrBuf = undefined;
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

            len = cc.ntohs(len);
            if (len < c.DNS_MSG_MINSIZE or len > c.DNS_QMSG_MAXSIZE) {
                log.err(@src(), "invalid query_msg length: %u", .{cc.to_uint(len)});
                break :e .{ .op = "read_len", .msg = "invalid query_msg length" };
            }

            const qmsg = free_qmsg orelse RcMsg.new(c.DNS_QMSG_MAXSIZE);
            free_qmsg = null;

            defer {
                if (qmsg.is_unique())
                    free_qmsg = qmsg
                else
                    qmsg.unref();
            }

            // read msg
            qmsg.len = len;
            g.evloop.recv_exactly(fdobj, qmsg.msg(), 0) orelse
                break :e .{ .op = "read_msg", .msg = if (cc.errno() == 0) "connection closed" else null };

            on_query(qmsg, fdobj, &src_addr, true);
        }
    };

    if (!g.verbose) src_addr.to_text(&ip, &port);

    const src = @src();
    if (e.msg) |msg|
        log.err(src, "%s(fd:%d, %s#%u) failed: %s", .{ e.op, fd, &ip, cc.to_uint(port), msg })
    else
        log.err(src, "%s(fd:%d, %s#%u) failed: (%d) %m", .{ e.op, fd, &ip, cc.to_uint(port), cc.errno() });
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

        defer {
            if (qmsg.is_unique())
                free_qmsg = qmsg
            else
                qmsg.unref();
        }

        var src_addr: cc.SockAddr = undefined;
        const len = g.evloop.recvfrom(fdobj, qmsg.buf(), 0, &src_addr) orelse {
            log.err(@src(), "recvfrom(fd:%d, %s#%u) failed: (%d) %m", .{ fd, bind_ip, cc.to_uint(g.bind_port), cc.errno() });
            continue;
        };
        qmsg.len = cc.to_u16(len);

        on_query(qmsg, fdobj, &src_addr, false);
    }
}

// =========================================================================

comptime {
    // @compileLog("sizeof(cc.ConstStr):", @sizeOf(cc.ConstStr), "alignof(cc.ConstStr):", @alignOf(cc.ConstStr));
    // @compileLog("sizeof(dnl.Tag):", @sizeOf(dnl.Tag), "alignof(dnl.Tag):", @alignOf(dnl.Tag));
    // @compileLog("sizeof(cc.IpStrBuf):", @sizeOf(cc.IpStrBuf), "alignof(cc.IpStrBuf):", @alignOf(cc.IpStrBuf));
}

const QueryLog = struct {
    name: cc.ConstStr,
    src_port: u16,
    id: u16,
    qtype: u16,
    tag: dnl.Tag,
    src_ip: cc.IpStrBuf,

    pub noinline fn query(self: *const QueryLog) void {
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:%u, '%s') from %s#%u",
            .{ cc.to_uint(self.id), self.tag.desc(), cc.to_uint(self.qtype), self.name, &self.src_ip, cc.to_uint(self.src_port) },
        );
    }

    pub noinline fn noaaaa(self: *const QueryLog, by_rule: cc.ConstStr) void {
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:AAAA, '%s') filterd by rule: %s",
            .{ cc.to_uint(self.id), self.tag.desc(), self.name, by_rule },
        );
    }

    pub noinline fn forward(self: *const QueryLog, qctx: *const QueryCtx, group: cc.ConstStr) void {
        log.info(
            @src(),
            "forward query(qid:%u, from:%s, '%s') to %s group",
            .{ cc.to_uint(qctx.qid), cc.b2s(qctx.from_tcp, "tcp", "udp"), self.name, group },
        );
    }
};

fn on_query(qmsg: *RcMsg, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, from_tcp: bool) void {
    const msg = qmsg.msg();

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose or !dnl.is_empty()) &ascii_namebuf else null;
    var wire_namelen: c_int = undefined;
    if (!dns.check_query(msg, p_ascii_namebuf, &wire_namelen)) {
        log.err(@src(), "dns.check_query(fd:%d) failed: invalid query msg", .{fdobj.fd});
        return;
    }

    const name_tag = dnl.get_name_tag(&ascii_namebuf, dns.to_ascii_namelen(wire_namelen));
    const qtype = dns.get_qtype(msg, wire_namelen);

    var querylog: QueryLog = if (g.verbose) .{
        .src_ip = undefined,
        .src_port = undefined,
        .id = dns.get_id(msg),
        .qtype = qtype,
        .tag = name_tag,
        .name = &ascii_namebuf,
    } else undefined;

    if (g.verbose) {
        src_addr.to_text(&querylog.src_ip, &querylog.src_port);

        querylog.query();
    }

    var tagnone_to_china = true;
    var tagnone_to_trust = true;

    // no-AAAA filter
    if (qtype == c.DNS_RECORD_TYPE_AAAA and !g.noaaaa_query.is_empty()) {
        if (g.noaaaa_query.filter(name_tag)) |by_rule| {
            if (g.verbose) querylog.noaaaa(by_rule);
            var reply_msg = msg;
            reply_msg.len = dns.empty_reply(reply_msg, wire_namelen);
            return send_reply(reply_msg, fdobj, src_addr, from_tcp, c.DNS_MSG_MAXSIZE);
        }

        // tag:none
        if (g.noaaaa_query.has_any(NoAAAA.ALL_DNS) and name_tag == .none) {
            if (g.noaaaa_query.has(NoAAAA.CHINA_DNS))
                tagnone_to_china = false
            else // if (g.noaaaa_query.has(NoAAAA.TRUST_DNS))
                tagnone_to_trust = false;
        }
    }

    var first_query: bool = undefined;

    const qctx = _qctx_list.add(
        msg,
        wire_namelen,
        fdobj,
        src_addr,
        from_tcp,
        name_tag,
        &first_query,
    ) orelse return;

    if (name_tag == .chn or (name_tag == .none and tagnone_to_china)) {
        if (g.verbose) querylog.forward(qctx, "china");
        nosuspend g.china_group.send(qmsg, from_tcp, first_query);
    }

    if (name_tag == .gfw or (name_tag == .none and tagnone_to_trust)) {
        if (g.verbose) querylog.forward(qctx, "trust");
        nosuspend g.trust_group.send(qmsg, from_tcp, first_query);
    }
}

// =========================================================================

comptime {
    // @compileLog("sizeof(ReplyLog):", @sizeOf(ReplyLog), "alignof(ReplyLog):", @alignOf(ReplyLog));
    // @compileLog("sizeof(u16):", @sizeOf(u16), "alignof(u16):", @alignOf(u16));
    // @compileLog("sizeof(?dnl.Tag):", @sizeOf(?dnl.Tag), "alignof(?dnl.Tag):", @alignOf(?dnl.Tag));
}

const ReplyLog = struct {
    name: cc.ConstStr,
    url: cc.ConstStr,
    qid: u16,
    qtype: u16,
    tag: ?dnl.Tag,

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

    pub noinline fn noaaaa(self: *const ReplyLog, by_rule: cc.ConstStr) void {
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:AAAA, '%s') filterd by rule: %s",
            .{ cc.to_uint(self.qid), self.tag_desc(), self.name, by_rule },
        );
    }

    pub noinline fn china_noip(self: *const ReplyLog) void {
        const action = cc.b2s(g.noip_as_chnip, "accept", "filter");
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:%u, '%s') has no answer ip [%s]",
            .{ cc.to_uint(self.qid), self.tag_desc(), cc.to_uint(self.qtype), self.name, action },
        );
    }
};

/// tag:none
fn use_china_reply(rmsg: *RcMsg, wire_namelen: c_int, replylog: *const ReplyLog) bool {
    const msg = rmsg.msg();
    const qtype = dns.get_qtype(msg, wire_namelen);

    // only filter A/AAAA
    if (qtype != c.DNS_RECORD_TYPE_A and qtype != c.DNS_RECORD_TYPE_AAAA)
        return true;

    // no-aaaa filter
    const only_china = qtype == c.DNS_RECORD_TYPE_AAAA and g.noaaaa_query.has(NoAAAA.TRUST_DNS);
    if (only_china and !g.noaaaa_query.has(NoAAAA.CHINA_IPCHK))
        return true;

    // test the answer ip
    switch (dns.test_ip(msg, wire_namelen)) {
        .is_chnip => return true,

        .not_chnip => {
            if (only_china) {
                if (g.verbose) replylog.noaaaa("china_ipchk");
                rmsg.len = dns.empty_reply(msg, wire_namelen); // `.len` updated
                return true;
            }
            return false;
        },

        .not_found => {
            if (only_china) {
                if (g.verbose) replylog.noaaaa("china_ipchk");
                return true;
            }
            if (g.verbose) replylog.china_noip();
            return g.noip_as_chnip;
        },

        else => return false,
    }
}

/// tag:none && !china_got
fn use_trust_reply(rmsg: *RcMsg, wire_namelen: c_int, replylog: *const ReplyLog) bool {
    const msg = rmsg.msg();
    const qtype = dns.get_qtype(msg, wire_namelen);

    // no-aaaa filter
    const only_trust = qtype == c.DNS_RECORD_TYPE_AAAA and g.noaaaa_query.has(NoAAAA.CHINA_DNS);
    if (!only_trust)
        return false; // waiting for chinadns

    // [only_trust]

    // no-aaaa ipchk
    if (g.noaaaa_query.has(NoAAAA.TRUST_IPCHK)) {
        const res = dns.test_ip(msg, wire_namelen);
        if (res == .not_chnip or res == .not_found) {
            if (g.verbose) replylog.noaaaa("trust_ipchk");
            if (res == .not_chnip) rmsg.len = dns.empty_reply(msg, wire_namelen); // `.len` updated
        }
    }

    return true;
}

pub fn on_reply(in_rmsg: *RcMsg, upstream: *const Upstream) void {
    var rmsg = in_rmsg;

    var ascii_name: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    var wire_namelen: c_int = undefined;
    if (!dns.check_reply(rmsg.msg(), &ascii_name, &wire_namelen)) {
        log.err(@src(), "dns.check_reply(upstream:%s) failed: invalid reply msg", .{upstream.url.ptr});
        return;
    }

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

    if (g.verbose)
        replylog.tag = qctx.name_tag;

    // determines whether to end the current query context
    nosuspend switch (upstream.group.tag) {
        .china => {
            if (qctx.name_tag == .chn or use_china_reply(rmsg, wire_namelen, &replylog)) {
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
            if (qctx.name_tag == .gfw or qctx.china_got or use_trust_reply(rmsg, wire_namelen, &replylog)) {
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
    };

    // see check_timeout()
    _qctx_list.del_nofree(qctx);

    // may be suspended
    send_reply(rmsg.msg(), qctx.fdobj, &qctx.src_addr, qctx.from_tcp, qctx.bufsz);

    qctx.free();
}

fn send_reply(msg: []u8, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, from_tcp: bool, bufsz: u16) void {
    if (from_tcp) {
        var iov = [_]cc.iovec_t{
            .{
                .iov_base = std.mem.asBytes(&cc.htons(cc.to_u16(msg.len))),
                .iov_len = @sizeOf(u16),
            },
            .{
                .iov_base = cc.remove_const(msg.ptr),
                .iov_len = msg.len,
            },
        };
        const msghdr = cc.msghdr_t{
            .msg_iov = &iov,
            .msg_iovlen = iov.len,
        };
        if (g.evloop.sendmsg(fdobj, &msghdr, 0) != null) return;
    } else {
        var reply_msg = msg;
        // log.debug(@src(), "bufsz: %u", .{cc.to_uint(bufsz)});
        if (reply_msg.len > bufsz) {
            reply_msg.len = dns.truncate(reply_msg);
            // log.debug(@src(), "msg truncated: %zu -> %zu", .{ msg.len, reply_msg.len }); // test code
        }
        if (cc.sendto(fdobj.fd, reply_msg, 0, src_addr) != null) return;
    }

    // error handling
    var ip: cc.IpStrBuf = undefined;
    var port: u16 = undefined;
    src_addr.to_text(&ip, &port);

    log.err(
        @src(),
        "reply(id:%u, sz:%zu) to %s://%s#%u failed: (%d) %m",
        .{ cc.to_uint(dns.get_id(msg)), msg.len, cc.b2s(from_tcp, "tcp", "udp"), &ip, cc.to_uint(port), cc.errno() },
    );
}

// =========================================================================

/// qctx will be free()
fn on_timeout(qctx: *QueryCtx) void {
    if (g.verbose) {
        var ip: cc.IpStrBuf = undefined;
        var port: u16 = undefined;
        qctx.src_addr.to_text(&ip, &port);

        const proto = cc.b2s(qctx.from_tcp, "tcp", "udp");

        log.warn(
            @src(),
            "query(qid:%u, id:%u, tag:%s) from %s://%s#%u [timeout]",
            .{ cc.to_uint(qctx.qid), cc.to_uint(qctx.id), qctx.name_tag.desc(), proto, &ip, cc.to_uint(port) },
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
            nosuspend on_timeout(qctx);
        } else {
            return cc.to_int((deadline - now) * 1000); // ms
        }
    }
    return -1;
}

// =========================================================================

/// listen socket (tcp + udp)
fn create_socks(ip: cc.ConstStr, port: u16) [2]c_int {
    const e: struct { op: cc.ConstStr, t: cc.ConstStr } = e: {
        const addr = cc.SockAddr.from_text(ip, port);

        const tcp = net.new_listen_sock(addr.family(), .tcp) orelse cc.exit(1);
        const udp = net.new_listen_sock(addr.family(), .udp) orelse cc.exit(1);

        cc.bind(tcp, &addr) orelse
            break :e .{ .op = "bind", .t = "tcp" };

        cc.bind(udp, &addr) orelse
            break :e .{ .op = "bind", .t = "udp" };

        // mark the socket as a listener
        cc.listen(tcp, 256) orelse
            break :e .{ .op = "listen", .t = "tcp" };

        return .{ tcp, udp };
    };

    log.err(@src(), "%s(%s, %s#%u) failed: (%d) %m", .{ e.op, e.t, ip, cc.to_uint(port), cc.errno() });
    cc.exit(1);
}

pub fn start() void {
    for (g.bind_ips.items) |ip| {
        const fds = create_socks(ip.?, g.bind_port);
        co.create(listen_tcp, .{ fds[0], ip.? });
        co.create(listen_udp, .{ fds[1], ip.? });
    }
}
