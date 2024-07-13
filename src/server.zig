const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const co = @import("co.zig");
const log = @import("log.zig");
const net = @import("net.zig");
const dnl = @import("dnl.zig");
const dns = @import("dns.zig");
const cache = @import("cache.zig");
const Tag = @import("tag.zig").Tag;
const groups = @import("groups.zig");
const Upstream = @import("Upstream.zig");
const NoAAAA = @import("NoAAAA.zig");
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const ListNode = @import("ListNode.zig");
const flags_op = @import("flags_op.zig");
const verdict_cache = @import("verdict_cache.zig");
const local_rr = @import("local_rr.zig");
const assert = std.debug.assert;

comptime {
    // @compileLog("sizeof(QueryCtx):", @sizeOf(QueryCtx), "alignof(QueryCtx):", @alignOf(QueryCtx));
    // @compileLog("sizeof(c.time_t):", @sizeOf(c.time_t), "alignof(c.time_t):", @alignOf(c.time_t));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
}

const QueryCtx = struct {
    // linked list
    list_node: ListNode = undefined,

    // alignment: 8/4
    fdobj: *EvLoop.Fd, // requester's fdobj
    trust_msg: ?*RcMsg = null,
    req_time: c.time_t,

    // alignment: 4
    src_addr: cc.SockAddr,

    // alignment: 2
    qid: u16,
    id: c.be16, // original id
    bufsz: u16, // requester's receive bufsz

    // alignment: 1
    tag: Tag,
    flags: Flags,

    pub const Flags = enum(u8) {
        from_local = 1 << 0, // {fdobj, src_addr} have undefined values (priority over other `.from_*`)
        from_tcp = 1 << 1, // default: from_udp
        is_china_domain = 1 << 2, // tag:none [verdict]
        non_china_domain = 1 << 3, // tag:none [verdict]
        _, // non-exhaustive enum
        pub usingnamespace flags_op.get(Flags);
    };

    fn new(qid: u16, id: c.be16, bufsz: u16, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, tag: Tag, flags: Flags) *QueryCtx {
        const from_local = flags.has(.from_local);

        const self = g.allocator.create(QueryCtx) catch unreachable;

        self.* = .{
            .qid = qid,
            .id = id,
            .bufsz = bufsz,
            .fdobj = if (!from_local) fdobj.ref() else undefined,
            .src_addr = if (!from_local) src_addr.* else undefined,
            .tag = tag,
            .flags = flags,
            .req_time = cc.time(),
        };

        return self;
    }

    fn free(self: *const QueryCtx) void {
        if (!self.flags.has(.from_local))
            self.fdobj.unref();

        if (self.trust_msg) |msg| {
            assert(msg.is_unique());
            msg.unref();
        }

        g.allocator.destroy(self);
    }

    pub fn from_list_node(node: *ListNode) *QueryCtx {
        return @fieldParentPtr(QueryCtx, "list_node", node);
    }

    pub const List = struct {
        map: std.AutoHashMapUnmanaged(u16, *QueryCtx),
        list: ListNode,

        var _last_qid: u16 = 0;

        pub fn init(self: *List) void {
            self.* = .{
                .map = .{},
                .list = undefined,
            };
            self.list.init();
        }

        pub fn len(self: *const List) usize {
            return self.map.count();
        }

        pub fn is_empty(self: *const List) bool {
            return self.len() == 0;
        }

        /// [on_query] msg.id => qid
        pub fn add(
            self: *List,
            msg: []u8,
            fdobj: *EvLoop.Fd,
            src_addr: *const cc.SockAddr,
            bufsz: u16,
            tag: Tag,
            flags: Flags,
            /// out param
            first_query: *bool,
        ) ?*QueryCtx {
            if (self.len() >= std.math.maxInt(u16) + 1) {
                log.warn(@src(), "too many pending requests: %zu", .{self.len()});
                return null;
            }

            first_query.* = self.is_empty();

            _last_qid +%= 1;
            const qid = _last_qid;

            const id = dns.get_id(msg);
            dns.set_id(msg, qid);

            const qctx = QueryCtx.new(qid, id, bufsz, fdobj, src_addr, tag, flags);

            self.map.putNoClobber(g.allocator, qid, qctx) catch unreachable;
            self.list.link_to_tail(&qctx.list_node);

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
            qctx.list_node.unlink();
            assert(self.map.remove(qctx.qid));
        }
    };
};

/// qid => *query_ctx
var _qctx_list: QueryCtx.List = undefined;

// =======================================================================================================

fn listen_tcp(fd: c_int, ip: cc.ConstStr) void {
    defer co.terminate(@frame(), @frameSize(listen_tcp));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    while (true) {
        var src_addr: cc.SockAddr = undefined;
        const conn_fd = g.evloop.accept(fdobj, &src_addr) orelse {
            log.warn(@src(), "accept(fd:%d, %s#%u) failed: (%d) %m", .{ fd, ip, cc.to_uint(g.bind_port), cc.errno() });
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
    if (g.verbose()) src_addr.to_text(&ip, &port);

    const src = @src();

    if (g.verbose()) log.info(src, "new connection:%d from %s#%u", .{ fd, &ip, cc.to_uint(port) });
    defer if (g.verbose()) log.info(src, "close connection:%d from %s#%u", .{ fd, &ip, cc.to_uint(port) });

    const e: struct { op: cc.ConstStr, msg: ?cc.ConstStr = null } = e: {
        var free_qmsg: ?*RcMsg = null;
        defer if (free_qmsg) |qmsg| qmsg.free();

        while (true) {
            // read len (be16)
            var len: u16 = undefined;
            g.evloop.recv_exactly(fdobj, std.mem.asBytes(&len), 0) catch |err| switch (err) {
                error.eof => return,
                error.other => break :e .{ .op = "read_len" },
            };

            len = cc.ntohs(len);
            if (len < c.DNS_MSG_MINSIZE or len > c.DNS_QMSG_MAXSIZE) {
                log.warn(src, "invalid query_msg length: %u", .{cc.to_uint(len)});
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
            g.evloop.recv_exactly(fdobj, qmsg.msg(), 0) catch |err| switch (err) {
                error.eof => break :e .{ .op = "read_msg", .msg = "connection closed" },
                error.other => break :e .{ .op = "read_msg" },
            };

            on_query(qmsg, fdobj, &src_addr, .from_tcp);
        }
    };

    // error handling

    if (!g.verbose()) src_addr.to_text(&ip, &port);

    if (e.msg) |msg|
        log.warn(src, "%s(fd:%d, %s#%u) failed: %s", .{ e.op, fd, &ip, cc.to_uint(port), msg })
    else
        log.warn(src, "%s(fd:%d, %s#%u) failed: (%d) %m", .{ e.op, fd, &ip, cc.to_uint(port), cc.errno() });
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
            log.warn(@src(), "recvfrom(fd:%d, %s#%u) failed: (%d) %m", .{ fd, bind_ip, cc.to_uint(g.bind_port), cc.errno() });
            continue;
        };
        qmsg.len = cc.to_u16(len);

        on_query(qmsg, fdobj, &src_addr, QueryCtx.Flags.empty());
    }
}

// =========================================================================

comptime {
    // @compileLog("sizeof(cc.ConstStr):", @sizeOf(cc.ConstStr), "alignof(cc.ConstStr):", @alignOf(cc.ConstStr));
    // @compileLog("sizeof(Tag):", @sizeOf(Tag), "alignof(Tag):", @alignOf(Tag));
    // @compileLog("sizeof(cc.IpStrBuf):", @sizeOf(cc.IpStrBuf), "alignof(cc.IpStrBuf):", @alignOf(cc.IpStrBuf));
}

const QueryLog = struct {
    name: cc.ConstStr,
    src_port: u16,
    id: u16,
    qtype: u16,
    tag: Tag,
    src_ip: cc.IpStrBuf,

    pub noinline fn query(self: *const QueryLog) void {
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:%u, '%s') from %s#%u",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, &self.src_ip, cc.to_uint(self.src_port) },
        );
    }

    pub noinline fn noaaaa(self: *const QueryLog, rule: NoAAAA.Rule.T) void {
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.id), self.tag.name(), self.name, NoAAAA.Rule.to_name(rule) },
        );
    }

    pub noinline fn filter(self: *const QueryLog, rule: enum { tag_null, qtype }) void {
        var buf: [20]u8 = undefined;
        const rule_str: cc.ConstStr = switch (rule) {
            .tag_null => "tag:null",
            .qtype => cc.snprintf(&buf, "qtype:%u", .{cc.to_uint(self.qtype)}).ptr,
        };
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:%u, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, rule_str },
        );
    }

    pub noinline fn local_rr(self: *const QueryLog, answer_n: u16, answer_sz: usize) void {
        log.info(
            @src(),
            "local_rr(id:%u, tag:%s, qtype:%u, '%s') answer_n:%u size:%zu",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, cc.to_uint(answer_n), answer_sz },
        );
    }

    pub noinline fn cache(self: *const QueryLog, cache_msg: []const u8, ttl: i32) void {
        log.info(
            @src(),
            "hit cache(id:%u, tag:%s, qtype:%u, '%s') size:%zu ttl:%ld",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, cache_msg.len, cc.to_long(ttl) },
        );
    }

    pub noinline fn refresh(self: *const QueryLog, ttl: i32) void {
        log.info(
            @src(),
            "refresh cache(id:%u, tag:%s, qtype:%u, '%s') ttl:%ld",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, cc.to_long(ttl) },
        );
    }

    pub noinline fn forward(self: *const QueryLog, qctx: *const QueryCtx, to_tag: Tag) void {
        const from: cc.ConstStr = if (qctx.flags.has(.from_local))
            "local"
        else if (qctx.flags.has(.from_tcp))
            "tcp"
        else
            "udp";

        const to: cc.ConstStr = switch (to_tag) {
            .chn => "china",
            .gfw => "trust",
            else => to_tag.name(),
        };

        log.info(
            @src(),
            "forward query(qid:%u, from:%s, '%s') to %s group",
            .{ cc.to_uint(qctx.qid), from, self.name, to },
        );
    }
};

fn on_query(qmsg: *RcMsg, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, in_qflags: QueryCtx.Flags) void {
    const msg = qmsg.msg();
    var qflags = in_qflags;

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose() or !dnl.is_empty()) &ascii_namebuf else null;
    var qnamelen: c_int = undefined;

    if (!dns.check_query(msg, p_ascii_namebuf, &qnamelen)) {
        var src_ip: cc.IpStrBuf = undefined;
        var src_port: u16 = undefined;
        src_addr.to_text(&src_ip, &src_port);
        log.warn(@src(), "dns.check_query(%s#%u) failed: invalid query msg", .{ &src_ip, cc.to_uint(src_port) });
        return send_reply_xxx(msg, fdobj, src_addr, in_qflags); // make the requester happy
    }

    const id = dns.get_id(msg);
    const tag = dnl.get_tag(&ascii_namebuf, dns.ascii_namelen(qnamelen));
    const qtype = dns.get_qtype(msg, qnamelen);

    var qlog: QueryLog = if (g.verbose()) .{
        .src_ip = undefined,
        .src_port = undefined,
        .id = id,
        .qtype = qtype,
        .tag = tag,
        .name = &ascii_namebuf,
    } else undefined;

    if (g.verbose()) {
        src_addr.to_text(&qlog.src_ip, &qlog.src_port);

        qlog.query();
    }

    const bufsz = if (qflags.has(.from_tcp))
        cc.to_u16(c.DNS_MSG_MAXSIZE)
    else
        dns.get_bufsz(msg, qnamelen);

    // tag:null filter
    if (tag.is_null()) {
        if (g.verbose()) qlog.filter(.tag_null);
        const rmsg = dns.empty_reply(msg, qnamelen);
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // AAAA filter
    if (qtype == c.DNS_TYPE_AAAA)
        if (g.noaaaa_rule.by_tag(tag)) |rule| {
            if (g.verbose()) qlog.noaaaa(rule);
            const rmsg = dns.empty_reply(msg, qnamelen);
            return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
        };

    // qtype filter
    if (std.mem.indexOfScalar(u16, g.filter_qtypes, qtype) != null) {
        if (g.verbose()) qlog.filter(.qtype);
        const rmsg = dns.empty_reply(msg, qnamelen);
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // check the local records
    var answer_n: u16 = undefined;
    if (local_rr.find_answer(msg, qnamelen, &answer_n)) |answer| {
        const static = struct {
            var free_msg: ?[]u8 = null;
        };

        const msgsz = dns.header_len() + dns.question_len(qnamelen) + answer.len;

        const rmsg = if (static.free_msg) |free_msg| b: {
            static.free_msg = null;
            break :b if (msgsz <= free_msg.len)
                free_msg
            else
                g.allocator.realloc(free_msg, msgsz) catch unreachable;
        } else b: {
            break :b g.allocator.alloc(u8, msgsz) catch unreachable;
        };

        defer {
            if (static.free_msg == null)
                static.free_msg = rmsg
            else
                g.allocator.free(rmsg);
        }

        dns.make_reply(rmsg, msg, qnamelen, answer, answer_n);

        // [async func]
        if (g.verbose()) qlog.local_rr(answer_n, answer.len);
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // for upstream_group.send()
    var send_flags: Upstream.SendFlags = Upstream.SendFlags.empty();

    if (qflags.has(.from_tcp))
        send_flags.add(.from_tcp);

    // check the cache
    var ttl: i32 = undefined;
    var ttl_r: i32 = undefined;
    if (cache.get(msg, qnamelen, &ttl, &ttl_r)) |cache_msg| {
        // because send_reply is async func
        cache.ref(cache_msg);
        defer cache.unref(cache_msg);

        if (g.verbose()) qlog.cache(cache_msg, ttl);
        send_reply(cache_msg, fdobj, src_addr, bufsz, id, qflags);

        if (ttl > ttl_r)
            return;

        // refresh cache in the background
        if (g.verbose())
            qlog.refresh(ttl);

        // avoid receiving truncated response
        if (!send_flags.has(.from_tcp) and cache_msg.len + 30 > c.DNS_EDNS_MINSIZE)
            send_flags.add(.from_tcp);

        // mark the qctx
        qflags.add(.from_local);
    }

    // [verdict cache]
    var tagnone_china = true;
    var tagnone_trust = true;

    // verdict cache for tag:none domain
    if (tag == .none) {
        if (verdict_cache.get(msg, qnamelen)) |is_china_domain| {
            if (is_china_domain) {
                tagnone_trust = false;
                qflags.add(.is_china_domain);
            } else {
                tagnone_china = false;
                qflags.add(.non_china_domain);
            }
        }
    }

    var first_query: bool = undefined;

    const qctx = _qctx_list.add(
        msg,
        fdobj,
        src_addr,
        bufsz,
        tag,
        qflags,
        &first_query,
    ) orelse return;

    if (first_query)
        send_flags.add(.first_query);

    if (tag == .none) {
        if (tagnone_china)
            send_query(.chn, qmsg, send_flags, qctx, &qlog);
        if (tagnone_trust)
            send_query(.gfw, qmsg, send_flags, qctx, &qlog);
    } else {
        send_query(tag, qmsg, send_flags, qctx, &qlog);
    }
}

/// nosuspend
fn send_query(to_tag: Tag, qmsg: *RcMsg, send_flags: Upstream.SendFlags, qctx: *const QueryCtx, qlog: *const QueryLog) void {
    if (g.verbose()) qlog.forward(qctx, to_tag);
    nosuspend groups.get_upstream_group(to_tag).send(qmsg, send_flags);
}

// =========================================================================

comptime {
    // @compileLog("sizeof(ReplyLog):", @sizeOf(ReplyLog), "alignof(ReplyLog):", @alignOf(ReplyLog));
    // @compileLog("sizeof(u16):", @sizeOf(u16), "alignof(u16):", @alignOf(u16));
    // @compileLog("sizeof(?Tag):", @sizeOf(?Tag), "alignof(?Tag):", @alignOf(?Tag));
}

const ReplyLog = struct {
    name: cc.ConstStr,
    url: cc.ConstStr,
    qid: u16,
    qtype: u16,
    tag: ?Tag,

    /// string literal
    fn tag_name(self: *const ReplyLog) cc.ConstStr {
        return if (self.tag) |tag| tag.name() else "(null)";
    }

    pub noinline fn reply(self: *const ReplyLog, action: cc.ConstStr, alt_url: ?cc.ConstStr) void {
        const url = alt_url orelse self.url;
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:%u, '%s') from %s [%s]",
            .{ cc.to_uint(self.qid), self.tag_name(), cc.to_uint(self.qtype), self.name, url, action },
        );
    }

    pub noinline fn add_ip(self: *const ReplyLog, setnames: cc.ConstStr) void {
        log.info(
            @src(),
            "add answer_ip(qid:%u, tag:%s, qtype:%u, '%s') to %s",
            .{ cc.to_uint(self.qid), self.tag_name(), cc.to_uint(self.qtype), self.name, setnames },
        );
    }

    pub noinline fn noaaaa(self: *const ReplyLog, rule: NoAAAA.Rule.T) void {
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.qid), self.tag_name(), self.name, NoAAAA.Rule.to_name(rule) },
        );
    }

    pub noinline fn china_noip(self: *const ReplyLog) void {
        const action = cc.b2s(g.flags.has(.noip_as_chnip), "accept", "filter");
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:%u, '%s') has no answer ip [%s]",
            .{ cc.to_uint(self.qid), self.tag_name(), cc.to_uint(self.qtype), self.name, action },
        );
    }

    pub noinline fn cache(self: *const ReplyLog, ttl: i32, sz: usize) void {
        log.info(
            @src(),
            "add cache(qid:%u, tag:%s, qtype:%u, '%s') size:%zu ttl:%ld",
            .{ cc.to_uint(self.qid), self.tag_name(), cc.to_uint(self.qtype), self.name, sz, cc.to_long(ttl) },
        );
    }
};

/// tag:none && qtype=A/AAAA
fn use_china_reply(msg: []const u8, qnamelen: c_int, p_test_res: *?dns.TestIpResult, rlog: *const ReplyLog) bool {
    const test_res = dns.test_ip(msg, qnamelen, g.chnroute_testctx);
    p_test_res.* = test_res;

    // get the verdict
    return switch (test_res) {
        .is_china_ip, .non_china_ip => b: {
            const accepted = test_res == .is_china_ip;
            verdict_cache.add(msg, qnamelen, accepted);
            break :b accepted;
        },
        .no_ip_found => b: {
            if (g.verbose()) rlog.china_noip();
            break :b g.flags.has(.noip_as_chnip);
        },
        .other_case => dns.is_tc(msg), // `truncated` or `rcode != 0`
    };
}

pub fn on_reply(rmsg: *RcMsg, upstream: *const Upstream) void {
    var msg = rmsg.msg();

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose()) &ascii_namebuf else null;
    var qnamelen: c_int = undefined;

    var newlen: u16 = undefined;

    if (!dns.check_reply(msg, p_ascii_namebuf, &qnamelen, &newlen)) {
        log.warn(@src(), "dns.check_reply(%s) failed: invalid reply msg", .{upstream.url});
        return;
    }

    rmsg.len = newlen;
    msg = rmsg.msg();

    const qtype = dns.get_qtype(msg, qnamelen);
    const is_qtype_A_AAAA = qtype == c.DNS_TYPE_A or qtype == c.DNS_TYPE_AAAA;

    var rlog: ReplyLog = if (g.verbose()) .{
        .qid = dns.get_id(msg),
        .tag = null,
        .qtype = qtype,
        .name = &ascii_namebuf,
        .url = upstream.url,
    } else undefined;

    const qctx = _qctx_list.get(msg) orelse {
        if (g.verbose())
            rlog.reply("ignore", null);
        return;
    };

    if (g.verbose())
        rlog.tag = qctx.tag;

    // query from tcp client && reply is truncated
    // NOTE: udp resolver will auto retry with TCP
    if (dns.is_tc(msg) and qctx.flags.has(.from_tcp)) {
        if (g.verbose())
            rlog.reply("drop_tc", null);
        return;
    }

    var ip_test_res: ?dns.TestIpResult = null;

    // end the query context ?
    nosuspend if (qctx.tag == .none and is_qtype_A_AAAA) {
        switch (upstream.tag) {
            .chn => {
                if (qctx.flags.has(.is_china_domain) or use_china_reply(msg, qnamelen, &ip_test_res, &rlog)) {
                    if (g.verbose()) {
                        rlog.reply("accept", null);

                        if (qctx.trust_msg != null)
                            rlog.reply("filter", "<previous-trustdns>");
                    }
                } else {
                    if (g.verbose())
                        rlog.reply("filter", null);

                    if (qctx.trust_msg) |trust_msg| {
                        if (g.verbose())
                            rlog.reply("accept", "<previous-trustdns>");
                        msg = trust_msg.msg();
                    } else {
                        // waiting for response from trust
                        qctx.flags.add(.non_china_domain);
                        return;
                    }
                }
            },
            .gfw => {
                if (qctx.flags.has(.non_china_domain)) {
                    if (g.verbose())
                        rlog.reply("accept", null);
                } else {
                    // waiting for response from china (get the verdict)
                    if (g.verbose())
                        rlog.reply(if (qctx.trust_msg == null) "waiting" else "ignore", null);
                    if (qctx.trust_msg == null)
                        qctx.trust_msg = rmsg.ref();
                    return;
                }
            },
            else => unreachable,
        }
    } else {
        if (g.verbose())
            rlog.reply("accept", null);
    };

    // must be deleted from the `qctx_list` immediately, see the `check_timeout()`
    _qctx_list.del_nofree(qctx);

    // AAAA filter (empty the reply)
    var ip_filtered = false;
    if (qtype == c.DNS_TYPE_AAAA) {
        if (g.noaaaa_rule.by_ip_test(msg, qnamelen, ip_test_res)) |rule| {
            if (g.verbose()) rlog.noaaaa(rule);
            msg = dns.empty_reply(msg, qnamelen);
            ip_filtered = true;
        }
    }

    // add the ip to the ipset/nftset
    if (is_qtype_A_AAAA and !ip_filtered and qctx.tag != .none)
        if (groups.get_ipset_addctx(qctx.tag)) |addctx| {
            if (g.verbose()) rlog.add_ip(groups.get_ipset_name46(qctx.tag).cstr());
            dns.add_ip(msg, qnamelen, addctx);
        };

    // [async] send reply to client
    if (!qctx.flags.has(.from_local))
        send_reply(msg, qctx.fdobj, &qctx.src_addr, qctx.bufsz, qctx.id, qctx.flags);

    // add to cache (may modify the msg)
    // must come after the `send_reply()`
    var ttl: i32 = undefined;
    if (cache.add(msg, qnamelen, &ttl))
        if (g.verbose()) rlog.cache(ttl, msg.len);

    // must be at the end
    qctx.free();
}

/// [async]
fn send_reply(msg: []const u8, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, bufsz: u16, id: c.be16, qflags: QueryCtx.Flags) void {
    var iov = [_]cc.iovec_t{
        undefined, // for tcp
        .{
            .iov_base = std.mem.asBytes(&cc.to_u16(id)),
            .iov_len = 2,
        },
        .{
            .iov_base = cc.remove_const(msg[2..].ptr),
            .iov_len = msg[2..].len,
        },
    };

    if (qflags.has(.from_tcp)) {
        iov[0] = .{
            .iov_base = std.mem.asBytes(&cc.htons(cc.to_u16(msg.len))),
            .iov_len = 2,
        };
        const msghdr = cc.msghdr_t{
            .msg_iov = &iov,
            .msg_iovlen = iov.len,
        };
        if (g.evloop.sendmsg(fdobj, &msghdr, 0) != null) return;
    } else {
        // from udp
        if (msg.len > bufsz) {
            const tc_msg = dns.truncate(msg); // ptr to static buffer
            iov[2] = .{
                .iov_base = tc_msg[2..].ptr,
                .iov_len = tc_msg[2..].len,
            };
        }
        const msghdr = cc.msghdr_t{
            .msg_name = cc.remove_const(src_addr),
            .msg_namelen = src_addr.len(),
            .msg_iov = iov[1..],
            .msg_iovlen = iov[1..].len,
        };
        if (cc.sendmsg(fdobj.fd, &msghdr, 0) != null) return;
    }

    // error handling

    const proto: cc.ConstStr = if (qflags.has(.from_tcp)) "tcp" else "udp";

    var ip: cc.IpStrBuf = undefined;
    var port: u16 = undefined;
    src_addr.to_text(&ip, &port);

    log.warn(
        @src(),
        "reply(id:%u, size:%zu) to %s://%s#%u failed: (%d) %m",
        .{ cc.to_uint(dns.get_id(msg)), msg.len, proto, &ip, cc.to_uint(port), cc.errno() },
    );
}

/// [async]
fn send_reply_xxx(msg: []u8, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, qflags: QueryCtx.Flags) void {
    if (msg.len >= dns.header_len())
        _ = dns.empty_reply(msg, 0);

    if (qflags.has(.from_tcp))
        g.evloop.send(fdobj, msg, 0) orelse {} // TODO: error handling
    else
        _ = cc.sendto(fdobj.fd, msg, 0, src_addr) orelse 0; // TODO: error handling
}

// =========================================================================

/// qctx will be free()
fn on_timeout(qctx: *const QueryCtx) void {
    if (g.verbose()) {
        const from: cc.ConstStr = if (qctx.flags.has(.from_local))
            "local"
        else if (qctx.flags.has(.from_tcp))
            "tcp"
        else
            "udp";

        var ip: cc.IpStrBuf = undefined;
        var port: u16 = undefined;
        if (qctx.flags.has(.from_local)) {
            ip[0] = '0';
            ip[1] = 0;
            port = 0;
        } else {
            qctx.src_addr.to_text(&ip, &port);
        }

        log.warn(
            @src(),
            "query(qid:%u, id:%u, tag:%s) from %s://%s#%u [timeout]",
            .{ cc.to_uint(qctx.qid), cc.to_uint(qctx.id), qctx.tag.name(), from, &ip, cc.to_uint(port) },
        );
    }

    _qctx_list.del(qctx);
}

pub fn check_timeout() c_int {
    const now = cc.time();
    var it = _qctx_list.list.iterator();
    while (it.next()) |qctx_node| {
        const qctx = QueryCtx.from_list_node(qctx_node);
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

noinline fn do_start(ip: cc.ConstStr, socktype: net.SockType) void {
    const err_op: cc.ConstStr = e: {
        const addr = cc.SockAddr.from_text(ip, g.bind_port);
        const fd = net.new_listen_sock(addr.family(), socktype) orelse break :e "socket";
        cc.bind(fd, &addr) orelse break :e "bind";
        switch (socktype) {
            .tcp => {
                cc.listen(fd, 1024) orelse break :e "listen";
                co.create(listen_tcp, .{ fd, ip });
            },
            .udp => {
                co.create(listen_udp, .{ fd, ip });
            },
        }
        return;
    };

    // error handling
    log.err(
        @src(),
        "%s(%s, %s#%u) failed: (%d) %m",
        .{ err_op, socktype.str(), ip, cc.to_uint(g.bind_port), cc.errno() },
    );
    cc.exit(1);
}

pub fn start() void {
    _qctx_list.init();

    for (g.bind_ips.items()) |ip| {
        if (g.flags.has(.bind_tcp))
            do_start(ip, .tcp);
        if (g.flags.has(.bind_udp))
            do_start(ip, .udp);
    }
}
