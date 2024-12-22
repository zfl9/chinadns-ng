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
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const Node = @import("Node.zig");
const verdict_cache = @import("verdict_cache.zig");
const local_rr = @import("local_rr.zig");
const assert = std.debug.assert;

comptime {
    // @compileLog("sizeof(QueryCtx):", @sizeOf(QueryCtx), "alignof(QueryCtx):", @alignOf(QueryCtx));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
    // @compileLog("sizeof(Query.Flags):", @sizeOf(Query.Flags), "bit_sizeof(Query.Flags):", @bitSizeOf(Query.Flags));
}

const Query = struct {
    // linked list
    node: Node = undefined,

    // alignment: 8/4
    fdobj: *EvLoop.Fd, // requester's fdobj
    trust_msg: ?*RcMsg = null,
    req_time: u64, // monotonic time (ms)

    // alignment: 4
    src_addr: cc.SockAddr,

    // alignment: 2
    qid: u16,
    id: c.be16, // original id
    bufsz: u16, // requester's receive bufsz

    // alignment: 1
    tag: Tag,
    flags: Flags,

    pub const Flags = packed struct {
        from: enum(u2) { udp, tcp, local }, // from.local: {fdobj, src_addr} = undefined
        verdict: enum(u2) { nil, is_china, non_china } = .nil, // [tag:none] `?bool` is better, but can't be used in packed struct

        /// query from udp/tcp client
        pub inline fn from_client(self: Flags) bool {
            return self.from != .local;
        }

        pub inline fn get_from_str(self: Flags) cc.ConstStr {
            return switch (self.from) {
                .udp => "udp",
                .tcp => "tcp",
                .local => "local",
            };
        }
    };

    fn new(qid: u16, id: c.be16, bufsz: u16, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, tag: Tag, flags: Flags) *Query {
        const self = g.allocator.create(Query) catch unreachable;

        self.* = .{
            .qid = qid,
            .id = id,
            .bufsz = bufsz,
            .fdobj = if (flags.from_client()) fdobj.ref() else undefined,
            .src_addr = if (flags.from_client()) src_addr.* else undefined,
            .tag = tag,
            .flags = flags,
            .req_time = g.evloop.time,
        };

        return self;
    }

    fn free(self: *const Query) void {
        if (self.flags.from_client())
            self.fdobj.unref();

        if (self.trust_msg) |msg| {
            assert(msg.is_unique());
            msg.unref();
        }

        g.allocator.destroy(self);
    }

    pub fn from_node(node: *Node) *Query {
        return @fieldParentPtr(Query, "node", node);
    }

    pub fn get_deadline(self: *const Query) u64 {
        return self.req_time + cc.to_u64(g.upstream_timeout) * 1000;
    }

    /// remove from query_list and free()
    pub fn on_timeout(self: *Query) void {
        if (g.verbose()) {
            const from = self.flags.get_from_str();

            var ip: cc.IpStrBuf = undefined;
            var port: u16 = undefined;

            if (self.flags.from_client()) {
                self.src_addr.to_text(&ip, &port);
            } else {
                ip[0] = '0';
                ip[1] = 0;
                port = 0;
            }

            log.warn(
                @src(),
                "query(qid:%u, id:%u, tag:%s) from %s://%s#%u [timeout]",
                .{ cc.to_uint(self.qid), cc.to_uint(self.id), self.tag.name(), from, &ip, cc.to_uint(port) },
            );
        }

        _query_list.del(self);
    }

    pub const List = struct {
        map: std.AutoHashMapUnmanaged(u16, *Query),
        list: Node,
        last_qid: u16 = 0,

        pub fn init(self: *List) void {
            self.* = .{
                .map = .{},
                .list = undefined,
            };
            self.list.init();
        }

        pub fn count(self: *const List) usize {
            return self.map.count();
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
        ) ?*Query {
            const src = @src();

            if (self.count() >= std.math.maxInt(u16) + 1) {
                log.warn(src, "too many pending queries: %zu", .{self.count()});
                return null;
            }

            var i: u32 = 0;
            const qid = while (i < 10) : (i += 1) {
                self.last_qid +%= 1;
                const qid = self.last_qid;
                if (!self.map.contains(qid))
                    break qid;
            } else {
                log.warn(src, "no available qid. pending queries: %zu", .{self.count()});
                return null;
            };

            const id = dns.get_id(msg);
            dns.set_id(msg, qid);

            const q = Query.new(qid, id, bufsz, fdobj, src_addr, tag, flags);

            self.map.putNoClobber(g.allocator, qid, q) catch unreachable;
            self.list.link_to_tail(&q.node);

            return q;
        }

        /// [on_reply] msg.id => original_id
        pub fn get(self: *const List, msg: []u8) ?*Query {
            const qid = dns.get_id(msg);
            const q = self.map.get(qid) orelse return null;
            dns.set_id(msg, q.id);
            return q;
        }

        /// remove from list and free(q)
        pub fn del(self: *List, q: *Query) void {
            assert(self.map.remove(q.qid));
            q.node.unlink();
            q.free();
        }
    };
};

/// qid => *query(q)
var _query_list: Query.List = undefined;

// =======================================================================================================

fn tcp_listener(fd: c_int, ip: cc.ConstStr, port: u16) void {
    defer co.terminate(@frame(), @frameSize(tcp_listener));

    const fdobj = EvLoop.Fd.new(fd);
    defer fdobj.free();

    while (true) {
        var src_addr: cc.SockAddr = undefined;
        const conn_fd = g.evloop.accept(fdobj, &src_addr) orelse {
            log.warn(@src(), "accept(fd:%d, %s#%u) failed: (%d) %m", .{ fd, ip, cc.to_uint(port), cc.errno() });
            continue;
        };
        net.setup_tcp_conn_sock(conn_fd);
        co.start(tcp_server, .{ conn_fd, &src_addr });
    }
}

fn tcp_server(fd: c_int, p_src_addr: *const cc.SockAddr) void {
    defer co.terminate(@frame(), @frameSize(tcp_server));

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
            g.evloop.read(fdobj, std.mem.asBytes(&len)) catch |err| switch (err) {
                error.eof => return,
                error.errno => break :e .{ .op = "read_len" },
            };

            len = cc.ntohs(len);
            if (len < 1 or len > c.DNS_QMSG_MAXSIZE) {
                log.warn(src, "invalid message length: %u", .{cc.to_uint(len)});
                break :e .{ .op = "read_len", .msg = "invalid len" };
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
            g.evloop.read(fdobj, qmsg.msg()) catch |err| switch (err) {
                error.eof => break :e .{ .op = "read_msg", .msg = "connection closed" },
                error.errno => break :e .{ .op = "read_msg" },
            };

            nosuspend on_query(qmsg, fdobj, &src_addr, .{ .from = .tcp });
        }
    };

    // error handling

    if (!g.verbose()) src_addr.to_text(&ip, &port);

    if (e.msg) |msg|
        log.warn(src, "%s(fd:%d, %s#%u) failed: %s", .{ e.op, fd, &ip, cc.to_uint(port), msg })
    else
        log.warn(src, "%s(fd:%d, %s#%u) failed: (%d) %m", .{ e.op, fd, &ip, cc.to_uint(port), cc.errno() });
}

fn udp_server(fd: c_int, ip: cc.ConstStr, port: u16) void {
    defer co.terminate(@frame(), @frameSize(udp_server));

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
        const len = g.evloop.read_udp(fdobj, qmsg.buf(), &src_addr) orelse {
            log.warn(@src(), "recvfrom(fd:%d, %s#%u) failed: (%d) %m", .{ fd, ip, cc.to_uint(port), cc.errno() });
            continue;
        };
        qmsg.len = cc.to_u16(len);

        nosuspend on_query(qmsg, fdobj, &src_addr, .{ .from = .udp });
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

    pub noinline fn noaaaa(self: *const QueryLog, rule: cc.ConstStr) void {
        log.info(
            @src(),
            "query(id:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.id), self.tag.name(), self.name, rule },
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

    pub noinline fn add_ip(self: *const QueryLog, setnames: cc.ConstStr) void {
        log.info(
            @src(),
            "add answer_ip(id:%u, tag:%s, qtype:%u, '%s') to %s",
            .{ cc.to_uint(self.id), self.tag.name(), cc.to_uint(self.qtype), self.name, setnames },
        );
    }

    pub noinline fn forward(self: *const QueryLog, q: *const Query, to_tag: Tag) void {
        const from = q.flags.get_from_str();

        const to: cc.ConstStr = switch (to_tag) {
            .chn => "china",
            .gfw => "trust",
            else => to_tag.name(),
        };

        log.info(
            @src(),
            "forward query(qid:%u, from:%s, '%s') to %s group",
            .{ cc.to_uint(q.qid), from, self.name, to },
        );
    }
};

/// nosuspend
fn on_query(qmsg: *RcMsg, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, in_qflags: Query.Flags) void {
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
        return send_reply_bad(msg, fdobj, src_addr, qflags); // make the requester happy
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

    const bufsz = switch (qflags.from) {
        .udp => dns.get_bufsz(msg, qnamelen),
        .tcp => cc.to_u16(c.DNS_MSG_MAXSIZE),
        .local => unreachable,
    };

    // tag:null filter
    if (tag.is_null()) {
        if (g.verbose()) qlog.filter(.tag_null);
        const rmsg = dns.empty_reply(msg, qnamelen);
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // AAAA filter
    if (qtype == c.DNS_TYPE_AAAA) {
        const filter = groups.get_ip6_filter(tag);
        if (filter.filter_query()) {
            if (g.verbose()) qlog.noaaaa(filter.rule_desc().?);
            const rmsg = dns.empty_reply(msg, qnamelen);
            return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
        }
    }

    // qtype filter
    if (std.mem.indexOfScalar(u16, g.filter_qtypes, qtype) != null) {
        if (g.verbose()) qlog.filter(.qtype);
        const rmsg = dns.empty_reply(msg, qnamelen);
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // check the local records
    var answer_n: u16 = undefined;
    if (local_rr.find_answer(msg, qnamelen, &answer_n)) |answer| {
        if (g.verbose())
            qlog.local_rr(answer_n, answer.len);

        const len = dns.header_len() + dns.question_len(qnamelen) + answer.len;
        const rmsg = cc.static_buf(len); // global static buffer
        dns.make_reply(rmsg, msg, qnamelen, answer, answer_n);

        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // for upstream_group.send()
    var udpi = qflags.from == .udp;

    // check the cache
    var ttl: i32 = undefined;
    var ttl_r: i32 = undefined;
    var add_ip: bool = undefined;
    if (cache.get(msg, qnamelen, &ttl, &ttl_r, &add_ip)) |cache_msg| {
        if (g.verbose()) qlog.cache(cache_msg, ttl);

        // add the ip to the ipset/nftset
        if (add_ip and tag != .none and (qtype == c.DNS_TYPE_A or qtype == c.DNS_TYPE_AAAA)) {
            if (groups.get_ipset_addctx(tag)) |addctx| {
                if (g.verbose()) qlog.add_ip(groups.get_ipset_name46(tag).cstr());
                dns.add_ip(cache_msg, qnamelen, addctx);
            }
        }

        // sync && nosuspend
        send_reply(cache_msg, fdobj, src_addr, bufsz, id, qflags);

        if (ttl > ttl_r)
            return;

        // refresh cache in the background
        if (g.verbose())
            qlog.refresh(ttl);

        // avoid receiving truncated response
        if (udpi and cache_msg.len + 30 > c.DNS_EDNS_MINSIZE)
            udpi = false; // change to tcpi://

        // mark the query
        qflags.from = .local;
    }

    // [verdict cache]
    var tagnone_to_china = true;
    var tagnone_to_trust = true;

    // verdict cache for tag:none domain
    if (tag == .none) {
        if (verdict_cache.get(msg, qnamelen)) |is_china_domain| {
            if (is_china_domain) {
                tagnone_to_trust = false;
                qflags.verdict = .is_china;
            } else {
                tagnone_to_china = false;
                qflags.verdict = .non_china;
            }
        }
    }

    const q = _query_list.add(
        msg,
        fdobj,
        src_addr,
        bufsz,
        tag,
        qflags,
    ) orelse return;

    if (tag == .none) {
        if (tagnone_to_china)
            send_query(.chn, qmsg, udpi, q, &qlog);
        if (tagnone_to_trust)
            send_query(.gfw, qmsg, udpi, q, &qlog);
    } else {
        send_query(tag, qmsg, udpi, q, &qlog);
    }
}

/// nosuspend
fn send_query(to_tag: Tag, qmsg: *RcMsg, udpi: bool, q: *const Query, qlog: *const QueryLog) void {
    if (g.verbose()) qlog.forward(q, to_tag);
    nosuspend groups.get_upstream_group(to_tag).send(qmsg, udpi);
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

    pub noinline fn noaaaa(self: *const ReplyLog, rule: cc.ConstStr) void {
        log.info(
            @src(),
            "reply(qid:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.qid), self.tag_name(), self.name, rule },
        );
    }

    pub noinline fn china_noip(self: *const ReplyLog) void {
        const action = cc.b2s(g.flags.noip_as_chnip, "accept", "filter");
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
            break :b g.flags.noip_as_chnip;
        },
        .other_case => dns.is_tc(msg), // `truncated` or `rcode != 0`
    };
}

/// [nosuspend]
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

    const q = _query_list.get(msg) orelse {
        if (g.verbose())
            rlog.reply("ignore", null);
        return;
    };

    if (g.verbose())
        rlog.tag = q.tag;

    // NOTE: udp resolver will auto retry with TCP
    if (q.flags.from != .udp and dns.is_tc(msg)) {
        if (g.verbose())
            rlog.reply("drop_tc", null);
        return;
    }

    var ip_test_res: ?dns.TestIpResult = null;

    // end the query context ?
    if (q.tag == .none and is_qtype_A_AAAA) {
        switch (upstream.tag) {
            .chn => {
                if (q.flags.verdict == .is_china or use_china_reply(msg, qnamelen, &ip_test_res, &rlog)) {
                    if (g.verbose()) {
                        rlog.reply("accept", null);

                        if (q.trust_msg != null)
                            rlog.reply("filter", "<previous-trustdns>");
                    }
                } else {
                    if (g.verbose())
                        rlog.reply("filter", null);

                    if (q.trust_msg) |trust_msg| {
                        if (g.verbose())
                            rlog.reply("accept", "<previous-trustdns>");
                        msg = trust_msg.msg();
                    } else {
                        // waiting for response from trust
                        q.flags.verdict = .non_china;
                        return;
                    }
                }
            },
            .gfw => {
                if (q.flags.verdict == .non_china) {
                    if (g.verbose())
                        rlog.reply("accept", null);
                } else {
                    // waiting for response from china (get the verdict)
                    if (g.verbose())
                        rlog.reply(if (q.trust_msg == null) "waiting" else "ignore", null);
                    if (q.trust_msg == null)
                        q.trust_msg = rmsg.ref();
                    return;
                }
            },
            else => unreachable,
        }
    } else {
        if (g.verbose())
            rlog.reply("accept", null);
    }

    // AAAA filter (empty the reply)
    var ip_filtered = false;
    if (qtype == c.DNS_TYPE_AAAA) {
        const filter = groups.get_ip6_filter(q.tag);
        if (filter.filter_reply(msg, qnamelen, ip_test_res)) {
            if (g.verbose()) rlog.noaaaa(filter.rule_desc().?);
            msg = dns.empty_reply(msg, qnamelen);
            ip_filtered = true;
        }
    }

    // add the ip to the ipset/nftset
    if (is_qtype_A_AAAA and !ip_filtered and q.tag != .none)
        if (groups.get_ipset_addctx(q.tag)) |addctx| {
            if (g.verbose()) rlog.add_ip(groups.get_ipset_name46(q.tag).cstr());
            dns.add_ip(msg, qnamelen, addctx);
        };

    // [sync && nosuspend] send reply to client
    if (q.flags.from_client())
        send_reply(msg, q.fdobj, &q.src_addr, q.bufsz, q.id, q.flags);

    // add to cache (may modify the msg)
    // must come after the `send_reply()`
    var ttl: i32 = undefined;
    if (cache.add(msg, qnamelen, &ttl))
        if (g.verbose()) rlog.cache(ttl, msg.len);

    // must be at the end
    _query_list.del(q);
}

// =========================================================================

/// [sync && nosuspend]
fn send_reply(msg: []const u8, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, bufsz: u16, id: c.be16, qflags: Query.Flags) void {
    var iovec = [_]cc.iovec_t{
        undefined, // for tcp (length field)
        .{
            .iov_base = std.mem.asBytes(&cc.to_u16(id)),
            .iov_len = 2,
        },
        .{
            .iov_base = cc.remove_const(msg[2..].ptr),
            .iov_len = msg[2..].len,
        },
    };

    switch (qflags.from) {
        .udp => {
            if (msg.len > bufsz) {
                const tc_msg = dns.truncate(msg); // global static buffer
                iovec[2] = .{
                    .iov_base = tc_msg[2..].ptr,
                    .iov_len = tc_msg[2..].len,
                };
            }
            const msghdr = cc.msghdr_t{
                .msg_name = cc.remove_const(src_addr),
                .msg_namelen = src_addr.len(),
                .msg_iov = iovec[1..],
                .msg_iovlen = iovec[1..].len,
            };
            _ = cc.sendmsg(fdobj.fd, &msghdr, 0);
        },
        .tcp => {
            iovec[0] = .{
                .iov_base = std.mem.asBytes(&cc.htons(cc.to_u16(msg.len))),
                .iov_len = 2,
            };
            _tcp_sender.send(fdobj, &iovec);
        },
        .local => unreachable,
    }
}

/// [sync && nosuspend] for bad query msg
fn send_reply_bad(msg: []u8, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, qflags: Query.Flags) void {
    if (msg.len >= dns.header_len())
        _ = dns.empty_reply(msg, 0);

    switch (qflags.from) {
        .udp => {
            _ = cc.sendto(fdobj.fd, msg, 0, src_addr);
        },
        .tcp => {
            var iovec = [_]cc.iovec_t{
                .{
                    .iov_base = std.mem.asBytes(&cc.htons(cc.to_u16(msg.len))),
                    .iov_len = 2,
                },
                .{
                    .iov_base = msg.ptr,
                    .iov_len = msg.len,
                },
            };
            _tcp_sender.send(fdobj, &iovec);
        },
        .local => unreachable,
    }
}

// =========================================================================

var _tcp_sender: TcpSender = undefined;

const TcpSender = struct {
    list: Node, // queue head
    pop_co: ?anyframe = null, // suspending on pop()
    sending_time: u64 = 0, // start time (ms)
    sending_fdobj: *EvLoop.Fd = undefined,

    const TaskNode = struct {
        node: Node, // queue node
        task: Task,

        pub fn from_node(node: *Node) *TaskNode {
            return @fieldParentPtr(TaskNode, "node", node);
        }
    };

    const Task = struct {
        fdobj: *EvLoop.Fd, // raw_ptr (sync_ctx) | referenced (async_ctx)
        data: union(enum) {
            iovec: []cc.iovec_t, // raw_ptr (sync_ctx)
            bytes: []const u8, // copied (async_ctx)
        },

        pub fn in_sync_ctx(self: *const Task) bool {
            return self.data == .iovec;
        }

        pub fn ref(self: *Task) void {
            assert(self.in_sync_ctx());
            _ = self.fdobj.ref();
            const bytes = cc.iovec_dupe(self.data.iovec);
            self.data = .{ .bytes = bytes };
        }

        pub fn unref(self: *const Task) void {
            assert(!self.in_sync_ctx());
            self.fdobj.unref();
            g.allocator.free(self.data.bytes);
        }
    };

    pub fn init(self: *TcpSender) void {
        self.* = .{
            .list = undefined,
        };
        self.list.init();

        co.start(sender, .{self});
    }

    fn sender(self: *TcpSender) void {
        defer co.terminate(@frame(), @frameSize(sender));

        while (true) {
            var task: Task = undefined;
            self.pop(&task);

            const src = @src();
            var logging = false;

            if (task.in_sync_ctx()) {
                const total = cc.iovec_len(task.data.iovec);

                // try sending it directly (non-blocking)
                const sent = cc.writev(task.fdobj.fd, task.data.iovec) orelse switch (cc.errno()) {
                    c.EAGAIN => 0,
                    else => {
                        on_error(task.fdobj);
                        continue;
                    },
                };

                // in the vast majority of cases it can be sent all at once
                if (sent == total) continue;

                // very unfortunately
                assert(sent < total);
                cc.iovec_skip(&task.data.iovec, sent);

                task.ref();

                log.warn(
                    src,
                    "send(fd:%d, total:%zu, sent:%zu) blocking ...",
                    .{ task.fdobj.fd, total, sent },
                );
                logging = true;
            }

            self.sending_time = g.evloop.time;
            self.sending_fdobj = task.fdobj;

            g.evloop.write(task.fdobj, task.data.bytes) orelse on_error(task.fdobj);

            if (logging)
                log.warn(
                    src,
                    "send(fd:%d, bytes:%zu, time:%llu) blocking end",
                    .{ task.fdobj.fd, task.data.bytes.len, cc.to_ulonglong(g.evloop.time - self.sending_time) },
                );

            self.sending_time = 0;
            self.sending_fdobj = undefined;

            task.unref();
        }
    }

    fn on_error(fdobj: *const EvLoop.Fd) void {
        log.warn(@src(), "send(fd:%d) failed: (%d) %m", .{ fdobj.fd, cc.errno() });
    }

    pub fn get_deadline(self: *const TcpSender) ?u64 {
        if (self.sending_time > 0)
            return self.sending_time + 100; // 100ms
        return null;
    }

    pub fn on_timeout(self: *TcpSender) void {
        assert(self.sending_time > 0);
        self.sending_fdobj.cancel();
    }

    fn co_data() *Task {
        return co.data(Task);
    }

    fn pop(self: *TcpSender, task: *Task) void {
        if (self.list.is_empty()) {
            self.pop_co = @frame();
            suspend {}
            self.pop_co = null;

            task.* = co_data().*;
        } else {
            const task_node = TaskNode.from_node(self.list.head());
            task_node.node.unlink();

            task.* = task_node.task;

            g.allocator.destroy(task_node);
        }
    }

    pub fn send(self: *TcpSender, fdobj: *EvLoop.Fd, iovec: []cc.iovec_t) void {
        if (self.pop_co) |pop_co| {
            assert(self.list.is_empty());
            co_data().* = .{
                .fdobj = fdobj,
                .data = .{ .iovec = iovec },
            };
            co.do_resume(pop_co);
        } else {
            const task_node = g.allocator.create(TaskNode) catch unreachable;
            task_node.* = .{
                .task = .{
                    .fdobj = fdobj,
                    .data = .{ .iovec = iovec },
                },
                .node = undefined,
            };
            task_node.task.ref();
            self.list.link_to_tail(&task_node.node);
        }
    }
};

// =========================================================================

pub fn check_timeout(timer: *EvLoop.Timer) void {
    // check tcp_sender
    while (_tcp_sender.get_deadline()) |deadline| {
        if (timer.check_deadline(deadline))
            nosuspend _tcp_sender.on_timeout()
        else
            break;
    }

    // check query_list
    var it = _query_list.list.iterator();
    while (it.next()) |q_node| {
        const q = Query.from_node(q_node);
        if (timer.check_deadline(q.get_deadline()))
            nosuspend q.on_timeout()
        else
            break;
    }
}

// =========================================================================

noinline fn do_start(ip: cc.ConstStr, port: u16, socktype: net.SockType) void {
    const err_op: cc.ConstStr = e: {
        const addr = cc.SockAddr.from_text(ip, port);
        const fd = net.new_listen_sock(addr.family(), socktype) orelse break :e "socket";
        cc.bind(fd, &addr) orelse break :e "bind";
        switch (socktype) {
            .tcp => {
                cc.listen(fd, 1024) orelse break :e "listen";
                co.start(tcp_listener, .{ fd, ip, port });
            },
            .udp => {
                co.start(udp_server, .{ fd, ip, port });
            },
        }
        return;
    };

    // error handling
    log.err(
        @src(),
        "%s(%s, %s#%u) failed: (%d) %m",
        .{ err_op, socktype.str(), ip, cc.to_uint(port), cc.errno() },
    );
    cc.exit(1);
}

pub fn start() void {
    _query_list.init();
    _tcp_sender.init();

    for (g.bind_ips.items()) |ip| {
        for (g.bind_ports) |p| {
            if (p.tcp)
                do_start(ip, p.port, .tcp);
            if (p.udp)
                do_start(ip, p.port, .udp);
        }
    }
}
