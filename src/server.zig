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
const Upstream = @import("Upstream.zig");
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const ListNode = @import("ListNode.zig");
const flags_op = @import("flags_op.zig");
const verdict_cache = @import("verdict_cache.zig");
const local_dns_rr = @import("local_dns_rr.zig");
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
    name_tag: dnl.Tag,
    flags: Flags,

    pub const Flags = enum(u8) {
        from_local = 1 << 0, // {fdobj, src_addr} have undefined values (priority over other `.from_*`)
        from_tcp = 1 << 1,
        is_china_domain = 1 << 2, // tag:none [verdict]
        non_china_domain = 1 << 3, // tag:none [verdict]
        _, // non-exhaustive enum
        usingnamespace flags_op.get(Flags);
    };

    fn new(qid: u16, id: c.be16, bufsz: u16, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, name_tag: dnl.Tag, flags: Flags) *QueryCtx {
        const from_local = flags.has(.from_local);

        const self = g.allocator.create(QueryCtx) catch unreachable;

        self.* = .{
            .qid = qid,
            .id = id,
            .bufsz = bufsz,
            .fdobj = if (!from_local) fdobj.ref() else undefined,
            .src_addr = if (!from_local) src_addr.* else undefined,
            .name_tag = name_tag,
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
            name_tag: dnl.Tag,
            bufsz: u16,
            flags: Flags,
            /// out param
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

            const qctx = QueryCtx.new(qid, id, bufsz, fdobj, src_addr, name_tag, flags);

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

            on_query(qmsg, fdobj, &src_addr, .from_tcp);
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

        on_query(qmsg, fdobj, &src_addr, QueryCtx.Flags.empty());
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
            "query(id:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
            .{ cc.to_uint(self.id), self.tag.desc(), self.name, by_rule },
        );
    }

    pub noinline fn cache(self: *const QueryLog, cache_msg: []const u8, ttl: i32) void {
        log.info(
            @src(),
            "hit cache(id:%u, tag:%s, qtype:%u, '%s') size:%zu ttl:%ld",
            .{ cc.to_uint(self.id), self.tag.desc(), cc.to_uint(self.qtype), self.name, cache_msg.len, cc.to_long(ttl) },
        );
    }

    pub noinline fn refresh(self: *const QueryLog, ttl: i32) void {
        log.info(
            @src(),
            "refresh cache(id:%u, tag:%s, qtype:%u, '%s') ttl:%ld",
            .{ cc.to_uint(self.id), self.tag.desc(), cc.to_uint(self.qtype), self.name, cc.to_long(ttl) },
        );
    }

    pub noinline fn forward(self: *const QueryLog, qctx: *const QueryCtx, group: cc.ConstStr) void {
        const from: cc.ConstStr = if (qctx.flags.has(.from_local))
            "local"
        else if (qctx.flags.has(.from_tcp))
            "tcp"
        else
            "udp";

        log.info(
            @src(),
            "forward query(qid:%u, from:%s, '%s') to %s group",
            .{ cc.to_uint(qctx.qid), from, self.name, group },
        );
    }
};

fn on_query(qmsg: *RcMsg, fdobj: *EvLoop.Fd, src_addr: *const cc.SockAddr, in_qflags: QueryCtx.Flags) void {
    const msg = qmsg.msg();
    var qflags = in_qflags;

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose or !dnl.is_empty()) &ascii_namebuf else null;
    var qnamelen: c_int = undefined;

    if (!dns.check_query(msg, p_ascii_namebuf, &qnamelen)) {
        log.err(@src(), "dns.check_query(fd:%d) failed: invalid query msg", .{fdobj.fd});
        return;
    }

    const id = dns.get_id(msg);
    const name_tag = dnl.get_name_tag(&ascii_namebuf, dns.ascii_namelen(qnamelen));
    const qtype = dns.get_qtype(msg, qnamelen);

    var querylog: QueryLog = if (g.verbose) .{
        .src_ip = undefined,
        .src_port = undefined,
        .id = id,
        .qtype = qtype,
        .tag = name_tag,
        .name = &ascii_namebuf,
    } else undefined;

    if (g.verbose) {
        src_addr.to_text(&querylog.src_ip, &querylog.src_port);

        querylog.query();
    }

    const bufsz = if (qflags.has(.from_tcp))
        cc.to_u16(c.DNS_MSG_MAXSIZE)
    else
        dns.get_bufsz(msg, qnamelen);

    // [AAAA filter] or [verdict cache]
    var tagnone_china = true;
    var tagnone_trust = true;

    // AAAA filter
    if (qtype == c.DNS_TYPE_AAAA)
        if (g.noaaaa_rule.filter(name_tag, &tagnone_china, &tagnone_trust)) |by_rule| {
            var rmsg = msg;
            rmsg.len = dns.empty_reply(rmsg, qnamelen);

            if (g.verbose) querylog.noaaaa(by_rule);
            return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
        };

    assert(tagnone_china or tagnone_trust);

    // check the local records
    var answer_n: u16 = undefined;
    if (local_dns_rr.find_answer(msg, qnamelen, &answer_n)) |answer| {
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
        return send_reply(rmsg, fdobj, src_addr, bufsz, id, qflags);
    }

    // for upstream_group.send()
    var in_proto: Upstream.Proto = if (qflags.has(.from_tcp)) .tcpin else .udpin;

    // check the cache
    var ttl: i32 = undefined;
    if (cache.get(msg, qnamelen, &ttl)) |cache_msg| {
        // because send_reply is async func
        cache.ref(cache_msg);
        defer cache.unref(cache_msg);

        if (g.verbose) querylog.cache(cache_msg, ttl);
        send_reply(cache_msg, fdobj, src_addr, bufsz, id, qflags);

        if (ttl > g.cache_refresh)
            return;

        // refresh cache in the background
        if (g.verbose)
            querylog.refresh(ttl);

        // avoid receiving truncated response
        if (in_proto == .udpin and cache_msg.len + 30 > c.DNS_EDNS_MINSIZE)
            in_proto = .tcpin;

        // mark the qctx
        qflags.add(.from_local);
    }

    // verdict cache for tag:none domain
    if (name_tag == .none and tagnone_china and tagnone_trust) {
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

    assert(tagnone_china or tagnone_trust);

    var first_query: bool = undefined;

    const qctx = _qctx_list.add(
        msg,
        fdobj,
        src_addr,
        name_tag,
        bufsz,
        qflags,
        &first_query,
    ) orelse return;

    if (name_tag == .chn or (name_tag == .none and tagnone_china)) {
        if (g.verbose) querylog.forward(qctx, "china");
        nosuspend g.china_group.send(qmsg, in_proto, first_query);
    }

    if (name_tag == .gfw or (name_tag == .none and tagnone_trust)) {
        if (g.verbose) querylog.forward(qctx, "trust");
        nosuspend g.trust_group.send(qmsg, in_proto, first_query);
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
            "reply(qid:%u, tag:%s, qtype:AAAA, '%s') filtered by rule: %s",
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

    pub noinline fn cache(self: *const ReplyLog, msg: []const u8, ttl: i32) void {
        log.info(
            @src(),
            "add cache(qid:%u, tag:%s, qtype:%u, '%s') size:%zu ttl:%ld",
            .{ cc.to_uint(self.qid), self.tag_desc(), cc.to_uint(self.qtype), self.name, msg.len, cc.to_long(ttl) },
        );
    }
};

/// tag:none
fn use_china_reply(rmsg: *RcMsg, qnamelen: c_int, replylog: *const ReplyLog) bool {
    const msg = rmsg.msg();
    const qtype = dns.get_qtype(msg, qnamelen);

    // only care about A/AAAA query
    if (qtype != c.DNS_TYPE_A and qtype != c.DNS_TYPE_AAAA)
        return true;

    // AAAA filter
    const only_china_path = qtype == c.DNS_TYPE_AAAA and g.noaaaa_rule.has(.trust_dns);
    if (only_china_path and !g.noaaaa_rule.has(.china_iptest))
        return true;

    const test_res = dns.test_ip(msg, qnamelen);
    if (!only_china_path) {
        // [A/AAAA]
        // get the verdict
        return switch (test_res) {
            .is_china_ip, .non_china_ip => b: {
                const accepted = test_res == .is_china_ip;
                verdict_cache.add(msg, qnamelen, accepted);
                break :b accepted;
            },
            .no_ip_found => b: {
                if (g.verbose) replylog.china_noip();
                break :b g.noip_as_chnip;
            },
            .other_case => dns.is_tc(msg), // `truncated` or `rcode != 0`
        };
    } else {
        // [AAAA] only_china_path
        if (test_res == .non_china_ip) {
            if (g.verbose) replylog.noaaaa("china_iptest");
            rmsg.len = dns.empty_reply(msg, qnamelen); // `.len` updated
        }
        return true;
    }
}

/// tag:none (trustdns returned before chinadns)
fn use_trust_reply(rmsg: *RcMsg, qnamelen: c_int, replylog: *const ReplyLog) bool {
    const msg = rmsg.msg();
    const qtype = dns.get_qtype(msg, qnamelen);

    // only care about A/AAAA query
    if (qtype != c.DNS_TYPE_A and qtype != c.DNS_TYPE_AAAA)
        return true;

    const only_trust_path = qtype == c.DNS_TYPE_AAAA and g.noaaaa_rule.has(.china_dns);
    if (!only_trust_path) {
        // [A/AAAA]
        // waiting for chinadns
        return false;
    } else {
        // [AAAA] only_trust_path
        if (g.noaaaa_rule.has(.trust_iptest)) {
            if (dns.test_ip(msg, qnamelen) == .non_china_ip) {
                if (g.verbose) replylog.noaaaa("trust_iptest");
                rmsg.len = dns.empty_reply(msg, qnamelen); // `.len` updated
            }
        }
        return true;
    }
}

pub fn on_reply(in_rmsg: *RcMsg, upstream: *const Upstream) void {
    var rmsg = in_rmsg;

    var ascii_namebuf: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
    const p_ascii_namebuf: ?[*]u8 = if (g.verbose) &ascii_namebuf else null;
    var qnamelen: c_int = undefined;

    if (!dns.check_reply(rmsg.msg(), p_ascii_namebuf, &qnamelen)) {
        log.err(@src(), "dns.check_reply(upstream:%s) failed: invalid reply msg", .{upstream.url.ptr});
        return;
    }

    const qtype = dns.get_qtype(rmsg.msg(), qnamelen);
    const is_qtype_A_AAAA = qtype == c.DNS_TYPE_A or qtype == c.DNS_TYPE_AAAA;

    var replylog: ReplyLog = if (g.verbose) .{
        .qid = dns.get_id(rmsg.msg()),
        .tag = null,
        .qtype = qtype,
        .name = &ascii_namebuf,
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
            if (qctx.name_tag == .chn or qctx.flags.has(.is_china_domain) or use_china_reply(rmsg, qnamelen, &replylog)) {
                if (g.verbose) {
                    replylog.reply("accept", null);

                    if (qctx.trust_msg != null)
                        replylog.reply("filter", "<previous-trustdns>");
                }

                if (is_qtype_A_AAAA and qctx.name_tag == .chn and !g.chnip_setnames.is_empty()) {
                    if (g.verbose)
                        replylog.add_ip(g.chnip_setnames.str);
                    dns.add_ip(rmsg.msg(), qnamelen, true);
                }
            } else {
                // tag:none && A/AAAA
                // verdict: non-china domain

                if (g.verbose)
                    replylog.reply("filter", null);

                if (qctx.trust_msg) |trust_msg| {
                    if (g.verbose)
                        replylog.reply("accept", "<previous-trustdns>");
                    rmsg = trust_msg;
                } else {
                    // waiting for trustdns
                    qctx.flags.add(.non_china_domain);
                    return;
                }
            }
        },
        .trust => {
            if (qctx.name_tag == .gfw or qctx.flags.has(.non_china_domain) or use_trust_reply(rmsg, qnamelen, &replylog)) {
                if (g.verbose)
                    replylog.reply("accept", null);

                if (is_qtype_A_AAAA and qctx.name_tag == .gfw and !g.gfwip_setnames.is_empty()) {
                    if (g.verbose)
                        replylog.add_ip(g.gfwip_setnames.str);
                    dns.add_ip(rmsg.msg(), qnamelen, false);
                }
            } else {
                // tag:none && A/AAAA
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

    const msg = rmsg.msg();

    if (!qctx.flags.has(.from_local)) {
        // request from tcp/udp client
        // may suspend the current coroutine
        send_reply(msg, qctx.fdobj, &qctx.src_addr, qctx.bufsz, qctx.id, qctx.flags);
    }

    // add to cache (may modify the msg)
    var ttl: i32 = undefined;
    if (cache.add(msg, qnamelen, &ttl))
        if (g.verbose) replylog.cache(msg, ttl);

    // must be at the end
    qctx.free();
}

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

    log.err(
        @src(),
        "reply(id:%u, size:%zu) to %s://%s#%u failed: (%d) %m",
        .{ cc.to_uint(dns.get_id(msg)), msg.len, proto, &ip, cc.to_uint(port), cc.errno() },
    );
}

// =========================================================================

/// qctx will be free()
fn on_timeout(qctx: *const QueryCtx) void {
    if (g.verbose) {
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
            .{ cc.to_uint(qctx.qid), cc.to_uint(qctx.id), qctx.name_tag.desc(), from, &ip, cc.to_uint(port) },
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
                cc.listen(fd, 256) orelse break :e "listen";
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

    for (g.bind_ips.items) |ip| {
        if (g.bind_tcp)
            do_start(ip.?, .tcp);
        if (g.bind_udp)
            do_start(ip.?, .udp);
    }
}
