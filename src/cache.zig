const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const ListNode = @import("ListNode.zig");
const CacheMsg = @import("CacheMsg.zig");
const cache_ignore = @import("cache_ignore.zig");
const log = @import("log.zig");
const assert = std.debug.assert;
const Bytes = cc.Bytes;

/// LRU
var _list: ListNode = undefined;

pub fn module_init() void {
    _list.init();
}

const map = opaque {
    var _buckets: []?*CacheMsg = &.{};
    var _nitems: usize = 0;

    fn calc_idx(hashv: c_uint) usize {
        return hashv & (_buckets.len - 1);
    }

    fn get(question: []const u8, hashv: c_uint) ?*CacheMsg {
        if (_buckets.len == 0)
            return null;

        const idx = calc_idx(hashv);

        var p: *?*CacheMsg = &_buckets[idx];
        while (p.*) |cur| : (p = &cur.next) {
            if (cur.hashv == hashv and cc.memeql(cur.question(), question)) {
                // move to head (easy to del it)
                if (cur != _buckets[idx]) {
                    p.* = cur.next;
                    cur.next = _buckets[idx];
                    _buckets[idx] = cur;
                }
                return cur;
            }
        }

        return null;
    }

    fn del(cmsg: *CacheMsg) void {
        if (_buckets.len == 0)
            return;

        const idx = calc_idx(cmsg.hashv);

        var p: *?*CacheMsg = &_buckets[idx];
        while (p.*) |cur| : (p = &cur.next) {
            if (cur == cmsg) {
                p.* = cur.next;
                _nitems -= 1;
                return;
            }
        }
    }

    /// assume not exists
    fn add(cmsg: *CacheMsg) void {
        try_resize();

        const idx = calc_idx(cmsg.hashv);

        cmsg.next = _buckets[idx];
        _buckets[idx] = cmsg;

        _nitems += 1;
    }

    const load_factor = 75;

    /// call before add()
    fn try_resize() void {
        const max_nitems = @divTrunc(_buckets.len * load_factor, 100);
        if (_nitems < max_nitems)
            return;

        const old_len = _buckets.len;
        const new_len = std.math.max(old_len << 1, 1 << 4);
        _buckets = g.allocator.realloc(_buckets, new_len) catch unreachable;

        // init
        const part2 = std.mem.sliceAsBytes(_buckets.ptr[0..new_len][old_len..]);
        @memset(part2.ptr, 0, part2.len);

        var idx: usize = 0;
        while (idx < old_len) : (idx += 1) {
            var p: *?*CacheMsg = &_buckets[idx];
            while (p.*) |cur| {
                const new_idx = calc_idx(cur.hashv);
                if (new_idx != idx) {
                    assert(new_idx >= old_len);
                    // remove from part 1
                    p.* = cur.next;
                    // add to part 2
                    cur.next = _buckets[new_idx];
                    _buckets[new_idx] = cur;
                } else {
                    p = &cur.next;
                }
            }
        }
    }
};

fn enabled() bool {
    return g.cache_size > 0;
}

fn del_nofree(cache_msg: *CacheMsg) void {
    map.del(cache_msg);
    cache_msg.list_node.unlink();
}

/// return the cached reply msg
pub fn get(qmsg: []const u8, qnamelen: c_int, p_ttl: *i32, p_ttl_r: *i32) ?[]const u8 {
    if (!enabled())
        return null;

    const question = dns.question(qmsg, qnamelen);
    const hashv = cc.calc_hashv(question);
    const cache_msg = map.get(question, hashv) orelse return null;

    // update ttl
    const ttl = cache_msg.update_ttl();
    p_ttl.* = ttl;
    p_ttl_r.* = cache_msg.ttl_r;

    if (ttl > 0 or (g.cache_stale > 0 and -ttl <= g.cache_stale)) {
        // not expired, or stale cache
        _list.move_to_head(&cache_msg.list_node);
        return cache_msg.msg();
    } else {
        // expired
        del_nofree(cache_msg);
        cache_msg.free();
        return null;
    }
}

/// call before using the cache msg
pub fn ref(msg: []const u8) void {
    return CacheMsg.from_msg(msg).ref();
}

/// call after using the cache msg (defer)
pub fn unref(msg: []const u8) void {
    return CacheMsg.from_msg(msg).unref();
}

pub fn add(msg: []const u8, qnamelen: c_int, p_ttl: *i32) bool {
    if (!enabled())
        return false;

    if (dns.is_tc(msg) or dns.get_rcode(msg) != c.DNS_RCODE_NOERROR)
        return false;

    if (cache_ignore.is_ignored(msg, qnamelen))
        return false;

    const ttl = dns.get_ttl(msg, qnamelen, g.cache_nodata_ttl) orelse return false;
    p_ttl.* = ttl;

    const cache_msg = b: {
        const question = dns.question(msg, qnamelen);
        const hashv = cc.calc_hashv(question);
        const old_msg = map.get(question, hashv);
        if (old_msg) |old| {
            // avoid duplicate add
            const old_ttl = old.get_ttl();
            if (std.math.absCast(ttl - old_ttl) <= 2) return false;
            del_nofree(old);
            break :b old.reuse_or_new(msg, qnamelen, ttl, hashv);
        } else if (map._nitems < g.cache_size) {
            break :b CacheMsg.new(msg, qnamelen, ttl, hashv);
        } else {
            const old = CacheMsg.from_list_node(_list.tail());
            del_nofree(old);
            break :b old.reuse_or_new(msg, qnamelen, ttl, hashv);
        }
    };

    map.add(cache_msg);
    _list.link_to_head(&cache_msg.list_node);

    return true;
}
