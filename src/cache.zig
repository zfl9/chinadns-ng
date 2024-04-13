const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const ListNode = @import("ListNode.zig");
const CacheMsg = @import("CacheMsg.zig");
const cache_ignore = @import("cache_ignore.zig");
const assert = std.debug.assert;
const Bytes = cc.Bytes;

/// question => CacheMsg
var _map: std.StringHashMapUnmanaged(*CacheMsg) = .{};
var _list: ListNode = undefined;

pub fn module_init() void {
    _list.init();
}

fn enabled() bool {
    return g.cache_size > 0;
}

/// return the cached reply msg
pub fn get(qmsg: []const u8, qnamelen: c_int, p_ttl: *i32, p_ttl_r: *i32) ?[]const u8 {
    if (!enabled())
        return null;

    const entry = _map.getEntry(dns.question(qmsg, qnamelen)) orelse return null;
    const cache_msg = entry.value_ptr.*;

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
        on_expired(entry.key_ptr, cache_msg);
        return null;
    }
}

fn on_expired(key_ptr: *[]const u8, cache_msg: *CacheMsg) void {
    _map.removeByPtr(key_ptr);
    cache_msg.list_node.unlink();
    cache_msg.free();
}

/// call before using the cache msg
pub fn ref(msg: []const u8) void {
    return CacheMsg.from_msg(msg).ref();
}

/// call after using the cache msg (defer)
pub fn unref(msg: []const u8) void {
    return CacheMsg.from_msg(msg).unref();
}

/// `in_msg` will be modified and copied
pub fn add(in_msg: []u8, qnamelen: c_int, p_ttl: *i32, p_sz: *usize) bool {
    var msg = in_msg;

    if (!enabled())
        return false;

    if (dns.is_tc(msg) or dns.get_rcode(msg) != c.DNS_RCODE_NOERROR)
        return false;

    if (cache_ignore.is_ignored(msg, qnamelen))
        return false;

    const ttl = dns.get_ttl(msg, qnamelen, g.cache_nodata_ttl) orelse return false;
    p_ttl.* = ttl;

    msg = dns.minimise(msg, qnamelen) orelse return false;
    p_sz.* = msg.len;

    const res = _map.getOrPut(g.allocator, dns.question(msg, qnamelen)) catch unreachable;
    if (res.found_existing) {
        // check ttl, avoid duplicate add
        const old_ttl = res.value_ptr.*.get_ttl();
        if (std.math.absCast(ttl - old_ttl) <= 2) return false;
    }

    // create cache msg
    const cache_msg = b: {
        if (res.found_existing) {
            const old = res.value_ptr.*;
            old.list_node.unlink(); // unlink from list
            break :b old.reuse_or_new(msg, qnamelen, ttl);
        } else if (_map.count() <= g.cache_size) {
            break :b CacheMsg.new(msg, qnamelen, ttl);
        } else {
            const old = CacheMsg.from_list_node(_list.tail());
            assert(_map.remove(old.question())); // remove from map
            assert(_map.count() == g.cache_size);
            old.list_node.unlink(); // unlink from list
            break :b old.reuse_or_new(msg, qnamelen, ttl);
        }
    };

    // update key/value
    res.key_ptr.* = cache_msg.question(); // ptr to `cache_msg`
    res.value_ptr.* = cache_msg;

    // link to list
    _list.link_to_head(&cache_msg.list_node);

    return true;
}
