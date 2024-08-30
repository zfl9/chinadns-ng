const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");
const str2int = @import("str2int.zig");
const assert = std.debug.assert;

/// for tag:none domains
/// [qname] => is_china_domain
var _map: std.StringHashMapUnmanaged(bool) = .{};

const GetOrPutResult = @TypeOf(_map).GetOrPutResult;

/// tag:none && has_china_path && has_trust_path
/// return `is_china_domain` from the cache
pub fn get(msg: []const u8, qnamelen: c_int) ?bool {
    if (_map.count() == 0)
        return null;

    return _map.get(dns.get_qname(msg, qnamelen));
}

/// tag:none && has_china_path && has_trust_path
pub fn add(msg: []const u8, qnamelen: c_int, is_china_domain: bool) void {
    if (g.verdict_cache_size == 0)
        return;

    const qname = dns.get_qname(msg, qnamelen);
    const res = _map.getOrPut(g.allocator, qname) catch unreachable;

    if (!res.found_existing)
        res.key_ptr.* = new_key(qname, &res);

    // update the value
    res.value_ptr.* = is_china_domain;
}

/// `_map.getOrPut() && !res.found_existing`
fn new_key(qname: []const u8, gop_res: *const GetOrPutResult) []const u8 {
    if (_map.count() > g.verdict_cache_size) {
        // remove an old cache
        var it = _map.keyIterator();
        while (it.next()) |key_ptr| {
            if (key_ptr != gop_res.key_ptr) {
                const removed_qname = cc.remove_const(key_ptr.*);

                _map.removeByPtr(key_ptr);
                assert(_map.count() == g.verdict_cache_size);

                // try reuse the removed_qname
                if (g.allocator.resize(removed_qname, qname.len)) |mem| {
                    const key = mem[0..qname.len];
                    @memcpy(key.ptr, qname.ptr, qname.len);
                    return key;
                } else {
                    g.allocator.free(removed_qname);
                    return g.allocator.dupe(u8, qname) catch unreachable;
                }
            }
        }
        unreachable;
    } else {
        return g.allocator.dupe(u8, qname) catch unreachable;
    }
}

// =============================================================

/// load from db file
pub fn load() void {
    assert(g.verdict_cache_size > 0);

    const src = @src();
    const path = g.verdict_cache_db orelse return;

    const mem = cc.mmap_file(path) orelse {
        if (cc.errno() != c.ENOENT)
            log.warn(src, "open(%s): (%d) %m", .{ path, cc.errno() });
        return;
    };
    defer _ = cc.munmap(mem);

    var line_it = std.mem.split(u8, mem, "\n");
    while (line_it.next()) |line| {
        var err: ?cc.ConstStr = null;
        defer if (err) |e| log.warn(src, "%s: %.*s", .{ e, cc.to_int(line.len), line.ptr });

        // is_china_domain(1/0) domain_name(ascii_format)
        var it = std.mem.tokenize(u8, line, " \t\r");

        const is_china_domain = str2int.parse(u8, it.next() orelse continue, 10) orelse {
            err = "invalid bool";
            continue;
        } > 0;

        const ascii_name = it.next() orelse {
            err = "invalid format";
            continue;
        };

        if (it.next() != null) {
            err = "invalid format";
            continue;
        }

        var buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
        const qname_z = dns.ascii_to_wire(ascii_name, &buf, null) orelse {
            err = "invalid domain";
            continue;
        };
        if (qname_z.len <= 1) continue;
        const qname = qname_z[0 .. qname_z.len - 1];

        const res = _map.getOrPut(g.allocator, qname) catch unreachable;
        if (!res.found_existing)
            res.key_ptr.* = g.allocator.dupe(u8, qname) catch unreachable;
        res.value_ptr.* = is_china_domain;

        if (_map.count() >= g.verdict_cache_size) break;
    }

    log.info(src, "%zu entries from %s", .{ cc.to_usize(_map.count()), path });
}

/// dump to db file
pub fn dump(event: enum { on_exit, on_manual }) void {
    if (g.verdict_cache_size == 0)
        return;

    const src = @src();

    const path = g.verdict_cache_db orelse switch (event) {
        .on_exit => return,
        .on_manual => "/tmp/chinadns@verdict-cache.db",
    };

    var count: usize = 0;

    const file = cc.fopen(path, "wb") orelse {
        log.warn(src, "fopen(%s) failed: (%d) %m", .{ path, cc.errno() });
        return;
    };
    defer {
        _ = cc.fclose(file);
        log.info(src, "%zu entries to %s", .{ count, path });
    }

    var it = _map.iterator();
    while (it.next()) |entry| {
        // "\3www\6google\3com" (without \0)
        const qname = entry.key_ptr.*;
        const is_china_domain = entry.value_ptr.*;

        if (qname.len + 1 > c.DNS_NAME_WIRE_MAXLEN)
            continue; // bad format

        // append \0
        var buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
        @memcpy(&buf, qname.ptr, qname.len);
        buf[qname.len] = 0;
        const wire_name = buf[0 .. qname.len + 1];

        var ascii: [c.DNS_NAME_MAXLEN:0]u8 = undefined;
        if (!dns.wire_to_ascii(wire_name, &ascii))
            continue; // bad format

        // is_china_domain(1/0) domain_name(ascii_format)
        cc.fprintf(file, "%u %s\n", .{ cc.to_uint(@boolToInt(is_china_domain)), &ascii });

        count += 1;
    }
}
