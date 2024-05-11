const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const dnl = @import("dnl.zig");
const ipset = @import("ipset.zig");
const Tag = @import("tag.zig").Tag;
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const Upstream = @import("Upstream.zig");
const assert = std.debug.assert;
const testing = std.testing;

// ========================================================

/// tag:chn, tag:gfw, tag:\<user-defined>
var _tag_to_group: std.ArrayListUnmanaged(Group) = .{};

const Group = struct {
    dnl_filenames: StrList = .{},
    upstream_group: Upstream.Group = .{},
    ipset_name46: DynStr = .{}, // add ip to ipset/nftset
    ipset_addctx: ?*ipset.addctx_t = null,
};

// ========================================================

pub fn module_init() void {
    // tag:chn, tag:gfw
    ensure_groups_n(2);
}

pub fn module_deinit() void {
    _tag_to_group.clearAndFree(g.allocator);
}

// ========================================================

noinline fn ensure_groups_n(new_n: usize) void {
    assert(new_n <= c.TAG__MAX + 1);

    const old_n = _tag_to_group.items.len;
    if (new_n <= old_n) return;

    _tag_to_group.ensureTotalCapacityPrecise(g.allocator, new_n) catch unreachable;

    var tag_v = cc.to_u8(old_n);
    while (tag_v < new_n) : (tag_v += 1)
        _tag_to_group.addOneAssumeCapacity().* = .{};
}

fn has(tag: Tag) bool {
    return tag.int() < _tag_to_group.items.len;
}

/// assume `tag` exists in `_tag_to_group`
fn get(tag: Tag) *Group {
    return &_tag_to_group.items[tag.int()];
}

fn get_or_add(tag: Tag) *Group {
    ensure_groups_n(tag.int() + 1);
    return get(tag);
}

/// assume `tag` exists in `_tag_to_group`
pub inline fn get_upstream_group(tag: Tag) *Upstream.Group {
    return &get(tag).upstream_group;
}

/// assume `tag` exists in `_tag_to_group`
pub inline fn get_ipset_addctx(tag: Tag) ?*ipset.addctx_t {
    return get(tag).ipset_addctx;
}

/// assume `tag` exists in `_tag_to_group`
pub inline fn get_ipset_name46(tag: Tag) *DynStr {
    return &get(tag).ipset_name46;
}

// ========================================================

/// for opt.zig
pub noinline fn add_dnl(tag: Tag, filenames: []const u8) ?void {
    const dnl_filenames = &get_or_add(tag).dnl_filenames;

    var it = std.mem.split(u8, filenames, ",");
    while (it.next()) |path| {
        if (path.len == 0 or path.len > c.PATH_MAX) {
            opt.print(@src(), "invalid path", path);
            return null;
        }
        dnl_filenames.add(path);
    }
}

/// for opt.zig
pub noinline fn add_upstream(tag: Tag, upstreams: []const u8) ?void {
    if (tag.is_null())
        return null;

    const upstream_group = &get_or_add(tag).upstream_group;

    var it = std.mem.split(u8, upstreams, ",");
    while (it.next()) |upstream|
        upstream_group.add(tag, upstream) orelse return null;
}

/// for opt.zig
pub noinline fn set_ipset(tag: Tag, name46: []const u8) ?void {
    if (tag.is_null())
        return null;

    get_or_add(tag).ipset_name46.set(name46);
}

// ========================================================

/// for main.zig
pub fn on_start() void {
    const src = @src();

    const err: struct { tag: Tag, msg: cc.ConstStr } = e: {
        var tag_to_filenames = [_]?dnl.filenames_t{null} ** (c.TAG__MAX + 1);
        var has_tls_upstream = false;

        var tag_v: u8 = 0; // make zls 0.12 happy
        for (_tag_to_group.items) |*group| {
            defer tag_v += 1;

            const tag = Tag.from_int(tag_v);

            if (!group.dnl_filenames.is_empty())
                tag_to_filenames[tag_v] = group.dnl_filenames.items_z().ptr
            else if (tag != .chn and tag != .gfw and tag != g.default_tag)
                break :e .{ .tag = tag, .msg = "dnl_filenames is empty" };

            if (tag.is_null())
                continue;

            group.upstream_group.rm_useless();

            if (group.upstream_group.is_empty())
                break :e .{ .tag = tag, .msg = "upstream_group is empty" };

            for (group.upstream_group.items()) |*upstream| {
                log.info(src, "tag:%s upstream: %s", .{ tag.name(), upstream.url });
                has_tls_upstream = has_tls_upstream or upstream.proto == .tls;
            }

            if (!group.ipset_name46.is_empty()) {
                const name46 = group.ipset_name46.cstr();
                group.ipset_addctx = ipset.new_addctx(name46);
                log.info(src, "tag:%s add ip to: %s", .{ tag.name(), name46 });
            }
        }

        if (Upstream.has_tls and has_tls_upstream)
            Upstream.TLS.init();

        dnl.init(&tag_to_filenames);

        // check for registered but not used tags
        tag_v = c.TAG__USER;
        while (tag_v <= c.TAG__MAX) : (tag_v += 1) {
            const tag = Tag.from_int(tag_v);
            if (tag.valid() and !has(tag))
                break :e .{ .tag = tag, .msg = "registered but not used" };
        }

        return;
    };

    // error handling

    log.err(src, "tag:%s %s", .{ err.tag.name(), err.msg });
    cc.exit(1);
}

// ========================================================

pub fn @"test: dnl.c"() !void {
    if (cc.getenv("DNL_TEST") != null) {
        add_dnl(.chn, "res/chnlist.txt").?;
        add_dnl(.gfw, "res/gfwlist.txt").?;
        add_upstream(.chn, "223.5.5.5").?;
        add_upstream(.gfw, "1.1.1.1").?;
        g.flags.rm(.gfwlist_first);
        on_start();
    }
}
