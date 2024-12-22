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
const IP6Filter = @import("ip6_filter.zig").IP6Filter;
const assert = std.debug.assert;
const testing = std.testing;

// ========================================================

var _all_groups = [_]Group{.{}} ** (c.TAG_NONE + 1);

const Group = struct {
    dnl_filenames: StrList = .{},
    upstream_group: Upstream.Group = .{},
    ipset_name46: DynStr = .{}, // add ip to ipset/nftset
    ipset_addctx: ?*ipset.addctx_t = null,
    ip6_filter: IP6Filter = .{},
};

fn get(tag: Tag) *Group {
    return &_all_groups[tag.int()];
}

pub inline fn get_upstream_group(tag: Tag) *Upstream.Group {
    return &get(tag).upstream_group;
}

pub inline fn get_ipset_addctx(tag: Tag) ?*ipset.addctx_t {
    return get(tag).ipset_addctx;
}

pub inline fn get_ipset_name46(tag: Tag) *DynStr {
    return &get(tag).ipset_name46;
}

pub inline fn get_ip6_filter(tag: Tag) IP6Filter {
    return get(tag).ip6_filter;
}

// ========================================================

/// for opt.zig
pub noinline fn add_dnl(tag: Tag, filenames: []const u8) ?void {
    const dnl_filenames = &get(tag).dnl_filenames;

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

    const upstream_group = &get(tag).upstream_group;

    var it = std.mem.split(u8, upstreams, ",");
    while (it.next()) |upstream|
        upstream_group.add(tag, upstream) orelse return null;
}

/// for opt.zig
pub noinline fn set_ipset(tag: Tag, name46: []const u8) ?void {
    if (tag.is_null())
        return null;

    get(tag).ipset_name46.set(name46);
}

/// for opt.zig
pub noinline fn add_ip6_filter(rules: ?[]const u8) ?void {
    if (rules != null) {
        var it = std.mem.split(u8, rules.?, ",");
        while (it.next()) |rule| {
            // "tag:xxx@ip:xxx" | "tag:xxx"(ip:*) | "ip:xxx"(tag:*)
            if (std.mem.startsWith(u8, rule, "tag:")) {
                // "tag:xxx@ip:xxx" | "tag:xxx"(ip:*)
                const tag_name_end = std.mem.indexOfScalar(u8, rule, '@') orelse rule.len;
                const tag_name = cc.to_cstr(rule[4..tag_name_end]);
                const tag = Tag.from_name(tag_name) orelse {
                    opt.print(@src(), "invalid tag", rule[0..tag_name_end]);
                    return null;
                };
                const ip_rule = if (tag_name_end != rule.len) rule[tag_name_end + 1 ..] else null;
                get(tag).ip6_filter.add_rule(ip_rule) orelse return null;
            } else {
                // "ip:xxx"(tag:*)
                const ip_rule = rule;
                for (_all_groups) |*group|
                    group.ip6_filter.add_rule(ip_rule) orelse return null;
            }
        }
    } else {
        // filter all AAAA query/reply
        const ip_rule = null;
        for (_all_groups) |*group|
            group.ip6_filter.add_rule(ip_rule) orelse return null;
    }
}

// ========================================================

/// for main.zig
pub fn on_start() void {
    const src = @src();

    const err: struct { tag: Tag, msg: cc.ConstStr } = e: {
        var tag_to_filenames = [_]?dnl.filenames_t{null} ** (c.TAG__MAX + 1);
        var has_tls_upstream = false;

        var tag_v: u8 = 0; // make zls 0.12 happy
        for (_all_groups) |*group| {
            defer tag_v += 1;

            const tag = Tag.from_int(tag_v);
            if (!tag.valid())
                continue;

            // `tag:none` not exist ?
            if (tag == .none and g.default_tag != .none)
                continue;

            // [dnl]
            if (!group.dnl_filenames.is_empty())
                tag_to_filenames[tag_v] = group.dnl_filenames.items_z().ptr
            else if (tag != .chn and tag != .gfw and tag != .none and tag != g.default_tag)
                break :e .{ .tag = tag, .msg = "dnl_filenames is empty" };

            if (tag != .none and !tag.is_null()) {
                // [upstream]
                group.upstream_group.rm_useless();

                if (group.upstream_group.is_empty())
                    break :e .{ .tag = tag, .msg = "upstream_group is empty" };

                for (group.upstream_group.items()) |*upstream| {
                    log.info(src, "tag:%s upstream: %s", .{ tag.name(), upstream.url });
                    has_tls_upstream = has_tls_upstream or upstream.proto == .tls;
                }

                // [ipset]
                if (!group.ipset_name46.is_empty()) {
                    const name46 = group.ipset_name46.cstr();
                    group.ipset_addctx = ipset.new_addctx(name46);
                    log.info(src, "tag:%s add ip to: %s", .{ tag.name(), name46 });
                }
            }

            // [ip6 filter]
            if (!tag.is_null()) {
                if (group.ip6_filter.rule_desc()) |rule|
                    log.info(src, "tag:%s ipv6 filter: %s", .{ tag.name(), rule });
            }
        }

        if (Upstream.has_tls and has_tls_upstream)
            Upstream.TLS.init();

        dnl.init(&tag_to_filenames);

        return;
    };

    // error handling

    log.err(src, "tag:%s %s", .{ err.tag.name(), err.msg });
    cc.exit(1);
}

pub fn require_ip_test() bool {
    for (_all_groups) |*group| {
        if (group.ip6_filter.require_ip_test())
            return true;
    }
    return false;
}

// ========================================================

pub fn @"test: dnl.c"() !void {
    if (cc.getenv("DNL_TEST") != null) {
        add_dnl(.chn, "res/chnlist.txt").?;
        add_dnl(.gfw, "res/gfwlist.txt").?;
        add_upstream(.chn, "223.5.5.5").?;
        add_upstream(.gfw, "1.1.1.1").?;
        g.flags.gfwlist_first = false;
        on_start();
    }
}
