const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");
const Tag = @import("tag.zig").Tag;

// ================================================

const NoAAAA = @This();

flags: Flags.T = 0,

// ================================================

/// index
pub const Rule = opaque {
    /// left-shift bits
    pub const T = u8;

    // tag:* [0, 8]

    // ip:* [9, 10]
    pub const ip_china: T = c.TAG_NONE + 1;
    pub const ip_non_china: T = ip_china + 1;

    pub fn to_flags(rule: Rule.T) Flags.T {
        return @as(Flags.T, 1) << @intCast(u4, rule);
    }

    /// global static buffer
    pub fn to_name(rule: Rule.T) cc.ConstStr {
        if (rule < ip_china) {
            const tag_name = Tag.from_int(rule).name();
            return cc.to_cstr_x(&.{ "tag:", cc.strslice_c(tag_name) });
        } else {
            return switch (rule) {
                ip_china => "ip:china",
                ip_non_china => "ip:non_china",
                else => unreachable,
            };
        }
    }
};

/// bit flags
const Flags = opaque {
    /// flags type
    pub const T = u16;

    pub const all: T = std.math.maxInt(T);
    pub const all_ip: T = (1 << Rule.ip_china) | (1 << Rule.ip_non_china);
};

// ================================================

fn is_empty(self: NoAAAA) bool {
    return self.flags == 0;
}

fn is_all(self: NoAAAA) bool {
    return self.flags == Flags.all;
}

fn has_rule(self: NoAAAA, rule: Rule.T) bool {
    return self.has_flags(Rule.to_flags(rule));
}

fn has_flags(self: NoAAAA, flags: Flags.T) bool {
    return self.flags & flags == flags;
}

fn has_flags_any(self: NoAAAA, flags: Flags.T) bool {
    return self.flags & flags != 0;
}

// ================================================

/// for opt.zig
pub fn add_rule(self: *NoAAAA, rule: Rule.T) ?void {
    if (self.is_all())
        return;

    self.flags |= Rule.to_flags(rule);

    if (self.has_flags(Flags.all_ip)) {
        opt.printf(@src(), "both 'ip:china' and 'ip:non_china' exist", .{});
        return null;
    }
}

/// for opt.zig
pub fn add_all(self: *NoAAAA) void {
    self.flags = Flags.all;
}

// ================================================

/// [on_query] filter by tag
pub fn by_tag(self: NoAAAA, tag: Tag) ?Rule.T {
    const rule: Rule.T = tag.int();
    return if (self.has_rule(rule)) rule else null;
}

/// [on_reply] filter by ip test
pub fn by_ip_test(self: NoAAAA, msg: []const u8, qnamelen: c_int, in_res: ?dns.TestIpResult) ?Rule.T {
    if (self.has_flags_any(Flags.all_ip)) {
        const res = in_res orelse dns.test_ip(msg, qnamelen, g.chnroute_testctx);
        return switch (res) {
            .is_china_ip => if (self.has_rule(Rule.ip_china)) Rule.ip_china else null,
            .non_china_ip => if (self.has_rule(Rule.ip_non_china)) Rule.ip_non_china else null,
            else => null,
        };
    }
    return null;
}

// ================================================

pub fn require_ip_test(self: NoAAAA) bool {
    return !self.is_all() and self.has_flags_any(Flags.all_ip);
}

pub fn display(self: NoAAAA) void {
    const src = @src();

    if (self.is_empty())
        return;

    if (self.is_all()) {
        log.info(src, "filter AAAA query: all", .{});
        return;
    }

    // tag:*
    var tag: u8 = 0;
    while (tag <= c.TAG_NONE) : (tag += 1) {
        if (self.has_rule(tag))
            log.info(src, "filter AAAA query: tag:%s", .{Tag.from_int(tag).name()});
    }

    // ip:*
    if (self.has_rule(Rule.ip_china))
        log.info(src, "filter AAAA reply: ip:china", .{});
    if (self.has_rule(Rule.ip_non_china))
        log.info(src, "filter AAAA reply: ip:non_china", .{});
}
