const log = @import("log.zig");
const dnl = @import("dnl.zig");
const cc = @import("cc.zig");
const flags_op = @import("flags_op.zig");

// ================================================

const NoAAAA = @This();

// struct fields
flags: Flags = Flags.empty(),

pub const Flags = enum(u8) {
    all = @import("std").math.maxInt(u8),

    tag_gfw = 1 << 0,
    tag_chn = 1 << 1,
    tag_none = 1 << 2,

    china_dns = 1 << 3,
    trust_dns = 1 << 4,

    /// tag:none + only_china_path: filter non-chnip reply
    china_ipchk = 1 << 5,
    /// tag:none + only_trust_path: filter non-chnip reply
    trust_ipchk = 1 << 6,

    _, // non-exhaustive enum

    usingnamespace flags_op.get(Flags);
};

// ================================================

pub fn is_empty(self: NoAAAA) bool {
    return self.flags.is_empty();
}

pub fn is_full(self: NoAAAA) bool {
    return self.flags.is_full();
}

/// try simplify to flags .all
fn check_full(self: *NoAAAA) void {
    const all_tag = Flags.from(.{ .tag_gfw, .tag_chn, .tag_none });
    const all_dns = Flags.from(.{ .china_dns, .trust_dns });

    if (self.flags != .all and (self.has(all_tag) or self.has(all_dns)))
        self.flags = .all;
}

/// for single flag bit
/// for multiple flag bits, equivalent to `has_all`
pub fn has(self: NoAAAA, flags: Flags) bool {
    return self.flags.has(flags);
}

/// for multiple flag bits
pub const has_all = has;

/// for multiple flag bits
pub fn has_any(self: NoAAAA, flags: Flags) bool {
    return self.flags.has_any(flags);
}

pub fn add(self: *NoAAAA, flags: Flags) void {
    self.flags.add(flags);
    self.check_full();
}

/// return the rule (string literal) that caused the filter
pub fn filter(self: NoAAAA, name_tag: dnl.Tag, p_tagnone_china: *bool, p_tagnone_trust: *bool) ?cc.ConstStr {
    if (self.is_empty())
        return null;

    if (self.is_full())
        return "all";

    switch (name_tag) {
        .chn => {
            if (self.has(.tag_chn)) return "tag_chn";
            if (self.has(.china_dns)) return "china_dns";
        },
        .gfw => {
            if (self.has(.tag_gfw)) return "tag_gfw";
            if (self.has(.trust_dns)) return "trust_dns";
        },
        .none => {
            if (self.has(.tag_none)) return "tag_none";
            if (self.has(.china_dns)) p_tagnone_china.* = false;
            if (self.has(.trust_dns)) p_tagnone_trust.* = false;
        },
    }

    return null;
}

pub fn display(self: NoAAAA) void {
    if (self.is_empty()) return;

    // zig fmt: off
    const list = .{
        .{ .flags = .all,         .msg = "filter AAAA for all domain", .brk = {} },
        .{ .flags = .tag_chn,     .msg = "filter AAAA for tag_chn domain" },
        .{ .flags = .tag_gfw,     .msg = "filter AAAA for tag_gfw domain" },
        .{ .flags = .tag_none,    .msg = "filter AAAA for tag_none domain" },
        .{ .flags = .china_dns,   .msg = "filter AAAA for china upstream" },
        .{ .flags = .trust_dns,   .msg = "filter AAAA for trust upstream" },
        .{ .flags = .china_ipchk, .msg = "check AAAA ip of china upstream" },
        .{ .flags = .trust_ipchk, .msg = "check AAAA ip of trust upstream" },
    };
    // zig fmt: on

    inline for (list) |v| {
        if (self.has(v.flags)) {
            log.info(@src(), v.msg, .{});
            if (@hasField(@TypeOf(v), "brk")) break;
        }
    }
}
