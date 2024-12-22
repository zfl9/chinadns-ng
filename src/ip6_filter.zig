const std = @import("std");
const g = @import("g.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const opt = @import("opt.zig");

pub const IP6Filter = packed struct {
    china_ip: bool = false,
    non_china_ip: bool = false,

    pub fn filter_query(filter: IP6Filter) bool {
        return filter.china_ip and filter.non_china_ip;
    }

    /// by ip test
    pub fn filter_reply(filter: IP6Filter, msg: []const u8, qnamelen: c_int, in_res: ?dns.TestIpResult) bool {
        if (filter.china_ip or filter.non_china_ip) {
            const res = in_res orelse dns.test_ip(msg, qnamelen, g.chnroute_testctx);
            return switch (res) {
                .is_china_ip => filter.china_ip,
                .non_china_ip => filter.non_china_ip,
                else => false,
            };
        }
        return false;
    }

    pub fn require_ip_test(filter: IP6Filter) bool {
        return filter.china_ip != filter.non_china_ip;
    }

    /// `null` means no filter
    pub fn rule_desc(filter: IP6Filter) ?cc.ConstStr {
        if (filter.china_ip and filter.non_china_ip)
            return "all_query";
        if (filter.china_ip)
            return "china_ip";
        if (filter.non_china_ip)
            return "non_china_ip";
        return null;
    }

    /// `null` means all_query
    pub fn add_rule(filter: *IP6Filter, rule: ?[]const u8) ?void {
        if (rule == null) {
            filter.china_ip = true;
            filter.non_china_ip = true;
        } else if (std.mem.eql(u8, rule.?, "ip:china")) {
            filter.china_ip = true;
        } else if (std.mem.eql(u8, rule.?, "ip:non_china")) {
            filter.non_china_ip = true;
        } else {
            opt.print(@src(), "invalid rule", rule.?);
            return null;
        }
    }
};
