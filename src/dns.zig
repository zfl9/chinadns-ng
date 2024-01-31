const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");

pub inline fn get_id(noalias msg: *const anyopaque) c.be16 {
    return c.dns_get_id(msg);
}

pub inline fn set_id(noalias msg: *anyopaque, id: c.be16) void {
    return c.dns_set_id(msg, id);
}

pub inline fn get_qtype(noalias msg: *const anyopaque, wire_namelen: c_int) u16 {
    return c.dns_get_qtype(msg, wire_namelen);
}

/// return the length of the modified response
pub inline fn remove_answer(noalias msg: *anyopaque, wire_namelen: c_int) usize {
    return c.dns_remove_answer(msg, wire_namelen);
}

/// convert query msg to response msg with rcode `NOERROR` (no-AAAA filter)
pub inline fn to_reply_msg(noalias msg: *anyopaque) void {
    return c.dns_to_reply_msg(msg);
}

/// get the ascii length based on the wire length
pub inline fn to_ascii_namelen(wire_namelen: c_int) c_int {
    return c.dns_ascii_namelen(wire_namelen);
}

/// check if the query msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_wire_namelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_query(msg: []const u8, noalias ascii_name: ?[*]u8, noalias p_wire_namelen: ?*c_int) bool {
    return c.dns_check_query(msg.ptr, cc.to_isize(msg.len), ascii_name, p_wire_namelen);
}

/// check if the reply msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_wire_namelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_reply(msg: []const u8, noalias ascii_name: ?[*]u8, noalias p_wire_namelen: ?*c_int) bool {
    return c.dns_check_reply(msg.ptr, cc.to_isize(msg.len), ascii_name, p_wire_namelen);
}

pub const TestIpResult = enum(c_int) {
    IS_CHNIP = c.DNS_TEST_IP_IS_CHNIP,
    NOT_CHNIP = c.DNS_TEST_IP_NOT_CHNIP,
    NOT_FOUND = c.DNS_TEST_IP_NOT_FOUND,
    BAD_MSG = c.DNS_TEST_IP_BAD_MSG,

    pub inline fn from_int(v: c_int) TestIpResult {
        return @intToEnum(TestIpResult, v);
    }
};

pub inline fn test_ip(msg: []const u8, wire_namelen: c_int) TestIpResult {
    return TestIpResult.from_int(c.dns_test_ip(msg.ptr, cc.to_isize(msg.len), wire_namelen));
}

pub inline fn add_ip(msg: []const u8, wire_namelen: c_int, is_chn: bool) void {
    return c.dns_add_ip(msg.ptr, cc.to_isize(msg.len), wire_namelen, is_chn);
}
