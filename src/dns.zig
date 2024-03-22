const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");

pub inline fn ascii_namelen(qnamelen: c_int) c_int {
    return c.dns_ascii_namelen(qnamelen);
}

pub inline fn header_len() u16 {
    return c.dns_header_len();
}

pub inline fn question_len(qnamelen: c_int) u16 {
    return c.dns_question_len(qnamelen);
}

pub inline fn question(msg: []const u8, qnamelen: c_int) []const u8 {
    return msg[header_len() .. header_len() + question_len(qnamelen)];
}

pub inline fn get_id(msg: []const u8) c.be16 {
    return c.dns_get_id(msg.ptr);
}

pub inline fn set_id(msg: []u8, id: c.be16) void {
    return c.dns_set_id(msg.ptr, id);
}

pub inline fn get_qtype(msg: []const u8, qnamelen: c_int) u16 {
    return c.dns_get_qtype(msg.ptr, qnamelen);
}

pub inline fn get_bufsz(msg: []const u8, qnamelen: c_int) u16 {
    return c.dns_get_bufsz(msg.ptr, cc.to_isize(msg.len), qnamelen);
}

pub inline fn get_rcode(msg: []const u8) u8 {
    return c.dns_get_rcode(msg.ptr);
}

pub inline fn is_tc(msg: []const u8) bool {
    return c.dns_is_tc(msg.ptr);
}

var _msgbuffer: [c.DNS_QMSG_MAXSIZE]u8 = undefined;

/// return the truncated msg (ptr to static buffer)
pub inline fn truncate(msg: []const u8) []u8 {
    const len = c.dns_truncate(msg.ptr, cc.to_isize(msg.len), &_msgbuffer);
    return _msgbuffer[0..len];
}

/// return the updated msg length
pub inline fn empty_reply(msg: []u8, qnamelen: c_int) u16 {
    return c.dns_empty_reply(msg.ptr, qnamelen);
}

/// check if the query msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_qnamelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_query(msg: []const u8, ascii_name: ?[*]u8, p_qnamelen: ?*c_int) bool {
    return c.dns_check_query(msg.ptr, cc.to_isize(msg.len), ascii_name, p_qnamelen);
}

/// check if the reply msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_qnamelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_reply(msg: []const u8, ascii_name: ?[*]u8, p_qnamelen: ?*c_int) bool {
    return c.dns_check_reply(msg.ptr, cc.to_isize(msg.len), ascii_name, p_qnamelen);
}

pub const TestIpResult = enum(c_int) {
    is_chnip = c.DNS_TEST_IP_IS_CHNIP,
    not_chnip = c.DNS_TEST_IP_NOT_CHNIP,
    not_found = c.DNS_TEST_IP_NOT_FOUND,
    bad_msg = c.DNS_TEST_IP_BAD_MSG,

    pub inline fn from_int(v: c_int) TestIpResult {
        return @intToEnum(TestIpResult, v);
    }
};

pub inline fn test_ip(msg: []const u8, qnamelen: c_int) TestIpResult {
    return TestIpResult.from_int(c.dns_test_ip(msg.ptr, cc.to_isize(msg.len), qnamelen));
}

pub inline fn add_ip(msg: []const u8, qnamelen: c_int, is_chn: bool) void {
    return c.dns_add_ip(msg.ptr, cc.to_isize(msg.len), qnamelen, is_chn);
}

/// return null if failed or has no record
pub inline fn get_ttl(msg: []const u8, qnamelen: c_int) ?i32 {
    const ttl = c.dns_get_ttl(msg.ptr, cc.to_isize(msg.len), qnamelen);
    return if (ttl > 0) ttl else null;
}

/// it should not fail because it has been checked by `get_ttl`
pub inline fn update_ttl(msg: []u8, qnamelen: c_int, ttl_change: i32) void {
    return c.dns_update_ttl(msg.ptr, cc.to_isize(msg.len), qnamelen, ttl_change);
}

/// get the domain suffixes (wire-format)
pub inline fn qname_domains(msg: []const u8, qnamelen: c_int, interest_levels: u8, p_domains: *[8][*]const u8, p_domain_end: *[*]const u8) ?u8 {
    const ptr_domains = @ptrCast([*c][*c]const u8, p_domains);
    const ptr_domain_end = @ptrCast([*c][*c]const u8, p_domain_end);
    const n = c.dns_qname_domains(msg.ptr, qnamelen, interest_levels, ptr_domains, ptr_domain_end);
    return if (n >= 0) cc.to_u8(n) else null;
}

pub inline fn ascii_to_wire(ascii_name: []const u8, p_buf: *[c.DNS_NAME_WIRE_MAXLEN]u8, p_level: *u8) ?[]u8 {
    const len = c.dns_ascii_to_wire(ascii_name.ptr, ascii_name.len, p_buf, p_level);
    return if (len > 0) p_buf[0..len] else null;
}
