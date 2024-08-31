const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const ipset = @import("ipset.zig");

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

/// null label (root domain) not included
pub inline fn get_qname(msg: []const u8, qnamelen: c_int) []const u8 {
    return msg[header_len() .. header_len() + cc.to_usize(qnamelen) - 1];
}

pub inline fn is_tc(msg: []const u8) bool {
    return c.dns_is_tc(msg.ptr);
}

/// return the truncated msg (global static buffer)
pub inline fn truncate(msg: []const u8) []u8 {
    const res_msg = cc.static_buf(c.DNS_QMSG_MAXSIZE);
    const len = c.dns_truncate(msg.ptr, cc.to_isize(msg.len), res_msg.ptr);
    return res_msg[0..len];
}

/// return the updated msg
pub inline fn empty_reply(msg: []u8, qnamelen: c_int) []u8 {
    const len = c.dns_empty_reply(msg.ptr, qnamelen);
    return msg[0..len];
}

/// check if the query msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_qnamelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_query(msg: []u8, ascii_name: ?[*]u8, p_qnamelen: *c_int) bool {
    return c.dns_check_query(msg.ptr, cc.to_isize(msg.len), ascii_name, p_qnamelen);
}

/// check if the reply msg is valid
/// `ascii_name`: the buffer used to get the domain-name (ASCII-format)
/// `p_qnamelen`: used to get the length of the domain-name (wire-format)
pub inline fn check_reply(msg: []u8, ascii_name: ?[*]u8, p_qnamelen: *c_int, p_newlen: *u16) bool {
    return c.dns_check_reply(msg.ptr, cc.to_isize(msg.len), ascii_name, p_qnamelen, p_newlen);
}

pub const TestIpResult = enum(c_int) {
    is_china_ip = c.DNS_TEST_IP_IS_CHINA_IP,
    non_china_ip = c.DNS_TEST_IP_NON_CHINA_IP,
    no_ip_found = c.DNS_TEST_IP_NO_IP_FOUND,
    other_case = c.DNS_TEST_IP_OTHER_CASE,

    pub inline fn from_int(v: c_int) TestIpResult {
        return @intToEnum(TestIpResult, v);
    }
};

/// [tag:none]
pub inline fn test_ip(msg: []const u8, qnamelen: c_int, testctx: *const ipset.testctx_t) TestIpResult {
    return TestIpResult.from_int(c.dns_test_ip(msg.ptr, cc.to_isize(msg.len), qnamelen, testctx));
}

/// [tag:chn, tag:gfw, ...]
pub inline fn add_ip(msg: []const u8, qnamelen: c_int, addctx: *ipset.addctx_t) void {
    return c.dns_add_ip(msg.ptr, cc.to_isize(msg.len), qnamelen, addctx);
}

/// return `null` if there is no effective TTL
pub inline fn get_ttl(msg: []const u8, qnamelen: c_int, nodata_ttl: i32) ?i32 {
    const ttl = c.dns_get_ttl(msg.ptr, cc.to_isize(msg.len), qnamelen, nodata_ttl);
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

pub inline fn ascii_to_wire(ascii_name: []const u8, p_buf: *[c.DNS_NAME_WIRE_MAXLEN]u8, p_level: ?*u8) ?[]u8 {
    const len = c.dns_ascii_to_wire(ascii_name.ptr, ascii_name.len, p_buf, p_level);
    return if (len > 0) p_buf[0..len] else null;
}

pub inline fn wire_to_ascii(wire_name: []const u8, p_buf: *[c.DNS_NAME_MAXLEN:0]u8) bool {
    return c.dns_wire_to_ascii(wire_name.ptr, cc.to_int(wire_name.len), p_buf);
}

pub inline fn make_reply(rmsg: []u8, qmsg: []const u8, qnamelen: c_int, answer: []const u8, answer_n: u16) void {
    return c.dns_make_reply(rmsg.ptr, qmsg.ptr, qnamelen, answer.ptr, answer.len, answer_n);
}
