const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const dns = @import("dns.zig");
const assert = std.debug.assert;

/// [name] => records
/// - name and records are in wire format
/// - name does not include the null label
var _name_to_records: std.StringHashMapUnmanaged(Records) = .{};

const Records = struct {
    ipv4: []RR_A = &.{},
    ipv6: []RR_AAAA = &.{},

    fn do_add_ip(self: *Records, net_ip: []const u8, comptime is_ipv4: bool) void {
        const field = if (is_ipv4) "ipv4" else "ipv6";
        var rrset = @field(self, field);

        // avoid duplicate
        for (rrset) |*rr| {
            if (std.mem.eql(u8, &rr.data, net_ip))
                return;
        }

        const new_n = rrset.len + 1;
        rrset = (g.allocator.realloc(rrset, new_n) catch unreachable)[0..new_n];
        @field(self, field) = rrset;

        const rr = &rrset[new_n - 1];
        rr.* = .{
            .name = cc.htons((0b11 << 14) + dns.header_len()),
            .type = cc.htons(if (is_ipv4) c.DNS_TYPE_A else c.DNS_TYPE_AAAA),
            .class = cc.htons(c.DNS_CLASS_IN),
            .ttl = 0,
            .datalen = cc.htons(if (is_ipv4) c.IPV4_LEN else c.IPV6_LEN),
            .data = undefined,
        };
        @memcpy(&rr.data, net_ip.ptr, net_ip.len);
    }

    pub fn add_ip(self: *Records, net_ip: []const u8) void {
        if (net_ip.len == c.IPV4_LEN)
            self.do_add_ip(net_ip, true)
        else
            self.do_add_ip(net_ip, false);
    }
};

const RR_A = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV4_LEN]u8,
};

const RR_AAAA = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV6_LEN]u8,
};

/// for opt.zig
pub fn read_hosts(in_path: []const u8) ?void {
    const path = g.allocator.dupeZ(u8, in_path) catch unreachable;
    defer g.allocator.free(path);

    const src = @src();

    const file = cc.fopen(path, "r") orelse {
        opt.print(src, "fopen(%s) failed: (%d) %m", .{ path.ptr, cc.errno() });
        return null;
    };
    defer _ = cc.fclose(file);

    var buf: [1024]u8 = undefined;
    while (cc.fgets(file, &buf)) |p_line| {
        const line = cc.strslice_c(p_line);

        const errmsg: [:0]const u8 = e: {
            if (line[line.len - 1] == '\n')
                p_line[line.len - 1] = 0 // remove \n
            else if (!cc.feof(file)) // last line may not have \n
                break :e "line is too long";

            // ip name name ...
            var it = std.mem.tokenize(u8, line, " \t\x00");

            const ip = it.next() orelse continue;
            if (std.mem.startsWith(u8, ip, "#")) continue;
            opt.check_ip(ip) orelse return null;

            var str_ip: cc.IpStrBuf = undefined;
            @memcpy(&str_ip, ip.ptr, ip.len);
            str_ip[ip.len] = 0;

            var net_ip: [c.IPV6_LEN]u8 = undefined;
            const ip_len = if (cc.inet_pton(c.AF_INET, &str_ip, &net_ip))
                cc.to_usize(c.IPV4_LEN)
            else if (cc.inet_pton(c.AF_INET6, &str_ip, &net_ip))
                cc.to_usize(c.IPV6_LEN)
            else
                unreachable;

            if (it.peek() == null) break :e "missing domain name";

            while (it.next()) |name|
                add_ip(name, net_ip[0..ip_len]) orelse return null;

            continue;
        };

        opt.err_print(src, errmsg, line);
        return null;
    }
}

/// for opt.zig
pub fn add_ip(ascii_name: []const u8, net_ip: []const u8) ?void {
    var buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    const name_z = dns.ascii_to_wire(ascii_name, &buf, null) orelse {
        opt.err_print(@src(), "invalid domain name", ascii_name);
        return null;
    };
    const name = name_z[0 .. name_z.len - 1];

    const res = _name_to_records.getOrPut(g.allocator, name) catch unreachable;
    if (!res.found_existing) {
        res.key_ptr.* = g.allocator.dupe(u8, name) catch unreachable;
        res.value_ptr.* = .{};
    }
    res.value_ptr.add_ip(net_ip);
}

pub fn find_answer(msg: []const u8, qnamelen: c_int, p_answer_n: *u16) ?[]const u8 {
    const qtype = dns.get_qtype(msg, qnamelen);
    if (qtype != c.DNS_TYPE_A and qtype != c.DNS_TYPE_AAAA)
        return null;

    const qname = dns.get_qname(msg, qnamelen);
    const records = _name_to_records.getPtr(qname) orelse return null;

    switch (qtype) {
        c.DNS_TYPE_A => {
            p_answer_n.* = cc.to_u16(records.ipv4.len);
            return std.mem.sliceAsBytes(records.ipv4);
        },
        c.DNS_TYPE_AAAA => {
            p_answer_n.* = cc.to_u16(records.ipv6.len);
            return std.mem.sliceAsBytes(records.ipv6);
        },
        else => unreachable,
    }
}
