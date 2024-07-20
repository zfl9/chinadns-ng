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

    pub noinline fn add_ip(self: *Records, net_ip: []const u8) void {
        if (net_ip.len == c.IPV4_LEN)
            self.do_add_ip(net_ip, true)
        else
            self.do_add_ip(net_ip, false);
    }
};

// TODO: change to extern struct
const RR_A = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV4_LEN]u8,
};

// TODO: change to extern struct
const RR_AAAA = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV6_LEN]u8,
};

comptime {
    assert(@sizeOf(RR_A) == 2 * 3 + 4 + 2 + c.IPV4_LEN);
    assert(@sizeOf(RR_AAAA) == 2 * 3 + 4 + 2 + c.IPV6_LEN);
}

/// for opt.zig
pub fn read_hosts(path: []const u8) ?void {
    const src = @src();

    const mem = cc.mmap_file(cc.to_cstr(path)) orelse {
        opt.printf(src, "open file: %m", .{});
        return null;
    };
    defer _ = cc.munmap(mem);

    var line_it = std.mem.split(u8, mem, "\n");
    while (line_it.next()) |raw_line| {
        // ignore comments
        const pos = std.mem.indexOfScalar(u8, raw_line, '#');
        const line = if (pos) |p| raw_line[0..p] else raw_line;

        // ip name name ...
        var it = std.mem.tokenize(u8, line, " \t\r");

        const ip = it.next() orelse continue;

        if (it.peek() == null) {
            opt.print(src, "missing domain", line);
            return null;
        }

        while (it.next()) |name|
            add_ip(name, ip) orelse return null;
    }
}

/// for opt.zig
pub noinline fn add_ip(ascii_name: []const u8, str_ip: []const u8) ?void {
    const src = @src();

    var name_buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    const name_z = dns.ascii_to_wire(ascii_name, &name_buf, null) orelse {
        opt.print(src, "invalid domain", ascii_name);
        return null;
    };
    const name = name_z[0 .. name_z.len - 1];

    const res = _name_to_records.getOrPut(g.allocator, name) catch unreachable;
    if (!res.found_existing) {
        res.key_ptr.* = g.allocator.dupe(u8, name) catch unreachable;
        res.value_ptr.* = .{};
    }

    var ip_buf: cc.IpNetBuf = undefined;
    const net_ip = cc.ip_to_net(cc.to_cstr(str_ip), &ip_buf) orelse {
        opt.print(src, "invalid ip", str_ip);
        return null;
    };
    res.value_ptr.add_ip(net_ip);
}

pub fn find_answer(msg: []const u8, qnamelen: c_int, p_answer_n: *u16) ?[]const u8 {
    if (_name_to_records.count() == 0)
        return null;

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
