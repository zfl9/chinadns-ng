const std = @import("std");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const DynStr = @import("DynStr.zig");

const Upstream = @This();

proto: Proto,
host: []const u8, // DoH
ip: []const u8,
port: u16,
path: []const u8, // DoH
url: [:0]const u8, // for printing

pub const Proto = enum {
    tcp_or_udp, // "1.1.1.1"
    tcp, // "tcp://1.1.1.1"
    udp, // "udp://1.1.1.1"
    https, // "https://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        // zig fmt: off
        const map = .{
            .{ .str = "",         .proto = .tcp_or_udp  },
            .{ .str = "tcp://",   .proto = .tcp         },
            .{ .str = "udp://",   .proto = .udp         },
            .{ .str = "https://", .proto = .https       },
        };
        // zig fmt: on
        inline for (map) |v| {
            if (std.mem.eql(u8, str, v.str))
                return v.proto;
        }
        return null;
    }

    /// "tcp://" (string literal)
    pub fn to_str(self: Proto) []const u8 {
        return switch (self) {
            .tcp_or_udp => "",
            .tcp => "tcp://",
            .udp => "udp://",
            .https => "https://",
        };
    }

    pub fn require_host(self: Proto) bool {
        return self == .https;
    }

    pub fn require_path(self: Proto) bool {
        return self == .https;
    }

    pub fn std_port(self: Proto) u16 {
        return switch (self) {
            .tcp_or_udp, .tcp, .udp => 53,
            .https => 443,
        };
    }

    pub fn is_std_port(self: Proto, port: u16) bool {
        return port == self.std_port();
    }
};

pub const List = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},

    pub inline fn items(self: *const List) []const Upstream {
        return self.list.items;
    }

    pub inline fn is_empty(self: *const List) bool {
        return self.items().len == 0;
    }

    /// "[proto://][host@]ip[#port][path]"
    pub noinline fn add(self: *List, in_value: []const u8) opt.Err!void {
        @setCold(true);

        var value = in_value;

        // proto
        const proto = b: {
            if (std.mem.indexOfPosLinear(u8, value, 0, "://")) |i| {
                const proto = value[0 .. i + 3];
                value = value[i + 3 ..];
                break :b Proto.from_str(proto) orelse {
                    opt.catch_print(@src(), "invalid proto", proto);
                    return opt.Err.optval_bad_format;
                };
            }
            break :b Proto.tcp_or_udp;
        };

        // host, only DoH needs it
        const host = b: {
            if (std.mem.indexOfPosLinear(u8, value, 0, "@")) |i| {
                const host = value[0..i];
                value = value[i + 1 ..];
                if (host.len == 0) {
                    opt.catch_print(@src(), "invalid host", host);
                    return opt.Err.optval_bad_format;
                }
                if (!proto.require_host()) {
                    opt.catch_print(@src(), "no host required", host);
                    return opt.Err.optval_bad_format;
                }
                break :b host;
            }
            break :b "";
        };

        // path, only DoH needs it
        const path = b: {
            if (std.mem.indexOfScalar(u8, value, '/')) |i| {
                const path = value[i..];
                value = value[0..i];
                if (!proto.require_path()) {
                    opt.catch_print(@src(), "no path required", path);
                    return opt.Err.optval_bad_format;
                }
                break :b path;
            }
            break :b "";
        };

        // port
        const port = b: {
            if (std.mem.indexOfScalar(u8, value, '#')) |i| {
                const port = value[i + 1 ..];
                value = value[0..i];
                break :b try opt.check_port(port);
            }
            break :b proto.std_port();
        };

        // ip
        const ip = value;
        try opt.check_ip(ip);

        self.add_to_list(proto, host, ip, port, path);
    }

    noinline fn add_to_list(self: *List, proto: Proto, host: []const u8, ip: []const u8, port: u16, path: []const u8) void {
        @setCold(true);

        for (self.items()) |v| {
            // zig fmt: off
            if (v.proto == proto
                and std.mem.eql(u8, v.host, host)
                and std.mem.eql(u8, v.ip, ip)
                and v.port == port
                and std.mem.eql(u8, v.path, path)) return;
            // zig fmt: on
        }

        var port_buf: [10]u8 = undefined;

        var url = DynStr{};

        url.set_ex(&.{
            // https://
            proto.to_str(),
            // host@
            host,
            cc.b2v(host.len > 0, "@", ""),
            // ip
            ip,
            // #port
            cc.b2v(proto.is_std_port(port), "", cc.snprintf(&port_buf, "#%u", .{cc.to_uint(port)})),
            // path (starts with /)
            path,
        });

        var item = Upstream{
            .proto = proto,
            .host = host,
            .ip = ip,
            .port = port,
            .path = path,
            .url = url.str,
        };

        const raw_values = .{ host, ip, path };
        const field_names = .{ "host", "ip", "path" };
        inline for (field_names) |field_name, i| {
            const raw_v = raw_values[i];
            if (raw_v.len > 0) {
                const pos = std.mem.indexOfPosLinear(u8, url.str, 0, raw_v).?;
                @field(item, field_name) = url.str[pos .. pos + raw_v.len];
            }
        }

        self.list.append(std.heap.raw_c_allocator, item) catch unreachable;
    }
};

pub fn @"test: upstream"() void {
    // _ =
}
