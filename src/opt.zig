const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const str2int = @import("str2int.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const NoAAAA = @import("NoAAAA.zig");
const testing = std.testing;

const help =
    \\usage: chinadns-ng <options...>. the existing options are as follows:
    \\ -C, --config <path>                  format similar to the long option
    \\ -b, --bind-addr <ip>                 listen address, default: 127.0.0.1
    \\ -l, --bind-port <port>               listen port number, default: 65353
    \\ -c, --china-dns <ip[#port],...>      china dns server, default: <114 DNS>
    \\ -t, --trust-dns <ip[#port],...>      trust dns server, default: <Google DNS>
    \\ -m, --chnlist-file <path,...>        path(s) of chnlist, '-' indicate stdin
    \\ -g, --gfwlist-file <path,...>        path(s) of gfwlist, '-' indicate stdin
    \\ -M, --chnlist-first                  match chnlist first, default gfwlist first
    \\ -d, --default-tag <tag>              domain default tag: chn,gfw,none(default)
    \\ -a, --add-tagchn-ip [set4,set6]      add the ip of name-tag:chn to ipset/nft
    \\                                      use '--ipset-name4/6' setname if no value
    \\ -A, --add-taggfw-ip <set4,set6>      add the ip of name-tag:gfw to ipset/nft
    \\ -4, --ipset-name4 <set4>             ip test for tag:none, default: chnroute
    \\ -6, --ipset-name6 <set6>             ip test for tag:none, default: chnroute6
    \\                                      if setname contains @, then use nft-set
    \\                                      format: family_name@table_name@set_name
    \\ -N, --no-ipv6 [rules]                filter AAAA query, rules can be a seq of:
    \\                                      rule a: filter all domain name (default)
    \\                                      rule m: filter the domain with tag chn
    \\                                      rule g: filter the domain with tag gfw
    \\                                      rule n: filter the domain with tag none
    \\                                      rule c: do not forward to china upstream
    \\                                      rule t: do not forward to trust upstream
    \\                                      rule C: check answer ip of china upstream
    \\                                      rule T: check answer ip of trust upstream
    \\                                      if no rules is given, it defaults to 'a'
    \\ -o, --timeout-sec <sec>              response timeout of upstream, default: 5
    \\ -p, --repeat-times <num>             num of packets to trustdns, default:1, max:5
    \\ -n, --noip-as-chnip                  allow no-ip reply from chinadns (tag:none)
    \\ -f, --fair-mode                      enable fair mode (nop, only fair mode now)
    \\ -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
    \\ -v, --verbose                        print the verbose log, default: <disabled>
    \\ -V, --version                        print `chinadns-ng` version number and exit
    \\ -h, --help                           print `chinadns-ng` help information and exit
    \\bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
;

const OptDef = struct {
    short: []const u8, // short name
    long: []const u8, // long name
    value: enum { required, optional, no_value },
    optfn: OptFn,
};

// zig fmt: off
const optdef_array = [_]OptDef{
    .{ .short = "C", .long = "config",        .value = .required, .optfn = opt_config,        },
    .{ .short = "b", .long = "bind-addr",     .value = .required, .optfn = opt_bind_addr,     },
    .{ .short = "l", .long = "bind-port",     .value = .required, .optfn = opt_bind_port,     },
    .{ .short = "c", .long = "china-dns",     .value = .required, .optfn = opt_china_dns,     },
    .{ .short = "t", .long = "trust-dns",     .value = .required, .optfn = opt_trust_dns,     },
    .{ .short = "m", .long = "chnlist-file",  .value = .required, .optfn = opt_chnlist_file,  },
    .{ .short = "g", .long = "gfwlist-file",  .value = .required, .optfn = opt_gfwlist_file,  },
    .{ .short = "M", .long = "chnlist-first", .value = .no_value, .optfn = opt_chnlist_first, },
    .{ .short = "d", .long = "default-tag",   .value = .required, .optfn = opt_default_tag,   },
    .{ .short = "a", .long = "add-tagchn-ip", .value = .optional, .optfn = opt_add_tagchn_ip, },
    .{ .short = "A", .long = "add-taggfw-ip", .value = .required, .optfn = opt_add_taggfw_ip, },
    .{ .short = "4", .long = "ipset-name4",   .value = .required, .optfn = opt_ipset_name4,   },
    .{ .short = "6", .long = "ipset-name6",   .value = .required, .optfn = opt_ipset_name6,   },
    .{ .short = "N", .long = "no-ipv6",       .value = .optional, .optfn = opt_no_ipv6,       },
    .{ .short = "o", .long = "timeout-sec",   .value = .required, .optfn = opt_timeout_sec,   },
    .{ .short = "p", .long = "repeat-times",  .value = .required, .optfn = opt_repeat_times,  },
    .{ .short = "n", .long = "noip-as-chnip", .value = .no_value, .optfn = opt_noip_as_chnip, },
    .{ .short = "f", .long = "fair-mode",     .value = .no_value, .optfn = opt_fair_mode,     },
    .{ .short = "r", .long = "reuse-port",    .value = .no_value, .optfn = opt_reuse_port,    },
    .{ .short = "v", .long = "verbose",       .value = .no_value, .optfn = opt_verbose,       },
    .{ .short = "V", .long = "version",       .value = .no_value, .optfn = opt_version,       },
    .{ .short = "h", .long = "help",          .value = .no_value, .optfn = opt_help,          },
};
// zig fmt: on

fn get_optdef(name: []const u8) ?OptDef {
    for (optdef_array) |optdef| {
        if (std.mem.eql(u8, optdef.short, name) or std.mem.eql(u8, optdef.long, name))
            return optdef;
    }
    return null;
}

const OptFn = fn (in_value: ?[]const u8) void;

fn opt_config(in_value: ?[]const u8) void {
    // prevent stack overflow due to recursion
    const static = struct {
        var depth: u8 = 0;
    };

    if (static.depth + 1 > 20)
        err_exit(@src(), "call chain is too deep, please check the config for a dead loop", .{});

    static.depth += 1;
    defer static.depth -= 1;

    const value = in_value.?;
    if (value.len > c.PATH_MAX)
        err_exit(@src(), "filename is too long: '%.*s'", .{ cc.to_int(value.len), value.ptr });

    // TODO: vla/alloca allocator
    const filename = cc.strdup(value);
    defer cc.free(filename);

    const file = cc.fopen(filename, "r") orelse
        err_exit(@src(), "failed to open the config file: '%s' (%m)", .{filename.ptr});
    defer cc.fclose(file);

    var buf: [512]u8 = undefined;
    while (cc.fgets(file, &buf)) |p_line| {
        const line = cc.strslice_c(p_line);

        if (line[line.len - 1] == '\n')
            p_line[line.len - 1] = 0 // remove \n
        else if (!cc.feof(file)) // last line may not have \n
            err_exit(@src(), "'%s': line is too long: %s", .{ filename.ptr, p_line });

        // optname [optvalue]
        var it = std.mem.tokenize(u8, line, " \t\r\n\x00");

        const optname = it.next() orelse continue;

        if (std.mem.startsWith(u8, optname, "#")) continue;

        const optvalue = it.next();

        if (it.next() != null)
            err_exit(@src(), "'%s': too many values: %s", .{ filename.ptr, p_line });

        const optdef = get_optdef(optname) orelse
            err_exit(@src(), "'%s': unknown option: %s", .{ filename.ptr, p_line });

        switch (optdef.value) {
            .required => {
                if (optvalue == null)
                    err_exit(@src(), "'%s': missing opt-value: %s", .{ filename.ptr, p_line });
            },
            .no_value => {
                if (optvalue != null)
                    err_exit(@src(), "'%s': unexpected opt-value: %s", .{ filename.ptr, p_line });
            },
            else => {},
        }

        if (optvalue != null and optvalue.?.len <= 0)
            err_exit(@src(), "'%s': invalid format: %s", .{ filename.ptr, p_line });

        optdef.optfn(optvalue);
    }
}

const Error = error{
    invalid,
};

fn catch_msg(comptime src: std.builtin.SourceLocation, comptime msg: [:0]const u8, value: []const u8) void {
    err_msg(src, msg ++ ": '%.*s'", .{ cc.to_int(value.len), value.ptr });
}

fn catch_exit(comptime src: std.builtin.SourceLocation, value: []const u8) noreturn {
    err_exit(src, "invalid opt-value: '%.*s'", .{ cc.to_int(value.len), value.ptr });
}

fn check_ip(value: []const u8) Error!void {
    var buf: [64]u8 = undefined;

    const ip = cc.strdup_r(value, &buf) catch {
        catch_msg(@src(), "ip is too long", value);
        return Error.invalid;
    };

    if (cc.get_ipstr_family(ip.ptr) == -1) {
        catch_msg(@src(), "invalid ip", value);
        return Error.invalid;
    }
}

fn check_port(value: []const u8) Error!u16 {
    const port = str2int.parse(u16, value, 10) catch 0;
    if (port == 0) {
        catch_msg(@src(), "invalid port", value);
        return Error.invalid;
    }
    return port;
}

fn opt_bind_addr(in_value: ?[]const u8) void {
    const value = in_value.?;
    check_ip(value) catch catch_exit(@src(), value);
    g.bind_ips.add(value);
}

fn opt_bind_port(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.bind_port = check_port(value) catch catch_exit(@src(), value);
}

/// "ip", "ip#port"
fn check_addr(value: []const u8) Error!void {
    if (std.mem.indexOfScalar(u8, value, '#')) |sep| {
        try check_ip(value[0..sep]);
        _ = try check_port(value[sep + 1 ..]);
    } else {
        try check_ip(value);
    }
}

/// "ip[#port],..."
fn add_addrs(list: *StrList, addrs: []const u8) Error!void {
    var it = std.mem.split(u8, addrs, ",");
    while (it.next()) |addr| {
        check_addr(addr) catch |err| {
            catch_msg(@src(), "invalid address", addr);
            return err;
        };
        list.add(addr);
    }
}

fn opt_china_dns(in_value: ?[]const u8) void {
    const value = in_value.?;
    add_addrs(&g.chinadns_addrs, value) catch catch_exit(@src(), value);
}

fn opt_trust_dns(in_value: ?[]const u8) void {
    const value = in_value.?;
    add_addrs(&g.trustdns_addrs, value) catch catch_exit(@src(), value);
}

/// "foo.txt,..."
fn add_paths(list: *StrList, paths: []const u8) Error!void {
    var it = std.mem.split(u8, paths, ",");
    while (it.next()) |path| {
        if (path.len <= 0) {
            catch_msg(@src(), "invalid paths format", paths);
            return Error.invalid;
        }
        if (path.len > c.PATH_MAX) {
            catch_msg(@src(), "path is too long", path);
            return Error.invalid;
        }
        list.add(path);
    }
}

fn opt_chnlist_file(in_value: ?[]const u8) void {
    const value = in_value.?;
    add_paths(&g.chnlist_filenames, value) catch catch_exit(@src(), value);
}

fn opt_gfwlist_file(in_value: ?[]const u8) void {
    const value = in_value.?;
    add_paths(&g.gfwlist_filenames, value) catch catch_exit(@src(), value);
}

fn opt_chnlist_first(_: ?[]const u8) void {
    g.gfwlist_first = false;
}

fn opt_default_tag(in_value: ?[]const u8) void {
    const value = in_value.?;
    const map = .{
        .{ .tagname = "chn", .tag = .chn },
        .{ .tagname = "gfw", .tag = .gfw },
        .{ .tagname = "none", .tag = .none },
    };
    inline for (map) |v| {
        if (std.mem.eql(u8, v.tagname, value)) {
            g.default_tag = v.tag;
            return;
        }
    }
    err_exit(@src(), "invalid domain tag: '%.*s'", .{ cc.to_int(value.len), value.ptr });
}

fn opt_add_tagchn_ip(in_value: ?[]const u8) void {
    // empty string means 'no_value'
    g.chnip_setnames.set(in_value orelse "");
}

fn opt_add_taggfw_ip(in_value: ?[]const u8) void {
    g.gfwip_setnames.set(in_value.?);
}

fn opt_ipset_name4(in_value: ?[]const u8) void {
    g.chnroute_name.set(in_value.?);
}

fn opt_ipset_name6(in_value: ?[]const u8) void {
    g.chnroute6_name.set(in_value.?);
}

fn opt_no_ipv6(in_value: ?[]const u8) void {
    if (in_value) |value| {
        for (value) |rule| {
            g.noaaaa_query.add(switch (rule) {
                'a' => NoAAAA.ALL,
                'm' => NoAAAA.TAG_CHN,
                'g' => NoAAAA.TAG_GFW,
                'n' => NoAAAA.TAG_NONE,
                'c' => NoAAAA.CHINA_DNS,
                't' => NoAAAA.TRUST_DNS,
                'C' => NoAAAA.CHINA_IPCHK,
                'T' => NoAAAA.TRUST_IPCHK,
                else => err_exit(@src(), "invalid no-aaaa rule: '%c'", .{rule}),
            });
        }
    } else {
        g.noaaaa_query.add(NoAAAA.ALL);
    }
}

fn opt_timeout_sec(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.upstream_timeout = str2int.parse(@TypeOf(g.upstream_timeout), value, 10) catch 0;
    if (g.upstream_timeout == 0)
        err_exit(@src(), "invalid upstream timeout: '%.*s'", .{ cc.to_int(value.len), value.ptr });
}

fn opt_repeat_times(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.trustdns_packet_n = str2int.parse(@TypeOf(g.trustdns_packet_n), value, 10) catch 0;
    if (g.trustdns_packet_n == 0)
        err_exit(@src(), "invalid trust-dns packets num: '%.*s'", .{ cc.to_int(value.len), value.ptr });
    g.trustdns_packet_n = std.math.min(g.trustdns_packet_n, g.TRUSTDNS_PACKET_MAX);
}

fn opt_noip_as_chnip(_: ?[]const u8) void {
    g.noip_as_chnip = true;
}

fn opt_fair_mode(_: ?[]const u8) void {
    // legacy option, deprecated
}

fn opt_reuse_port(_: ?[]const u8) void {
    g.reuse_port = true;
}

fn opt_verbose(_: ?[]const u8) void {
    g.verbose = true;
}

fn opt_version(_: ?[]const u8) void {
    cc.printf("%s\n", .{g.VERSION});
    c.exit(0);
}

fn opt_help(_: ?[]const u8) void {
    cc.printf("%s\n", .{help});
    c.exit(0);
}

// ================================================================

idx: usize,

const Self = @This();

fn init() Self {
    return .{ .idx = 1 };
}

fn parse_opt(self: *Self) void {
    const arg = self.pop_arg() orelse return;

    if (std.mem.startsWith(u8, arg, "--")) {
        if (arg.len < 4)
            err_exit(@src(), "invalid long option: '%s'", .{arg.ptr});

        // --name
        // --name=value
        // --name value
        if (std.mem.indexOfScalar(u8, arg, '=')) |sep|
            self.handle_opt(arg[2..sep], arg[sep + 1 ..])
        else
            self.handle_opt(arg[2..], null);
        //
    } else if (std.mem.startsWith(u8, arg, "-")) {
        if (arg.len < 2)
            err_exit(@src(), "invalid short option: '%s'", .{arg.ptr});

        // -x
        // -x5
        // -x=5
        // -x 5
        if (arg.len == 2)
            self.handle_opt(arg[1..], null)
        else if (arg[2] == '=')
            self.handle_opt(arg[1..2], arg[3..])
        else
            self.handle_opt(arg[1..2], arg[2..]);
        //
    } else {
        err_exit(@src(), "expect an option, but got a positional-argument: '%s'", .{arg.ptr});
    }

    return @call(.{ .modifier = .always_tail }, Self.parse_opt, .{self});
}

fn peek_arg(self: Self) ?[:0]const u8 {
    const argv = std.os.argv;

    return if (self.idx < argv.len)
        std.mem.sliceTo(argv[self.idx], 0)
    else
        null;
}

fn pop_arg(self: *Self) ?[:0]const u8 {
    if (self.peek_arg()) |arg| {
        self.idx += 1;
        return arg;
    }
    return null;
}

fn handle_opt(self: *Self, name: []const u8, in_value: ?[:0]const u8) void {
    const optdef = get_optdef(name) orelse
        err_exit(@src(), "unknown option: '%.*s'", .{ cc.to_int(name.len), name.ptr });

    const value = switch (optdef.value) {
        .required => if (in_value) |v| v else self.take_value(name, true),
        .optional => if (in_value) |v| v else self.take_value(name, false),
        .no_value => if (in_value == null) null else {
            err_exit(@src(), "option '%.*s' does not accept any values: '%s'", .{ cc.to_int(name.len), name.ptr, in_value.?.ptr });
        },
    };

    if (value != null and value.?.len <= 0)
        err_exit(@src(), "option '%.*s' does not accept empty string", .{ cc.to_int(name.len), name.ptr });

    optdef.optfn(value);
}

fn take_value(self: *Self, name: []const u8, required: bool) ?[:0]const u8 {
    const arg = self.peek_arg() orelse {
        if (required)
            err_exit(@src(), "expect a value for option '%.*s'", .{ cc.to_int(name.len), name.ptr });
        return null;
    };

    if (required or !std.mem.startsWith(u8, arg, "-")) {
        _ = self.pop_arg();
        return arg;
    }

    return null;
}

fn err_msg(comptime src: std.builtin.SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    cc.printf(log.srcinfo(src, true) ++ " " ++ fmt ++ "\n", args);
}

fn err_exit(comptime src: std.builtin.SourceLocation, comptime fmt: [:0]const u8, args: anytype) noreturn {
    cc.printf(log.srcinfo(src, true) ++ " " ++ fmt ++ "\n", args);
    cc.printf("%s\n", .{help});
    c.exit(1);
}

pub fn parse() void {
    var parser = Self.init();
    parser.parse_opt();

    if (g.chnroute_name.is_null())
        g.chnroute_name.set("chnroute");

    if (g.chnroute6_name.is_null())
        g.chnroute6_name.set("chnroute6");

    if (!g.chnip_setnames.is_null() and g.chnip_setnames.is_empty())
        g.chnip_setnames.set_ex(&.{ g.chnroute_name.str, ",", g.chnroute6_name.str });

    if (g.bind_ips.is_null())
        g.bind_ips.add("127.0.0.1");

    if (g.chinadns_addrs.is_null())
        g.chinadns_addrs.add("114.114.114.114");

    if (g.trustdns_addrs.is_null())
        g.trustdns_addrs.add("8.8.8.8");
}

pub fn @"test: parse option and config"() !void {
    _ = parse;
}
