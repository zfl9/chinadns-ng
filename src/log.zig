const std = @import("std");
const cc = @import("cc.zig");
const SourceLocation = std.builtin.SourceLocation;

const Level = enum {
    Debug,
    Info,
    Warning,
    Error,

    fn desc(level: Level) [:0]const u8 {
        return switch (level) {
            .Debug => "D",
            .Info => "I",
            .Warning => "W",
            .Error => "E",
        };
    }

    fn color(level: Level) [:0]const u8 {
        return switch (level) {
            .Debug => "34",
            .Info => "32",
            .Warning => "33",
            .Error => "35",
        };
    }
};

/// year, month, day, hour, min, sec
noinline fn time() [6]c_int {
    const tm = cc.localtime(cc.time()).?;
    return .{ tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec };
}

pub fn srcinfo(comptime src: SourceLocation) [:0]const u8 {
    const filename = b: {
        // remove directories from path
        // can't use std.mem.lastIndexOfScalar because of compiler bugs
        var i = src.file.len - 1;
        while (i >= 0) : (i -= 1)
            if (src.file[i] == '/') break;
        break :b src.file[i + 1 ..];
    };
    const fn_name = b: {
        // remove top-level namespace (filename)
        const i = std.mem.indexOfScalar(u8, src.fn_name, '.') orelse -1;
        break :b src.fn_name[i + 1 ..];
    };
    return std.fmt.comptimePrint("[{s}:{d} {s}]", .{ filename, src.line, fn_name });
}

fn log_write(comptime level: Level, comptime src: SourceLocation, comptime in_fmt: [:0]const u8, in_args: anytype) void {
    const timefmt = "%d-%02d-%02d %02d:%02d:%02d";
    const fmt = "\x1b[" ++ level.color() ++ ";1m" ++ timefmt ++ " " ++ level.desc() ++ "\x1b[0m \x1b[1m%s\x1b[0m" ++ " " ++ in_fmt ++ "\n";
    const t = time();
    const args = .{ t[0], t[1], t[2], t[3], t[4], t[5], comptime srcinfo(src).ptr } ++ in_args;
    @call(.{}, cc.printf, .{ fmt, args });
}

pub fn debug(comptime src: SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    return log_write(.Debug, src, fmt, args);
}

pub fn info(comptime src: SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    return log_write(.Info, src, fmt, args);
}

pub fn warn(comptime src: SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    return log_write(.Warning, src, fmt, args);
}

pub fn err(comptime src: SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    return log_write(.Error, src, fmt, args);
}
