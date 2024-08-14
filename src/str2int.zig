const std = @import("std");

pub fn parse(comptime T: type, str: []const u8, radix: u8) ?T {
    if (@bitSizeOf(T) < 1 or @bitSizeOf(T) > 64)
        @compileError("expected i1..i64 or u1..u64, found " ++ @typeName(T));

    return @intCast(T, parse_internal(
        if (comptime std.meta.trait.isSignedInt(T)) i64 else u64,
        std.math.minInt(T),
        std.math.maxInt(T),
        str,
        radix,
    ) orelse return null);
}

fn parse_internal(
    comptime T: type,
    min_value: T,
    max_value: T,
    str: []const u8,
    radix: u8,
) ?T {
    const res = std.fmt.parseInt(T, str, radix) catch return null;
    if (res < min_value or res > max_value)
        return null;
    return res;
}
