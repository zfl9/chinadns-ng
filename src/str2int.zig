const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const ParseIntError = fmt.ParseIntError;

pub fn parse(comptime T: type, str: []const u8, radix: u8) ParseIntError!T {
    if (@bitSizeOf(T) < 1 or @bitSizeOf(T) > 64)
        @compileError("expected i1..i64 or s1..s64, found " ++ @typeName(T));

    if (comptime std.meta.trait.isSignedInt(T)) {
        const res = try fmt.parseInt(i64, str, radix);
        if (res < math.minInt(T) or res > math.maxInt(T))
            return ParseIntError.Overflow;
        return @intCast(T, res);
    } else {
        const res = try fmt.parseInt(u64, str, radix);
        if (res > math.maxInt(T))
            return ParseIntError.Overflow;
        return @intCast(T, res);
    }
}
