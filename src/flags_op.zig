const std = @import("std");
const assert = std.debug.assert;

/// ```zig
/// const Flags = enum(u8) {
///     foo = 1 << 0,
///     bar = 1 << 1,
///     xyz = 1 << 2,
///     _, // non-exhaustive enum
///     pub usingnamespace flags_op.get(Flags);
/// };
/// ```
pub fn get(comptime Self: type) type {
    comptime assert(@typeInfo(Self) == .Enum);
    const enum_info = @typeInfo(Self).Enum;
    const Int = enum_info.tag_type;
    comptime assert(!enum_info.is_exhaustive);

    return struct {
        /// ```zig
        /// const flags = Flags.init(.{.flag_a, .flag_b, .flag_c});
        /// const flags = Flags.init(0xff);
        /// ```
        pub inline fn init(flags: anytype) Self {
            switch (@typeInfo(@TypeOf(flags))) {
                .Enum, .EnumLiteral => return flags,
                .Int, .ComptimeInt => return @intToEnum(Self, flags),
                else => comptime {
                    // .{.flag_a, .flag_b, .flag_c}
                    var res = empty();
                    for (flags) |f|
                        res.add(f);
                    return res;
                },
            }
        }

        pub inline fn empty() Self {
            return init(0);
        }

        pub inline fn full() Self {
            return init(std.math.maxInt(Int));
        }

        // =====================================================

        pub inline fn int(self: Self) Int {
            return @enumToInt(self);
        }

        // =====================================================

        pub inline fn add(self: *Self, in_flags: anytype) void {
            const flags = init(in_flags);
            self.* = init(self.int() | flags.int());
        }

        pub inline fn rm(self: *Self, in_flags: anytype) void {
            const flags = init(in_flags);
            self.* = init(self.int() & ~flags.int());
        }

        // =====================================================

        /// for single flag bit
        /// for multiple flag bits, equivalent to `has_all`
        pub inline fn has(self: Self, in_flags: anytype) bool {
            const flags = init(in_flags);
            return self.int() & flags.int() == flags.int();
        }

        /// for multiple flag bits
        pub inline fn has_all(self: Self, in_flags: anytype) bool {
            return self.has(in_flags);
        }

        /// for multiple flag bits
        pub inline fn has_any(self: Self, in_flags: anytype) bool {
            const flags = init(in_flags);
            return self.int() & flags.int() != 0;
        }

        // =====================================================

        pub inline fn is_empty(self: Self) bool {
            return self.int() == 0;
        }

        pub inline fn is_full(self: Self) bool {
            return self.int() == std.math.maxInt(Int);
        }

        // =====================================================

        pub inline fn to_empty(self: *Self) void {
            self.* = empty();
        }

        pub inline fn to_full(self: *Self) void {
            self.* = full();
        }
    };
}
