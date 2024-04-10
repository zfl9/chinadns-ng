const std = @import("std");
const assert = std.debug.assert;

/// ```zig
/// const Flags = enum(u8) {
///     foo = 1 << 0,
///     bar = 1 << 1,
///     xyz = 1 << 2,
///     _, // non-exhaustive enum
///     usingnamespace flags_op.get(Flags);
/// };
/// ```
pub fn get(comptime Enum: type) type {
    comptime assert(@typeInfo(Enum) == .Enum);
    const enum_info = @typeInfo(Enum).Enum;
    const Int = enum_info.tag_type;
    comptime assert(!enum_info.is_exhaustive);

    return struct {
        /// ```zig
        /// const flags = Flags.init(.{.flag_a, .flag_b, .flag_c});
        /// const flags = Flags.init(0xff);
        /// ```
        pub inline fn init(flags: anytype) Enum {
            switch (@typeInfo(@TypeOf(flags))) {
                .Enum, .EnumLiteral => return flags,
                .Int, .ComptimeInt => return @intToEnum(Enum, flags),
                else => comptime {
                    // .{.flag_a, .flag_b, .flag_c}
                    var res = empty();
                    for (flags) |f|
                        res.add(f);
                    return res;
                },
            }
        }

        pub inline fn empty() Enum {
            return init(0);
        }

        pub inline fn full() Enum {
            return init(std.math.maxInt(Int));
        }

        // =====================================================

        pub inline fn int(self: Enum) Int {
            return @enumToInt(self);
        }

        // =====================================================

        pub inline fn add(self: *Enum, in_flags: anytype) void {
            const flags = init(in_flags);
            self.* = init(self.int() | flags.int());
        }

        pub inline fn rm(self: *Enum, in_flags: anytype) void {
            const flags = init(in_flags);
            self.* = init(self.int() & ~flags.int());
        }

        // =====================================================

        /// for single flag bit
        /// for multiple flag bits, equivalent to `has_all`
        pub inline fn has(self: Enum, in_flags: anytype) bool {
            const flags = init(in_flags);
            return self.int() & flags.int() == flags.int();
        }

        /// for multiple flag bits
        pub const has_all = has;

        /// for multiple flag bits
        pub inline fn has_any(self: Enum, in_flags: anytype) bool {
            const flags = init(in_flags);
            return self.int() & flags.int() != 0;
        }

        // =====================================================

        pub inline fn is_empty(self: Enum) bool {
            return self.int() == 0;
        }

        pub inline fn is_full(self: Enum) bool {
            return self.int() == std.math.maxInt(Int);
        }

        // =====================================================

        pub inline fn to_empty(self: *Enum) void {
            self.* = empty();
        }

        pub inline fn to_full(self: *Enum) void {
            self.* = full();
        }
    };
}
